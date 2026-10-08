const { fetchAiJson } = require('./aiRequest');
const { DEFAULT_MODEL, REFUSAL_RETRY_MODEL, aiRoute, modelFamily, timeoutFor, firstByteFor, requestControls, anthropicHeaders, promptOverCap, logPromptCap, warnIgnoredSettings, logRefusalRetry } = require('./aiModels');

const DEFAULT_ANTHROPIC_MODEL = DEFAULT_MODEL;
const clone = value => JSON.parse(JSON.stringify(value));
const count = value => Number.isInteger(value) && value >= 0 ? value : 0;
const baybayProvider = config => String(config.BAYBAY_AI_PROVIDER || 'openai').trim().toLowerCase();
// A BayBay route's model (the agent route unless named). Since R0 the agent route
// defaults to Claude Sonnet 5.5 (lib/aiModels.js); BAYBAY_MODEL_AGENT overrides it.
const baybayModel = (config, route = 'baybay_agent') => baybayProvider(config) === 'anthropic'
  ? aiRoute(route, config).model
  : config.OPENAI_BAYBAY_MODEL || 'gpt-6.1-sol';
// The Claude route for one BayBay run. Guarded professional-topic runs (safetyTopic)
// use baybay_professional, which never resolves to Haiku (RC-20). baybayAgent.js
// creates every run with createAnthropicBaybay({ config, fetchImpl, route: baybayRoute({ safetyTopic }) }).
const baybayRoute = ({ safetyTopic } = {}) => safetyTopic ? 'baybay_professional' : 'baybay_agent';

function anthropicAvailable(config, now = Date.now()) {
  if (typeof config.ANTHROPIC_API_KEY !== 'string' || !config.ANTHROPIC_API_KEY.trim()) return false;
  const until = config.ANTHROPIC_USE_UNTIL;
  if (until == null || until === '') return true;
  if (typeof until !== 'string' || !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?$/.test(until)) return false;
  const expiry = Date.parse(until), day = until.slice(0, 10);
  const [year, month, date] = day.split('-').map(Number);
  const validDay = new Date(Date.UTC(year, month - 1, date)).toISOString().slice(0, 10) === day;
  return validDay && Number.isFinite(expiry) && Number.isFinite(now) && now < expiry;
}

// Claude's constrained decoder does not support these bounds. The BayBay
// parsers/tool handlers retain their application limits after decoding.
const UNSUPPORTED_BOUNDS = new Set(['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'minLength', 'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'minProperties', 'maxProperties']);
function anthropicSchema(schema) {
  if (Array.isArray(schema)) return schema.map(anthropicSchema);
  if (!schema || typeof schema !== 'object') return schema;
  return Object.fromEntries(Object.entries(schema).filter(([key]) => !UNSUPPORTED_BOUNDS.has(key)).map(([key, value]) => [key,
    // Property names are data, even when named "maximum" or "maxItems".
    ['properties', '$defs', 'definitions'].includes(key) ? Object.fromEntries(Object.entries(value).map(([name, child]) => [name, anthropicSchema(child)])) : anthropicSchema(value)]));
}

function normalizedResponse(response) {
  const rawUsage = response?.usage || {};
  const usage = { ...rawUsage,
    input_tokens: count(rawUsage.input_tokens) + count(rawUsage.cache_creation_input_tokens) + count(rawUsage.cache_read_input_tokens),
    output_tokens: count(rawUsage.output_tokens),
    input_tokens_details: { cached_tokens: count(rawUsage.cache_read_input_tokens) },
    ...(Number.isInteger(rawUsage.output_tokens_details?.thinking_tokens) ? { output_tokens_details: { ...rawUsage.output_tokens_details, reasoning_tokens: rawUsage.output_tokens_details.thinking_tokens } } : {}),
  };
  const base = { id: response?.id, model: response?.model, usage, output: [] };
  if (response?.type === 'error' || response?.error) return { ...base, status: 'failed' };
  if (response?.stop_reason === 'refusal') return { ...base, status: 'incomplete', incomplete_details: { reason: 'content_filter' } };
  if (['max_tokens', 'model_context_window_exceeded'].includes(response?.stop_reason)) {
    // Even valid-looking JSON can be an unfinished answer. Never expose text or
    // execute a partial tool call from a token-limited Anthropic response.
    return { ...base, status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } };
  }
  if (!['end_turn', 'tool_use'].includes(response?.stop_reason) || !Array.isArray(response?.content)) return { ...base, status: 'failed' };
  const output = [];
  // After a server-side fallback marker only the serving model's blocks count.
  for (const block of replayableContent(response.content)) {
    if (block.type === 'text' && typeof block.text === 'string') output.push({ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: block.text }] });
    if (block.type === 'tool_use') {
      if (!block.id || !block.name || !block.input || typeof block.input !== 'object' || Array.isArray(block.input)) return { ...base, status: 'failed' };
      output.push({ type: 'function_call', call_id: block.id, name: block.name, arguments: JSON.stringify(block.input) });
    }
  }
  const hasTools = output.some(item => item.type === 'function_call');
  if ((response.stop_reason === 'tool_use') !== hasTools) return { ...base, status: 'failed' };
  return { ...base, status: 'completed', output };
}

// After a server-side fallback switch, blocks the declining model produced before
// the last `fallback` marker are not replayed (only its text continues), and the
// marker itself is an audit block. Without a marker the content replays verbatim.
function replayableContent(content) {
  const blocks = clone(content);
  const boundary = blocks.map(block => block?.type).lastIndexOf('fallback');
  if (boundary < 0) return blocks;
  return [...blocks.slice(0, boundary).filter(block => block?.type === 'text'), ...blocks.slice(boundary + 1)];
}

/** One instance per assistant run: preserve raw assistant blocks/signatures and
 * their complete prefix, while exposing only Responses-shaped text/tool calls.
 * The caller appends normalized output and tool results to its input cursor.
 * `route` selects the aiModels configuration (model, effort, output budget,
 * deadlines). On a route other than baybay_agent the route also decides the model:
 * baybayAgent sends baybayModel(config) (the agent route's model) on every run, so
 * that value is accepted and replaced by the route's model; any other model is an
 * error rather than a silent mix of one route's model with another's controls. */
function createAnthropicBaybay({ config = {}, fetchImpl, route = 'baybay_agent', log } = {}) {
  const routeConfig = aiRoute(route, config);
  warnIgnoredSettings(routeConfig, log);
  const agentModel = route === 'baybay_agent' ? null : aiRoute('baybay_agent', config).model;
  const modelFor = requested => {
    if (!agentModel) return requested || routeConfig.model;
    if (!requested || requested === routeConfig.model || requested === agentModel) return routeConfig.model;
    throw new Error('Anthropic model must come from the route configuration');
  };
  let history = [], consumed = [], initialSystem, initialTools, initialModel, retryModel;
  return async (payload, { timeoutMs = 18000, signal } = {}) => {
    if (!anthropicAvailable(config)) throw new Error('Anthropic is unavailable or its configured usage window has ended');
    const input = clone(payload.input || []);
    if (JSON.stringify(input.slice(0, consumed.length)) !== JSON.stringify(consumed)) throw new Error('Anthropic conversation must remain append-only');
    const toolDefinitions = (payload.tools || []).map(tool => ({ name: tool.name, description: tool.description, input_schema: anthropicSchema(tool.parameters), strict: true }));
    const system = payload.instructions || '';
    const model = modelFor(payload.model);
    if (initialSystem !== undefined && (system !== initialSystem || model !== initialModel || JSON.stringify(toolDefinitions) !== JSON.stringify(initialTools))) {
      throw new Error('Anthropic system, model and tools must remain unchanged during a run');
    }
    const additions = [];
    for (const item of input.slice(consumed.length)) {
      if (item.type === 'function_call_output') {
        let isError = false;
        try { isError = !!JSON.parse(item.output)?.error; } catch { /* Non-JSON tool results remain text. */ }
        const block = { type: 'tool_result', tool_use_id: item.call_id, content: String(item.output), ...(isError ? { is_error: true } : {}) };
        const previous = additions.at(-1);
        if (previous?.role === 'user' && previous.content.every(part => part.type === 'tool_result')) previous.content.push(block);
        else additions.push({ role: 'user', content: [block] });
      } else if (['user', 'assistant'].includes(item.role) && typeof item.content === 'string') {
        additions.push({ role: item.role, content: [{ type: 'text', text: item.content }] });
      } else throw new Error('Unsupported Anthropic conversation input');
    }
    const messages = [...history, ...additions];
    const started = Date.now(), deadline = timeoutFor(routeConfig, timeoutMs);
    // Only route-controlled fields reach the provider: never temperature/top_p/top_k.
    const send = async (target, budgetMs) => {
      const controls = requestControls(routeConfig, target, payload.max_output_tokens);
      const body = { model: target, system, messages, max_tokens: controls.maxTokens,
        ...(controls.thinking ? { thinking: controls.thinking } : {}),
        tools: toolDefinitions, tool_choice: { type: payload.tool_choice === 'none' ? 'none' : 'auto' },
        output_config: { effort: controls.effort,
          ...(payload.text?.format?.schema ? { format: { type: 'json_schema', schema: anthropicSchema(payload.text.format.schema) } } : {}) },
        ...(controls.fallbacks ? { fallbacks: controls.fallbacks } : {}),
      };
      return fetchAiJson('https://api.anthropic.com/v1/messages', {
        method: 'POST', headers: anthropicHeaders(config, controls.betas), body: JSON.stringify(body), ...(signal ? { signal } : {}),
      }, { timeoutMs: budgetMs, firstByteMs: firstByteFor(routeConfig, budgetMs), fetchImpl: (url, init) => {
        // Quota reservation is asynchronous; the use window can end while it runs.
        if (!anthropicAvailable(config)) throw new Error('Anthropic is unavailable or its configured usage window has ended');
        return (fetchImpl || fetch)(url, init);
      } });
    };
    // After a Haiku refusal or prompt-cap escalation the rest of this run stays on the retry model.
    let target = retryModel || model;
    const overCap = promptOverCap({ model: target, system, messages, tools: toolDefinitions });
    if (overCap) {
      // A Haiku prompt above the cap is answered by Claude Sonnet 5.5 instead of failing:
      // it has no 100K price cliff and reads Haiku 5.5 thinking blocks already in history.
      retryModel = REFUSAL_RETRY_MODEL;
      logPromptCap({ route: routeConfig.route, from: target, to: retryModel, ...overCap }, log);
      target = retryModel;
    }
    let response = await send(target, deadline);
    if (response?.stop_reason === 'refusal' && modelFamily(target) === 'haiku') {
      // Claude Haiku 5.5 has no server-side fallback. Retry the identical request
      // once on Claude Sonnet 5.5, which reads Haiku 5.5 thinking blocks.
      retryModel = REFUSAL_RETRY_MODEL;
      logRefusalRetry({ route: routeConfig.route, from: target, to: retryModel, response }, log);
      response = await send(retryModel, deadline === undefined ? undefined : Math.max(1000, deadline - (Date.now() - started)));
    }
    const normalized = normalizedResponse(response);
    initialSystem = system; initialModel = model; initialTools = clone(toolDefinitions);
    consumed = [...input, ...clone(normalized.output)];
    // Incomplete/refused assistant turns are never replayed as valid history.
    history = normalized.status === 'completed' ? [...messages, { role: 'assistant', content: replayableContent(response.content) }] : messages;
    return normalized;
  };
}

module.exports = { createAnthropicBaybay, anthropicSchema, normalizedResponse, replayableContent, baybayProvider, baybayModel, baybayRoute, anthropicAvailable, DEFAULT_ANTHROPIC_MODEL };
