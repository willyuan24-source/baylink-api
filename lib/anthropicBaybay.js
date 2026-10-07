const { fetchAiJson } = require('./aiRequest');

const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5-5';
const clone = value => JSON.parse(JSON.stringify(value));
const count = value => Number.isInteger(value) && value >= 0 ? value : 0;
const baybayProvider = config => String(config.BAYBAY_AI_PROVIDER || 'openai').trim().toLowerCase();
const baybayModel = config => baybayProvider(config) === 'anthropic'
  ? config.ANTHROPIC_BAYBAY_MODEL || DEFAULT_ANTHROPIC_MODEL
  : config.OPENAI_BAYBAY_MODEL || 'gpt-6.1-sol';

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
  for (const block of response.content) {
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

/** One instance per assistant run: preserve raw assistant blocks/signatures and
 * their complete prefix, while exposing only Responses-shaped text/tool calls.
 * The caller appends normalized output and tool results to its input cursor. */
function createAnthropicBaybay({ config = {}, fetchImpl } = {}) {
  let history = [], consumed = [], initialSystem, initialTools, initialModel;
  return async (payload, { timeoutMs = 18000, signal } = {}) => {
    if (!anthropicAvailable(config)) throw new Error('Anthropic is unavailable or its configured usage window has ended');
    const input = clone(payload.input || []);
    if (JSON.stringify(input.slice(0, consumed.length)) !== JSON.stringify(consumed)) throw new Error('Anthropic conversation must remain append-only');
    const toolDefinitions = (payload.tools || []).map(tool => ({ name: tool.name, description: tool.description, input_schema: anthropicSchema(tool.parameters), strict: true }));
    const system = payload.instructions || '';
    const model = payload.model || baybayModel({ ...config, BAYBAY_AI_PROVIDER: 'anthropic' });
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
    const body = { model, system, messages, max_tokens: payload.max_output_tokens,
      tools: toolDefinitions, tool_choice: { type: payload.tool_choice === 'none' ? 'none' : 'auto' },
      output_config: { effort: config.ANTHROPIC_BAYBAY_EFFORT === 'low' ? 'low' : 'medium',
        ...(payload.text?.format?.schema ? { format: { type: 'json_schema', schema: anthropicSchema(payload.text.format.schema) } } : {}) },
    };
    const response = await fetchAiJson('https://api.anthropic.com/v1/messages', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.ANTHROPIC_API_KEY}`, 'anthropic-version': '2023-06-01',
        ...(config.ANTHROPIC_WORKSPACE_ID ? { 'anthropic-workspace-id': config.ANTHROPIC_WORKSPACE_ID } : {}) },
      body: JSON.stringify(body), ...(signal ? { signal } : {}),
    }, { timeoutMs, fetchImpl: (url, init) => {
      // Quota reservation is asynchronous; the use window can end while it runs.
      if (!anthropicAvailable(config)) throw new Error('Anthropic is unavailable or its configured usage window has ended');
      return (fetchImpl || fetch)(url, init);
    } });
    const normalized = normalizedResponse(response);
    initialSystem = system; initialModel = model; initialTools = clone(toolDefinitions);
    consumed = [...input, ...clone(normalized.output)];
    // Incomplete/refused assistant turns are never replayed as valid history.
    history = normalized.status === 'completed' ? [...messages, { role: 'assistant', content: clone(response.content) }] : messages;
    return normalized;
  };
}

module.exports = { createAnthropicBaybay, anthropicSchema, normalizedResponse, baybayProvider, baybayModel, anthropicAvailable, DEFAULT_ANTHROPIC_MODEL };
