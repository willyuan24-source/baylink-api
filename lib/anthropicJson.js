const { fetchAiJson } = require('./aiRequest');
const { aiExecution } = require('./aiGovernance');
const { anthropicAvailable, anthropicSchema, baybayProvider } = require('./anthropicBaybay');
const { REFUSAL_RETRY_MODEL, aiRoute, routeForFeature, modelFamily, timeoutFor, firstByteFor, requestControls, anthropicHeaders, assertPromptWithinCap, logRefusalRetry } = require('./aiModels');

const error = (status, code, message) => Object.assign(new Error(message), { status, code });
const unavailable = () => error(503, 'AI_PROVIDER_UNAVAILABLE', 'AI is temporarily unavailable. Please try again.');
const positive = (value, fallback, maximum) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Math.min(Number(value), maximum) : fallback;
const object = value => value && typeof value === 'object' && !Array.isArray(value);

function selectedAiAvailable(config = {}, now = Date.now()) {
  const provider = baybayProvider(config);
  return provider === 'anthropic' ? anthropicAvailable(config, now) : provider === 'openai' && !!config.OPENAI_API_KEY;
}

function imageBlock(value) {
  const invalid = () => error(400, 'AI_IMAGE_INVALID', 'Use a PNG, JPEG, GIF or WebP data image up to 3 MB.');
  if (typeof value !== 'string' || value.length > 4 * 1024 * 1024 + 50) throw invalid();
  const match = value.match(/^data:image\/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!match || match[2].length % 4 !== 0) throw invalid();
  const bytes = Buffer.from(match[2], 'base64');
  const valid = match[1] === 'png' ? bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
    : match[1] === 'jpeg' ? bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255
      : match[1] === 'gif' ? ['GIF87a', 'GIF89a'].includes(bytes.toString('ascii', 0, 6))
        : bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP';
  if (!valid || !bytes.length || bytes.length > 3 * 1024 * 1024 || bytes.toString('base64') !== match[2]) throw invalid();
  return { type: 'image', source: { type: 'base64', media_type: `image/${match[1]}`, data: match[2] } };
}

function nativeMessages(messages) {
  if (!Array.isArray(messages) || !messages.length) throw unavailable();
  const system = [], conversation = [];
  for (const message of messages) {
    if (message?.role === 'system' && typeof message.content === 'string' && !conversation.length) {
      system.push(message.content); continue;
    }
    if (!['user', 'assistant'].includes(message?.role)) throw unavailable();
    const parts = typeof message.content === 'string' ? [{ type: 'text', text: message.content }] : message.content;
    if (!Array.isArray(parts) || !parts.length) throw unavailable();
    const content = parts.map(part => {
      if (part?.type === 'text' && typeof part.text === 'string' && part.text.trim()) return { type: 'text', text: part.text };
      if (message.role === 'user' && part?.type === 'image_url') return imageBlock(part.image_url?.url);
      throw unavailable();
    });
    conversation.push({ role: message.role, content });
  }
  if (conversation[0]?.role !== 'user' || conversation.at(-1)?.role !== 'user') throw unavailable();
  system.push('Return exactly one valid JSON object and nothing else. Do not wrap it in Markdown or include reasoning, commentary or text outside the JSON object.');
  return { system: system.join('\n\n'), messages: conversation };
}

/** One bounded Claude JSON request. Callers select the provider before entering
 * this helper and retain their application-specific output validators. `route`
 * names the aiModels helper route; without it the governed request's feature
 * decides (post-assist -> helper_post_assist, and so on), else helper_other. */
async function requestAnthropicJson(messages, { config = {}, fetchImpl, timeoutMs = 28000, maxTokens = 6000, schema, signal, route, log } = {}) {
  if (!['openai', 'anthropic'].includes(baybayProvider(config)) || !anthropicAvailable(config)) throw unavailable();
  const routeConfig = aiRoute(route || routeForFeature(aiExecution()?.feature), config);
  const input = nativeMessages(messages);
  const deadline = timeoutFor(routeConfig, positive(timeoutMs, 28000, 28000));
  const bodyFor = model => {
    const controls = requestControls(routeConfig, model, maxTokens);
    // Only route-controlled fields reach the provider: never temperature/top_p/top_k.
    const body = { model, ...input, max_tokens: controls.maxTokens,
      ...(controls.thinking ? { thinking: controls.thinking } : {}),
      output_config: { effort: controls.effort,
        ...(schema ? { format: { type: 'json_schema', schema: anthropicSchema(schema) } } : {}) },
      ...(controls.fallbacks ? { fallbacks: controls.fallbacks } : {}),
    };
    try { assertPromptWithinCap(body); } catch { throw error(503, 'AI_PROMPT_TOO_LARGE', 'AI is temporarily unavailable. Please try again.'); }
    return { body, betas: controls.betas };
  };
  const signals = [signal, aiExecution()?.signal].filter(Boolean);
  const upstream = signals.length > 1 ? AbortSignal.any(signals) : signals[0];
  // Check now and again after governance reservation, which may itself wait
  // beyond the usage window before starting paid transport.
  if (!anthropicAvailable(config)) throw unavailable();
  const transport = fetchImpl || fetch;
  const started = Date.now();
  const send = ({ body, betas }, budgetMs) => fetchAiJson('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: anthropicHeaders(config, betas),
    body: JSON.stringify(body), ...(upstream ? { signal: upstream } : {}),
  }, { timeoutMs: budgetMs, firstByteMs: firstByteFor(routeConfig, budgetMs), fetchImpl: (url, init) => {
    if (!anthropicAvailable(config)) throw unavailable();
    return transport(url, init);
  } });
  let data = await send(bodyFor(routeConfig.model), deadline);
  if (data?.stop_reason === 'refusal' && modelFamily(routeConfig.model) === 'haiku') {
    // Claude Haiku 5.5 has no server-side fallback: retry once on Claude Sonnet 5.5.
    logRefusalRetry({ route: routeConfig.route, from: routeConfig.model, to: REFUSAL_RETRY_MODEL, response: data }, log);
    data = await send(bodyFor(REFUSAL_RETRY_MODEL), Math.max(1000, deadline - (Date.now() - started)));
  }
  if (data?.type === 'error' || data?.error) throw unavailable();
  if (data?.stop_reason === 'refusal') throw error(502, 'AI_RESPONSE_REFUSED', 'AI could not complete this JSON response.');
  if (['max_tokens', 'model_context_window_exceeded'].includes(data?.stop_reason)) throw error(502, 'AI_RESPONSE_INCOMPLETE', 'AI could not complete this JSON response.');
  const invalid = () => error(502, 'AI_RESPONSE_INVALID', 'AI returned an unusable JSON response.');
  if (data?.stop_reason !== 'end_turn' || !Array.isArray(data?.content) || data.content.some(block => block?.type === 'tool_use')) throw invalid();
  const text = data.content.filter(block => block?.type === 'text' && typeof block.text === 'string').map(block => block.text).join('');
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw invalid(); }
  if (!object(parsed)) throw invalid();
  return parsed;
}

module.exports = { selectedAiAvailable, requestAnthropicJson };
