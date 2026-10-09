const { fetchAiJson } = require('./aiRequest');
const { aiExecution } = require('./aiGovernance');
const { anthropicAvailable } = require('./anthropicBaybay');
const { DEFAULT_MODEL, SERVER_FALLBACK_BETA, aiRoute, timeoutFor, firstByteFor, requestControls, anthropicHeaders, warnIgnoredSettings } = require('./aiModels');

const WEB_SEARCH_TOOL = 'web_search_20260318';
const searchError = code => Object.assign(new Error('Claude web search did not return verified results'), { code });
const urlIdentity = value => {
  if (typeof value !== 'string' || value.length > 2000) return null;
  try { const url = new URL(value); url.hash = ''; return url.href; } catch { return null; }
};

function searchPayload(input, { config = {}, instructions, scope, maxToolCalls = 2 } = {}) {
  // Only the service's bounded public query goes to search, never a chat transcript.
  const publicInput = Object.fromEntries(['query', 'locale', 'date', 'region', 'city']
    .filter(key => input[key] !== undefined).map(key => [key, input[key]]));
  // The baybay_web route never resolves to Haiku 5.5: native web search on it is unverified.
  const route = aiRoute('baybay_web', config);
  const controls = requestControls(route, route.model);
  return {
    model: route.model,
    max_tokens: controls.maxTokens,
    output_config: { effort: controls.effort },
    ...(controls.fallbacks ? { fallbacks: controls.fallbacks } : {}),
    // Opus 5.5 does not accept forced tool_choice or disabled thinking.
    tool_choice: { type: 'auto' },
    tools: [{ type: WEB_SEARCH_TOOL, name: 'web_search', allowed_callers: ['direct'], response_inclusion: 'full',
      max_uses: Number.isInteger(maxToolCalls) && maxToolCalls > 0 ? Math.min(maxToolCalls, 2) : 2,
      user_location: { type: 'approximate', country: 'US', region: 'California', city: scope.city || 'San Francisco', timezone: scope.timezone } }],
    system: `${instructions}\nUse the native web_search tool before answering this public lookup. Attach native web search citations to the factual text they support. Do not write citation numbers yourself or include a place-candidate JSON block. If a tool fails or facts are not established, describe them as unknown; never infer that a venue, event or policy does not exist from a failed search.`,
    messages: [{ role: 'user', content: JSON.stringify(publicInput) }],
  };
}

// The server-side search loop can stop at its iteration limit with stop_reason
// "pause_turn". The turn is resumed by sending the same request with the paused
// assistant content appended (no extra user text); each reply continues the same
// assistant turn, so the blocks are joined before normalization. At most
// MAX_CONTINUATIONS resumes, all inside the original deadline.
const MAX_CONTINUATIONS = 2;
const MIN_CONTINUATION_MS = 2000;

async function requestAnthropicSearch(payload, { config = {}, ai, fetchImpl, timeoutMs, signal } = {}) {
  const route = aiRoute('baybay_web', config), deadline = timeoutFor(route, timeoutMs), started = Date.now();
  let send;
  if (ai) send = body => ai(body);
  else {
    const upstream = aiExecution()?.signal;
    const requestSignal = signal && upstream ? AbortSignal.any([signal, upstream]) : signal || upstream;
    warnIgnoredSettings(route);
    send = (body, budgetMs) => fetchAiJson('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: anthropicHeaders(config, body.fallbacks ? [SERVER_FALLBACK_BETA] : []),
      body: JSON.stringify(body), ...(requestSignal ? { signal: requestSignal } : {}),
    }, { timeoutMs: budgetMs, firstByteMs: firstByteFor(route, budgetMs), fetchImpl: (url, init) => {
      // Recheck after fetchAiJson's asynchronous quota reservation, before transport.
      if (!anthropicAvailable(config)) throw searchError('web_not_configured');
      return (fetchImpl || fetch)(url, init);
    } });
  }
  let response = await send(payload, deadline);
  const turn = [];
  for (let resumes = 0; response?.stop_reason === 'pause_turn' && Array.isArray(response.content) && resumes < MAX_CONTINUATIONS; resumes++) {
    const remaining = deadline - (Date.now() - started);
    if (!(remaining >= MIN_CONTINUATION_MS)) break;
    turn.push(...response.content);
    response = await send({ ...payload, messages: [...payload.messages, { role: 'assistant', content: [...turn] }] }, remaining);
  }
  // A turn still paused after the last resume stays "pause_turn" and is rejected
  // by normalizeAnthropicSearch as an incomplete response.
  return turn.length && Array.isArray(response?.content) ? { ...response, content: [...turn, ...response.content] } : response;
}

// Adapt native, block-level citations to the existing search validator. The
// adapter never promotes hand-written links or search snippets into citations.
// DNS/SSRF, scope, numbered citations and candidate checks remain centralized.
function normalizeAnthropicSearch(response, { maxToolCalls = 2 } = {}) {
  if (response?.role !== 'assistant' || response.stop_reason !== 'end_turn' || !Array.isArray(response.content)
    || response.content.length > 128 || response.content.some(block => ['refusal', 'tool_use'].includes(block?.type))) {
    throw searchError('web_incomplete_response');
  }
  const toolCalls = new Set(); const completedCalls = new Set(); const retrieved = new Map();
  let lastResult = -1;
  for (let index = 0; index < response.content.length; index++) {
    const block = response.content[index];
    if (block?.type === 'server_tool_use') {
      if (block.name !== 'web_search' || typeof block.id !== 'string' || !block.id || toolCalls.has(block.id)) throw searchError('web_incomplete_response');
      toolCalls.add(block.id);
    }
    if (block?.type !== 'web_search_tool_result') continue;
    if (!toolCalls.has(block.tool_use_id) || completedCalls.has(block.tool_use_id)) throw searchError('web_incomplete_response');
    if (!Array.isArray(block.content)) {
      const error = block.content?.error_code;
      throw searchError(error === 'too_many_requests' ? 'web_provider_rate_limit'
        : ['invalid_tool_input', 'query_too_long', 'request_too_large'].includes(error) ? 'web_provider_request'
          : error === 'max_uses_exceeded' ? 'web_incomplete_response' : 'web_provider_unavailable');
    }
    if (block.content.length > 100) throw searchError('web_incomplete_response');
    for (const source of block.content) {
      if (source?.type !== 'web_search_result') throw searchError('web_provider_unavailable');
      const url = urlIdentity(source.url);
      if (url) retrieved.set(url, source);
    }
    completedCalls.add(block.tool_use_id); lastResult = index;
  }
  if (!completedCalls.size || toolCalls.size !== completedCalls.size || toolCalls.size > Math.min(maxToolCalls, 2)) throw searchError('web_incomplete_response');
  let text = ''; const annotations = [];
  // Only render final answer blocks after the final search; intermediate plans
  // and reasoning must not be mistaken for an evidence-backed answer.
  for (const block of response.content.slice(lastResult + 1)) {
    if (block?.type !== 'text' || typeof block.text !== 'string') continue;
    text += block.text;
    for (const citation of (Array.isArray(block.citations) ? block.citations : []).slice(0, 60)) {
      const source = retrieved.get(urlIdentity(citation?.url));
      if (!block.text.trim() || citation?.type !== 'web_search_result_location' || !source
        || typeof citation.encrypted_index !== 'string' || !citation.encrypted_index.trim() || annotations.length >= 60) continue;
      text += ' ';
      const start = text.length;
      text += '\uFFFC';
      annotations.push({ type: 'url_citation', url: source.url, title: source.title,
        start_index: start, end_index: text.length });
    }
    if (text.length > 12000) throw searchError('web_incomplete_response');
  }
  return { status: 'completed', model: response.model,
    output: [
      ...[...completedCalls].map(() => ({ type: 'web_search_call', status: 'completed', action: { type: 'search' } })),
      { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations }] },
    ],
  };
}

module.exports = { searchPayload, requestAnthropicSearch, normalizeAnthropicSearch, DEFAULT_MODEL, WEB_SEARCH_TOOL, MAX_CONTINUATIONS };
