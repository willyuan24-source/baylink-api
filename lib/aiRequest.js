const { aiExecution, assertActive, reserveAiCall, cancelled } = require('./aiGovernance');
const { claudeCost } = require('./aiPricing');
const { bayAreaDate } = require('./eventEngagement');
const { performance } = require('node:perf_hooks');
const tokenCount = value => Number.isSafeInteger(value) && value >= 0;
function normalizedUsage(result) {
  const usage = result?.usage || {};
  if (result?.type !== 'message' || !tokenCount(usage.input_tokens)) return usage;
  // Claude reports uncached input separately from cache writes/reads. Output
  // already includes thinking; adding thinking tokens would double-count it.
  const input = usage.input_tokens + (tokenCount(usage.cache_creation_input_tokens) ? usage.cache_creation_input_tokens : 0)
    + (tokenCount(usage.cache_read_input_tokens) ? usage.cache_read_input_tokens : 0);
  return { ...usage, input_tokens: input };
}
// Billing view of one parsed provider response. Raw Claude cache reads and cache
// writes stay separate here (normalizedUsage folds them into total input for the
// existing token counters). Non-Claude or unknown models are reported unpriced.
function billingFor(result, requestedModel, now = Date.now()) {
  if (result?.type !== 'message' || !result.usage || typeof result.usage !== 'object') return { priced: false };
  const cost = claudeCost({ model: result.model || requestedModel, usage: result.usage, day: bayAreaDate(now) });
  return cost.priced ? { priced: true, microUsd: cost.microUsd, card: cost.card, cacheReadTokens: cost.usage.cacheReadTokens, cacheWriteTokens: cost.usage.cacheWriteTokens }
    : { priced: false };
}
const timeoutError = message => Object.assign(new Error(message), { code: 'AI_PROVIDER_TIMEOUT' });
// Seconds form of retry-after only (the providers send integers); anything else is ignored.
function retryAfterMs(response) {
  let value;
  try { value = response?.headers?.get?.('retry-after'); } catch { return undefined; }
  return typeof value === 'string' && /^\d{1,5}$/.test(value.trim()) ? Number(value.trim()) * 1000 : undefined;
}
// The message stays "AI provider HTTP <status>" (callers parse it); the status and
// retry-after travel as fields so a caller can retry 429/529 without string matching.
function httpError(response) {
  const retryAfter = retryAfterMs(response);
  return Object.assign(new Error(`AI provider HTTP ${response.status}`), { providerStatus: response.status,
    ...(retryAfter !== undefined ? { retryAfterMs: retryAfter } : {}) });
}
// Bound request/body read; propagate caller disconnects into provider fetches.
// `firstByteMs` (optional, shorter than timeoutMs) bounds the wait for response headers.
async function fetchAiJson(url, options, { fetchImpl = fetch, timeoutMs = 12000, firstByteMs } = {}) {
  await reserveAiCall();
  const execution = aiExecution(), upstream = options.signal || execution?.signal;
  assertActive(upstream);
  const controller = new AbortController();
  let rejectAbort;
  const abort = () => { controller.abort(); rejectAbort?.(cancelled()); };
  upstream?.addEventListener('abort', abort, { once: true });
  let timer, firstByteTimer, ttftMs;
  const started = performance.now();
  let requestedModel;
  try { requestedModel = JSON.parse(options.body)?.model; } catch { /* Non-JSON inputs use the fixed 'other' bucket. */ }
  const recordRuntime = execution?.runtime?.providerStarted(requestedModel);
  const waitForFirstByte = Number.isSafeInteger(firstByteMs) && firstByteMs > 0 && firstByteMs < timeoutMs;
  try {
    const result = await Promise.race([
      new Promise((_, reject) => { rejectAbort = reject; if (upstream?.aborted) abort(); }),
      (async () => {
        const response = await fetchImpl(url, { ...options, signal: controller.signal });
        // Time to response headers. For non-streaming Messages calls this is
        // close to the complete generation; streaming calls will start earlier.
        ttftMs = performance.now() - started; clearTimeout(firstByteTimer);
        if (!response.ok) throw httpError(response);
        return response.json();
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(timeoutError('AI request timed out')); }, timeoutMs);
        if (waitForFirstByte) firstByteTimer = setTimeout(() => { if (ttftMs === undefined) { controller.abort(); reject(timeoutError('AI request timed out before the first byte')); } }, firstByteMs);
      }),
    ]);
    const usage = normalizedUsage(result);
    const durationMs = performance.now() - started;
    const refusal = result?.stop_reason === 'refusal';
    const outcome = result?.status === 'failed' || result?.type === 'error' || refusal ? 'error'
      : result?.status === 'cancelled' ? 'cancelled'
        : ['incomplete', 'queued', 'in_progress'].includes(result?.status) || ['max_tokens', 'model_context_window_exceeded', 'pause_turn'].includes(result?.stop_reason) ? 'incomplete' : 'completed';
    const billing = billingFor(result, requestedModel);
    recordRuntime?.({ outcome, durationMs, usage, model: result?.model, ttftMs, billing, refusal });
    await Promise.all([
      execution?.record({ calls: 1, inputTokens: usage.input_tokens ?? usage.prompt_tokens ?? 0, outputTokens: usage.output_tokens ?? usage.completion_tokens ?? 0, latencyMs: Math.round(durationMs) }),
      execution?.recordSpend?.(billing),
    ]);
    return result;
  } catch (error) {
    recordRuntime?.({ outcome: upstream?.aborted ? 'cancelled' : error.code === 'AI_PROVIDER_TIMEOUT' ? 'timeout' : 'error', durationMs: performance.now() - started });
    await execution?.record({ failures: 1 });
    if (upstream?.aborted) throw cancelled();
    throw error;
  } finally { clearTimeout(timer); clearTimeout(firstByteTimer); upstream?.removeEventListener('abort', abort); }
}
module.exports = { fetchAiJson, normalizedUsage, billingFor };
