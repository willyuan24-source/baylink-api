const { aiExecution, assertActive, reserveAiCall, cancelled } = require('./aiGovernance');
const { claudeCost } = require('./aiPricing');
const { bayAreaDate } = require('./eventEngagement');
const { performance } = require('node:perf_hooks');
const { createMessageAccumulator, readMessageStream, estimatedUsage } = require('./anthropicStream');
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
// Bound request/body read; propagate caller disconnects into provider fetches.
// `firstByteMs` (optional, shorter than timeoutMs) bounds the wait for response headers.
async function fetchAiJson(url, options, { fetchImpl = fetch, timeoutMs = 12000, firstByteMs } = {}) {
  return governedFetch(url, options, { fetchImpl, timeoutMs, firstByteMs });
}
/** A streamed Claude Messages call (`stream: true` in the body, API-BB-STREAM): the
 * same governance, deadlines and accounting as fetchAiJson, and the same result (the
 * complete message rebuilt from the SSE events, lib/anthropicStream.js).
 * `onDelta` sees content as it arrives. TTFT is the first text or tool-input delta.
 * A stream cut by a timeout or an abort records an estimated usage and spend
 * (input as reported at message_start, output estimated from the text received). */
async function fetchAiStream(url, options, { fetchImpl = fetch, timeoutMs = 12000, firstByteMs, onDelta } = {}) {
  return governedFetch(url, options, { fetchImpl, timeoutMs, firstByteMs, stream: { onDelta } });
}
async function governedFetch(url, options, { fetchImpl, timeoutMs, firstByteMs, stream }) {
  let requestedModel, webSearch = false;
  try {
    const body = JSON.parse(options.body);
    requestedModel = body?.model;
    // Claude `web_search_*` and OpenAI `web_search*` tools: refused past the soft $ cap (API-BB-CUTOVER).
    webSearch = Array.isArray(body?.tools) && body.tools.some(tool => /^web_search/.test(String(tool?.type || '')));
  } catch { /* Non-JSON inputs use the fixed 'other' bucket. */ }
  await reserveAiCall({ webSearch });
  const execution = aiExecution(), upstream = options.signal || execution?.signal;
  assertActive(upstream);
  const controller = new AbortController();
  let rejectAbort;
  const abort = () => { controller.abort(); rejectAbort?.(cancelled()); };
  upstream?.addEventListener('abort', abort, { once: true });
  let timer, firstByteTimer, ttftMs, headersMs;
  const started = performance.now();
  const recordRuntime = execution?.runtime?.providerStarted(requestedModel);
  const waitForFirstByte = Number.isSafeInteger(firstByteMs) && firstByteMs > 0 && firstByteMs < timeoutMs;
  const accumulator = stream ? createMessageAccumulator({ onDelta: delta => {
    if (ttftMs === undefined && (delta.type === 'text' || delta.type === 'input_json')) ttftMs = performance.now() - started;
    stream.onDelta?.(delta);
  } }) : null;
  try {
    const result = await Promise.race([
      new Promise((_, reject) => { rejectAbort = reject; if (upstream?.aborted) abort(); }),
      (async () => {
        const response = await fetchImpl(url, { ...options, signal: controller.signal });
        // Time to response headers. For non-streaming Messages calls this is
        // close to the complete generation; a streamed call measures its first
        // text or tool-input delta instead (no delta: the headers time).
        headersMs = performance.now() - started; clearTimeout(firstByteTimer);
        if (!stream) ttftMs = headersMs;
        if (!response.ok) throw new Error(`AI provider HTTP ${response.status}`);
        if (!stream) return response.json();
        const message = await readMessageStream(response.body, accumulator);
        ttftMs ??= headersMs;
        return message;
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(timeoutError('AI request timed out')); }, timeoutMs);
        if (waitForFirstByte) firstByteTimer = setTimeout(() => { if (headersMs === undefined) { controller.abort(); reject(timeoutError('AI request timed out before the first byte')); } }, firstByteMs);
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
    const outcome = upstream?.aborted ? 'cancelled' : error.code === 'AI_PROVIDER_TIMEOUT' ? 'timeout' : 'error';
    // A streamed call that was cut after message_start has billable usage the
    // provider never reported: record an estimate instead of nothing.
    const partial = accumulator?.partial();
    if (partial?.usage) {
      const estimate = { type: 'message', model: partial.model, usage: estimatedUsage(partial) };
      const usage = normalizedUsage(estimate), billing = { ...billingFor(estimate, requestedModel), estimated: true };
      recordRuntime?.({ outcome, durationMs: performance.now() - started, usage, model: partial.model, billing });
      await Promise.all([
        execution?.record({ failures: 1, inputTokens: usage.input_tokens ?? 0, outputTokens: usage.output_tokens ?? 0 }),
        execution?.recordSpend?.(billing),
      ]);
    } else {
      recordRuntime?.({ outcome, durationMs: performance.now() - started });
      await execution?.record({ failures: 1 });
    }
    if (upstream?.aborted) throw cancelled();
    throw error;
  } finally { clearTimeout(timer); clearTimeout(firstByteTimer); upstream?.removeEventListener('abort', abort); }
}
module.exports = { fetchAiJson, fetchAiStream, normalizedUsage, billingFor };
