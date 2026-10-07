const { aiExecution, assertActive, reserveAiCall, cancelled } = require('./aiGovernance');
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
// Bound request/body read; propagate caller disconnects into provider fetches.
async function fetchAiJson(url, options, { fetchImpl = fetch, timeoutMs = 12000 } = {}) {
  await reserveAiCall();
  const execution = aiExecution(), upstream = options.signal || execution?.signal;
  assertActive(upstream);
  const controller = new AbortController();
  let rejectAbort;
  const abort = () => { controller.abort(); rejectAbort?.(cancelled()); };
  upstream?.addEventListener('abort', abort, { once: true });
  let timer;
  const started = performance.now();
  let requestedModel;
  try { requestedModel = JSON.parse(options.body)?.model; } catch { /* Non-JSON inputs use the fixed 'other' bucket. */ }
  const recordRuntime = execution?.runtime?.providerStarted(requestedModel);
  try {
    const result = await Promise.race([
      new Promise((_, reject) => { rejectAbort = reject; if (upstream?.aborted) abort(); }),
      (async () => {
        const response = await fetchImpl(url, { ...options, signal: controller.signal });
        if (!response.ok) throw new Error(`AI provider HTTP ${response.status}`);
        return response.json();
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(Object.assign(new Error('AI request timed out'), { code: 'AI_PROVIDER_TIMEOUT' })); }, timeoutMs);
      }),
    ]);
    const usage = normalizedUsage(result);
    const durationMs = performance.now() - started;
    const outcome = result?.status === 'failed' || result?.type === 'error' || result?.stop_reason === 'refusal' ? 'error'
      : result?.status === 'cancelled' ? 'cancelled'
        : ['incomplete', 'queued', 'in_progress'].includes(result?.status) || ['max_tokens', 'model_context_window_exceeded', 'pause_turn'].includes(result?.stop_reason) ? 'incomplete' : 'completed';
    recordRuntime?.({ outcome, durationMs, usage, model: result?.model });
    await execution?.record({ calls: 1, inputTokens: usage.input_tokens ?? usage.prompt_tokens ?? 0, outputTokens: usage.output_tokens ?? usage.completion_tokens ?? 0, latencyMs: Math.round(durationMs) });
    return result;
  } catch (error) {
    recordRuntime?.({ outcome: upstream?.aborted ? 'cancelled' : error.code === 'AI_PROVIDER_TIMEOUT' ? 'timeout' : 'error', durationMs: performance.now() - started });
    await execution?.record({ failures: 1 });
    if (upstream?.aborted) throw cancelled();
    throw error;
  } finally { clearTimeout(timer); upstream?.removeEventListener('abort', abort); }
}
module.exports = { fetchAiJson, normalizedUsage };
