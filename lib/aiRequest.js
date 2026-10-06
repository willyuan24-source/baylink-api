const { aiExecution, assertActive, reserveAiCall, cancelled } = require('./aiGovernance');
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
  const started = Date.now();
  try {
    const result = await Promise.race([
      new Promise((_, reject) => { rejectAbort = reject; if (upstream?.aborted) abort(); }),
      (async () => {
        const response = await fetchImpl(url, { ...options, signal: controller.signal });
        if (!response.ok) throw new Error(`AI provider HTTP ${response.status}`);
        return response.json();
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('AI request timed out')); }, timeoutMs);
      }),
    ]);
    const usage = result?.usage || {};
    await execution?.record({ calls: 1, inputTokens: usage.input_tokens ?? usage.prompt_tokens ?? 0, outputTokens: usage.output_tokens ?? usage.completion_tokens ?? 0, latencyMs: Date.now() - started });
    return result;
  } catch (error) {
    await execution?.record({ failures: 1 });
    if (upstream?.aborted) throw cancelled();
    throw error;
  } finally { clearTimeout(timer); upstream?.removeEventListener('abort', abort); }
}
module.exports = { fetchAiJson };
