// Bound both the request and response-body read. The race also protects non-cooperative transports.
async function fetchAiJson(url, options, { fetchImpl = fetch, timeoutMs = 12000 } = {}) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      (async () => {
        const response = await fetchImpl(url, { ...options, signal: controller.signal });
        if (!response.ok) throw new Error(`AI provider HTTP ${response.status}`);
        return response.json();
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('AI request timed out')); }, timeoutMs);
      }),
    ]);
  } finally { clearTimeout(timer); }
}
module.exports = { fetchAiJson };
