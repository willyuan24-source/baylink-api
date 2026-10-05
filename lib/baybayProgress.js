const PHASES = new Set(['site', 'research', 'sources', 'routes', 'answer']);
const STATUSES = new Set(['running', 'completed']);

/** Optional transport only: the final result remains the ordinary JSON contract.
 * Progress contains fixed phase names, never model text, tool inputs or tokens. */
function createBayBayProgressStream(res) {
  res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  let ended = false, last = '', count = 0;
  const open = () => !ended && !res.destroyed && !res.writableEnded;
  const write = (event, value) => {
    if (!open()) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`);
  };
  // Keep an idle model request open through buffering proxies. A heartbeat is
  // not progress and must never advance the displayed research stage.
  const heartbeat = setInterval(() => { if (open()) res.write(': keepalive\n\n'); }, 15000);
  heartbeat.unref?.();
  res.once('close', () => { ended = true; clearInterval(heartbeat); });
  const finish = (event, value) => {
    if (!open()) return;
    write(event, value); ended = true; clearInterval(heartbeat); res.end();
  };
  return {
    progress(value) {
      if (!PHASES.has(value?.phase) || !STATUSES.has(value?.status) || count >= 80) return;
      const key = `${value.phase}:${value.status}`;
      if (key === last) return;
      last = key; count++;
      write('progress', { phase: value.phase, status: value.status });
    },
    result: value => finish('result', value),
    error: value => finish('error', value),
  };
}

module.exports = { createBayBayProgressStream };
