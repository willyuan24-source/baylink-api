const PHASES = new Set(['site', 'research', 'sources', 'routes', 'answer']);
const STATUSES = new Set(['running', 'completed']);

/** Optional transport only: the final result remains the ordinary JSON contract.
 * Progress contains fixed phase names, never model text, tool inputs or tokens. */
function createBayBayProgressStream(res, runtime) {
  res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  let ended = false, last = '', count = 0;
  const open = () => !ended && !res.destroyed && !res.writableEnded;
  const write = (event, value) => {
    if (!open()) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`);
    if (event === 'quick_card') runtime?.mark('firstQuickCard');
    if (event === 'delta') runtime?.mark('firstValidatedText');
    if (event === 'result' || event === 'error') runtime?.response({ ok: event === 'error' ? false : value?.ok, degraded: value?.degraded }, res.statusCode);
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
    quickCard: cards => {
      const safe = (Array.isArray(cards) ? cards : []).filter(card => ['guide', 'event', 'offer', 'opening'].includes(card.kind) && /^[A-Za-z0-9_-]{1,160}$/.test(card.id) && card.url === `/${{ guide: 'guides', event: 'events', offer: 'offers', opening: 'openings' }[card.kind]}/${card.id}`).slice(0, 3).map(card => Object.fromEntries(['kind', 'id', 'title', 'url', 'summary', 'date', 'startDate', 'endDate', 'temporalStatus'].filter(key => card[key] !== undefined).map(key => [key, card[key]])));
      if (safe.length) write('quick_card', { cards: safe, verified: true, provenance: 'site-record', verifiedLive: false });
    },
    // Only the already validated final plain text reaches this channel. Raw
    // provider deltas can contain rejected citations, private data or JSON.
    validatedText(text) {
      if (typeof text !== 'string' || text.length > 10000) return;
      for (let offset = 0; offset < text.length; offset += 160) write('delta', { text: text.slice(offset, offset + 160), validated: true });
    },
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
