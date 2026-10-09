const { readerProse } = require('./baybayFastPath');

const PHASES = new Set(['site', 'research', 'sources', 'routes', 'answer']);
const STATUSES = new Set(['running', 'completed']);

// Streamed answer drafts (API-BB-STREAM; web contract WEB-BB-STREAMPREP #25, plan §3.0
// "SSE draft"): {seq, field: 'lead'|'point', index?, text}, appended in order by the
// client; the final `result` stays authoritative and replaces them.
const DRAFT_MAX_CHARS = 4000, DRAFT_MAX_POINTS = 5, DRAFT_BATCH_MS = 120, DRAFT_BATCH_CHARS = 40;

/** Reader text of unvalidated model prose: the same removals renderCitations makes
 * ([n] markers, Markdown links to their label, bare URLs) plus every [[ref]] marker
 * (only the validated result can number citations), then readerProse (ISO dates and
 * region codes). */
function sanitizeDraft(text, locale) {
  return readerProse(String(text || '').replace(/\s*\[\[[^\]]*\]\]/g, '').replace(/\[\d+\]/g, '')
    .replace(/\[([^\]]+)\]\(https?:[^)]*\)/g, '$1').replace(/https?:\/\/[^\s<>]+/g, ''), locale);
}

// A draft may only show text that later characters cannot change: everything before
// the last whitespace (trailing whitespace held back) or after the last CJK
// character or punctuation, and never from inside an unclosed [ … ] or ( … ) of a
// citation or link. URLs, ISO dates and region codes contain neither, so a cut never
// splits one.
const BOUNDARY = /[　-〿㐀-鿿豈-﫿＀-￯]/;
function stablePrefix(text) {
  let limit = text.length;
  const open = [];
  let link = -1;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (link >= 0) { if (char === ')') link = -1; continue; }
    if (char === '[') open.push(index);
    else if (char === ']' && open.length) {
      const start = open.pop();
      // "]" at the end may still become "](…)": hold the bracket.
      if (index === text.length - 1) limit = Math.min(limit, open.length ? open[0] : start);
      else if (text[index + 1] === '(') { link = open.length ? open[0] : start; index++; }
    }
  }
  if (link >= 0) limit = Math.min(limit, link);
  if (open.length) limit = Math.min(limit, open[0]);
  for (let index = limit - 1; index >= 0; index--) {
    if (/\s/.test(text[index])) return text.slice(0, index).trimEnd();
    if (BOUNDARY.test(text[index])) return text.slice(0, index + 1);
  }
  return '';
}

/** Turns the model's streamed `lead` / `points[i].text` characters into draft events:
 * sanitised stable text only, batched (>=120 ms or >=40 characters, a finished field
 * at once), numbered with `seq`, at most 4,000 characters in total (then the draft
 * closes), point index 0-4. A field whose sanitised text stops extending what was
 * already sent is frozen (the result corrects it). `emit` errors are swallowed. */
function createDraftWriter({ emit, locale = 'zh-Hans', batchMs = DRAFT_BATCH_MS, batchChars = DRAFT_BATCH_CHARS, maxChars = DRAFT_MAX_CHARS,
  setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  const fields = new Map();
  let seq = 0, total = 0, unsent = 0, closed = false, timer = null;
  const keyOf = (field, index) => field === 'lead' ? 'lead' : `point:${index}`;
  const valid = (field, index) => field === 'lead' || (field === 'point' && Number.isInteger(index) && index >= 0 && index < DRAFT_MAX_POINTS);
  const send = event => { try { emit?.(event); } catch { /* transport errors cannot affect the answer */ } };
  function flush() {
    if (timer) { clearTimer(timer); timer = null; }
    unsent = 0;
    for (const item of fields.values()) {
      if (closed) return;
      if (item.frozen) continue;
      const clean = sanitizeDraft(item.done ? item.raw : stablePrefix(item.raw), locale).trimStart();
      if (!clean.startsWith(item.sent)) { item.frozen = true; continue; }
      let text = clean.slice(item.sent.length);
      if (!text) continue;
      const room = maxChars - total;
      if (text.length > room) {
        // Never split a surrogate pair at the budget edge.
        let cut = room;
        if (cut > 0 && /[\ud800-\udbff]/.test(text[cut - 1])) cut--;
        text = text.slice(0, cut); closed = true;
        if (!text) return;
      }
      send({ seq: ++seq, field: item.field, ...(item.field === 'point' ? { index: item.index } : {}), text });
      item.sent += text; total += text.length;
    }
  }
  return {
    /** Characters of one field, in arrival order. */
    text(field, index, text) {
      if (closed || !valid(field, index) || typeof text !== 'string' || !text) return;
      const key = keyOf(field, index);
      if (!fields.has(key)) fields.set(key, { field, index, raw: '', sent: '', done: false, frozen: false });
      const item = fields.get(key);
      if (item.done) return;
      item.raw += text; unsent += text.length;
      if (unsent >= batchChars) flush();
      else if (!timer) { timer = setTimer(flush, batchMs); timer?.unref?.(); }
    },
    /** The field's string closed: its remaining text is final and sent now. */
    done(field, index) {
      const item = fields.get(keyOf(field, index));
      if (closed || !item || item.done) return;
      item.done = true; flush();
    },
    /** The provider call ended. `complete` sends the finished fields' remaining text;
     * otherwise held-back text is dropped. No draft follows either way. */
    end({ complete = false } = {}) {
      if (closed) return;
      if (complete) flush();
      closed = true;
      if (timer) { clearTimer(timer); timer = null; }
    },
    /** What the client has been sent, per field. */
    sent() {
      const points = [];
      for (const item of fields.values()) if (item.field === 'point' && item.sent) points[item.index] = item.sent;
      return { lead: fields.get('lead')?.sent || '', points, chars: total, events: seq };
    },
  };
}

/** True when the reader saw draft text that the final answer does not continue: a
 * guard rewrite, a retry, a template answer or a frozen field. Citation numbers and
 * whitespace are ignored; a draft cut by the 4,000-character stop is a prefix. */
const visible = value => String(value || '').replace(/\[\d+\]/g, '').replace(/\s+/g, '');
function draftCorrected(sent, response) {
  const parts = [[sent?.lead, response?.lead]];
  (sent?.points || []).forEach((text, index) => parts.push([text, response?.points?.[index]?.text]));
  return parts.some(([text, final]) => text && !visible(final).startsWith(visible(text)));
}

/** Optional transport only: the final result remains the ordinary JSON contract.
 * Progress contains fixed phase names, never model text, tool inputs or tokens.
 * Drafts (model text after the server sanitiser) are written only when the caller
 * passes them (guide-chat: the client sent streamVersion >= 3, RC-21). */
function createBayBayProgressStream(res, runtime) {
  res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  let ended = false, last = '', count = 0, draftSeq = 0, draftChars = 0;
  const open = () => !ended && !res.destroyed && !res.writableEnded;
  const write = (event, value) => {
    if (!open()) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`);
    if (event === 'quick_card') runtime?.mark('firstQuickCard');
    if (event === 'draft') runtime?.mark('firstDraft');
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
    // Already-sanitised draft events from createDraftWriter. Re-checked here: fixed
    // keys only, increasing seq, point index 0-4, the 4,000-character total.
    draft(value) {
      const point = value?.field === 'point';
      if (!value || !['lead', 'point'].includes(value.field) || !Number.isSafeInteger(value.seq) || value.seq <= draftSeq) return;
      if (point && !(Number.isInteger(value.index) && value.index >= 0 && value.index < DRAFT_MAX_POINTS)) return;
      if (typeof value.text !== 'string' || !value.text || draftChars + value.text.length > DRAFT_MAX_CHARS) return;
      draftSeq = value.seq; draftChars += value.text.length;
      write('draft', { seq: value.seq, field: value.field, ...(point ? { index: value.index } : {}), text: value.text });
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

module.exports = { createBayBayProgressStream, createDraftWriter, draftCorrected, sanitizeDraft, stablePrefix, DRAFT_MAX_CHARS, DRAFT_MAX_POINTS, DRAFT_BATCH_MS, DRAFT_BATCH_CHARS };
