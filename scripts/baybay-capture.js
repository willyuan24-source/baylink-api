#!/usr/bin/env node
// BayBay behaviour capture for refactors (API-BB-4A, H40; $0, no network, no keys).
// Runs every eval casebook turn (scripts/eval/cases-A…K) through createBayBayAssistant from
// <api root> under 8 arms (v1/v2, guest/member, soft and hard $ cap, no-draft client, Haiku
// fast route) and scripted synthetic providers (cited answer, tool rounds, HTTP 529 then
// retry, invalid JSON then retry), and writes one JSON line per turn with:
//   - the SHA-256 and length of every provider request body exactly as sent,
//   - the full result payload (fields ending in Ms removed),
//   - every onProgress / onQuickCard / onDraft event, in order.
// A refactor with no behaviour change gives byte-identical files for the base and the branch:
//   git archive <base> | tar -x -C <base dir>        (no node_modules there, hence NODE_PATH)
//   NODE_PATH=<this checkout>/node_modules node scripts/baybay-capture.js <base dir> before.jsonl
//   node scripts/baybay-capture.js . after.jsonl && cmp before.jsonl after.jsonl
// --only <arm>[:<script>],… limits the run (e.g. the v2 arms); --dump <turnId> also writes
// that turn's request bodies. The casebook always comes from this checkout, so both roots
// answer the same turns.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const [rootArg, outArg, ...rest] = process.argv.slice(2);
if (!rootArg || !outArg) { console.error('usage: node scripts/baybay-capture.js <api root> <out.jsonl> [--only arm[:script],…] [--dump <turnId>]'); process.exit(2); }
const ROOT = path.resolve(rootArg);
const flag = name => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : null; };
const only = flag('only')?.split(',') || null;
const dumpTurn = flag('dump');
const req = file => require(path.join(ROOT, file));

const { createBayBayAssistant } = req('lib/baybayAgent');
const { createPublicContext } = req('lib/publicContext');
const { bayAreaDate } = req('lib/bayAreaSearchScope');
const { normalizeGuideHistory } = req('lib/guideConversation');
const { validateChatSearchContext } = req('lib/guideWebSearch');
const { baybayWebAccess } = req('lib/baybayAccess');

// Catalogs shaped exactly as scripts/baybay-eval-local.mjs (and server.js) shape them.
const guideCatalog = req('data/guide-catalog.json');
const englishGuides = req('data/guide-catalog.en.json');
const englishGuideMap = new Map(englishGuides.filter(guide => guideCatalog.some(source => source.slug === guide.slug)).map(guide => [guide.slug, guide]));
const englishSearchCatalog = guideCatalog.map(guide => {
  const english = englishGuideMap.get(guide.slug);
  return english ? { ...guide, title: `${guide.title} ${english.title}`, summary: `${guide.summary || ''} ${english.summary || ''}`, keywords: [...(guide.keywords || []), ...(english.keywords || [])], content: `${english.content || ''}\n${guide.content || ''}` } : guide;
});
// The casebook always comes from this checkout so both roots answer the same turns.
const EVAL_DIR = path.join(__dirname, 'eval');
const books = fs.readdirSync(EVAL_DIR).filter(file => /^cases-[A-L]-.+\.json$/.test(file)).sort().map(file => JSON.parse(fs.readFileSync(path.join(EVAL_DIR, file), 'utf8')));
const cases = books.flatMap(book => book.cases.map(item => ({ ...item, pinnedNow: book.pinnedNow })));

function createMemoryQuota() {
  const rows = new Map();
  return {
    async updateOne(filter, update, options) { if (!rows.has(filter.id) && options?.upsert) rows.set(filter.id, { ...update.$setOnInsert }); return { acknowledged: true }; },
    async findOneAndUpdate(filter, update, options) {
      let row = rows.get(filter.id);
      // API-BB-5: an upsert inserts a new row; a row at its limit meets the unique id (E11000), as in MongoDB.
      if (!row && options?.upsert) { row = { count: 0, ...update.$setOnInsert }; rows.set(filter.id, row); }
      else if (row && options?.upsert && !(row.count < filter.count.$lt)) throw Object.assign(new Error('E11000 duplicate key error'), { code: 11000 });
      if (!row || !(row.count < filter.count.$lt)) return null; row.count += update.$inc.count; return { ...row };
    },
  };
}

// ---- synthetic provider -------------------------------------------------------------
const MESSAGES_URL = 'https://api.anthropic.com/v1/messages';
const uniq = values => [...new Set(values)];
function refsIn(text) {
  return {
    refs: uniq([...text.matchAll(/\\?"ref\\?":\\?"((?:e|r)\d+)\\?"/g)].map(m => m[1])),
    sourceIds: uniq([...text.matchAll(/\b(s-[a-z0-9]{6,})/g)].map(m => m[1])),
    candidateIds: uniq([...text.matchAll(/\\?"candidates\\?":\[\{\\?"id\\?":\\?"([^"\\]+)/g)].map(m => m[1])),
    hasPage: /\\?"currentPage\\?":/.test(text),
  };
}
function answerText(body, v2) {
  const text = JSON.stringify(body.messages);
  const { refs, sourceIds, candidateIds, hasPage } = refsIn(text);
  if (v2) {
    const [a = 'e1', b = 'e2'] = refs;
    return JSON.stringify({ lead: `Synthetic lead [[${a}]].`, points: [{ text: `First point [[${a}]].`, cardIds: [a] }, { text: `Second point [[${b}]]${hasPage ? ' and [[page]]' : ''}.`, cardIds: [b] }],
      candidateIds: [a, b, ...candidateIds.slice(0, 1)], followups: ['Synthetic follow-up?'], coverage: [], gap: 'Synthetic gap.' });
  }
  const [s1, s2] = sourceIds;
  return JSON.stringify({ answer: `Synthetic answer${s1 ? ` [[${s1}]]` : ''}${s2 ? `. Second [[${s2}]]` : ''}${hasPage ? ' [[page]]' : ''}.`, candidateIds: candidateIds.slice(0, 2), followups: ['Synthetic follow-up?'], coverage: [] });
}
function toolUse(body, round) {
  const offered = new Set((body.tools || []).map(tool => tool.name));
  if (!offered.size || body.tool_choice?.type === 'none') return null;
  const text = JSON.stringify(body.messages);
  const { refs, sourceIds, candidateIds } = refsIn(text);
  if (round === 0 && offered.has('create_plan') && candidateIds.length) return { name: 'create_plan', input: { candidateIds: candidateIds.slice(0, 2) } };
  if (round <= 1 && offered.has('read_source')) return { name: 'read_source', input: { sourceId: refs[0] || sourceIds[0] || 'e1' } };
  if (round <= 2 && offered.has('search_site')) return { name: 'search_site', input: { query: 'museum family free' } };
  return null;
}
function message(body, content, stop) {
  return { id: 'msg_capture', type: 'message', role: 'assistant', model: body.model, stop_reason: stop, content,
    usage: { input_tokens: 100, output_tokens: 60, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } };
}
function sse(msg) {
  const event = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
  const text = msg.content[0].text;
  let out = event('message_start', { type: 'message_start', message: { ...msg, content: [], stop_reason: null, usage: { ...msg.usage, output_tokens: 1 } } })
    + event('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
  for (let i = 0; i < text.length; i += 6) out += event('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: text.slice(i, i + 6) } });
  out += event('content_block_stop', { type: 'content_block_stop', index: 0 })
    + event('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 60 } }) + event('message_stop', { type: 'message_stop' });
  const bytes = Buffer.from(out, 'utf8'), chunks = [];
  for (let i = 0; i < bytes.length; i += 97) chunks.push(bytes.subarray(i, i + 97));
  return new Response(new ReadableStream({ pull(c) { if (chunks.length) c.enqueue(chunks.shift()); else c.close(); } }), { status: 200, headers: { 'content-type': 'text/event-stream' } });
}
function provider(script, record) {
  return async (url, init) => {
    if (url !== MESSAGES_URL) throw new Error(`capture blocks network access to ${(() => { try { return new URL(url).host; } catch { return 'invalid'; } })()}`);
    const raw = String(init.body);
    record.requests.push({ sha256: crypto.createHash('sha256').update(raw).digest('hex'), bytes: raw.length });
    if (dumpTurn && record.turnId === dumpTurn) record.bodies.push(raw);
    const body = JSON.parse(raw);
    const index = record.calls++;
    const v2 = !!body.output_config?.format?.schema?.properties?.lead;
    if (index === 0 && script === 'fail529') return new Response(JSON.stringify({ type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } }), { status: 529, headers: { 'content-type': 'application/json' } });
    if (index === 0 && script === 'badjson') {
      const msg = message(body, [{ type: 'text', text: 'not json at all' }], 'end_turn');
      return body.stream === true ? sse(msg) : new Response(JSON.stringify(msg), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (script === 'tool') {
      const use = toolUse(body, index);
      if (use) return new Response(JSON.stringify(message(body, [{ type: 'tool_use', id: `toolu_${index}`, name: use.name, input: use.input }], 'tool_use')), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const msg = message(body, [{ type: 'text', text: answerText(body, v2) }], 'end_turn');
    return body.stream === true ? sse(msg) : new Response(JSON.stringify(msg), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

// ---- volatile fields ------------------------------------------------------------------
function scrub(value) {
  if (Array.isArray(value)) return value.map(item => scrub(item));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) { if (/Ms$/.test(k)) continue; out[k] = scrub(v); }
    return out;
  }
  return value;
}

const ARMS = [
  { id: 'v1-guest', engine: 'v1', member: false, scripts: ['cite', 'tool', 'fail529', 'badjson'] },
  { id: 'v1-member', engine: 'v1', member: true, scripts: ['cite', 'tool', 'fail529', 'badjson'] },
  { id: 'v2-guest', engine: 'v2', member: false, scripts: ['cite', 'tool', 'fail529', 'badjson'] },
  { id: 'v2-member', engine: 'v2', member: true, scripts: ['cite', 'tool', 'fail529', 'badjson'] },
  { id: 'v2-member-soft', engine: 'v2', member: true, budget: 'soft', scripts: ['cite', 'tool'] },
  { id: 'v2-guest-hard', engine: 'v2', member: false, budget: 'hard', scripts: ['cite'] },
  { id: 'v2-guest-nodraft', engine: 'v2', member: false, drafts: false, scripts: ['cite', 'tool'] },
  { id: 'v2-member-haiku', engine: 'v2', member: true, config: { BAYBAY_MODEL_FAST: 'claude-haiku-5-5', BAYBAY_EFFORT_FAST: 'low' }, scripts: ['cite'] },
];
const SECRET = 'capture-task-secret-0123456789abcdef0123456789';

async function main() {
  const out = fs.createWriteStream(outArg);
  globalThis.fetch = async url => { throw new Error(`capture blocks global fetch to ${url}`); };
  const publicContext = createPublicContext({ guideCatalog, englishGuideCatalog: englishGuideMap });
  let rows = 0;
  for (const arm of ARMS) for (const script of arm.scripts) {
    if (only && !only.includes(arm.id) && !only.includes(`${arm.id}:${script}`)) continue;
    // One assistant per arm and script (as the eval builds one per arm); the clock follows each casebook.
    let nowMs = 0; const now = () => nowMs;
    const record = { requests: [], bodies: [], turnId: null, calls: 0 };
    const assistants = new Map();
    for (const item of cases) {
      nowMs = Date.parse(item.pinnedNow);
      const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'capture-synthetic-key', BAYBAY_STATE_SECRET: SECRET, BAYBAY_DAILY_RUN_LIMIT: '100000',
        BAYBAY_VISITOR_RUN_LIMIT: '100000', BAYBAY_MEMBER_RUN_LIMIT: '100000', BAYBAY_AGENT_ENABLED: 'true', BAYBAY_ENGINE: arm.engine, ...(arm.config || {}), ...(item.config || {}),
        ...(item.degradedReplay ? { ANTHROPIC_USE_UNTIL: '2026-10-01T00:00:00Z' } : {}) };
      const key = JSON.stringify(config);
      if (!assistants.has(key)) assistants.set(key, createBayBayAssistant({ config, guideCatalog, englishGuideCatalog: englishSearchCatalog, isTest: false, Quota: createMemoryQuota(), now,
        fetchImpl: provider(script, record),
        sourceFetch: async source => ({ text: `Official page for ${source.title}. Open daily 10am to 5pm. General admission is free for children under 12; adults $25. Closed Mondays.`, links: [] }),
        webSearch: async () => ({ answer: 'Stub web lead: a free family festival is listed for this weekend.', sources: [{ title: 'Stub official calendar', url: 'https://example.org/calendar' }], candidates: [], checkedAt: new Date(nowMs).toISOString(), cached: false, model: 'stub' }),
        ...(arm.budget ? { budget: async () => ({ level: arm.budget, caps: { enforced: true }, day: bayAreaDate(now) }) } : {}) }));
      const assistant = assistants.get(key);
      const history = []; let sessionToken;
      for (const turn of item.turns) {
        record.requests = []; record.bodies = []; record.turnId = turn.id; record.calls = 0;
        const events = [];
        let payload, error;
        try {
          const searchContext = validateChatSearchContext(turn.searchContext);
          const normalized = normalizeGuideHistory(history.length ? history : undefined);
          if (!normalized.ok) throw new Error(normalized.error);
          const webAccess = baybayWebAccess(arm.member || item.member ? 'capture-member' : null);
          const searchMode = webAccess.allowed ? item.searchMode || 'smart' : 'site';
          const pageContext = publicContext.resolve({ context: { currentPath: item.currentPath }, currentPath: item.currentPath, today: bayAreaDate(now), locale: item.locale });
          payload = await assistant.run({ message: turn.message, history: normalized.history, searchContext, sessionToken, searchMode, locale: item.locale, currentPath: item.currentPath,
            webAccess, pageContext, ip: 'capture', ...(arm.member ? { userId: 'capture-member' } : {}),
            onProgress: event => { events.push(['progress', event]); },
            onQuickCard: cards => { events.push(['quick', cards]); },
            ...(arm.drafts === false ? {} : { onDraft: event => { events.push(['draft', event]); } }) });
        } catch (caught) { error = String(caught?.message || caught).slice(0, 300); }
        out.write(JSON.stringify({ arm: arm.id, script, caseId: item.id, turnId: turn.id, error: error || null, requests: record.requests, events, payload: scrub(payload) }) + '\n');
        if (dumpTurn && turn.id === dumpTurn) fs.writeFileSync(`${outArg}.${arm.id}.${script}.${turn.id}.bodies.json`, JSON.stringify(record.bodies.map(b => JSON.parse(b)), null, 1));
        rows++;
        const answer = String(payload?.answer || '').trim();
        if (answer) { history.push({ role: 'user', content: turn.message.trim().slice(0, 500) }, { role: 'assistant', content: answer.slice(0, 1200) }); history.splice(0, Math.max(0, history.length - 8)); }
        sessionToken = payload?.assistantSessionToken || sessionToken;
      }
    }
    console.log(`${arm.id}:${script} done (${rows} rows)`);
  }
  await new Promise(resolve => out.end(resolve));
  console.log(`rows ${rows}`);
}
main().catch(error => { console.error(error); process.exit(1); });
