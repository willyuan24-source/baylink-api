#!/usr/bin/env node
// H03 (audit 10-13, BB-1013-01): BayBay's non-model time, measured locally ($0, no network,
// no Mongo). Each question runs through the real v2 assistant inside the real AI governance
// middleware; Mongo round trips, the source-monitor list and the spend ledger are fakes with a
// fixed delay, and the provider answers at once. "preModelMs" is the wall time from run() to
// the provider request: what a reader waits before the model can start writing.
//
//   node scripts/baybay-latency-bench.js [--api <checkout>] [--rtt 80] [--monitor-ms 400] [--rounds 3] [--settle 0] [--json out.json]
//
// --api points at another checkout (for example the base commit's lib/, data/ and
// tests/support/ extracted to a folder) so before and after use the same harness.
// --settle <ms> waits that long after the assistant is created before the first question, as a
// production instance does between boot and its first reader. API-BB-4B: with --settle the
// bench starts the boot warm-up first (startWarmUp, as server.js does after listen) when the
// checkout has one; without --settle nothing warms.
'use strict';
const path = require('node:path');
const { EventEmitter } = require('node:events');

const args = process.argv.slice(2);
const option = (name, fallback) => { const index = args.indexOf(`--${name}`); return index >= 0 ? args[index + 1] : fallback; };
const API = path.resolve(option('api', path.join(__dirname, '..')));
const RTT = Number(option('rtt', 80)), MONITOR_MS = Number(option('monitor-ms', 400)), ROUNDS = Number(option('rounds', 3)), SETTLE_MS = Number(option('settle', 0));
const out = option('json', '');

const { createBayBayAssistant } = require(path.join(API, 'lib/baybayAgent'));
const { createAiGovernance } = require(path.join(API, 'lib/aiGovernance'));
const { loadPlannerCatalog } = require(path.join(API, 'lib/planner'));
const { createPublicContext } = require(path.join(API, 'lib/publicContext'));
const { createMemoryModels } = require(path.join(API, 'tests/support/memory-models'));
const guides = require(path.join(API, 'data/guide-catalog.json'));

const NOW = Date.parse('2026-10-13T19:00:00Z'), TODAY = '2026-10-13';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// Every Mongo call waits one round trip, then runs on the in-memory model.
const slow = model => new Proxy(model, { get(target, key) {
  const value = target[key];
  return typeof value === 'function' && ['updateOne', 'findOneAndUpdate', 'findOne', 'find'].includes(key)
    ? (...input) => { const result = value.apply(target, input); const lean = result && typeof result.lean === 'function';
      return lean ? { ...result, select() { return this; }, sort() { return this; }, limit() { return this; }, lean: async () => { await sleep(RTT); return result.lean(); } } : sleep(RTT).then(() => result); }
    : value;
} });
// A monitor list shaped like production's (1,389 rows), returned after MONITOR_MS.
const monitorRows = Array.from({ length: 1389 }, (_, index) => ({ url: `https://monitor.example/source-${index}?utm_source=x`, reviewStatus: index % 7 ? 'none' : 'pending' }));

// The audit's ten model turns (BB-1013-01) plus a professional and a plan question.
const QUESTIONS = [
  ['zh-Hans', '这周末带 5 岁孩子去哪玩比较好？'], ['zh-Hans', '这周六旧金山有什么适合全家的免费活动？'], ['zh-Hans', '一家四口预算 50 刀以内，哪些完全免费？'],
  ['zh-Hans', '这周末想带孩子在东湾玩，有什么推荐？'], ['zh-Hans', '孩子一个 4 岁一个 9 岁，两个都要能玩的'], ['zh-Hant', '這週末灣區有華人社區的活動嗎？比如重陽節敬老、中文講座之類的'],
  ['zh-Hant', '我明天下午就有空，明天有嗎？'], ['en', 'We live in Fremont with a 3-year-old. Anything fun and free this Sunday?'],
  ['zh-Hans', '刚拿移民签证来美国，社安号 SSN 还要自己去社安局办公室申请吗？'], ['zh-Hans', '我爸妈 68 岁刚拿绿卡来湾区，可以申请 Medi-Cal 吗？去哪里申请？'],
  ['en', 'Is the Exploratorium free for kids this weekend?'], ['zh-Hans', '帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家'],
];
const reply = { type: 'message', id: 'bench', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
  content: [{ type: 'text', text: JSON.stringify({ lead: '可以。', points: [{ text: '示例。', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' }) }] };

async function main() {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: slow(models.AiGovernance), config: { JWT_SECRET: 'bench-secret' }, now: () => NOW });
  let firstFetchAt = 0;
  const assistant = createBayBayAssistant({
    config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'bench-fixture', BAYBAY_ENGINE: 'v2', BAYBAY_STATE_SECRET: 'bench-task-secret-0123456789abcdef' },
    guideCatalog: guides, catalog: loadPlannerCatalog(), now: () => NOW, isTest: false, Quota: slow(models.PostTranslationQuota),
    monitorStatus: async () => { await sleep(MONITOR_MS); return monitorRows; }, budget: governance.spendLevel,
    fetchImpl: async () => { firstFetchAt ||= Date.now(); return { ok: true, status: 200, json: async () => reply, clone() { return this; }, text: async () => JSON.stringify(reply) }; },
  });
  const publicContext = createPublicContext({ guideCatalog: guides });
  // One question inside the governance middleware, as /api/ai/guide-chat runs it.
  const ask = (locale, message, ip) => new Promise((resolve, reject) => {
    const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.method = 'POST'; req.ip = ip; req.body = { locale };
    const res = new EventEmitter(); res.statusCode = 200; res.writableEnded = false; res.status = code => { res.statusCode = code; return res; }; res.set = () => res;
    res.json = body => { res.writableEnded = true; res.emit('finish'); return body; };
    governance.middleware(async () => null)(req, res, async () => {
      firstFetchAt = 0;
      const started = Date.now();
      try {
        const result = await assistant.run({ message, locale, currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false }, ip,
          pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }) });
        res.json({ ok: true });
        resolve({ preModelMs: firstFetchAt ? firstFetchAt - started : null, totalMs: Date.now() - started, timings: result.research?.timings || {}, route: result.route?.reason });
      } catch (error) { res.json({ ok: false }); reject(error); }
    });
  });
  if (SETTLE_MS > 0) { assistant.startWarmUp?.(); await sleep(SETTLE_MS); }
  const rows = [];
  for (let round = 0; round < ROUNDS; round++) {
    for (const [index, [locale, message]] of QUESTIONS.entries()) {
      const row = await ask(locale, message, `198.51.100.${round * 20 + index}`);
      rows.push({ round, locale, message, ...row });
    }
  }
  const pick = key => rows.map(row => row[key] ?? row.timings[key]).filter(value => Number.isFinite(value)).sort((a, b) => a - b);
  const pct = (values, p) => values.length ? values[Math.min(values.length - 1, Math.floor(p * (values.length - 1) + 0.5))] : null;
  const summary = Object.fromEntries(['preModelMs', 'stateMs', 'siteMs', 'monitorMs', 'quotaMs'].map(key => [key, { p50: pct(pick(key), 0.5), p90: pct(pick(key), 0.9), max: pct(pick(key), 1) }]));
  const firstQuestion = rows[0];
  const report = { api: API, rttMs: RTT, monitorListMs: MONITOR_MS, rounds: ROUNDS, settleMs: SETTLE_MS, questions: QUESTIONS.length, firstQuestion: { preModelMs: firstQuestion.preModelMs, timings: firstQuestion.timings }, summary };
  console.log(JSON.stringify(report, null, 1));
  if (out) require('node:fs').writeFileSync(out, JSON.stringify({ ...report, rows }, null, 1));
}
main().catch(error => { console.error(error); process.exit(1); });
