// CODE-API-02: BAYBAY_DAILY_RUN_LIMIT was one site-wide counter, so a single visitor
// (or bot) who kept asking used up every member's BayBay for the rest of the Pacific
// day. Each member and each visitor now has a daily share inside it. $0: stub model.
const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const catalog = require('../data/planner-catalog.json');
const guideCatalog = require('../data/guide-catalog.json');

const NOW = Date.parse('2026-10-08T17:00:00Z');
const fastText = JSON.stringify({ lead: '金门公园这周末有免费活动。', points: [], candidateIds: [], followups: [], coverage: [], gap: '' });
const completed = () => ({ status: 'completed', model: 'claude-sonnet-5-5', usage: { input_tokens: 10, output_tokens: 10 }, output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: fastText }] }] });

// The quota operation claim() uses, over a Map: one findOneAndUpdate, an upsert for a row this process has
// not claimed yet (API-BB-5); a row at its limit meets the unique id (E11000), as in MongoDB. `shareStart`
// pre-fills each per-person row, so a default limit can be checked without asking 80 times.
function memoryQuota({ shareStart = 0 } = {}) {
  const rows = new Map();
  return { rows,
    findOneAndUpdate: async ({ id, count }, update = {}, options = {}) => {
      let row = rows.get(id);
      if (!row && options.upsert) { row = { ...update.$setOnInsert, count: id.startsWith('baybay-run:') ? shareStart : 0 }; rows.set(id, row); }
      if (!row) return null;
      if (!(row.count < count.$lt)) { if (options.upsert) throw Object.assign(new Error('E11000 duplicate key error'), { code: 11000 }); return null; }
      row.count += 1; return { ...row };
    } };
}

function setup(config = {}, quota = {}) {
  const Quota = memoryQuota(quota); let modelCalls = 0;
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', BAYBAY_STATE_SECRET: 'run-share-test-secret-0123456789', ...config },
    catalog, guideCatalog, isTest: true, now: () => NOW, Quota, ai: async () => { modelCalls++; return completed(); } });
  const ask = (who, n = 0) => assistant.run({ message: `旧金山这周末有什么活动 ${n}`, locale: 'zh-Hans', searchMode: 'site', ...who });
  const site = () => [...Quota.rows.entries()].find(([id]) => id.startsWith('baybay-agent:'))?.[1].count || 0;
  return { Quota, ask, site, calls: () => modelCalls };
}

test('one visitor uses their own share, then gets the daily notice without touching the site-wide count', async () => {
  const f = setup({ BAYBAY_DAILY_RUN_LIMIT: '10', BAYBAY_VISITOR_RUN_LIMIT: '3' });
  const visitor = { ip: '203.0.113.7' };
  for (let n = 0; n < 3; n++) assert.notEqual((await f.ask(visitor, n)).notice?.kind, 'ai_daily_budget');
  assert.equal(f.site(), 3); assert.equal(f.calls(), 3);
  for (let n = 3; n < 8; n++) {
    const result = await f.ask(visitor, n);
    assert.equal(result.notice?.kind, 'ai_daily_budget', `request ${n}`);
    assert.ok(result.research.warnings.includes('baybay_visitor_run_limit'));
    assert.ok(!result.research.warnings.includes('baybay_run_limit'));
  }
  assert.equal(f.site(), 3, 'the site-wide count did not move');
  assert.equal(f.calls(), 3, 'no model call past the share');
  // Another visitor and a member still have theirs.
  assert.equal((await f.ask({ ip: '198.51.100.9' })).notice, undefined);
  assert.equal((await f.ask({ ip: '203.0.113.7', userId: 'member-1' })).notice, undefined, 'signing in uses the member share');
  assert.equal(f.site(), 5);
  // Quota rows never hold the raw IP or user id.
  assert.doesNotMatch(JSON.stringify([...f.Quota.rows.keys()]), /203\.0\.113\.7|198\.51|member-1/);
});

test('a member share is separate from the visitor share and has its own limit', async () => {
  const f = setup({ BAYBAY_DAILY_RUN_LIMIT: '100', BAYBAY_VISITOR_RUN_LIMIT: '1', BAYBAY_MEMBER_RUN_LIMIT: '2' });
  const member = { ip: '203.0.113.7', userId: 'member-1' };
  assert.equal((await f.ask(member, 0)).notice, undefined);
  assert.equal((await f.ask(member, 1)).notice, undefined);
  const third = await f.ask(member, 2);
  assert.equal(third.notice?.kind, 'ai_daily_budget');
  assert.ok(third.research.warnings.includes('baybay_member_run_limit'));
  assert.equal((await f.ask({ ip: '203.0.113.7' })).notice, undefined, 'the same IP signed out has the visitor share');
});

test('the site-wide limit still applies on top of the shares', async () => {
  const f = setup({ BAYBAY_DAILY_RUN_LIMIT: '2' });
  assert.equal((await f.ask({ ip: '192.0.2.1' })).notice, undefined);
  assert.equal((await f.ask({ ip: '192.0.2.2' })).notice, undefined);
  const third = await f.ask({ ip: '192.0.2.3' });
  assert.equal(third.notice?.kind, 'ai_daily_budget');
  assert.ok(third.research.warnings.includes('baybay_run_limit'));
});

test('defaults: 30 runs per visitor and 80 per member; an invalid value keeps the default', async () => {
  for (const [config, who, expected] of [[{}, { ip: '192.0.2.1' }, 30], [{ BAYBAY_VISITOR_RUN_LIMIT: '0' }, { ip: '192.0.2.1' }, 30], [{ BAYBAY_VISITOR_RUN_LIMIT: 'lots' }, { ip: '192.0.2.1' }, 30], [{}, { userId: 'm' }, 80]]) {
    const f = setup(config, { shareStart: expected - 3 });
    let served = 0;
    for (let n = 0; n < 5; n++) if (!(await f.ask(who, n)).notice) served++;
    assert.equal(served, 3, `${JSON.stringify(config)}: the share ends at ${expected}`);
  }
});

// The audit's probe (probe-run-drain.js): guest limit 1, site limit 4. One guest asking
// five times used all four site runs and the member then got "今日 AI 名额已满".
test('HTTP: a guest who keeps asking no longer locks a member out of BayBay', async t => {
  const models = createMemoryModels({ User: [{ id: 'member-1', role: 'user', accountStatus: 'active', email: 'm@example.test' }] });
  let calls = 0;
  const SECRET = 'run-share-http-secret-0123456789abcdef';
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', AI_GUEST_DAILY_LIMIT: '1',
    BAYBAY_DAILY_RUN_LIMIT: '4', BAYBAY_VISITOR_RUN_LIMIT: '2', BAYBAY_STATE_SECRET: 'run-share-http-task-secret-0123456789' }, models, plannerNow: () => NOW,
  ai: { baybay: async () => { calls++; return completed(); } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const url = `http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`;
  const ask = async (message, headers = {}) => (await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans' }) })).json();
  for (let n = 0; n < 5; n++) await ask(`旧金山这周末有什么活动 ${n}`);
  const token = jwt.sign({ id: 'member-1', purpose: 'session', sessionIssuedAt: Date.now() - 1000 }, SECRET, { expiresIn: '1h' });
  const member = await ask('金门公园这周末有什么免费活动', { Authorization: `Bearer ${token}` });
  assert.equal(member.notice, undefined, JSON.stringify(member.notice));
  assert.equal(member.degraded, false);
  const site = models.PostTranslationQuota?.rows?.find(row => /^baybay-agent:/.test(row.id));
  assert.equal(site.count, 3, 'the guest used two site runs (its share), the member one');
  assert.equal(calls, 2, 'the guest got one model answer, the member one');
});
