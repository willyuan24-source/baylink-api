const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const NOW = Date.parse('2026-10-04T19:00:00Z');
const final = answer => ({ model: 'fixture-baybay', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: ['换成周日'] }) }] }] });
async function fixture(t, extra = {}) {
  let calls = 0;
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-baybay-agent-route-secret', OPENAI_API_KEY: 'test-key-never-print' }, models: createMemoryModels(), plannerNow: () => NOW,
    ai: { baybay: async input => { calls++; const data = JSON.parse(input.input[0].content); return final(`已参考站内资料，并保留你的条件。${data.evidence[0] ? ` [[${data.evidence[0].id}]]` : ''}`); } }, ...extra });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const ask = async body => { const r = await fetch(`${base}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ assistantVersion: 2, searchMode: 'site', ...body }) }); return { status: r.status, body: await r.json() }; };
  return { ask, base, calls: () => calls };
}

test('version 2 route returns structured state, plan, evidence and continuation without altering legacy clients', async t => {
  const f = await fixture(t);
  const result = await f.ask({ message: '10月10日从Fremont出发，两大一小孩子6岁，全家预算100美元，帮我安排一天' });
  assert.equal(result.status, 200); assert.equal(result.body.responseMode, 'assistant'); assert.ok(result.body.assistantSessionToken); assert.ok(result.body.assistantPlan);
  assert.equal(result.body.taskState.origin, 'Fremont'); assert.equal(result.body.taskState.budgetScope, 'total');
  assert.ok(new Set(result.body.assistantPlan.stops.map(s => s.city)).size <= 1, 'unknown routes must not produce a cross-Bay itinerary');
  assert.doesNotMatch(JSON.stringify(result.body), /test-key-never-print|isolated-baybay-agent-route-secret/);
  const legacy = await f.ask({ assistantVersion: undefined, message: '今天旧金山有什么免费活动？' });
  assert.equal(legacy.status, 200); assert.equal(legacy.body.responseMode, 'catalog'); assert.equal(legacy.body.assistantSessionToken, undefined);
});

test('continuations use server-signed state and ignore forged client task state', async t => {
  const f = await fixture(t);
  const first = await f.ask({ message: '周六San Jose亲子活动，全家预算100美元，3个人' });
  const next = await f.ask({ message: '改成明天', assistantSessionToken: first.body.assistantSessionToken, taskState: { city: 'Shanghai', budget: 99999 } });
  assert.equal(next.status, 200); assert.equal(next.body.taskState.city, 'San Jose'); assert.equal(next.body.taskState.date, '2026-10-05'); assert.equal(next.body.taskState.budget, 100);
});

test('invalid or expired task token fails with a recoverable error, without invoking model', async t => {
  const f = await fixture(t);
  const r = await f.ask({ message: '明天还有什么选择', assistantSessionToken: 'forged-value' });
  assert.equal(r.status, 400); assert.equal(r.body.code, 'INVALID_ASSISTANT_SESSION'); assert.equal(f.calls(), 0);
});

test('capability endpoint reports configuration without credentials or false model verification', async t => {
  const f = await fixture(t); const r = await (await fetch(`${f.base}/api/ai/baybay-capabilities`)).json();
  assert.equal(r.version, 2); assert.equal(r.routeEstimates, false); assert.equal(r.modelAccessVerified, false); assert.ok(r.tools.includes('plans'));
  assert.doesNotMatch(JSON.stringify(r), /test-key-never-print/);
});

test('assistant kill switch retains the tested legacy route', async t => {
  const f = await fixture(t, { config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-baybay-agent-route-secret', BAYBAY_AGENT_ENABLED: 'false' } });
  const r = await f.ask({ message: '今天旧金山有什么免费活动？' }); assert.equal(r.status, 200); assert.equal(r.body.responseMode, 'catalog'); assert.equal(f.calls(), 0);
});
