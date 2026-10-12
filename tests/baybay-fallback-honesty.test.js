// CODE-API-05 (API-SEC re-check): when BayBay has no model answer, the site-record list says so
// in its first sentence, in every locale, and the response stays marked degraded. The guest
// quota case also carries the daily notice (API-BB-QUALITY).
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const NOW = Date.parse('2026-10-11T20:00:00Z');
const fastText = JSON.stringify({ lead: '金门公园这周末有免费活动[[e1]]。', points: [], candidateIds: [], followups: [], coverage: [], gap: '' });

async function start(t, { baybay, config = {} }) {
  const application = createApplication({ models: createMemoryModels(), plannerNow: () => NOW, ai: { baybay },
    config: { NODE_ENV: 'test', JWT_SECRET: 'fallback-honesty-secret-0123456789', BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', BAYBAY_STATE_SECRET: 'fallback-honesty-task-secret-0123456789ab', ...config } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return async (message, locale = 'zh-Hans') => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, assistantVersion: 2, searchMode: 'site', locale }) });
    return { status: response.status, body: await response.json() };
  };
}

test('provider down: the fallback list opens with "no AI answer this time", in Chinese and English, and is marked degraded', async t => {
  const ask = await start(t, { baybay: async () => { throw Object.assign(new Error('overloaded'), { status: 529 }); } });
  const zh = await ask('旧金山这周末有什么亲子活动');
  assert.equal(zh.status, 200); assert.equal(zh.body.degraded, true);
  assert.match(zh.body.answer, /^这次没能生成 AI 回答。下面是站内收录的/);
  assert.match(zh.body.answer, /没有逐条核对你的全部条件，出发前请看官方页面/);
  assert.doesNotMatch(zh.body.answer, /整理了这些选择/);
  const en = await ask('family things to do in San Francisco this weekend', 'en');
  assert.equal(en.body.degraded, true);
  assert.match(en.body.answer, /^An AI answer could not be generated this time\. Below are site records for /);
});

test('guest daily AI count used up: the same honest opening plus the daily notice', async t => {
  let calls = 0;
  const ask = await start(t, { config: { AI_GUEST_DAILY_LIMIT: '1' }, baybay: async () => { calls++; return { status: 'completed', model: 'claude-sonnet-5-5', usage: { input_tokens: 10, output_tokens: 10 },
    output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: fastText }] }] }; } });
  assert.equal((await ask('金门公园这周末有什么免费活动')).body.degraded, false);
  const second = await ask('旧金山这周末有什么亲子活动');
  assert.equal(calls, 1);
  assert.equal(second.body.degraded, true);
  assert.equal(second.body.notice?.kind, 'ai_daily_budget');
  assert.match(second.body.answer, /^这次没能生成 AI 回答。/);
});
