const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState } = require('../lib/baybayState');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const catalog = require('../data/planner-catalog.json');
const NOW = Date.parse('2026-10-05T19:00:00Z');
const message = '11月7日两个大人带5岁孩子，10点从旧金山Ferry Building出发，只去PIER39看海狮，坐公交，15点前结束，不回原点，总预算120美元。帮我安排半天，不要加别的站。';
const resolve = text => resolveTaskState({ message: text, today: '2026-10-05', catalog });
const final = answer => ({ status: 'completed', model: 'fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });

test('the exact mobile half-day request selects its one named destination and keeps every supplied condition', () => {
  const result = resolve(message), state = result.state;
  assert.equal(result.clarification, undefined);
  assert.equal(state.goal, 'day-plan');
  assert.equal(state.city, 'San Francisco');
  assert.equal(state.region, 'sf');
  assert.deepEqual(result.explicitCandidateIds, ['pier39']);
  assert.deepEqual(state.selectedCandidateIds, ['pier39']);
  assert.equal(state.date, '2026-11-07');
  assert.equal(state.originCandidateId, 'venue-ferry-building');
  assert.equal(state.partySize, 3); assert.deepEqual(state.childAges, [5]);
  assert.equal(state.startTime, '10:00'); assert.equal(state.finishBy, '15:00');
  assert.equal(state.travelMode, 'transit'); assert.equal(state.returnToOrigin, false);
  assert.equal(state.budget, 120); assert.equal(state.budgetScope, 'total');
});

test('half-day planning works in Simplified, Traditional and English without choosing negated or unknown destinations', () => {
  for (const text of ['只去 PIER39，帮我安排半天。', '只去 PIER39，幫我安排半日。', 'Plan a half-day visit to PIER39 only.']) {
    const result = resolve(text);
    assert.equal(result.state.goal, 'day-plan', text);
    assert.equal(result.state.city, 'San Francisco', text);
    assert.deepEqual(result.explicitCandidateIds, ['pier39'], text);
  }
  for (const text of ['不要安排半天，只问 PIER39 免费公共区的规则。', '不用安排行程，只去 PIER39 需要门票吗？', '不要安排半日，只問 PIER39 的票價。', 'Do not plan a half-day visit to PIER39; just explain admission.']) {
    assert.notEqual(resolve(text).state.goal, 'day-plan', text);
    assert.equal(resolve(text).explicitCandidateIds, undefined, text);
  }
  assert.equal(resolve('安排半天，但不要只去PIER39。').explicitCandidateIds, undefined);
  assert.equal(resolve('只看 PIER39 的票价，不用去。帮我安排半天。').explicitCandidateIds, undefined);
  for (const text of ['不只去PIER39，还去Exploratorium，帮我安排半天。', '不只是去PIER39，还去Exploratorium，帮我安排半天。', '不仅去PIER39，还去Exploratorium，帮我安排半天。', 'Plan a half-day visit, not only PIER39 but also Exploratorium.']) {
    assert.deepEqual(resolve(text).explicitCandidateIds, ['pier39', 'venue-exploratorium-daytime'], text);
  }
  assert.equal(resolve('安排半天，不想去PIER39。').explicitCandidateIds, undefined);
  assert.equal(resolve('安排半天，只去PIER399。').state.city, null);
  assert.equal(resolve('安排半天，只去那个看海狮的地方。').state.city, null);
  const outside = resolve('安排半天，只去PIER39，但目的城市是San Jose。');
  assert.equal(outside.state.city, 'San Jose', 'a selected venue does not overwrite an explicit different city');
  const multiple = resolve('安排半天，只去PIER39，再比较San Francisco和Berkeley。');
  assert.match(multiple.clarification, /目的城市|地点|城市/);
  assert.match(resolve('安排半天，只去PIER39和Oakland Museum of California。').clarification, /目的城市/);
});

async function fixture(t, answer) {
  const contexts = [], legacyCalls = [];
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'half-day-local-fixture' }, models: createMemoryModels(), plannerNow: () => NOW,
    ai: { guideChat: async payload => { legacyCalls.push(payload); return { answer: 'Legacy route must not be used.' }; },
      baybay: async payload => { const context = JSON.parse(payload.input[0].content); contexts.push({ context, tools: payload.tools }); return final(answer(context)); },
      plannerWebSearch: async () => assert.fail('site-only must not perform a web search') },
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans', context: { currentPath: '/' } }) });
  assert.equal(response.status, 200);
  return { result: await response.json(), contexts, legacyCalls };
}

test('the frontend V2 request reaches a sourced one-stop plan rather than an unplanned legacy answer', async t => {
  const { result, contexts, legacyCalls } = await fixture(t, context => {
    const stop = context.currentPlan?.stops[0];
    return stop ? `只保留 PIER39。公共区入场记录为免费，收费项目另算。 [[${stop.sourceIds[0]}]] 公交线路、耗时及票价还未核实。` : '目前无法组成安排。';
  });
  assert.equal(legacyCalls.length, 0);
  assert.equal(contexts.length, 1);
  assert.deepEqual(contexts[0].tools, []);
  assert.equal(result.responseMode, 'assistant');
  assert.equal(result.taskState.goal, 'day-plan');
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['pier39']);
  assert.deepEqual(result.assistantPlan.alternatives, []);
  assert.ok(result.assistantPlan.handoff);
  assert.ok(result.sources.length > 0);
  assert.equal(result.degraded, false);
  assert.equal(result.retrieval.webStatus, 'not_requested');
  assert.ok(result.assistantPlan.unknowns.some(item => /交通|Travel|travel/.test(item)));
});

test('an uncited invented transit answer for that same half-day request is repaired from plan evidence', async t => {
  const { result, contexts, legacyCalls } = await fixture(t, () => 'F-line 直达只要15–20分钟，成人约3美元，儿童票较低，一定来得及。');
  assert.equal(legacyCalls.length, 0);
  assert.equal(contexts.length, 2, 'one bounded synthesis recovery precedes the safe fallback');
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['pier39']);
  assert.deepEqual(result.assistantPlan.alternatives, []);
  assert.ok(result.sources.length > 0, 'the factual fallback must cite actual plan evidence');
  assert.equal(result.degraded, true);
  assert.ok(result.research.warnings.includes('answer_plan_citations_repaired'));
  assert.doesNotMatch(result.answer, /F-line|15–20|成人约3|儿童票较低|一定来得及/);
});
