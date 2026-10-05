const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState } = require('../lib/baybayState');
const { loadPlannerCatalog } = require('../lib/planner');
const catalog = loadPlannerCatalog();
const query = require('../scripts/baybay-quality-cases.json').cases.find(item => item.id === 'strict-sf-family-plan').request.message;

test('an ordered visit without the word itinerary keeps named origin and exact stops', () => {
  const result = resolveTaskState({ message: query, catalog, today: '2026-10-04' });
  assert.equal(result.clarification, undefined);
  assert.equal(result.state.goal, 'day-plan');
  assert.equal(result.state.originCandidateId, 'venue-ferry-building');
  assert.match(result.state.origin, /Ferry Building/i);
  assert.deepEqual(result.explicitCandidateIds, ['venue-exploratorium-daytime', 'pier39']);
  assert.equal(result.state.startTime, '10:00');
  assert.equal(result.state.finishBy, '17:00');
  assert.equal(result.state.returnToOrigin, false);
});

test('ordered price comparisons and explicitly declined routes do not start a visit plan', () => {
  for (const message of ['请按价格顺序介绍 Exploratorium 和 Pier 39，不安排行程。', '不要按照 Exploratorium、Pier 39 的顺序走，只解释儿童票价。', '我已经严格按 Exploratorium、Pier 39 的顺序走过，只想了解儿童票价规则。']) {
    const result = resolveTaskState({ message, catalog, today: '2026-10-04' });
    assert.notEqual(result.state.goal, 'day-plan');
  }
});

test('ordered visit variants share the same exact stop selection and a negated origin is not adopted', () => {
  for (const message of [query.replace('严格按', '按照'), query.replace('严格按', '依照'), 'On 2026-10-10 tour Exploratorium and Pier 39 in this order.']) {
    const result = resolveTaskState({ message, catalog, today: '2026-10-04' });
    assert.equal(result.state.goal, 'day-plan');
    assert.deepEqual(result.explicitCandidateIds, ['venue-exploratorium-daytime', 'pier39']);
  }
  const result = resolveTaskState({ message: query.replace('从 San Francisco', '不是从 San Francisco'), catalog, today: '2026-10-04' });
  assert.equal(result.state.originCandidateId, null);
});

test('the ordered visit produces a priced card and its ordinary child-price followup keeps both stops', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const agent = createBayBayAssistant({ catalog, guideCatalog: require('../data/guide-catalog.json'),
    config: { NODE_ENV: 'test', JWT_SECRET: 'ordered-visit-fixture-secret' }, now: () => Date.parse('2026-10-04T19:00:00Z'),
    ai: async () => ({ model: 'fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '保留原顺序，尚未确认的费用和时间请看行程卡。', candidateIds: [], followups: [], coverage: [] }) }] }] }),
  });
  const first = await agent.run({ message: query, searchMode: 'site' });
  assert.deepEqual(first.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39']);
  assert.equal(first.assistantPlan.budget.knownTotalUsd, 109.85);
  const second = await agent.run({ message: '不改行程和顺序，只再解释5岁孩子的门票，以及哪些费用仍没算进120美元总预算。不要加景点或替换地点。', sessionToken: first.assistantSessionToken, searchMode: 'site' });
  assert.deepEqual(second.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39']);
  assert.equal(second.assistantPlan.budget.knownTotalUsd, 109.85);
  assert.deepEqual(second.assistantPlan.alternatives, []);
});
