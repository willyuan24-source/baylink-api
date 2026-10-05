const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { encodeTaskToken, decodeTaskToken } = require('../lib/baybayState');

const NOW = Date.parse('2026-10-05T06:45:00Z');
const secret = 'synthetic-human-conversation-test-key';
const state = { goal: 'day-plan', city: 'San Francisco', date: '2026-10-10', partySize: 3, childAges: [5], budget: 120, budgetScope: 'total', travelMode: 'transit', finishBy: '15:00', selectedCandidateIds: ['venue-exploratorium-daytime', 'pier39'] };
const lastPlan = { selectedIds: state.selectedCandidateIds, candidateIds: state.selectedCandidateIds, title: 'Exploratorium then PIER 39', date: state.date };
const final = answer => ({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });

test('pausing itinerary creation keeps the previous places for the question and rejects an unwanted plan tool call', async () => {
  let calls = 0;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: secret }, isTest: true, now: () => NOW, ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    assert.equal(context.state.goal, 'information');
    assert.deepEqual(context.previousPlan.selectedIds, state.selectedCandidateIds);
    assert.equal(context.state.budget, 120);
    assert.deepEqual(context.state.childAges, [5]);
    assert.ok(!payload.tools.some(tool => tool.name === 'create_plan'));
    if (!calls++) return { status: 'completed', output: [{ type: 'function_call', name: 'create_plan', call_id: 'unwanted-plan', arguments: JSON.stringify({ candidateIds: ['pier39'] }) }] };
    const rejected = payload.input.find(item => item.type === 'function_call_output');
    assert.equal(JSON.parse(rejected.output).code, 'plan_not_requested');
    return final('先不重新排行程。要判断公交能否赶上，还需要你预计几点、从哪个公共地点出发；目前没有核实班次和耗时。');
  } });
  const result = await assistant.run({ message: '先别排了，我只是问坐公交来不来得及', searchMode: 'site', sessionToken: encodeTaskToken({ state, lastPlan }, { secret, now: NOW }) });
  assert.equal(result.assistantPlan, undefined);
  assert.equal(result.degraded, false);
  assert.deepEqual(decodeTaskToken(result.assistantSessionToken, { secret, now: NOW }).lastPlan.selectedIds, state.selectedCandidateIds);
  assert.ok(!result.research.steps.some(step => step.tool === 'create_plan' && step.status === 'completed'));
});

test('a new service question does not receive the prior sightseeing plan as current context', async () => {
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: secret }, isTest: true, now: () => NOW, ai: async payload => {
    assert.equal(JSON.parse(payload.input[0].content).previousPlan, null);
    return final('图书馆打印和出游路线是不同事项，请告诉我你使用哪家图书馆。');
  } });
  const result = await assistant.run({ message: '换个话题，图书馆打印怎么收费？', searchMode: 'site', sessionToken: encodeTaskToken({ state, lastPlan }, { secret, now: NOW }) });
  assert.equal(result.assistantPlan, undefined);
});
