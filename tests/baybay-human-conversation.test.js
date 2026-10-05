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

test('an uncited casual plan gets one evidence-based synthesis recovery without replaying its unsupported prose', async () => {
  let rounds = 0;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: secret }, isTest: true, now: () => NOW, ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    assert.deepEqual(payload.tools, []);
    assert.deepEqual(context.currentPlan.stops.map(stop => stop.entityId), state.selectedCandidateIds);
    if (!rounds++) return final('这两站走路只要三分钟，随便安排都来得及。');
    assert.match(payload.instructions, /previous final answer did not cite/);
    assert.doesNotMatch(JSON.stringify(payload.input), /走路只要三分钟/);
    const refs = context.currentPlan.stops.map(stop => stop.sourceIds[0]);
    assert.ok(refs.every(id => context.evidence.some(source => source.id === id)));
    return final(`保留先科学馆、再 PIER 39 的两站框架。PIER 39 公共区域入场记录为免费，付费项目另算。 [[${refs[1]}]] 具体路程和所选日期开放仍需核对。你预计几点到首站、从哪个公共地点出发？`);
  } });
  const result = await assistant.run({ message: '周六想去 Exploratorium 再去 Pier 39，带5岁小朋友，怎么排比较轻松？', searchMode: 'site' });
  assert.equal(rounds, 2);
  assert.equal(result.degraded, false);
  assert.equal(result.research.steps.filter(step => step.tool === 'create_plan').length, 2, 'recovery reuses the existing plan instead of starting another route-enrichment pass');
  assert.ok(result.research.warnings.includes('answer_plan_citation_retry'));
  assert.ok(!result.research.warnings.includes('answer_plan_citations_repaired'));
  assert.doesNotMatch(result.answer, /三分钟|随便安排/);
  assert.match(result.answer, /预计几点/);
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), state.selectedCandidateIds);
  assert.ok(result.sources.some(source => /pier39\.com/.test(source.url)));
});

test('repeated uncited plan output stops after one recovery and remains visibly degraded', async () => {
  let rounds = 0;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: secret }, isTest: true, now: () => NOW, ai: async () => {
    rounds++;
    return final('去两站就好，门票一共只要 $1，完全来得及。');
  } });
  const result = await assistant.run({ message: '周六想去 Exploratorium 再去 Pier 39，带5岁小朋友，怎么排比较轻松？', searchMode: 'site' });
  assert.equal(rounds, 2);
  assert.equal(result.degraded, true);
  assert.ok(result.research.warnings.includes('answer_plan_citations_repaired'));
  assert.doesNotMatch(result.answer, /只要 \$1|完全来得及/);
  assert.ok(result.sources.length > 0);
});
