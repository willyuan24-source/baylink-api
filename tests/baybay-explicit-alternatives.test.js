const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');

const message = require('../scripts/baybay-november-refresh-cases-2026-10-05.json').cases.find(row => row.id === 'sf-family-budget-two-stops').request.message;
const selected = ['venue-exploratorium-daytime', 'pier39'];
const changed = ['venue-exploratorium-daytime', 'restaurant-gotts-ferry-building'];
const final = value => ({ model: 'fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify(value) }] }] });

for (const searchMode of ['site', 'smart']) test(`the production two-stop request constrains every ${searchMode} card even when the model proposes a replacement`, async () => {
  const contexts = [], toolResults = [];
  let proposalSent = false;
  const assistant = createBayBayAssistant({ catalog: loadPlannerCatalog(), guideCatalog: require('../data/guide-catalog.json'),
    config: { JWT_SECRET: 'synthetic-november-exact-selection-key' }, isTest: true, now: () => Date.parse('2026-10-05T19:00:00Z'),
    webSearch: async () => { throw new Error('This named-venue test must not perform discovery'); },
    sourceFetch: async () => { throw new Error('This fixture must not read live pages'); },
    ai: async payload => {
      const context = JSON.parse(payload.input[0].content);
      contexts.push(context);
      for (const item of payload.input.filter(row => row.type === 'function_call_output')) toolResults.push(JSON.parse(item.output));
      if (searchMode === 'smart' && !proposalSent) {
        proposalSent = true;
        return { model: 'fixture', status: 'completed', output: [{ type: 'function_call', name: 'create_plan', call_id: 'replacement-proposal', arguments: JSON.stringify({ candidateIds: changed }) }] };
      }
      const sourceId = context.currentPlan.stops[0].sourceIds[0];
      return final({ answer: `保留两处目的地和原顺序；所选日期的开放、交通及完整费用仍待确认。 [[${sourceId}]]`, candidateIds: changed, followups: [] });
    },
  });
  const result = await assistant.run({ message, searchMode });
  assert.equal(result.degraded, false);
  assert.deepEqual(result.taskState.selectedCandidateIds, selected);
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), selected);
  assert.deepEqual(result.assistantPlan.handoff.stops.map(stop => stop.id), selected);
  assert.deepEqual(result.assistantPlan.alternatives, [], 'a budget gap does not authorize replacing PIER 39 with a restaurant');
  assert.equal(result.assistantPlan.budget.knownTotalUsd, 109.85);
  assert.equal(result.assistantPlan.constraints.returnToOrigin, false);
  assert.ok(contexts.every(context => context.currentPlan.alternatives.length === 0), 'synthesis must not receive an unauthorized alternative to describe');
  if (searchMode === 'smart') {
    assert.equal(proposalSent, true);
    assert.ok(toolResults.some(plan => plan.stops));
    for (const plan of toolResults.filter(row => row.stops)) {
      assert.deepEqual(plan.stops.map(stop => stop.entityId), selected);
      assert.deepEqual(plan.alternatives, []);
    }
  }
});

test('a negated request for alternatives does not authorize changing the explicitly ordered stops', async () => {
  const assistant = createBayBayAssistant({ catalog: loadPlannerCatalog(), guideCatalog: [],
    config: { JWT_SECRET: 'synthetic-no-alternatives-key' }, isTest: true, now: () => Date.parse('2026-10-05T19:00:00Z'),
    ai: async payload => {
      const context = JSON.parse(payload.input[0].content);
      return final({ answer: `只保留原地点，交通仍待核对。 [[${context.currentPlan.stops[0].sourceIds[0]}]]`, candidateIds: selected });
    },
  });
  for (const instruction of ['不要给备选方案。', '請不要給替代方案。', 'Do not suggest an alternative.']) {
    const result = await assistant.run({ message: `${message}${instruction}`, searchMode: 'site' });
    assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), selected);
    assert.deepEqual(result.assistantPlan.alternatives, [], instruction);
  }
});
