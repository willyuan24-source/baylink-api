const test = require('node:test');
const assert = require('node:assert/strict');
const { preparePlanEdit, resolvePlanSelection } = require('../lib/baybayPlanEdits');

const NOW = Date.parse('2026-10-04T16:00:00Z');
const state = { goal: 'day-plan', date: '2026-10-05', city: 'Fremont', origin: 'Fremont', partySize: 2, budget: 100, budgetScope: 'total', selectedCandidateIds: [], excludedCandidateIds: [] };
const place = (id, fields = {}) => ({ id, kind: 'place', title: `Place ${id}`, city: 'Fremont', officialUrl: `https://example.org/${id}`, planning: { admissionUsd: 0 }, ...fields });
const rows = ['a', 'b', 'c', 'd', 'e', 'f'].map(id => place(id));
const catalog = { events: [], places: rows };
const lastPlan = { selectedIds: ['a', 'b', 'c'], date: state.date };
const prepare = (message, options = {}) => preparePlanEdit({ message, state, previousState: state, lastPlan, catalog, ...options });
const select = (edit, candidateIds, candidates = rows) => resolvePlanSelection({ edit, candidateIds, candidates, now: NOW });

test('replace second stop keeps first and third in original order despite model proposing an entirely new day', () => {
  const prepared = prepare('换掉第二站');
  assert.deepEqual(prepared.state.selectedCandidateIds, ['a', 'c']);
  assert.deepEqual(prepared.state.excludedCandidateIds, ['b']);
  const selected = select(prepared.edit, ['d', 'e', 'f']);
  assert.deepEqual(selected.selectedIds, ['a', 'd', 'c']);
  assert.equal(selected.replacementId, 'd');
  assert.equal(selected.needsRevalidation, false);
});

test('reverse-order Chinese and English ordinal instructions identify the same indexed edit', () => {
  for (const message of ['第二站太远，换一个', '請替換第二個', 'Replace the second stop', 'Swap the 2nd stop', 'The second place is too far; replace it']) {
    const prepared = prepare(message);
    assert.equal(prepared.edit.index, 1, message);
    assert.deepEqual(select(prepared.edit, ['d']).selectedIds, ['a', 'd', 'c'], message);
  }
});

test('remove only deletes requested stop and cannot be turned into an extra visit by the model', () => {
  for (const message of ['删除第二站', '取消第二站', '第二個不要了', 'Remove stop 2', 'Skip the second place']) {
    const prepared = prepare(message);
    assert.equal(prepared.edit.kind, 'remove', message);
    assert.deepEqual(select(prepared.edit, ['f', 'e', 'd']).selectedIds, ['a', 'c']);
  }
});

test('missing replacement leaves a clear gap instead of regenerating the full day', () => {
  const prepared = prepare('换掉第二站');
  const result = select(prepared.edit, [], rows.slice(0, 3));
  assert.deepEqual(result.selectedIds, ['a', 'c']);
  assert.equal(result.replacementId, null);
  assert.equal(result.needsRevalidation, true);
  assert.match(result.notice, /未虚构/);
});

test('deleting the only stop is an explicit empty selection, not automatic selection', () => {
  const prepared = prepare('删除第一站', { lastPlan: { selectedIds: ['a'], date: state.date } });
  const result = select(prepared.edit, ['b']);
  assert.deepEqual(result.selectedIds, []);
  assert.equal(result.explicitSelection, true);
});

test('changing city, date or goal invalidates old selection before a new search', () => {
  for (const patch of [{ city: 'Berkeley' }, { date: '2026-10-06' }, { goal: 'newcomer' }]) {
    const prepared = prepare('改条件后换掉第二站', { state: { ...state, ...patch, selectedCandidateIds: ['a', 'b', 'c'] } });
    assert.equal(prepared.edit.kind, 'invalidated');
    assert.deepEqual(prepared.state.selectedCandidateIds, []);
    const result = select(prepared.edit, ['d']);
    assert.equal(result.explicitSelection, false);
    assert.deepEqual(result.selectedIds, ['d']);
  }
  const dateOnly = prepare('改成明天', { state: { ...state, date: '2026-10-06', selectedCandidateIds: ['a', 'b', 'c'] } });
  assert.equal(dateOnly.edit.kind, 'invalidated');
  assert.deepEqual(dateOnly.state.selectedCandidateIds, []);
});

test('remaining stops are revalidated for age, budget and availability', () => {
  const strict = { ...state, childAges: [6], partySize: 3, budget: 20 };
  const candidates = [place('a', { planning: { minAge: 18, admissionUsd: 0 } }), place('b'), place('c', { availability: 'sold_out' }), place('d', { planning: { admissionUsd: 50, admissionAppliesTo: 'all' } }), place('e')];
  const prepared = prepare('换掉第二站', { state: strict });
  const selected = select(prepared.edit, ['d', 'e'], candidates);
  assert.deepEqual(selected.selectedIds, ['e']);
  assert.ok(selected.invalidIds.includes('a'));
  assert.ok(selected.invalidIds.includes('c'));
  assert.ok(selected.invalidIds.includes('d'));
  assert.equal(selected.needsRevalidation, true);
});

test('old web identity refs are not resurrected into verified plan candidates', () => {
  const prepared = prepare('删除第二站', { lastPlan: { selectedIds: ['a', 'b', 'web-old'], date: state.date, selectedRefs: [{ id: 'web-old', title: 'Old Venue', city: 'Fremont', sourceUrl: 'https://example.org/old', previousKind: 'place' }] } });
  assert.equal(prepared.edit.needsRevalidation, true);
  assert.deepEqual(prepared.edit.missingIds, ['web-old']);
  const selected = select(prepared.edit, ['f']);
  assert.deepEqual(selected.selectedIds, ['a']);
  assert.deepEqual(selected.missingIds, ['web-old']);
  assert.equal(selected.needsRevalidation, true);
});

test('an old web stop can remain only after new source verification populates the current store', () => {
  const prepared = prepare('删除第二站', { lastPlan: { selectedIds: ['a', 'b', 'web-old'], date: state.date } });
  const web = place('web-old', { origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont', kind: 'Old Venue is a museum in Fremont.' } });
  const result = select(prepared.edit, [], new Map([...rows, web].map(row => [row.id, row])));
  assert.deepEqual(result.selectedIds, ['a', 'web-old']);
  assert.deepEqual(result.missingIds, []);
  assert.equal(result.needsRevalidation, false);
});

test('replacement stays in the same geographic cluster when travel remains unknown', () => {
  const prepared = prepare('换掉第二站');
  const result = select(prepared.edit, ['far', 'd'], [...rows, place('far', { city: 'Novato' })]);
  assert.deepEqual(result.selectedIds, ['a', 'd', 'c']);
});

test('duplicate and prefixed proposed IDs do not duplicate surviving stops', () => {
  const prepared = prepare('换掉第二站');
  const result = select(prepared.edit, ['place:a', 'place:d', 'd', 'place:c']);
  assert.deepEqual(result.selectedIds, ['a', 'd', 'c']);
});

test('invalid numbered edits return clarification data without silently changing a different stop', () => {
  for (const message of ['删除第六站', '删除第一站和第二站']) {
    const prepared = prepare(message);
    assert.equal(prepared.edit.kind, 'invalid');
    assert.equal(prepared.edit.needsRevalidation, true);
    assert.deepEqual(prepared.state.excludedCandidateIds, []);
  }
});

test('no edit leaves normal model selection untouched and inputs remain immutable', () => {
  const before = JSON.stringify({ state, lastPlan, rows });
  const prepared = prepare('推荐其他活动');
  assert.equal(prepared.edit, null);
  assert.deepEqual(select(null, ['d']).selectedIds, ['d']);
  select(prepare('换掉第二站').edit, ['e']);
  assert.equal(JSON.stringify({ state, lastPlan, rows }), before);
});

test('generic same-scope follow-up seeds retrieval with the published plan in its original order', () => {
  const prepared = prepare('检查这份安排费用', { lastPlan: { selectedIds: ['c', 'a', 'b'], date: state.date } });
  assert.equal(prepared.edit, null);
  assert.deepEqual(prepared.state.selectedCandidateIds, ['c', 'a', 'b']);
  const result = select(prepared.edit, ['e', 'f']);
  assert.deepEqual(result.selectedIds, ['e', 'f']);
  assert.equal(result.explicitSelection, false);
});

test('same-scope context seeding never revives an explicitly excluded old stop', () => {
  const prepared = prepare('检查这份安排费用', { state: { ...state, selectedCandidateIds: [], excludedCandidateIds: ['place:b'] } });
  assert.equal(prepared.edit, null);
  assert.deepEqual(prepared.state.selectedCandidateIds, ['a', 'c']);
});

test('generic city, date or goal changes clear previous selections without an indexed instruction', () => {
  for (const [message, patch] of [['改去 Berkeley', { city: 'Berkeley' }], ['改成明天', { date: '2026-10-06' }], ['查搬家资料', { goal: 'newcomer' }]]) {
    const prepared = prepare(message, { state: { ...state, ...patch, selectedCandidateIds: ['a', 'b', 'c'] } });
    assert.equal(prepared.edit.kind, 'invalidated');
    assert.deepEqual(prepared.state.selectedCandidateIds, []);
    assert.equal(select(prepared.edit).explicitSelection, false);
  }
});

test('named cancellation keeps signed surviving stops in order and blocks invented replacements', () => {
  for (const message of ['取消 Place b', '请去掉 Place b', '不要 Place b', 'Place b 不要了', 'Cancel Place b', 'Remove Place b']) {
    const prepared = prepare(message);
    assert.equal(prepared.edit.kind, 'remove', message);
    assert.equal(prepared.edit.named, true, message);
    assert.deepEqual(prepared.state.excludedCandidateIds, ['b'], message);
    assert.deepEqual(select(prepared.edit, ['d', 'b', 'f']).selectedIds, ['a', 'c'], message);
  }
});

test('only keeping named stops preserves their original order and cannot revive cancelled stops', () => {
  for (const message of ['取消 Place b，只保留 Place c 和 Place a', 'Only keep Place c and Place a', '只去 Place a']) {
    const prepared = prepare(message);
    const expected = message === '只去 Place a' ? ['a'] : ['a', 'c'];
    assert.deepEqual(select(prepared.edit, ['b', 'd', 'f']).selectedIds, expected, message);
    assert.equal(select(prepared.edit, []).explicitSelection, true);
  }
});

test('real removal prompt leaves an explicitly empty plan until its newly named museum is verified', () => {
  const explorer = place('exploratorium', { title: 'Exploratorium · 日间科学探索馆' });
  const prepared = prepare('临时没有车了，改成公共交通，全程总预算降到70美元。取消Exploratorium，只保留SFMOMA，不要补一个替代景点。', {
    catalog: { places: [explorer] }, lastPlan: { selectedIds: [explorer.id], date: state.date }, state: { ...state, travelMode: 'transit', budget: 70 },
  });
  assert.deepEqual(prepared.state.excludedCandidateIds, [explorer.id]);
  const unknown = place('web-sfmoma', { title: 'SFMOMA', origin: 'web', kind: 'unknown', verification: 'search-result' });
  const result = select(prepared.edit, [explorer.id, 'web-sfmoma'], [explorer, unknown, ...rows]);
  assert.deepEqual(result.selectedIds, []);
  assert.equal(result.explicitSelection, true);
  assert.equal(result.needsRevalidation, true);
  assert.match(result.notice, /重新核实/);
  const verified = { ...unknown, kind: 'place', verification: 'page-verified', verifiedFacts: { city: 'Fremont', kind: 'SFMOMA is a museum in Fremont.' } };
  assert.deepEqual(select(prepared.edit, [explorer.id, 'd'], [explorer, verified, ...rows]).selectedIds, ['web-sfmoma']);
});

test('named signed web stops establish identity but must be reverified before being retained', () => {
  const prepared = prepare('取消 Place b，只保留 Old Venue', { lastPlan: { selectedIds: ['b', 'web-old'], date: state.date,
    selectedRefs: [{ id: 'web-old', title: 'Old Venue', city: 'Fremont', sourceUrl: 'https://example.org/old', previousKind: 'place' }] } });
  const result = select(prepared.edit, ['d']);
  assert.deepEqual(result.selectedIds, []);
  assert.deepEqual(result.missingIds, ['web-old']);
  assert.equal(result.needsRevalidation, true);
});

test('a new unknown museum is not silently dropped when the only-list also includes a catalog stop', () => {
  const prepared = prepare('只保留 Place a 和 SFMOMA');
  assert.deepEqual(prepared.edit.keepNames, ['place a', 'sfmoma']);
  const waiting = select(prepared.edit, ['a']);
  assert.deepEqual(waiting.selectedIds, ['a']);
  assert.equal(waiting.needsRevalidation, true);
  const sfmoma = place('sfmoma', { title: 'SFMOMA', origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont', kind: 'SFMOMA is a museum in Fremont.' } });
  assert.deepEqual(select(prepared.edit, ['d'], [...rows, sfmoma]).selectedIds, ['a', 'sfmoma']);
});

test('duplicate or ambiguous fresh web identities do not become multiple museum visits', () => {
  const prepared = prepare('只保留 SFMOMA');
  const web = place('web-one', { title: 'SFMOMA', origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont', kind: 'SFMOMA is a museum in Fremont.' } });
  const result = select(prepared.edit, ['web-one'], [...rows, web, { ...web, id: 'web-two' }]);
  assert.deepEqual(result.selectedIds, []);
  assert.equal(result.needsRevalidation, true);
});

test('named only-selection still revalidates budget, age and closed venues', () => {
  const prepared = prepare('只保留 Place a 和 Place c', { state: { ...state, budget: 1, partySize: 2, childAges: [6] } });
  const candidates = [place('a', { planning: { minAge: 18, admissionUsd: 0 } }), place('c', { status: 'closed' })];
  const selected = select(prepared.edit, ['d'], candidates);
  assert.deepEqual(selected.selectedIds, []);
  assert.equal(selected.needsRevalidation, true);
});

test('a changed city does not revive the cancelled stop while validating an explicit new-only destination', () => {
  const prepared = prepare('改去 Berkeley，取消 Place b，只去 Place d', { state: { ...state, city: 'Berkeley' } });
  assert.equal(prepared.edit.kind, 'remove');
  assert.deepEqual(prepared.edit.retainedIds, []);
  assert.deepEqual(select(prepared.edit, ['b', 'e'], [...rows, place('d', { city: 'Berkeley' })]).selectedIds, ['d']);
});

test('negative cancellation and retaining child constraints do not delete destinations', () => {
  for (const message of ['不要取消 Place b', '不要删除 Place b', '只保留孩子6岁、公共交通和150美元限制', '保留原来安排，检查 Place b 是否取消了', '如果取消 Place b 会怎么样？']) {
    const prepared = prepare(message);
    assert.equal(prepared.edit, null, message);
    assert.deepEqual(prepared.state.selectedCandidateIds, ['a', 'b', 'c'], message);
  }
});

test('a longer named venue is never mistaken for the similarly named old stop', () => {
  const daytime = place('day', { title: 'Exploratorium · 日间科学探索馆' });
  const night = place('night', { title: 'Exploratorium After Dark · 18岁以上夜场' });
  const prepared = prepare('取消 Exploratorium After Dark', { catalog: { places: [daytime, night] }, lastPlan: { selectedIds: ['day', 'night'], date: state.date } });
  assert.deepEqual(select(prepared.edit, ['day'], [daytime, night]).selectedIds, ['day']);
  assert.deepEqual(prepared.state.excludedCandidateIds, ['night']);
});

test('assistant plan and save handoff cannot retain a named cancelled stop even if the model proposes it', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const { encodeTaskToken } = require('../lib/baybayState');
  const secret = 'named-edit-test-state-secret-only';
  const explorer = place('exploratorium', { title: 'Exploratorium · 日间科学探索馆' });
  const previous = { ...state, selectedCandidateIds: [explorer.id] };
  const token = encodeTaskToken({ state: previous, lastPlan: { selectedIds: [explorer.id], date: state.date } }, { secret, now: () => NOW });
  const assistant = createBayBayAssistant({ config: { BAYBAY_STATE_SECRET: secret }, catalog: { version: 1, checkedAt: '2026-10-04', events: [], guides: [], places: [explorer, ...rows] }, guideCatalog: [], isTest: true, now: () => NOW,
    ai: async () => ({ model: 'fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '只保留的 SFMOMA 尚需核实。', candidateIds: ['exploratorium', 'd'] }) }] }] }) });
  const result = await assistant.run({ message: '取消Exploratorium，只保留SFMOMA，不要补一个替代景点。', sessionToken: token, searchMode: 'site' });
  assert.ok(result.assistantPlan);
  assert.deepEqual(result.assistantPlan.stops, []);
  assert.deepEqual(result.assistantPlan.handoff?.stops || [], []);
  assert.ok(result.taskState.excludedCandidateIds.includes('exploratorium'));
  assert.match(result.assistantPlan.unknowns.join('\n'), /重新核实/);
});

test('named cancellation works after a signed clarification with selected IDs but no previous plan', () => {
  const previousState = { ...state, selectedCandidateIds: ['a', 'b', 'c'] };
  const prepared = prepare('取消 Place b，只保留 Place a', { previousState, lastPlan: undefined });
  assert.deepEqual(prepared.state.selectedCandidateIds, ['a']);
  assert.deepEqual(prepared.state.excludedCandidateIds, ['b', 'c']);
  const result = select(prepared.edit, ['b', 'd']);
  assert.deepEqual(result.selectedIds, ['a']);
  assert.equal(result.explicitSelection, true);
  assert.equal(result.suppressAlternatives, true);
});

test('pending signed identities are revalidated and are never substituted with current-turn IDs', () => {
  const prepared = prepare('取消 Place b，只保留 Place a', {
    previousState: { ...state, selectedCandidateIds: ['a', 'b'] }, lastPlan: undefined,
    state: { ...state, selectedCandidateIds: ['d'], childAges: [6] },
  });
  const result = select(prepared.edit, ['d'], [place('a', { planning: { admissionUsd: 0, minAge: 18 } }), ...rows.slice(1)]);
  assert.deepEqual(result.selectedIds, []);
  assert.equal(result.needsRevalidation, true);
  assert.ok(result.invalidIds.includes('a'));
  const unsigned = prepare('删除第二站', { lastPlan: undefined, previousState: {}, state: { ...state, selectedCandidateIds: ['a', 'b'] } });
  assert.equal(unsigned.edit, null);
});

test('fresh only-selection forbids automatic alternatives without treating current IDs as signed history', () => {
  const prepared = prepare('只去 Place a', { previousState: {}, lastPlan: undefined, state: { ...state, selectedCandidateIds: ['d'] } });
  const result = select(prepared.edit, ['d', 'e']);
  assert.deepEqual(result.selectedIds, ['a']);
  assert.equal(result.suppressAlternatives, true);
  assert.deepEqual(prepared.edit.previousIds, []);
});

test('named cancellation excludes signed requested stops that the displayed partial plan could not include', () => {
  const previousState = { ...state, selectedCandidateIds: ['a', 'b', 'c'] };
  const prepared = prepare('取消 Place b，只去 Place a', { previousState, lastPlan: { selectedIds: ['a'], date: state.date } });
  assert.deepEqual(prepared.state.selectedCandidateIds, ['a']);
  assert.deepEqual(prepared.state.excludedCandidateIds, ['b', 'c']);
  const result = select(prepared.edit, ['b', 'c', 'd']);
  assert.deepEqual(result.selectedIds, ['a']);
  assert.equal(result.suppressAlternatives, true);
  const removeOnly = prepare('取消 Place b', { previousState, lastPlan: { selectedIds: ['a'], date: state.date } });
  assert.deepEqual(select(removeOnly.edit, ['c']).selectedIds, ['a']);
  assert.deepEqual(removeOnly.state.excludedCandidateIds, ['b']);
});

test('numbered edits still address displayed plan order instead of omitted signed requests', () => {
  const prepared = prepare('删除第二站', { previousState: { ...state, selectedCandidateIds: ['a', 'b', 'c'] }, lastPlan: { selectedIds: ['c', 'a'], date: state.date } });
  assert.equal(prepared.edit.targetId, 'a');
  assert.deepEqual(select(prepared.edit, ['d']).selectedIds, ['c']);
});

test('clarification-only family session cancels OMCA in state, visible plan and handoff without suggesting another museum', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const { encodeTaskToken, decodeTaskToken } = require('../lib/baybayState');
  const secret = 'clarification-plan-test-state-secret';
  const explorer = place('venue-exploratorium-daytime', { title: 'Exploratorium · 日间科学探索馆', city: 'San Francisco' });
  const omca = place('venue-omca', { title: 'Oakland Museum of California · OMCA 展馆', city: 'Oakland' });
  const sfmoma = place('venue-sfmoma', { title: 'SFMOMA', city: 'San Francisco' });
  const previous = { ...state, city: null, region: 'sf', date: '2026-10-10', origin: null, startTime: '09:30', finishBy: '17:00',
    partySize: 3, childAges: [6], travelMode: 'transit', budget: 150, selectedCandidateIds: [explorer.id, omca.id] };
  const token = encodeTaskToken({ state: previous }, { secret, now: () => NOW });
  assert.equal(decodeTaskToken(token, { secret, now: () => NOW }).lastPlan, null);
  const assistant = createBayBayAssistant({ config: { BAYBAY_STATE_SECRET: secret }, catalog: { version: 1, checkedAt: '2026-10-04', events: [], guides: [], places: [explorer, omca, sfmoma] }, guideCatalog: [], isTest: true, now: () => NOW,
    ai: async () => ({ model: 'fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '只保留 Exploratorium；当日交通与费用仍待核实。', candidateIds: [omca.id, sfmoma.id] }) }] }] }) });
  const result = await assistant.run({ message: '那就取消Oakland Museum of California，只去旧金山Exploratorium，其他条件保持不变。请保留孩子6岁、公共交通、150美元全家总预算和17:00回Millbrae BART站的限制；查不到当日返程时刻就明确说不能保证。', sessionToken: token, searchMode: 'site' });
  assert.deepEqual(result.taskState.selectedCandidateIds, [explorer.id]);
  assert.ok(result.taskState.excludedCandidateIds.includes(omca.id));
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), [explorer.id]);
  assert.deepEqual(result.assistantPlan.handoff.stops, [{ kind: 'place', id: explorer.id }]);
  assert.deepEqual(result.assistantPlan.alternatives, []);
  assert.equal(result.taskState.budget, 150);
  assert.deepEqual(result.taskState.childAges, [6]);
  assert.equal(result.taskState.startTime, '09:30');
  assert.equal(result.taskState.finishBy, '17:00');
});
