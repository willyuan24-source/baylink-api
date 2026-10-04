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
  for (const message of ['删除第二站', '第二個不要了', 'Remove stop 2', 'Skip the second place']) {
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
