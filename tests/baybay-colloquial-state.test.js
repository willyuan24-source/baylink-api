const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState, encodeTaskToken, decodeTaskToken, pausesPlanRequest } = require('../lib/baybayState');
const { preparePlanEdit, resolvePlanSelection } = require('../lib/baybayPlanEdits');
const { buildItinerary } = require('../lib/baybayPlan');
const catalog = require('../data/planner-catalog.json');

const NOW = Date.parse('2026-10-04T16:00:00Z');
const tokenOptions = { secret: 'colloquial-regression-synthetic-secret', now: NOW };
const sign = value => decodeTaskToken(encodeTaskToken(value.state ? value : { state: value }, tokenOptions), tokenOptions);
const resolve = (message, previous, options = {}) => resolveTaskState({ message, previous, catalog, today: '2026-10-04', ...options });
const base = () => resolve('2026年10月10日，两位成人和一个5岁孩子，10点从 San Francisco 的 Ferry Building 出发，严格按 Exploratorium、Pier 39 的顺序走，全家总预算120美元，只坐公交，17点在 Pier 39 结束，不返回起点。').state;
const assertRetained = (state, previous, except = []) => {
  for (const field of ['date', 'city', 'origin', 'originCandidateId', 'partySize', 'childAges', 'budget', 'budgetScope', 'travelMode', 'startTime', 'finishBy', 'returnToOrigin', 'selectedCandidateIds']) {
    if (!except.includes(field)) assert.deepEqual(state[field], previous[field], field);
  }
};

test('crowd, pace and nearby preferences survive signed followups without inventing party, route or times', () => {
  const original = base();
  let previous = sign(original);
  for (const message of ['人少点吧，不想挤。', '不要太赶，中间歇会儿。', '顺路加个公园就行，别跑远。', '走一会就累，能坐着歇最好。', '再看看门票。', '其他条件不变。']) {
    const state = resolve(message, previous).state;
    assertRetained(state, original);
    previous = sign(state);
  }
  assert.deepEqual(previous.state.preferences, ['avoid-crowds', 'relaxed-pace', 'rest-breaks', 'nearby-stops', 'limited-walking']);
  assert.equal(resolve('人少点吧，不想挤。').state.partySize, null);
});

test('after-lunch duration is bounded soft context, not a made-up departure or return clock', () => {
  for (const message of ['午饭后出去两个小时，开车别太远。', '午飯後出去兩個小時，開車別太遠。', 'After lunch, out for two hours. Nearby stops please.']) {
    let previous = sign(resolve(message).state);
    for (let turn = 0; turn < 5; turn++) previous = sign(resolve('再看看', previous).state);
    assert.ok(previous.state.preferences.includes('after-lunch'), message);
    assert.ok(previous.state.preferences.includes('outing-duration:120-minutes'), message);
    assert.ok(previous.state.preferences.includes('nearby-stops'), message);
    assert.equal(previous.state.startTime, null, message);
    assert.equal(previous.state.finishBy, null, message);
    assert.equal(previous.state.partySize, null, message);
    const changed = resolve('这次出去三个小时。', previous).state;
    assert.ok(changed.preferences.includes('outing-duration:180-minutes'));
    assert.ok(!changed.preferences.includes('outing-duration:120-minutes'));
    assert.ok(!resolve('时间不限', sign(changed)).state.preferences.some(value => value.startsWith('outing-duration:')));
  }
});

test('a vague afternoon revision clears incompatible morning time and asks instead of assuming two pm', () => {
  const original = base();
  const next = resolve('改下午吧，上午有事。', sign(original));
  assertRetained(next.state, original, ['startTime']);
  assert.equal(next.state.startTime, null);
  assert.match(next.clarification, /具体几点/);
  assert.ok(next.state.clearedFields.includes('startTime'));
  const signed = sign(next.state);
  assert.equal(resolve('门票再查一下', signed).state.startTime, null);
  const exact = resolve('那就下午两点从原来的地方出发，五点还是要结束。', signed).state;
  assert.equal(exact.startTime, '14:00');
  assert.equal(exact.originCandidateId, original.originCandidateId);
  assert.equal(exact.origin, original.origin);
  assert.equal(resolve('改下午吧', sign(exact)).clarification, undefined);
});

test('an unresolved previous origin cannot turn a demonstrative into a public location', () => {
  const result = resolve('那就下午两点从原来的地方出发。');
  assert.equal(result.state.origin, null);
  assert.equal(result.state.originCandidateId, null);
  assert.equal(result.state.startTime, '14:00');
  assert.match(result.clarification, /出发地点尚未确定/);
});

test('a weekday correction needs the actual date when the referenced week is ambiguous', () => {
  const original = base();
  const result = resolve('我说的是周日，其他不变。', sign(original));
  assert.equal(result.state.date, null);
  assert.match(result.clarification, /几月几日/);
  assertRetained(result.state, original, ['date']);
  const sunday = { ...original, date: '2026-10-11' };
  assert.equal(resolve('我说的是周日，其他不变。', sign(sunday)).state.date, sunday.date);
  assert.equal(resolve('我说的是10月11日周日，其他不变。', sign(original)).state.date, sunday.date);
});

test('weekend ranges never manufacture one chosen date and casual mentions preserve an explicit day', () => {
  for (const today of ['2026-10-04', '2026-10-07']) {
    for (const message of ['这周末想出去透透气，有啥不折腾的？', '周末有什么轻松的？', 'What is easy this weekend?']) {
      const fresh = resolve(message, undefined, { today }).state;
      assert.equal(fresh.date, null, `${today}: ${message}`);
      assert.equal(fresh.partySize, null);
      assert.equal(fresh.origin, null);
    }
  }
  const previous = sign(base());
  assert.equal(resolve('周末人会很多吗？', previous).state.date, '2026-10-10');
  const moved = resolve('改下周末吧。', previous);
  assert.equal(moved.state.date, null);
  assert.match(moved.clarification, /具体哪一天/);
  assert.equal(resolve('这周末10月10日去。').state.date, '2026-10-10');
  assert.equal(resolve('这周末周六去。').state.date, '2026-10-10');
});

test('destination and origin corrections are scoped separately without invented coordinates', () => {
  const original = base();
  const destination = resolve('不是去 San Jose，我说的是 San Francisco，别换地方。', sign(original));
  assert.equal(destination.clarification, undefined);
  assertRetained(destination.state, original);
  assert.ok(destination.state.excludedCities.includes('San Jose'));
  const origin = resolve('起点不在我家，我说的是 Fremont BART 站。', sign(original));
  assertRetained(origin.state, original, ['origin', 'originCandidateId']);
  assert.equal(origin.state.origin, 'Fremont BART 站');
  assert.equal(origin.state.originCandidateId, null);
});

test('explicit pause changes the task but preserves facts for answering the feasibility question', () => {
  const original = { ...base(), maxStops: 2 };
  const result = resolve('先别排了，我只是问坐公交来不来得及。', sign(original));
  assert.equal(result.planningPaused, true);
  assert.equal(result.state.goal, 'information');
  assertRetained(result.state, original);
  assert.equal(result.state.maxStops, 2);
  assert.equal(resolve('那什么时候走比较稳？', sign(result.state)).state.goal, 'information');
  for (const text of ['不要太赶，中间歇会儿。', '不改行程和顺序，只解释门票。', '先别排了，重新安排一天。']) assert.equal(pausesPlanRequest(text), false, text);
});

test('age corrections and child participation updates retain the explicit total budget', () => {
  const original = base();
  assertRetained(resolve('人不变，孩子不是3岁，是5岁。', sign(original)).state, original);
  assertRetained(resolve('预算还是全家120，不是每人120。', sign(original)).state, original);
  const adults = resolve('我们就两个人去，孩子不去了。', sign(original)).state;
  assertRetained(adults, original, ['partySize', 'childAges']);
  assert.equal(adults.partySize, 2);
  assert.deepEqual(adults.childAges, []);
  assert.deepEqual(sign(adults).state.childAges, []);
});

test('clear return requirement removes only the optional return condition across signed tokens', () => {
  for (const command of ['清除返回要求', 'Clear return requirement']) {
    for (const returnToOrigin of [true, false]) {
      const original = { ...base(), returnToOrigin };
      const cleared = resolve(command, sign(original)).state;
      assertRetained(cleared, original, ['returnToOrigin']);
      assert.equal(cleared.returnToOrigin, undefined);
      assert.ok(cleared.clearedFields.includes('returnToOrigin'));
      assert.equal(resolve('其他不变', sign(cleared)).state.returnToOrigin, undefined);
    }
  }
});

test('a conversational leave deadline is distinct from departure and a venue schedule question', () => {
  for (const message of ['那两个顺路吗？下午3点得走，来得及吗？', '下午三点就得走了。', '下午3点前要离开。']) {
    const state = resolve(message).state;
    assert.equal(state.finishBy, '15:00', message);
    assert.equal(state.startTime, null, message);
    assert.equal(state.returnToOrigin, undefined, message);
  }
  for (const message of ['活动下午3点得走吗？', '官网写下午3点得走。', '下午3点得走过去。']) assert.equal(resolve(message).state.finishBy, null, message);
});

test('live casual three-turn route keeps the correct final stop in state, plan and save handoff', () => {
  let previous;
  const queries = ['周六想去 Exploratorium 再去 Pier 39，带5岁小朋友，怎么排比较轻松？', '那两个顺路吗？下午3点得走，来得及吗？', '不是自己开车，我们坐公交。那就只去后面那个，别赶了。'];
  let prepared;
  for (const message of queries) {
    const resolved = resolve(message, previous);
    prepared = preparePlanEdit({ message, previousState: previous?.state, state: resolved.state, lastPlan: previous?.lastPlan, catalog });
    assert.equal(resolved.clarification, undefined, message);
    assert.equal(prepared.state.goal, 'day-plan', message);
    assert.equal(prepared.state.partySize, null, message);
    assert.equal(prepared.state.origin, null, message);
    assert.deepEqual(prepared.state.childAges, [5], message);
    previous = sign({ state: prepared.state, lastPlan: { selectedIds: prepared.state.selectedCandidateIds, date: prepared.state.date } });
  }
  assert.equal(prepared.state.finishBy, '15:00');
  assert.equal(prepared.state.travelMode, 'transit');
  assert.equal(prepared.state.startTime, null);
  assert.equal(prepared.state.returnToOrigin, undefined);
  assert.deepEqual(prepared.state.selectedCandidateIds, ['pier39']);
  assert.deepEqual(prepared.state.excludedCandidateIds, ['venue-exploratorium-daytime']);
  const candidates = catalog.places.filter(row => ['venue-exploratorium-daytime', 'pier39'].includes(row.id)).map(row => ({ ...row, kind: 'place' }));
  const selection = resolvePlanSelection({ edit: prepared.edit, candidateIds: ['venue-exploratorium-daytime'], candidates, now: NOW });
  assert.deepEqual(selection.selectedIds, ['pier39']);
  assert.equal(selection.suppressAlternatives, true);
  const plan = buildItinerary({ state: prepared.state, candidates, selectedIds: selection.selectedIds, now: NOW });
  assert.deepEqual(plan.stops.map(stop => stop.entityId), ['pier39']);
  assert.deepEqual(plan.handoff.stops.map(stop => stop.id), ['pier39']);
  assert.ok(plan.checks.some(check => check.status === 'unknown'), 'missing departure/route facts remain unknown');
});

test('casual schedule wording does not turn administrative or historical questions into a day plan', () => {
  for (const message of ['办卡预约怎么安排？', '工资怎么安排比较合适？', '以前去过两个馆，怎么排过的我忘了。']) assert.notEqual(resolve(message).state.goal, 'day-plan', message);
});

test('a named station nearby is a text origin only and never overwrites a different destination', () => {
  const live = "I'm near Fremont BART，想出去 chill 一下午，no car，走路别太多。有啥轻松的？";
  const fresh = resolve(live).state;
  assert.equal(fresh.origin, 'Fremont BART 附近');
  assert.equal(fresh.originCandidateId, null);
  assert.equal(fresh.travelMode, 'transit');
  assert.ok(fresh.preferences.includes('limited-walking'));
  assert.equal(fresh.partySize, null);
  assert.equal(fresh.startTime, null);
  assert.equal(fresh.finishBy, null);
  const original = base();
  const corrected = resolve(live, sign(original)).state;
  assertRetained(corrected, original, ['origin', 'originCandidateId']);
  assert.equal(corrected.origin, 'Fremont BART 附近');
  assert.equal(corrected.originCandidateId, null);
  assert.equal(resolve('继续看看', sign(corrected)).state.origin, corrected.origin);
  assert.equal(resolve('我在 Fremont BART 附近，想去旧金山。').state.origin, corrected.origin);
  assert.equal(resolve('Is the park near Fremont BART?').state.origin, null);
  assert.equal(resolve("I'm near home.").state.origin, null);
});

test('comparing transport modes does not choose one, while a later affirmative choice still applies', () => {
  for (const message of ['去那个看海狮的地方要多久，坐车还是开车省事？', '公交还是开车？', '坐公交和开车哪个方便？', 'Drive or transit? Which is easier?']) {
    assert.equal(resolve(message).state.travelMode, null, message);
    const original = { ...base(), preferences: ['no-car'] };
    assertRetained(resolve(message, sign(original)).state, original);
    assert.ok(resolve(message, sign(original)).state.preferences.includes('no-car'));
  }
  const previous = sign({ ...base(), preferences: ['no-car'] });
  for (const message of ['那就开车吧。', '公交还是开车比较好？那就开车。']) {
    const chosen = resolve(message, previous).state;
    assert.equal(chosen.travelMode, 'drive', message);
    assert.ok(!chosen.preferences.includes('no-car'), message);
    assertRetained(chosen, previous.state, ['travelMode']);
  }
});
