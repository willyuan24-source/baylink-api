const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState, validateTaskState, applyTaskStatePatch, encodeTaskToken, decodeTaskToken, TOKEN_TTL } = require('../lib/baybayState');
const TODAY = '2026-10-04';
const catalog = { events: [], places: [{ city: 'San Jose', region: 'south-bay' }, { city: 'Alameda', region: 'east-bay' }, { city: 'Fremont', region: 'east-bay' }] };
const resolve = (message, previous, rest = {}) => resolveTaskState({ message, previous, catalog, today: TODAY, ...rest });
const originCatalog = { events: [], places: [
  { id: 'tech', title: 'San Jose 科技馆与日本城', city: 'San Jose', location: { label: 'The Tech Interactive', precision: 'venue', lat: 37.3316, lng: -121.89 } },
  { id: 'gate', title: '金门大桥与 Fort Point', city: 'San Francisco', venue: 'Golden Gate Bridge Welcome Center', location: { label: 'Golden Gate Bridge Welcome Center', precision: 'venue', lat: 37.80779, lng: -122.47484 } },
  { id: 'center', title: 'Fremont Center', city: 'Fremont', location: { precision: 'city', lat: 37.54, lng: -121.98 } },
] };

test('a structured one-day request distinguishes origin from destination and keeps explicit party constraints', () => {
  const { state, clarification } = resolve('从 Fremont 出发，周六在 San Jose 安排一天。两大一小，孩子6岁，不开车，全家预算$100，上午10点出发，下午5点前回来。');
  assert.equal(clarification, undefined);
  assert.equal(state.goal, 'day-plan');
  assert.equal(state.origin, 'Fremont'); assert.equal(state.city, 'San Jose');
  assert.equal(state.region, 'south-bay'); assert.equal(state.date, '2026-10-10');
  assert.equal(state.partySize, 3); assert.deepEqual(state.childAges, [6]);
  assert.equal(state.budget, 100); assert.equal(state.budgetScope, 'total');
  assert.ok(state.preferences.includes('no-car'));
  assert.equal(state.startTime, '10:00'); assert.equal(state.finishBy, '17:00');
});

test('natural named-venue trip with driving calculations becomes a day plan with exact departure and return times', () => {
  const message = '2026-10-10 从 The Tech Interactive 出发，早上9点开车，两位成人，想去 San Jose 的 King Library 和 San José Museum of Art，17点前回出发点，总预算100美元。请安排并核算车程。';
  const { state, clarification } = resolve(message, undefined, { catalog: originCatalog });
  assert.equal(clarification, undefined);
  assert.equal(state.goal, 'day-plan');
  assert.equal(state.startTime, '09:00');
  assert.equal(state.finishBy, '17:00');
  assert.equal(state.originCandidateId, 'tech');
  assert.equal(state.city, 'San Jose');
  assert.equal(state.travelMode, 'drive');
  assert.equal(state.partySize, 2);
  assert.equal(state.budget, 100);
  assert.equal(state.budgetScope, 'total');
});

test('half-hour Chinese departure and return-to-start wording preserve explicit clock values', () => {
  for (const departure of ['早上8点半开车', '早上八点半出发', '上午8:30出发']) {
    const result = resolve(`明天从The Tech Interactive出发，${departure}，参观博物馆和图书馆，下午5点前回到起点。请安排并核算车程。`, undefined, { catalog: originCatalog });
    assert.equal(result.state.goal, 'day-plan', departure);
    assert.equal(result.state.startTime, '08:30', departure);
    assert.equal(result.state.finishBy, '17:00', departure);
  }
  assert.equal(resolve('安排一天，下午五点半前返回出发点').state.finishBy, '17:30');
});

test('English visit schedule and travel-time request supports explicit 12-hour and 24-hour clocks', () => {
  const result = resolve('Tomorrow from The Tech Interactive, leave at 9 am, visit King Library and San Jose Museum of Art, return to the starting point by 17:00. Please arrange the visits and calculate driving time.', undefined, { catalog: originCatalog });
  assert.equal(result.state.goal, 'day-plan');
  assert.equal(result.state.startTime, '09:00');
  assert.equal(result.state.finishBy, '17:00');
  const explicit = resolve('Plan my itinerary, start at 08:30 and return by 5 pm.');
  assert.equal(explicit.state.startTime, '08:30');
  assert.equal(explicit.state.finishBy, '17:00');
});

test('ordinary one-off route/time inquiries remain transit and do not receive invented clock times', () => {
  for (const message of ['从SFO到San Jose开车要多久？', 'How long does it take to drive from SFO to San Jose?', 'Calculate the travel time from Fremont to San Jose.', '请安排从SFO到San Jose的路线，并计算车程。']) {
    const result = resolve(message);
    assert.equal(result.state.goal, 'transit', message);
    assert.equal(result.state.startTime, null);
    assert.equal(result.state.finishBy, null);
  }
  const unknown = resolve('明天想去博物馆和图书馆，请安排并核算车程。');
  assert.equal(unknown.state.goal, 'day-plan');
  assert.equal(unknown.state.startTime, null);
  assert.equal(unknown.state.finishBy, null);
});

test('unrelated opening hours and invalid or negated clock values are not departure times', () => {
  const opening = resolve('SFMOMA早上9点开门吗？');
  assert.equal(opening.state.startTime, null);
  assert.equal(opening.state.finishBy, null);
  assert.equal(resolve('安排一天，25点出发').state.startTime, null);
  assert.equal(resolve('Plan a day, leave at 13 pm').state.startTime, null);
  assert.equal(resolve('安排一天，不要9点出发，11点再出发').state.startTime, '11:00');
});

test('free museum areas and eligibility questions do not become a zero-budget free-only search', () => {
  for (const message of ['SFMOMA 平常周三开馆吗？免费公共空间是不是也可以进去？请核对官网。', 'Does SFMOMA have free public spaces?', '图书馆会员免费入场的规则是什么？']) {
    const result = resolve(message);
    assert.equal(result.state.goal, 'information', message);
    assert.equal(result.state.budget, null, message);
    assert.equal(result.state.freeOnly, null, message);
  }
  const previous = resolve('San Jose今天有什么免费活动？').state;
  assert.equal(previous.freeOnly, true);
  const followup = resolve('SFMOMA的免费公共空间有哪些限制？', previous).state;
  assert.equal(followup.freeOnly, true);
  assert.equal(followup.budget, 0);
  const paidPlan = resolve('明天在San Francisco安排一天，总预算100美元。').state;
  const freeAreaQuestion = resolve('帮我查SFMOMA的免费公共空间有哪些限制？', paidPlan).state;
  assert.equal(freeAreaQuestion.freeOnly, null);
  assert.equal(freeAreaQuestion.budget, 100);
});

test('explicit free-only instructions and free activity discovery still set real search constraints', () => {
  for (const message of ['今天San Jose有什么免费活动？', '明天安排一天，找免费景点', 'Only show free options', '只看免费']) {
    const result = resolve(message);
    assert.equal(result.state.freeOnly, true, message);
    assert.equal(result.state.budget, 0, message);
  }
  assert.equal(resolve('SFMOMA门票怎么收费？预算0美元。').state.budget, 0);
});

test('state persists through many short turns without reparsing assistant statements or old dates', () => {
  let state = resolve('Plan a day in San Jose tomorrow, from Fremont, two adults and one child aged 6, total budget $100, by 5 pm.').state;
  for (const message of ['多说一点', '这个怎么样', '再比较一下', '保留这个条件', '还有哪些需要预约', '继续', '先不改', '多看一些']) state = resolve(message, state).state;
  const updated = resolve('改成10/05/2027', state).state;
  assert.equal(updated.revision, 10); assert.equal(updated.goal, 'day-plan');
  assert.equal(updated.city, 'San Jose'); assert.equal(updated.origin, 'Fremont');
  assert.equal(updated.date, '2027-10-05'); assert.equal(updated.partySize, 3);
  assert.deepEqual(updated.childAges, [6]); assert.equal(updated.budget, 100); assert.equal(updated.finishBy, '17:00');
});

test('explicit destination changes do not select an excluded city or lose origin', () => {
  const initial = resolve('从Fremont去旧金山，今天有什么免费活动？').state;
  const result = resolve('不要旧金山，改去Alameda，收费也可以', initial);
  assert.equal(result.clarification, undefined);
  assert.equal(result.state.city, 'Alameda'); assert.equal(result.state.origin, 'Fremont');
  assert.equal(result.state.region, 'east-bay'); assert.equal(result.state.date, TODAY);
  assert.equal(result.state.freeOnly, false); assert.equal(result.state.budget, null);
  assert.deepEqual(result.state.excludedCities, ['San Francisco']);
  const negativeOnly = resolve('今天不要旧金山，有什么活动？');
  assert.ok(negativeOnly.clarification); assert.equal(negativeOnly.state.city, null); assert.equal(negativeOnly.state.region, null);
  assert.equal(resolve('今天不要Oakland，有什么活动？', result.state).state.city, 'Alameda');
});

test('origin-only and multilingual Bay Area aliases are never destinations', () => {
  const origin = resolve('从Fremont出发，不开车，安排一天');
  assert.equal(origin.state.origin, 'Fremont'); assert.equal(origin.state.city, null); assert.equal(origin.state.region, null);
  assert.equal(resolve('San Francisco Bay Area events tomorrow').state.city, null);
  assert.equal(resolve('聖荷西今天有什么活动').state.city, 'San Jose');
  assert.equal(resolve('From SFO to San Jose, plan a day tomorrow').state.origin, 'SFO');
  assert.equal(resolve('出发地改为 Alameda', resolve('San Jose events today').state).state.city, 'San Jose');
  assert.equal(resolve('出发地改为 Alameda').state.origin, 'Alameda');
});

test('a unique exact venue departure resolves an existing precise catalog origin without changing destination', () => {
  for (const message of ['从The Tech Interactive出发，明天在Alameda安排一天', 'From The Tech Interactive to Alameda, plan a day tomorrow', '从San Jose 科技馆与日本城出发，去Alameda安排一天']) {
    const result = resolve(message, undefined, { catalog: originCatalog });
    assert.equal(result.clarification, undefined, message);
    assert.equal(result.state.originCandidateId, 'tech', message); assert.equal(result.state.origin, 'The Tech Interactive');
    assert.equal(result.state.city, 'Alameda', message);
  }
  assert.equal(resolve('从Golden Gate Bridge Welcome Center出发，明天安排一天', undefined, { catalog: originCatalog }).state.originCandidateId, 'gate');
  assert.equal(resolve('The Tech Interactive有什么活动', undefined, { catalog: originCatalog }).state.originCandidateId, null);
});

test('city-only, ambiguous, inexact, missing-coordinate and negative departures do not create precise origin IDs', () => {
  for (const message of ['从Fremont出发，安排一天', '从Fremont Center出发，安排一天', 'From The Tech to Alameda', '不要从The Tech Interactive出发', '从SFO出发，安排一天']) {
    assert.equal(resolve(message, undefined, { catalog: originCatalog }).state.originCandidateId, null, message);
  }
  const duplicate = { ...originCatalog, places: [...originCatalog.places, { ...originCatalog.places[0], id: 'tech-duplicate' }] };
  assert.equal(resolve('从The Tech Interactive出发，安排一天', undefined, { catalog: duplicate }).state.originCandidateId, null);
});

test('clearing or changing origin invalidates its precise ID, while ordinary followups preserve it', () => {
  const first = resolve('从The Tech Interactive出发，明天在Alameda安排一天', undefined, { catalog: originCatalog }).state;
  assert.equal(resolve('明天呢', first, { catalog: originCatalog }).state.originCandidateId, 'tech');
  assert.equal(resolve('from 9 am, finish by 5 pm', first, { catalog: originCatalog }).state.originCandidateId, 'tech');
  const city = resolve('出发地改为Fremont', first, { catalog: originCatalog }).state;
  assert.equal(city.origin, 'Fremont'); assert.equal(city.originCandidateId, null);
  const unknown = resolve('from Another Unknown Museum', first, { catalog: originCatalog }).state;
  assert.equal(unknown.origin, null); assert.equal(unknown.originCandidateId, null);
  for (const message of ['清除出发地', 'clear origin']) {
    const cleared = resolve(message, first, { catalog: originCatalog }).state;
    assert.equal(cleared.origin, null); assert.equal(cleared.originCandidateId, null);
  }
  const options = { secret: 'a-test-secret-longer-than-16' };
  assert.equal(decodeTaskToken(encodeTaskToken({ state: first }, options), options).state.originCandidateId, 'tech');
});

test('airport origin becomes precise only with an existing verified venue coordinate record', () => {
  const airports = { ...originCatalog, places: [...originCatalog.places, { id: 'sfo', title: 'SFO', city: 'San Francisco', location: { label: 'SFO International Terminal', precision: 'venue', lat: 37.616, lng: -122.39 } }] };
  assert.equal(resolve('从SFO出发，去Alameda安排一天', undefined, { catalog: airports }).state.originCandidateId, 'sfo');
  assert.equal(resolve('从SFO出发，去Alameda安排一天', undefined, { catalog: originCatalog }).state.originCandidateId, null);
});

test('the live named two-stop prompt preserves King Library then SJMA and excludes its Tech origin', () => {
  const actual = require('../data/planner-catalog.json');
  const message = '2026-10-10 从 The Tech Interactive 出发，早上9点开车，两位成人，想去 San Jose 的 King Library 和 San José Museum of Art，17点前回出发点，总预算100美元。请安排并核算车程。';
  const result = resolve(message, undefined, { catalog: actual });
  assert.equal(result.clarification, undefined);
  assert.equal(result.state.goal, 'day-plan'); assert.equal(result.state.originCandidateId, 'san-jose');
  assert.deepEqual(result.explicitCandidateIds, ['venue-sj-king-library', 'venue-sjma']);
  assert.deepEqual(result.state.selectedCandidateIds, result.explicitCandidateIds);
  assert.equal(result.state.city, 'San Jose');
});

test('explicit visits use unique published names in mention order, including accent and descriptor variants', () => {
  const actual = require('../data/planner-catalog.json');
  for (const message of [
    'Plan a day in San Jose, visit San Jose Museum of Art and King Library.',
    '明天在San Jose安排一天，先去 San José Museum of Art，再去 Dr. Martin Luther King, Jr. Library。',
  ]) {
    const result = resolve(message, undefined, { catalog: actual });
    assert.deepEqual(result.explicitCandidateIds, ['venue-sjma', 'venue-sj-king-library'], message);
  }
  const prior = resolve('明天安排一天，想去San Jose Museum of Art', undefined, { catalog: actual }).state;
  const followup = resolve('核算一下预算', prior, { catalog: actual });
  assert.deepEqual(followup.state.selectedCandidateIds, ['venue-sjma']); assert.equal(followup.explicitCandidateIds, undefined);
});

test('bare venue facts, negative visits, generic names and alternative choices do not become invented desired stops', () => {
  const actual = require('../data/planner-catalog.json');
  const prior = resolve('明天在San Jose安排一天', undefined, { catalog: actual }).state;
  for (const message of ['King Library 和 San Jose Museum of Art 的票价是多少？', '不想去King Library', '不想去King Library和San Jose Museum of Art', 'Do not visit King Library and San Jose Museum of Art', '安排一天，想去博物馆和公园', 'Plan a day, visit a museum and library']) assert.equal(resolve(message, prior, { catalog: actual }).explicitCandidateIds, undefined, message);
  const alternative = resolve('明天安排一天，想去King Library或者San Jose Museum of Art', prior, { catalog: actual });
  assert.ok(alternative.clarification); assert.equal(alternative.explicitCandidateIds, undefined);
  const negative = resolve('明天安排一天，不要去King Library，想去San Jose Museum of Art', prior, { catalog: actual });
  assert.deepEqual(negative.explicitCandidateIds, ['venue-sjma']);
});

test('a shared published venue alias asks for clarification instead of choosing one record', () => {
  const duplicate = { events: [], places: [
    { id: 'one', title: 'Example Art Museum', city: 'San Jose' },
    { id: 'two', title: 'Example Art Museum', city: 'Oakland' },
  ] };
  const result = resolve('Plan a day and visit Example Art Museum', undefined, { catalog: duplicate });
  assert.ok(result.clarification); assert.equal(result.explicitCandidateIds, undefined); assert.deepEqual(result.state.selectedCandidateIds, []);
});

test('a place name in an event venue does not select the event as a desired visit', () => {
  const venues = { places: [{ id: 'museum', title: 'Example Art Museum', city: 'San Jose' }], events: [
    { id: 'museum-concert', title: 'Friday Jazz Night', venue: 'Example Art Museum', city: 'San Jose' },
  ] };
  assert.deepEqual(resolve('Plan a day and visit Example Art Museum', undefined, { catalog: venues }).explicitCandidateIds, ['museum']);
  assert.deepEqual(resolve('Plan a day and visit Friday Jazz Night', undefined, { catalog: venues }).explicitCandidateIds, ['museum-concert']);
});

test('a destination outside the Bay Area does not silently reuse the prior Bay Area city', () => {
  const prior = resolve('旧金山今天安排一天').state;
  for (const message of ['改去上海', '明天在洛杉矶安排一天', 'Plan a day in Seattle', 'From Fremont to Sacramento, plan a day']) {
    const result = resolve(message, prior);
    assert.ok(result.clarification, message); assert.equal(result.state.city, null, message);
  }
  assert.equal(resolve('从洛杉矶去旧金山，明天安排一天').clarification, undefined);
  assert.equal(resolve('San Francisco Shanghai Dumpling 今天有什么活动').clarification, undefined);
});

test('city/date clears survive stale UI context and later unrelated turns', () => {
  const searchContext = { city: 'San Francisco', region: 'sf', date: TODAY };
  let state = resolve('San Jose events today', undefined, { searchContext }).state;
  state = resolve('城市不限', state, { searchContext }).state;
  assert.equal(state.city, null); assert.equal(state.region, 'all');
  const cleared = resolve('日期不限', state, { searchContext });
  assert.ok(cleared.clarification); assert.equal(cleared.state.date, null);
  state = resolve('还有呢', cleared.state, { searchContext }).state;
  assert.equal(state.city, null); assert.equal(state.date, null); assert.equal(state.region, 'all');
  state = resolve('改去Alameda，明天', state, { searchContext }).state;
  assert.equal(state.city, 'Alameda'); assert.equal(state.date, '2026-10-05');
  assert.ok(!state.clearedFields.includes('city')); assert.ok(!state.clearedFields.includes('date'));
});

test('ambiguous, impossible and past dates ask rather than silently substituting today', () => {
  for (const text of ['San Jose events 10/05/2027 or 10/06/2027', 'San Jose events 2027/02/29', 'San Jose events yesterday']) assert.ok(resolve(text).clarification, text);
  assert.equal(resolve('San Jose events 2027/10/05').state.date, '2027-10-05');
  assert.ok(resolve('Plan a day in San Jose today, start 5 pm, home by 4 pm').clarification);
});

test('a regular weekly hours question is not silently converted to this coming weekday', () => {
  assert.equal(resolve('SFMOMA 平常週三開館嗎？').state.date, null);
  assert.equal(resolve('Is SFMOMA normally open on Wednesdays?').state.date, null);
  assert.equal(resolve('SFMOMA 下周三开馆吗？').state.date, '2026-10-07');
});

test('chip editing phrases update only their explicit field', () => {
  let state = resolve('从Fremont去San Jose，明天安排一天，预算$100').state;
  const edits = [
    ['城市改为 Alameda', 'city', 'Alameda'], ['日期改为2027-10-05', 'date', '2027-10-05'],
    ['出发地改为Fremont', 'origin', 'Fremont'], ['同行总人数改为4', 'partySize', 4],
    ['孩子年龄改为6、8', 'childAges', [6, 8]], ['每人预算改为$60', 'budget', 60],
    ['总预算改为180', 'budgetScope', 'total'], ['出行方式改为transit', 'travelMode', 'transit'],
    ['场景改为indoor', 'setting', 'indoor'], ['开始时间改为09:30', 'startTime', '09:30'],
    ['最晚结束时间改为17:00', 'finishBy', '17:00'],
  ];
  for (const [message, key, expected] of edits) { state = resolve(message, state).state; assert.deepEqual(state[key], expected, message); assert.equal(state.goal, 'day-plan'); }
  assert.equal(state.city, 'Alameda'); assert.equal(state.origin, 'Fremont');
});

test('all public chip clear commands persist without UI reinjection', () => {
  let state = validateTaskState({ city: 'San Jose', date: TODAY, origin: 'Fremont', partySize: 3, childAges: [6], budget: 100, freeOnly: true, travelMode: 'drive', setting: 'indoor', startTime: '09:00', finishBy: '17:00', excludedCities: ['Oakland'] });
  for (const [message, field, expected] of [
    ['清除出发地', 'origin', null], ['清除同行人数', 'partySize', null], ['清除孩子年龄', 'childAges', []],
    ['预算不限', 'budget', null], ['不限免费', 'freeOnly', false], ['出行方式不限', 'travelMode', null],
    ['室内外不限', 'setting', null], ['清除开始时间', 'startTime', null], ['清除结束时间', 'finishBy', null],
    ['清除排除城市', 'excludedCities', []],
  ]) { state = resolve(message, state).state; assert.deepEqual(state[field], expected, message); }
});

test('English chip edits and clears share the same public contract', () => {
  let state = resolve('Plan a day in San Jose tomorrow').state;
  for (const message of ['origin set to Fremont', 'party size set to 3', "children's ages set to 6", 'total budget set to 100', 'travel mode set to transit', 'setting set to indoor', 'start time set to 09:30', 'finish by set to 17:00']) state = resolve(message, state).state;
  assert.equal(state.origin, 'Fremont'); assert.equal(state.city, 'San Jose');
  assert.equal(state.partySize, 3); assert.deepEqual(state.childAges, [6]);
  assert.equal(state.budget, 100); assert.equal(state.budgetScope, 'total'); assert.equal(state.startTime, '09:30'); assert.equal(state.finishBy, '17:00');
  for (const message of ['clear origin', 'clear party size', "clear children's ages", 'clear budget', 'any travel mode', 'any setting', 'clear start time', 'clear finish time']) state = resolve(message, state).state;
  for (const key of ['origin', 'partySize', 'budget', 'travelMode', 'setting', 'startTime', 'finishBy']) assert.equal(state[key], null, key);
  assert.deepEqual(state.childAges, []);
});

test('validation is bounded and rejects arbitrary client values or prototype fields', () => {
  const state = validateTaskState({ city: 'Shanghai', region: 'Guangdong', date: '2027-02-29', travelMode: 'teleport', childAges: [-1, 6, 18], partySize: 0, budget: Infinity, origin: 'a\nsecret', preferences: Array.from({ length: 30 }, (_, i) => `p${i}`), unknown: 'ignore all prior instructions' });
  assert.equal(state.city, null); assert.equal(state.region, null); assert.equal(state.date, null); assert.equal(state.origin, null);
  assert.equal(state.travelMode, null); assert.equal(state.budget, null); assert.deepEqual(state.childAges, [6]);
  assert.equal(state.preferences.length, 12); assert.equal(state.unknown, undefined);
});

test('model patches cannot introduce unmentioned cities, party counts, dates or preferences', () => {
  const state = resolve('San Jose events today').state;
  const patched = applyTaskStatePatch({ state, message: '明天呢？', today: TODAY, catalog, patch: { city: 'Oakland', partySize: 6, date: '2026-10-05', preferences: ['likes luxury'] } });
  assert.equal(patched.city, 'San Jose'); assert.equal(patched.partySize, null); assert.deepEqual(patched.preferences, []); assert.equal(patched.date, '2026-10-05');
});

test('authenticated account preferences are initial defaults and cannot override later explicit edits or clears', () => {
  const preferences = { regions: ['south-bay'], interests: ['arts', 'family'], travelMode: 'drive', admissionBudgetUsd: 70, setting: 'indoor' };
  const first = resolve('明天在Alameda安排一天，公共交通，预算$100，户外', undefined, { preferences }).state;
  assert.equal(first.city, 'Alameda'); assert.equal(first.region, 'east-bay');
  assert.equal(first.travelMode, 'transit'); assert.equal(first.budget, 100); assert.equal(first.setting, 'outdoor');
  assert.deepEqual(first.preferences, ['arts', 'family']); assert.equal(first.topic, null);
  const cleared = resolve('出行方式不限，预算不限，室内外不限', first, { preferences }).state;
  const later = resolve('继续', cleared, { preferences }).state;
  assert.equal(later.travelMode, null); assert.equal(later.budget, null); assert.equal(later.setting, null);
  const defaults = resolve('安排一天', undefined, { preferences }).state;
  assert.equal(defaults.region, 'south-bay'); assert.equal(defaults.travelMode, 'drive'); assert.equal(defaults.budget, 70);
});

test('task token preserves only validated state and plan references, with a 24h expiry', () => {
  const now = Date.parse(`${TODAY}T20:00:00Z`); const options = { secret: 'a-test-secret-longer-than-16', now };
  const state = resolve('San Jose events today').state;
  const token = encodeTaskToken({ state, lastPlan: { candidateIds: ['event:one', 'place:two'], selectedIds: ['place:two', 'event:one'], title: 'Day plan', date: TODAY, webFacts: ['invented facts'] } }, options);
  const decoded = decodeTaskToken(token, options);
  assert.deepEqual(decoded.state, state); assert.deepEqual(decoded.lastPlan.selectedIds, ['place:two', 'event:one']); assert.equal(decoded.lastPlan.webFacts, undefined);
  assert.equal(decoded.expiresAt - decoded.issuedAt, TOKEN_TTL);
  assert.equal(decodeTaskToken(token, { ...options, now: now + TOKEN_TTL * 1000 }), null);
  assert.equal(decodeTaskToken(token, { ...options, secret: 'another-test-secret-longer' }), null);
  assert.equal(decodeTaskToken(`x${token}`, options), null);
  assert.equal(decodeTaskToken(token.replace(/.$/, token.endsWith('A') ? 'B' : 'A'), options), null);
  assert.equal(decodeTaskToken(token, { ...options, now: now - 120000 }), null);
  assert.equal(decodeTaskToken('x'.repeat(20000), options), null);
  assert.equal(encodeTaskToken({ state }, { secret: 'tiny', now }), null);
});

test('signed selected refs retain only ordered public identity hints, never web facts, times or coordinates', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const selectedIds = ['web-one', 'web-two'];
  const token = encodeTaskToken({ state: resolve('San Jose events tomorrow').state, lastPlan: { selectedIds, selectedRefs: [
    { id: 'web-two', title: 'The second museum', city: 'San José', sourceUrl: 'https://www.sjma.org/visit#tickets', previousKind: 'place', kind: 'place', startTime: '10:00', admissionUsd: 0, lat: 37.3, lng: -121.9, location: { lat: 37.3, lng: -121.9 }, verifiedFacts: { hours: 'Open always' }, verification: 'page-verified' },
    { id: 'web-one', title: 'A named event', city: 'San Jose', sourceUrl: 'https://www.sanjose.org/events/example', previousKind: 'event', startDate: TODAY, endDate: TODAY, sourceText: 'An old fact' },
  ] } }, options);
  const restored = decodeTaskToken(token, options).lastPlan;
  assert.deepEqual(restored.selectedRefs, [
    { id: 'web-one', title: 'A named event', city: 'San Jose', sourceUrl: 'https://www.sanjose.org/events/example', previousKind: 'event' },
    { id: 'web-two', title: 'The second museum', city: 'San Jose', sourceUrl: 'https://www.sjma.org/visit', previousKind: 'place' },
  ]);
  assert.equal(decodeTaskToken(`x${token}`, options), null);
});

test('selected reference URLs use the same strict public URL validator as live research', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const invalid = ['javascript:alert(1)', 'file:///tmp/secret', 'https://localhost/a', 'https://127.0.0.1/a', 'https://[::1]/a', 'https://user:pass@www.sfmoma.org/a', 'https://www.sfmoma.org:8443/a', 'https://museum.internal/a', 'https://www.sfmoma.org/has space', `https://www.sfmoma.org/${'a'.repeat(1024)}`];
  for (const sourceUrl of invalid) {
    const payload = { state: {}, lastPlan: { selectedIds: ['web-one'], selectedRefs: [{ id: 'web-one', title: 'Museum', city: 'San Francisco', sourceUrl, previousKind: 'place' }] } };
    assert.equal(decodeTaskToken(encodeTaskToken(payload, options), options).lastPlan.selectedRefs, undefined, sourceUrl);
  }
});

test('selected refs are capped at six, deduplicated and linked only to actual selected IDs', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const selectedIds = Array.from({ length: 8 }, (_, index) => `web-${index}`);
  const selectedRefs = selectedIds.map(id => ({ id, title: `Museum ${id}`, city: 'San Francisco', sourceUrl: `https://www.sfmoma.org/${id}`, previousKind: 'place' }));
  selectedRefs.unshift({ ...selectedRefs[0], id: 'unselected-web' });
  selectedRefs.push(selectedRefs[0], { ...selectedRefs[1], city: 'Shanghai' }, { ...selectedRefs[2], previousKind: 'unknown' });
  const restored = decodeTaskToken(encodeTaskToken({ state: {}, lastPlan: { selectedIds, selectedRefs } }, options), options).lastPlan;
  assert.equal(restored.selectedRefs.length, 6);
  assert.deepEqual(restored.selectedRefs.map(ref => ref.id), selectedIds.slice(0, 6));
});

test('the six longest allowed source refs remain inside the token budget for a normal plan', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const selectedRefs = Array.from({ length: 6 }, (_, index) => ({ id: `web-${index}`, title: 'T'.repeat(160), city: 'San Francisco', sourceUrl: `https://www.sfmoma.org/${'p'.repeat(980)}/${index}`, previousKind: 'place' }));
  const token = encodeTaskToken({ state: resolve('从Fremont去San Francisco，明天安排一天，全家预算100美元').state, lastPlan: { selectedIds: selectedRefs.map(ref => ref.id), selectedRefs } }, options);
  assert.ok(token); assert.ok(token.length <= 16384); assert.equal(decodeTaskToken(token, options).lastPlan.selectedRefs.length, 6);
});
