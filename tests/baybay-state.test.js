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

test('utility and newcomer questions do not adopt explicitly rejected sightseeing intents', () => {
  for (const [message, expected] of [
    ['我刚搬到 Santa Clara 市租房，电力一定是PG&E吗？水、垃圾怎么转名？给我官方电话和入口，请不要推荐景点。', 'newcomer'],
    ['剛來灣區，沒有車，日常買菜和交通用哪些 App？別給我安排旅遊路線。', 'newcomer'],
    ['I just moved to Santa Clara. Which utilities should I contact? Do not recommend attractions or plan a day trip.', 'newcomer'],
    ['只回答优惠资格和适用日期，不安排路线。', 'information'],
  ]) {
    const result = resolve(message);
    assert.equal(result.state.goal, expected, message); assert.equal(result.clarification, undefined, message);
  }
  assert.equal(resolve('安排一天，请不要只推荐景点，也要留吃饭时间。').state.goal, 'day-plan');
  assert.equal(resolve('Do not plan a day trip. Recommend events in San Jose.').state.goal, 'discover');
});

test('explicit service topic switches exit a signed day plan while normal followups keep its conditions', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const initial = resolve('明天在San Jose安排一天，总预算100美元，两大一小，孩子6岁。').state;
  const previous = decodeTaskToken(encodeTaskToken({ state: initial }, options), options);
  for (const message of ['还有哪些需要预约', '再推荐几个景点', '帮我看看附近购物选择']) {
    const result = resolve(message, previous);
    assert.equal(result.state.goal, 'day-plan', message); assert.equal(result.state.date, initial.date);
    assert.equal(result.state.budget, 100); assert.equal(result.state.partySize, 3);
  }
  for (const [message, goal] of [
    ['现在问生活服务：电力、水和垃圾怎么转名？不要安排旅游路线。', 'newcomer'],
    ['不用安排行程，只回答优惠资格和适用日期。', 'information'],
    ['Do not plan an itinerary. I need electricity service contacts.', 'newcomer'],
    ['不要安排行程了，只推荐可买日用品的购物中心。', 'shopping'],
  ]) assert.equal(resolve(message, previous).state.goal, goal, message);
});

test('county-qualified city corrections work independently and with signed previous state', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const first = resolve('我刚搬到 Santa Clara 市租房，电力一定是PG&E吗？水、垃圾怎么转名？给我官方电话和入口，请不要推荐景点。');
  const previous = decodeTaskToken(encodeTaskToken({ state: first.state }, options), options);
  for (const prior of [undefined, previous]) for (const message of [
    '更正，不是 Santa Clara 市，是 Santa Clara 县的 Sunnyvale 市。上面电力、水和垃圾的电话还能照用吗？只给我更正后的办理入口。',
    '更正，不是 Santa Clara 市，是 Santa Clara 縣的 Sunnyvale 市。電力和供水如何開戶？',
    'Not in Santa Clara city. I need utilities in Sunnyvale, Santa Clara County.',
    'Utilities in Sunnyvale in the County of Santa Clara.',
  ]) {
    const result = resolve(message, prior);
    assert.equal(result.clarification, undefined, message); assert.equal(result.state.city, 'Sunnyvale', message);
    assert.equal(result.state.goal, 'newcomer', message);
  }
  assert.equal(resolve('San Mateo County 的 Redwood City 怎么开户？').state.city, 'Redwood City');
  assert.equal(resolve('Alameda County 有哪些公共服务？').state.city, null);
  for (const message of ['Santa Clara 或 Sunnyvale 的电力服务怎么办？', 'Utilities in Santa Clara and Sunnyvale', '不要Santa Clara，给我官方办理入口']) assert.ok(resolve(message).clarification, message);
});

test('a stated home city is an origin hint rather than a competing destination or precise home location', () => {
  const message = '我住Fremont，今天是2026年10月4日。我有一张 Bank of America 借记卡，同行成年朋友没有卡，今天去旧金山 de Young 能两个人都免费吗？这项优惠包括特别展吗？请核实官网，只回答优惠资格和适用日期，不安排路线。';
  const options = { secret: 'a-test-secret-longer-than-16' };
  const previous = decodeTaskToken(encodeTaskToken({ state: resolve('明天在San Jose安排一天').state }, options), options);
  for (const prior of [undefined, previous]) for (const value of [message, '我住在Fremont，今天去旧金山 de Young，只问门票优惠，不安排行程。', 'I live in Fremont. What are the admission rules at de Young in San Francisco? No itinerary.']) {
    const result = resolve(value, prior);
    assert.equal(result.clarification, undefined, value); assert.equal(result.state.city, 'San Francisco', value);
    assert.equal(result.state.origin, 'Fremont', value); assert.equal(result.state.originCandidateId, null, value);
    assert.equal(result.state.goal, 'information', value);
  }
  assert.ok(resolve('Fremont 或 San Francisco 今天有什么活动？').clarification);
});

test('explicit whole-trip spending caps persist without confusing venue-price questions with budgets', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  for (const message of [
    '明天从我家出发去那个博物馆，下午3点回来，总共不要超过50美元，帮我算准确车程。',
    '明天安排一天，全程不超过50美元。', '明天安排一天，總共不要超過50美元。',
    'Plan my day with a total no more than 50 dollars.',
    'Plan my day, in total at most $50.',
    'Plan my day, total under50.',
  ]) {
    const result = resolve(message); assert.equal(result.state.budget, 50, message); assert.equal(result.state.budgetScope, 'total', message);
    const previous = decodeTaskToken(encodeTaskToken({ state: result.state }, options), options);
    const next = resolve('再核对一下', previous).state;
    assert.equal(next.budget, 50); assert.equal(next.budgetScope, 'total');
  }
  assert.equal(resolve('de Young 的门票总共不超过50美元吗？').state.budget, null);
  assert.equal(resolve('门票总共是不是不超过50美元？').state.budget, null);
  const prior = resolve('明天安排一天，全程不超过100美元。').state;
  assert.equal(resolve('Would admission tickets cost a total no more than $50?', prior).state.budget, 100);
  for (const message of ['总共超过50美元也可以', '总共超过$50也可以', '超过50美元也可以', '全程超過$50也沒關係', '一共多于50美元也可以']) {
    assert.equal(resolve(message).state.budget, null, message);
    assert.equal(resolve(message, prior).state.budget, 100, message);
  }
  assert.equal(resolve('总共不超过$50', prior).state.budget, 50);
  assert.equal(resolve('不超过$50也可以', prior).state.budget, 50);
  assert.equal(resolve('超过$50也可以，但总预算降到70美元', prior).state.budget, 70);
});

test('explicit total budget sums and reductions update the saved cap, not quoted admission prices', () => {
  const previous = resolve('安排一天，总预算200美元').state;
  for (const message of ['门票加停车预算总共50美元', '門票加停車預算總共50美元', 'Admission and parking budget total $50']) {
    const result = resolve(message, previous).state;
    assert.equal(result.budget, 50, message); assert.equal(result.budgetScope, 'total', message);
  }
  assert.equal(resolve('全程总预算降到70美元', previous).state.budget, 70);
  assert.equal(resolve('Total budget reduced to $70', previous).state.budget, 70);
  assert.equal(resolve('门票加停车总共50美元吗？', previous).state.budget, 200);
});

test('a known branded venue uses its catalog city without replacing an explicit departure city', () => {
  const actual = require('../data/planner-catalog.json');
  const message = '我第一次来湾区，想去 San Francisco Premium Outlets。它是在旧金山市区吗？2026年10月4日周日，从旧金山 Powell Street BART 站出发，没有车是否现实？请核实商场和公交官网，告诉我实际城市、公交接驳方式和周末班次的大致频率。没有实时路线结果就不要编精确全程分钟数，也不用安排其他景点。';
  const result = resolve(message, undefined, { catalog: actual });
  assert.equal(result.clarification, undefined); assert.equal(result.state.city, 'Livermore');
  assert.equal(result.state.origin, '旧金山 Powell Street BART 站'); assert.equal(result.state.originCandidateId, null);
  assert.equal(result.state.goal, 'shopping'); assert.deepEqual(result.state.selectedCandidateIds, []);
  const priced = resolve('San Francisco Premium Outlets 的停车收费是多少？', undefined, { catalog: actual });
  assert.equal(priced.state.city, 'Livermore'); assert.notEqual(priced.state.goal, 'day-plan');
  assert.deepEqual(priced.state.selectedCandidateIds, []);
  const ambiguous = { places: [{ id: 'one', title: 'Example Museum', city: 'San Jose' }, { id: 'two', title: 'Example Museum', city: 'Oakland' }], events: [] };
  assert.ok(resolve('Example Museum 的门票多少钱？', undefined, { catalog: ambiguous }).clarification);
});

test('negated venue names and a return city are not destination alternatives', () => {
  const actual = require('../data/planner-catalog.json');
  const previous = validateTaskState({ goal: 'day-plan', city: 'Oakland', origin: 'Millbrae', date: '2026-10-10', budget: 150, budgetScope: 'total', partySize: 3, childAges: [6] });
  const message = '那就取消Oakland Museum of California，只去旧金山Exploratorium，其他条件保持不变。请保留孩子6岁、公共交通、150美元全家总预算和17:00回Millbrae BART站的限制；查不到当日返程时刻就明确说不能保证。';
  const result = resolve(message, previous, { catalog: actual });
  assert.equal(result.clarification, undefined); assert.equal(result.state.city, 'San Francisco');
  assert.equal(result.state.origin, 'Millbrae'); assert.equal(result.state.finishBy, '17:00');
  assert.equal(result.state.budget, 150); assert.deepEqual(result.state.childAges, [6]);
  assert.ok(resolve('想去旧金山Exploratorium或Oakland Museum of California，安排一天', previous, { catalog: actual }).clarification);
});

test('clock-before-departure phrasing and an explicit multi-visit return schedule retain planning intent', () => {
  const first = resolve('两名成人带6岁孩子，09:30从Millbrae BART站出发，17:00前必须回到同一站。想去旧金山Exploratorium和奥克兰Oakland Museum of California。请判断跨城是否现实，再安排。');
  assert.equal(first.state.goal, 'day-plan'); assert.equal(first.state.startTime, '09:30'); assert.equal(first.state.finishBy, '17:00');
  const named = resolve('10:00从San Jose的The Tech Interactive出发，请安排一天', undefined, { catalog: originCatalog });
  // An extra unrecognized joiner must not manufacture a precise venue origin.
  assert.equal(named.state.originCandidateId, null);
  const precise = resolve('10:00从San Jose The Tech Interactive出发，请安排一天', undefined, { catalog: originCatalog });
  assert.equal(precise.state.originCandidateId, 'tech'); assert.equal(precise.state.startTime, '10:00');
  assert.equal(precise.state.origin, 'The Tech Interactive');
  assert.equal(resolve('博物馆10:00开门吗？').state.startTime, null);
});

test('the live Millbrae family feasibility question keeps its origin and exact cross-city visits without inventing coordinates', () => {
  const actual = require('../data/planner-catalog.json');
  const message = '2026年10月10日周六，两名成人带6岁孩子，09:30从Millbrae BART站出发，17:00前必须回到同一站。我们不开车，不打Uber，想去旧金山Exploratorium和奥克兰Oakland Museum of California，全家门票加公共交通总预算150美元。请判断跨城是否现实，再安排；若做不到请明确缩减，不要假设孩子全部免费或省略返程。';
  const result = resolve(message, undefined, { catalog: actual });
  assert.equal(result.clarification, undefined); assert.equal(result.state.goal, 'day-plan');
  assert.equal(result.state.origin, 'Millbrae BART站'); assert.equal(result.state.originCandidateId, null);
  assert.equal(result.state.city, null); assert.equal(result.state.region, 'all');
  assert.equal(result.state.startTime, '09:30'); assert.equal(result.state.finishBy, '17:00');
  assert.equal(result.state.budget, 150); assert.equal(result.state.budgetScope, 'total');
  assert.equal(result.state.partySize, 3); assert.deepEqual(result.state.childAges, [6]);
  assert.equal(result.state.freeOnly, null); assert.equal(result.state.travelMode, 'transit');
  assert.deepEqual(result.explicitCandidateIds, ['venue-exploratorium-daytime', 'venue-omca']);
  const options = { secret: 'a-test-secret-longer-than-16' };
  const previous = decodeTaskToken(encodeTaskToken({ state: result.state }, options), options);
  const next = resolve('那就取消Oakland Museum of California，只去旧金山Exploratorium，其他条件保持不变。请保留孩子6岁、公共交通、150美元全家总预算和17:00回Millbrae BART站的限制；查不到当日返程时刻就明确说不能保证。', previous, { catalog: actual });
  assert.equal(next.clarification, undefined); assert.equal(next.state.city, 'San Francisco');
  assert.equal(next.state.goal, 'day-plan'); assert.equal(next.state.origin, 'Millbrae BART站');
  assert.equal(next.state.budget, 150); assert.deepEqual(next.state.childAges, [6]);
  assert.equal(next.state.startTime, '09:30'); assert.equal(next.state.finishBy, '17:00');
});

test('cross-city feasibility does not waive alternative destinations, uncertain venues or invalid date and origin constraints', () => {
  const actual = require('../data/planner-catalog.json');
  for (const message of [
    'Plan a day from Millbrae: visit Exploratorium and Oakland Museum of California. Is this cross-city plan realistic?',
    '從Millbrae出發，想去Exploratorium和Oakland Museum of California，安排一天，請判斷跨城是否現實。',
  ]) {
    const result = resolve(message, undefined, { catalog: actual });
    assert.equal(result.clarification, undefined, message); assert.equal(result.state.origin, 'Millbrae');
    assert.equal(result.state.city, null); assert.equal(result.state.region, 'all');
  }
  for (const message of [
    '从Millbrae出发，想去Exploratorium或Oakland Museum of California，判断跨城是否现实，再安排一天。',
    '从Millbrae出发，想去旧金山和Oakland，判断跨城是否现实，再安排一天。',
    '从Millbrae出发，想去Exploratorium和Oakland Museum of California，安排一天。',
    '从Millbrae出发，也从Fremont出发，想去Exploratorium和Oakland Museum of California，判断跨城是否现实，再安排一天。',
    '2026-02-30从Millbrae出发，想去Exploratorium和Oakland Museum of California，判断跨城是否现实，再安排一天。',
  ]) assert.ok(resolve(message, undefined, { catalog: actual }).clarification, message);
  const ambiguous = resolve('从Millbrae出发，想去Exploratorium或Oakland Museum of California，安排一天。', undefined, { catalog: actual });
  assert.equal(ambiguous.state.origin, 'Millbrae'); assert.equal(ambiguous.state.originCandidateId, null);
});

test('the live Ferry Building departure remains an origin through a signed transport and budget correction', () => {
  const actual = require('../data/planner-catalog.json');
  const message = '2026年10月11日周日，我们两名成人，10:00从旧金山Ferry Building出发，先按开车考虑，18:00前回到出发点，全程总预算200美元。想去SFMOMA和Exploratorium，请安排轻松的一天，不要添加别的景点；核对当天开馆和门票，交通不确定就说明。';
  const result = resolve(message, undefined, { catalog: actual });
  assert.equal(result.clarification, undefined); assert.equal(result.state.originCandidateId, 'venue-ferry-building');
  assert.equal(result.state.origin, actual.places.find(row => row.id === 'venue-ferry-building').location.label);
  assert.deepEqual(result.explicitCandidateIds, ['venue-sfmoma', 'venue-exploratorium-daytime']);
  assert.ok(!result.state.selectedCandidateIds.includes(result.state.originCandidateId));
  const options = { secret: 'a-test-secret-longer-than-16' };
  const previous = decodeTaskToken(encodeTaskToken({ state: result.state }, options), options);
  const next = resolve('临时没有车了，改成公共交通，全程总预算降到70美元。取消Exploratorium，只保留SFMOMA，不要补一个替代景点。仍是两名成人、10月11日、10:00从Ferry Building出发、18:00前回去；请更新原安排并说明还有哪些费用或返程条件没有确认。', previous, { catalog: actual });
  assert.equal(next.clarification, undefined); assert.equal(next.state.originCandidateId, 'venue-ferry-building');
  assert.equal(next.state.origin, result.state.origin); assert.equal(next.state.city, 'San Francisco');
  assert.equal(next.state.budget, 70); assert.equal(next.state.budgetScope, 'total'); assert.equal(next.state.travelMode, 'transit');
  assert.equal(next.state.startTime, '10:00'); assert.equal(next.state.finishBy, '18:00');
  assert.ok(!next.state.selectedCandidateIds.includes(next.state.originCandidateId));
});

test('a named departure never becomes a desired stop just because its catalog coordinates are missing or ambiguous', () => {
  const actual = require('../data/planner-catalog.json');
  const incomplete = { ...actual, places: actual.places.map(row => row.id === 'venue-ferry-building' ? { ...row, location: undefined } : row) };
  const result = resolve('10:00从旧金山Ferry Building出发，想去SFMOMA和Exploratorium，请安排一天。', undefined, { catalog: incomplete });
  assert.equal(result.state.originCandidateId, null); assert.equal(result.state.origin, 'San Francisco');
  assert.deepEqual(result.explicitCandidateIds, ['venue-sfmoma', 'venue-exploratorium-daytime']);
  const duplicate = { ...actual, places: [...actual.places, { ...actual.places.find(row => row.id === 'venue-ferry-building'), id: 'other-ferry-building' }] };
  assert.equal(resolve('从Ferry Building出发，想去SFMOMA，请安排一天。', undefined, { catalog: duplicate }).state.originCandidateId, null);
});

test('the exact live family question reaches assistant reasoning while unverified cross-city travel stays unconfirmed', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const actual = require('../data/planner-catalog.json');
  const message = '2026年10月10日周六，两名成人带6岁孩子，09:30从Millbrae BART站出发，17:00前必须回到同一站。我们不开车，不打Uber，想去旧金山Exploratorium和奥克兰Oakland Museum of California，全家门票加公共交通总预算150美元。请判断跨城是否现实，再安排；若做不到请明确缩减，不要假设孩子全部免费或省略返程。';
  let calls = 0, context;
  const assistant = createBayBayAssistant({
    config: { JWT_SECRET: 'a-test-secret-longer-than-16' }, catalog: actual, guideCatalog: [], isTest: true,
    now: () => Date.parse('2026-10-04T19:00:00Z'),
    webSearch: async () => { throw new Error('This named-venue fixture must not make external searches'); },
    sourceFetch: async () => { throw new Error('No source-page network in this fixture'); },
    ai: async payload => {
      calls++; context = JSON.parse(payload.input[0].content);
      return { model: 'fixture-reasoner', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '两馆已经明确；跨城及返程没有核实，不能保证17:00返回，建议先核对后缩减安排。', candidateIds: ['venue-exploratorium-daytime', 'venue-omca'], followups: [] }) }] }] };
    },
  });
  const result = await assistant.run({ message, locale: 'zh-Hans', searchMode: 'smart' });
  assert.equal(calls, 1); assert.equal(result.degraded, false);
  assert.equal(context.state.origin, 'Millbrae BART站'); assert.equal(context.state.originCandidateId, null);
  assert.deepEqual(context.state.selectedCandidateIds, ['venue-exploratorium-daytime', 'venue-omca']);
  assert.ok(context.candidates.some(row => row.id === 'venue-exploratorium-daytime'));
  assert.ok(context.candidates.some(row => row.id === 'venue-omca'));
  assert.doesNotMatch(result.answer, /请先选择一个目的城市|scope_rejected/);
  assert.match(result.answer, /不能保证17:00/);
  assert.ok(result.assistantPlan); assert.notEqual(result.assistantPlan.status, 'ready');
  assert.ok(new Set(result.assistantPlan.stops.map(stop => stop.city)).size < 2, 'without route evidence the plan must not assert a cross-city itinerary');
  assert.equal(result.assistantPlan.returnTime ?? null, null);
  assert.ok(result.assistantPlan.unknowns.length > 0);
});

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

test('the live verification-first Ferry request retains return-to-origin synonyms without becoming a day plan', () => {
  const actual = require('../data/planner-catalog.json');
  const message = '10月11日两名成人，10:00从Ferry Building出发，公共交通，只去SFMOMA，18:00前回原地，全程总预算70美元。先核对门票和当天交通；未核实的费用不要当0，也不要增加其他景点。';
  for (const phrase of ['18:00前回原地', '18:00回原地', '18:00前回起点', '18:00前回出发点', '18:00前回起點', '18:00前回出發點']) {
    const result = resolve(message.replace('18:00前回原地', phrase), undefined, { catalog: actual });
    assert.equal(result.clarification, undefined, phrase); assert.notEqual(result.state.goal, 'day-plan', phrase);
    assert.equal(result.state.finishBy, '18:00', phrase); assert.equal(result.state.startTime, '10:00');
    assert.equal(result.state.originCandidateId, 'venue-ferry-building'); assert.equal(result.state.date, '2026-10-11');
    assert.equal(result.state.budget, 70); assert.equal(result.state.budgetScope, 'total');
    assert.equal(result.state.partySize, 2); assert.equal(result.state.travelMode, 'transit');
  }
  const information = resolve('先核实交通，不要安排行程，18:00前回原地。');
  assert.equal(information.state.goal, 'information'); assert.equal(information.state.finishBy, '18:00');
  const options = { secret: 'a-test-secret-longer-than-16' };
  const previous = decodeTaskToken(encodeTaskToken({ state: information.state }, options), options);
  assert.equal(resolve('再核对费用', previous).state.finishBy, '18:00');
  assert.equal(resolve('不要18:00回原地，20:00前回原地。').state.finishBy, '20:00');
  assert.equal(resolve('博物馆18:00关门吗？').state.finishBy, null);
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

test('requests not to assume free child admission are not free-only filters', () => {
  const previous = resolve('明天安排一天，两大一小，孩子6岁，全家总预算150美元。').state;
  for (const message of ['请继续安排，不要假设孩子全部免费。', '請繼續安排，別假設孩子全部免費。', 'Continue the day plan. Do not assume all children enter free.']) {
    const result = resolve(message, previous).state;
    assert.equal(result.freeOnly, null, message); assert.equal(result.budget, 150, message);
  }
  for (const message of ['只要免费，不要假设孩子全部免费，请核实规则。', 'Only show free options. Do not assume children are free.']) {
    assert.equal(resolve(message, previous).state.freeOnly, true, message);
  }
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

test('same-source venue overview aliases defer only to one exact primary venue name', () => {
  const actual = require('../data/planner-catalog.json');
  assert.deepEqual(resolve('明天安排一天，想去Oakland Museum of California', undefined, { catalog: actual }).explicitCandidateIds, ['venue-omca']);
  const officialUrl = 'https://museumca.org/visit/';
  const fixtures = { events: [], places: [
    { id: 'overview', title: 'The lake and its museums', city: 'Oakland', officialUrl, location: { label: 'Example Museum' } },
    { id: 'museum', title: 'Example Museum · Visitor galleries', city: 'Oakland', officialUrl },
    { id: 'cafe', title: 'Example Cafe · Example Museum', city: 'Oakland', officialUrl },
  ] };
  assert.deepEqual(resolve('Plan a day and visit Example Museum', undefined, { catalog: fixtures }).explicitCandidateIds, ['museum']);
  assert.deepEqual(resolve('Plan a day and visit Example Cafe', undefined, { catalog: fixtures }).explicitCandidateIds, ['cafe']);
  const distinctSource = { ...fixtures, places: fixtures.places.map(row => row.id === 'overview' ? { ...row, officialUrl: 'https://differentmuseum.org/visit/' } : row) };
  assert.ok(resolve('Plan a day and visit Example Museum', undefined, { catalog: distinctSource }).clarification);
  const duplicatePrimary = { ...fixtures, places: [...fixtures.places, { ...fixtures.places[1], id: 'other-primary' }] };
  assert.ok(resolve('Plan a day and visit Example Museum', undefined, { catalog: duplicatePrimary }).clarification);
  const conflictingCoordinates = { ...fixtures, places: fixtures.places.map(row => ({ ...row, location: { ...row.location, precision: 'venue', lat: row.id === 'museum' ? 37.8 : 37.7, lng: -122.2 } })) };
  assert.ok(resolve('Plan a day and visit Example Museum', undefined, { catalog: conflictingCoordinates }).clarification);
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

test('a former home is distinct from the new service city, including overlapping long city names', () => {
  for (const [message, origin, city] of [
    ['我原来住 Palo Alto，现在搬到 East Palo Alto，垃圾和供水怎样开户？', 'Palo Alto', 'East Palo Alto'],
    ['我原來住在 East Palo Alto，現在搬到 Palo Alto，供水怎樣開戶？', 'East Palo Alto', 'Palo Alto'],
    ['I used to live in South San Francisco. Now I am moving to San Francisco and need utilities.', 'South San Francisco', 'San Francisco'],
    ['I previously lived in San Francisco; now I am moving to South San Francisco. Which utilities do I contact?', 'San Francisco', 'South San Francisco'],
  ]) {
    const result = resolve(message);
    assert.equal(result.clarification, undefined, message); assert.equal(result.state.city, city, message);
    assert.equal(result.state.origin, origin, message); assert.equal(result.state.originCandidateId, null, message);
    assert.equal(result.state.goal, 'newcomer', message);
  }
  const corrected = resolve('不是 Palo Alto，是 East Palo Alto，供水怎样开户？');
  assert.equal(corrected.state.city, 'East Palo Alto'); assert.equal(corrected.clarification, undefined);
  assert.ok(resolve('我想在 Palo Alto 或 East Palo Alto 租房，两个城市的水电怎么开户？').clarification);
});

test('new outside service and information topics clear old Bay Area geography but retain other confirmed requirements', () => {
  const options = { secret: 'a-test-secret-longer-than-16' };
  const state = resolve('San Jose明天安排一天，总预算100美元，3个人。').state;
  const previous = decodeTaskToken(encodeTaskToken({ state }, options), options);
  for (const message of [
    '我现在从 San Jose 搬到 Seattle，只问水电和垃圾开户，不要安排旅游路线。',
    '現在問 Los Angeles 的圖書館辦卡條件，只回答生活資訊，不安排行程。',
    'I am moving to Seattle. How do I start electricity service? No itinerary.',
    'Now tell me about library cards in LA. Do not plan an itinerary.',
  ]) {
    for (const prior of [undefined, previous]) {
      const result = resolve(message, prior);
      assert.match(result.clarification || '', /湾区/, message); assert.equal(result.state.city, null, message); assert.equal(result.state.region, null, message);
      assert.ok(result.state.clearedFields.includes('city')); assert.ok(result.state.clearedFields.includes('region'));
      assert.equal(result.state.budget, prior ? 100 : null, message); assert.equal(result.state.partySize, prior ? 3 : null, message);
    }
  }
  const outside = resolve('现在问 Seattle 的供水开户，不安排行程。', previous);
  const later = resolveTaskState({ message: '继续', previous: outside.state, searchContext: { city: 'San Jose', region: 'south-bay' }, today: TODAY });
  assert.equal(later.state.city, null); assert.equal(later.state.region, null); assert.equal(later.state.budget, 100);
});

test('outside departure, residence and rejected outside cities do not block Bay Area questions', () => {
  for (const [message, city] of [
    ['我从 Seattle 搬到 San Jose，水电怎么开户？', 'San Jose'],
    ['I used to live in Seattle. Now I am moving to San Jose and need utilities.', 'San Jose'],
    ['我以前住洛杉矶，现在搬到 East Palo Alto，供水怎么开户？', 'East Palo Alto'],
    ['I live in Los Angeles. What are the utility providers in Palo Alto?', 'Palo Alto'],
    ['不是 Seattle，而是 San Jose，电力怎么开户？', 'San Jose'],
    ['不查 Seattle，仍问 San Jose 的生活信息。', 'San Jose'],
    ['Not about Seattle. Tell me about libraries in San Jose.', 'San Jose'],
  ]) {
    const result = resolve(message); assert.equal(result.clarification, undefined, message); assert.equal(result.state.city, city, message);
  }
  for (const message of ['我住 LA，明天飞 SFO。', 'I live in LA and fly to SFO tomorrow.']) assert.equal(resolve(message).clarification, undefined, message);
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
