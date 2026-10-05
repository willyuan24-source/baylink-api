const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState, validateTaskState, applyTaskStatePatch, encodeTaskToken, decodeTaskToken } = require('../lib/baybayState');
const catalog = require('../data/planner-catalog.json');
const resolve = (message, previous, overrides = {}) => resolveTaskState({ message, previous, catalog, today: '2026-10-04', ...overrides });
const sign = state => {
  const options = { secret: 'audit-regression-secret-not-production' };
  return decodeTaskToken(encodeTaskToken({ state }, options), options);
};
const lowesQuestion = 'Lowe’s 10月24日 MrBeast 那两只 Swarms，普通人不用会员也能领吗？湾区是不是每家早上10点开始？请把确认和未确认的部分分开。';
const familyRequest = '请帮我安排 2026 年 10 月 10 日在 Fremont 的亲子一日行程：2 位成人加 1 名 5 岁孩子，只坐公交和步行，上午 10:00 从 Fremont BART 站出发，17:00 前回到同一站。全家总预算 $50，要包括门票、交通和午餐，不是每人 $50。请结合 BAYLINK 站内资料与场馆官方站外信息核实，安排休息；没有核实的营业、票价和交通时间请明确说不知道。';

test('live offer time questions cannot become signed personal trip constraints', () => {
  const first = resolve(lowesQuestion).state;
  assert.equal(first.startTime, null); assert.equal(first.finishBy, null);
  const next = resolve('帮我安排当天在 Fremont 的行程', sign(first)).state;
  assert.equal(next.startTime, null); assert.equal(next.finishBy, null);
});

test('event schedule inquiries and quoted source clocks preserve existing personal times', () => {
  const previous = sign(resolve('明天安排一天，9点出发，17点前回家。').state);
  for (const message of [
    lowesQuestion, '活动是不是10点开始？', '市集10点开始吗？', '活动10点开始，几点结束？',
    '官网说10点开始，请核实。', '官网说10点开门，活动开始时间：10:00。',
    '海报写“10点出发”，是真的吗？', '工作坊最晚结束时间：18:00，是官网写的吗？',
    'Does the event start at 10 am?', 'The workshop starts at 10 am. Is that confirmed?',
    'According to the website, start time is 10:00. Can you verify?',
    'The event page says start at 10 am and finish by 6 pm.',
    'Does the workshop finish by 6 pm?',
  ]) {
    const state = resolve(message, previous).state;
    assert.equal(state.startTime, '09:00', message); assert.equal(state.finishBy, '17:00', message);
    const fresh = resolve(message).state;
    assert.equal(fresh.startTime, null, message); assert.equal(fresh.finishBy, null, message);
  }
});

test('explicit personal starts, clock-before-origin, and return-time corrections still apply', () => {
  for (const [message, startTime, finishBy] of [
    ['10点出发，17点前回家。', '10:00', '17:00'],
    ['10点开始安排。', '10:00', null],
    ['我们10点开始，下午5点半回家。', '10:00', '17:30'],
    ['上午 10:00 从 Fremont BART 站出发，17:00 前回到同一站。', '10:00', '17:00'],
    ['官网说活动9点开始，但我们10点出发。', '10:00', null],
    ['官网说9点开门，10点出发。', '10:00', null],
    ['官网说9点开门，10点开始安排。', '10:00', null],
    ['活动10点开始，我们11点出发，18点回家。', '11:00', '18:00'],
    ['Plan my itinerary, start at 10 am and return by 5 pm.', '10:00', '17:00'],
    ['Can we leave at 10 am and return by 5 pm?', '10:00', '17:00'],
    ['The museum opens at 9 am, but we leave at 10 am.', '10:00', null],
    ['开始时间改为10:00，最晚结束时间改为17:00。', '10:00', '17:00'],
    ['start time set to 10:00, return time set to 17:00', '10:00', '17:00'],
  ]) {
    const state = resolve(message).state;
    assert.equal(state.startTime, startTime, message); assert.equal(state.finishBy, finishBy, message);
  }
});

test('live whole-family budget negation keeps the total cap and complete unverified public station', () => {
  const state = resolve(familyRequest).state;
  assert.equal(state.budget, 50); assert.equal(state.budgetScope, 'total');
  assert.equal(state.origin, 'Fremont BART 站'); assert.equal(state.originCandidateId, null);
  assert.equal(state.startTime, '10:00'); assert.equal(state.finishBy, '17:00');
  assert.equal(state.returnToOrigin, true);
  assert.equal(state.partySize, 3); assert.deepEqual(state.childAges, [5]);
  assert.equal(state.date, '2026-10-10'); assert.equal(state.city, 'Fremont');
  const next = resolve('再核对一下，其他条件不变', sign(state)).state;
  assert.equal(next.budget, 50); assert.equal(next.budgetScope, 'total');
  assert.equal(next.origin, 'Fremont BART 站'); assert.equal(next.originCandidateId, null);
});

test('affirmative budget revisions win over negated scope or amount in either language', () => {
  for (const [message, budget, scope] of [
    ['全家总预算 $50，不是每人 $50。', 50, 'total'],
    ['不是每人 $50，全家总预算 $80。', 80, 'total'],
    ['不是总预算 $50，而是每人预算 $30。', 30, 'person'],
    ['每人预算改为30，不是总共50。', 30, 'person'],
    ['The total budget is $50, not $50 per person.', 50, 'total'],
    ['Not $50 per person; the total budget is $80.', 80, 'total'],
    ['Not a total budget of $50, but $30 per person.', 30, 'person'],
  ]) {
    const state = resolve(message).state;
    assert.equal(state.budget, budget, message); assert.equal(state.budgetScope, scope, message);
  }
  const previous = sign(resolve('总预算100美元').state);
  for (const message of ['不是每人 $50。', 'Not $50 per person.', '博物馆门票是每人 $50，不是总共 $50 吗？', 'Are admission tickets $50 per person, not $50 total?']) {
    const state = resolve(message, previous).state;
    assert.equal(state.budget, 100, message); assert.equal(state.budgetScope, 'total', message);
  }
  assert.equal(resolve('每人预算改为30', previous).state.budgetScope, 'person');
  assert.equal(resolve('总预算改为80', previous).state.budget, 80);
});

test('named public transit origins retain supplied spelling without manufacturing catalog identity', () => {
  for (const [message, origin] of [
    ['从 Fremont BART 站出发，去旧金山。', 'Fremont BART 站'],
    ['从Millbrae BART站出发，17:00前回同一站。', 'Millbrae BART站'],
    ['从旧金山 Powell Street BART 站出发，去Livermore。', '旧金山 Powell Street BART 站'],
    ['Leave from Fremont BART station at 10 am.', 'Fremont BART station'],
    ['From Palo Alto Caltrain station, plan my day.', 'Palo Alto Caltrain station'],
  ]) {
    const state = resolve(message).state;
    assert.equal(state.origin, origin, message); assert.equal(state.originCandidateId, null, message);
  }
  assert.equal(resolve('Fremont BART 站在哪里？').state.origin, null);
  assert.equal(resolve('从Fremont出发').state.origin, 'Fremont');
  assert.equal(resolve('从BART站出发').state.origin, null);
  const precise = resolve('从 Ferry Building 出发，去SFMOMA。').state;
  assert.equal(precise.originCandidateId, 'venue-ferry-building');
});

test('the live ordered route request retains planning, paid budget, and a named finishing point', () => {
  const message = '请规划 2026 年 10 月 10 日的旧金山路线，严格按 Ferry Building → Exploratorium → Pier 39 的顺序，不加其他景点。2 位成人和 1 名 5 岁孩子，10:00 从 Ferry Building 出发，17:00 在 Pier 39 结束，只步行或公交，全家总预算 $120 包括门票、交通和午餐。请核对三处的营业安排、孩子票价与路线时长；预算不够或没有查到的内容请直接说明，不要当作免费或已确认。';
  const state = resolve(message).state;
  assert.equal(state.goal, 'day-plan'); assert.notEqual(state.freeOnly, true);
  assert.equal(state.budget, 120); assert.equal(state.budgetScope, 'total');
  assert.equal(state.startTime, '10:00'); assert.equal(state.finishBy, '17:00');
  assert.equal(state.returnToOrigin, false);
  assert.equal(state.originCandidateId, 'venue-ferry-building');
  assert.deepEqual(state.selectedCandidateIds, ['venue-exploratorium-daytime', 'pier39']);
});

test('unconfirmed free admission is not a filter while explicit free-only selection and clearing still work', () => {
  for (const message of [
    '安排一天，不要当作免费或已确认。', '安排一天，门票不保证免费。', '安排一天，孩子门票未确认免费。',
    'Plan my day. Do not treat the admission as free or confirmed.',
  ]) assert.notEqual(resolve(message).state.freeOnly, true, message);
  for (const message of ['安排一天，只要免费。', '安排一天，不要收费。', 'Plan my day with free-only options.']) assert.equal(resolve(message).state.freeOnly, true, message);
  const previous = sign(resolve('安排一天，只要免费。').state);
  assert.equal(resolve('不限免费', previous).state.freeOnly, false);
  assert.equal(resolve('不限免费', previous).state.budget, null);
});

test('explicit stop limits survive signed followups, valid revisions, clears, and a service topic switch', () => {
  const state = resolve(familyRequest).state;
  const limited = resolve('不想跑远，只在 Fremont 市内，别换到其他城市。还是刚才的家庭、日期、全家总预算和往返时间；把方案收紧成两站，保留孩子休息和午饭。', sign(state)).state;
  assert.equal(limited.maxStops, 2);
  const next = resolve('这些地方孩子门票是多少？', sign(limited)).state;
  assert.equal(next.maxStops, 2); assert.equal(next.budget, 50); assert.equal(next.budgetScope, 'total');
  assert.equal(resolve('最多三站', sign(next)).state.maxStops, 3);
  assert.equal(resolve('站数不限', sign(next)).state.maxStops, undefined);
  assert.equal(resolve('不用安排行程，改问Fremont的水电开户。', sign(next)).state.maxStops, undefined);
  assert.equal(resolve('请安排一个新行程').state.maxStops, undefined);
  for (const value of [0, 7, -1, 1.5, '2', true, null]) assert.equal(validateTaskState({ maxStops: value }).maxStops, undefined);
  for (const maxStops of [1, 2, 6]) assert.equal(sign({ maxStops }).state.maxStops, maxStops);
  assert.equal(applyTaskStatePatch({ state, message: '再查一下门票', patch: { maxStops: 2 }, catalog, today: '2026-10-04' }).maxStops, undefined);
});

test('explicit endpoint and return requests persist without converting a venue closing time into a trip condition', () => {
  for (const message of ['17:00 在 Pier 39 结束。', '安排一天，不返回起点。', 'Plan my day. Do not return to the starting point.']) {
    const state = resolve(message).state;
    assert.equal(state.returnToOrigin, false, message);
    assert.equal(resolve('再查一下交通', sign(state)).state.returnToOrigin, false, message);
  }
  for (const message of ['17:00前回到同一站', '17:00在出发点结束', 'Return to the starting point by 5 pm.']) assert.equal(resolve(message).state.returnToOrigin, true, message);
  assert.equal(resolve('活动17:00在Pier39结束吗？').state.returnToOrigin, undefined);
  assert.equal(resolve('活动17:00在Pier39结束吗？').state.finishBy, null);
  assert.equal(resolve('官网说不返回起点，这是活动规则吗？').state.returnToOrigin, undefined);
  assert.equal(validateTaskState({ returnToOrigin: 'false' }).returnToOrigin, undefined);
});

test('the live cross-library eligibility comparison retains residence without inventing a destination city', () => {
  const message = '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。';
  for (const previous of [undefined, sign({ goal: 'information', city: 'San Francisco', region: 'sf' })]) {
    const result = resolve(message, previous);
    assert.equal(result.clarification, undefined); assert.equal(result.state.goal, 'information');
    assert.equal(result.state.city, null); assert.equal(result.state.region, null);
    assert.equal(result.state.origin, 'Fremont'); assert.equal(result.state.originCandidateId, null);
    assert.equal(result.state.freeOnly, null);
    assert.equal(resolve('继续核对这些资源', sign(result.state)).state.city, null);
  }
  const trip = resolve('我住Fremont，明天去旧金山 SFPL 办卡。请比较 SFPL 和 San Mateo County Libraries 的图书证资格。').state;
  assert.equal(trip.city, 'San Francisco'); assert.equal(trip.origin, 'Fremont');
  assert.equal(resolve('SFPL 的地址在哪里？').state.city, 'San Francisco');
  assert.ok(resolve('明天去San Francisco或San Mateo，请安排一天。').clarification);
});

test('the live ticket followup preserves the signed itinerary when the user says not to change it', () => {
  const initial = resolve('10月10日从Ferry Building出发，想去Exploratorium和Pier 39，10点出发，17点在Pier 39结束，请安排一天。').state;
  assert.equal(initial.goal, 'day-plan'); assert.equal(initial.returnToOrigin, false);
  assert.deepEqual(initial.selectedCandidateIds, ['venue-exploratorium-daytime', 'pier39']);
  const previous = sign(initial);
  for (const message of [
    '再核对刚才行程的儿童门票，保留顺序和地点，不改行程。',
    '再核對剛才行程的兒童門票，保留順序和地點，不改行程。',
    '核对儿童票价，不修改原来的行程。', '核對兒童票價，不改變原來的行程。',
    '不需要修改行程，只查儿童票价。',
    '查一下票价，不要调整当前行程。', '查一下票價，別更改這份行程。',
    'Recheck child admission. Keep the order and places; do not change the itinerary.',
    "Check the tickets without modifying our existing itinerary.",
  ]) {
    const state = resolve(message, previous).state;
    assert.equal(state.goal, 'day-plan', message); assert.equal(state.returnToOrigin, false, message);
    assert.deepEqual(state.selectedCandidateIds, initial.selectedCandidateIds, message);
    assert.equal(state.date, initial.date, message); assert.equal(state.originCandidateId, initial.originCandidateId, message);
  }
  assert.equal(resolve('不需要行程，改问水电。', previous).state.goal, 'newcomer');
  assert.equal(resolve('不用再安排行程，只问儿童票价。', previous).state.goal, 'information');
  assert.equal(resolve('不改预算，但不需要行程。', previous).state.goal, 'information');
  assert.equal(resolve('No itinerary. I need electricity service contacts.', previous).state.goal, 'newcomer');
});
