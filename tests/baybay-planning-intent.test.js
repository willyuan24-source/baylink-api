const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveTaskState, validateTaskState, encodeTaskToken, decodeTaskToken } = require('../lib/baybayState');
const catalog = require('../data/planner-catalog.json');
const TODAY = '2026-10-06', now = Date.parse(`${TODAY}T19:00:00Z`);
const options = { secret: 'synthetic-planning-speech-act-secret', now };
const signed = state => decodeTaskToken(encodeTaskToken({ state }, options), options);
const resolve = (message, previous) => resolveTaskState({ message, previous, catalog, today: TODAY });

test('planning actions combine with leisure, duration and itinerary objects across three languages', () => {
  for (const message of [
    '周末带娃逛半天，帮我排个顺路的走法', '周末带娃逛半天，帮我安排行程',
    '想在Fremont散步一整天，帮我们设计一个轻松的游程', '把周末的几个景点串成半天的行程',
    '在旧金山玩一天，给我排个走法', '我想出游半天，可以帮我规划吗？',
    '週末帶小孩出門走走，幫我串成半天的遊程', '在Fremont逛一整天，幫我們設計行程',
    '把幾個景點串起來，安排半日遊', '想去公園散步半天，幫我排個順路的走法',
    'Could you put together a half-day outing for my family in Fremont?',
    'Map out a full-day trip around San Francisco for us.', 'Organize a relaxed half-day outing in Oakland.',
    'We have a whole day to visit parks in Fremont. Could you sketch out an itinerary?',
    'Build a day trip for my family. Leave time for lunch.',
  ]) assert.equal(resolve(message).state.goal, 'day-plan', message);
});

test('negated, reported, quoted and administrative planning words do not request a leisure itinerary', () => {
  for (const message of [
    '不要帮我排个半天行程，只解释门票。', '不用安排半日游，请告诉我开放时间。',
    '別幫我串成半天的遊程，只比較門票。', '不要安排一天，只列办理图书证所需的材料。',
    'Do not put together a half-day outing. Just explain the admission rules.',
    'I do not need you to build an itinerary; compare museum prices.',
    '上次我们安排半天去公园，今天只想知道门票。', '昨天安排一日游，现在问报税材料。',
    'The website says “plan a half-day outing”. What does that phrase mean?',
    'Previously we planned a day trip. What are the museum hours?',
    '官网写着「半日遊行程」，请解释这个词。', '帮我安排预约牙医的时间，半天请假够吗？',
  ]) assert.notEqual(resolve(message).state.goal, 'day-plan', message);
  assert.equal(resolve('请安排从SFO到San Jose的路线，并计算车程。').state.goal, 'transit');
  assert.equal(resolve('我刚搬到Fremont，请列出水电开户材料，不要安排行程。').state.goal, 'newcomer');
});

test('the latest explicit planning or cancellation clause wins without discarding unrelated service requests', () => {
  for (const message of ['先别排了，重新安排一天。', '不要安排半天，而是安排一天。', '先別排了，重新安排半日遊。', 'Cancel the itinerary, but put together a half-day outing instead.']) {
    const result = resolve(message);
    assert.equal(result.state.goal, 'day-plan', message); assert.equal(result.planningPaused, false, message);
  }
  for (const message of ['帮我安排半天，算了先别排了。', '幫我串成半天遊程，取消行程。', 'Put together a half-day outing. Cancel the itinerary.']) {
    const result = resolve(message);
    assert.equal(result.state.goal, 'information', message); assert.equal(result.planningPaused, true, message);
  }
  assert.equal(resolve('我刚搬家需要开通供水，别给我安排旅游行程。').state.goal, 'newcomer');
});

test('signed multilingual pause, correction and resume retain explicit constraints without inventing a clock or price', () => {
  const initial = validateTaskState({ goal: 'day-plan', city: 'Fremont', date: '2026-10-10', partySize: 3,
    childAges: [6], travelMode: 'drive', budget: 80, budgetScope: 'total', preferences: ['outing-duration:half-day'] });
  for (const [pause, correct, resume] of [
    ['先别排了，只解释门票。', '改坐公交，其他条件不变。', '继续规划'],
    ['先別排了，只解釋門票。', '改坐公車，其他條件不變。', '繼續規劃'],
    ['Pause the itinerary. Just explain admission.', 'Use public transit instead. Keep the other requirements.', 'Resume planning'],
  ]) {
    let result = resolve(pause, signed(initial));
    assert.equal(result.state.goal, 'information', pause); assert.equal(result.planningPaused, true, pause);
    result = resolve(correct, signed(result.state));
    assert.equal(result.state.travelMode, 'transit', correct);
    result = resolve(resume, signed(result.state));
    assert.equal(result.state.goal, 'day-plan', resume);
    for (const field of ['city', 'date', 'partySize', 'childAges', 'budget', 'budgetScope', 'preferences']) assert.deepEqual(result.state[field], initial[field], `${resume}: ${field}`);
    assert.equal(result.state.startTime, null); assert.equal(result.state.finishBy, null);
  }
});
