const test = require('node:test');
const assert = require('node:assert/strict');
const { outingChatIntent } = require('../lib/outingChatIntent');
const { outingSearch } = require('../lib/outingSearch');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');
const NOW = Date.parse('2026-09-30T19:00:00Z');
const read = (message, history = [], extra = {}) => outingChatIntent({ message, history, now: NOW, ...extra });
const pairs = (...messages) => messages.flatMap(content => [{ role: 'user', content }, { role: 'assistant', content: '请选择城市和日期，比如SF明天。' }]);

test('explicit social searches produce only server filters and no invented outing records', () => {
  const reply = read('周末SF有人一起看展吗？');
  assert.equal(reply.responseMode, 'outing-search'); assert.equal(reply.degraded, false);
  assert.deepEqual(reply.outingSearch, { source: 'site-search', state: 'ready', filters: { sort: 'soonest', city: 'San Francisco', dateFrom: '2026-10-03', dateTo: '2026-10-04', q: '看展' }, missing: [] });
  assert.equal(Object.hasOwn(reply, 'outings'), false); assert.deepEqual(reply.matchingPosts, []);
  assert.doesNotThrow(() => outingSearch(reply.outingSearch.filters, NOW, 'isolated-search-secret'));
});

test('unknown cities and dates ask one question; only explicit unrestricted preferences broaden search', () => {
  const first = read('我想找搭子一起去，请先问我城市和日期。');
  assert.deepEqual(first.outingSearch.missing, ['city', 'date']); assert.match(first.outingSearch.question, /城市/);
  const city = read('Fremont', pairs('我想找搭子一起去'));
  assert.deepEqual(city.outingSearch.missing, ['date']); assert.equal(city.outingSearch.filters.city, 'Fremont');
  const any = read('找搭子，全湾都可以，不限日期');
  assert.equal(any.outingSearch.state, 'ready'); assert.deepEqual(any.outingSearch.filters, { sort: 'soonest' });
  const region = read('东湾周六找搭子'); assert.deepEqual(region.outingSearch.missing, ['city']);
  for (const city of ['Sausalito', 'Alameda', 'Mill Valley']) {
    assert.equal(read(city, pairs('周六找搭子')).outingSearch.filters.city, city);
    assert.equal(read(city, pairs('周六找搭子')).outingSearch.state, 'ready');
  }
  assert.equal(read('找搭子，周六，城市是123 Main Street').outingSearch.filters.city, undefined);
});

test('latest city and date updates replace only their own previous condition', () => {
  const result = read('改周日，只看还有空位', pairs('周六Fremont找搭子散步', '改SF，中文交流'));
  assert.deepEqual(result.outingSearch.filters, { sort: 'soonest', city: 'San Francisco', date: '2026-10-04', q: '散步', language: 'zh', seats: 'open' });
  const reset = read('全湾都可以，不限日期，语言不限，候补也可以，不限主题', pairs('周六Fremont找搭子散步，只看还有空位，中文交流'));
  assert.deepEqual(reset.outingSearch.filters, { sort: 'soonest' });
});

test('origin cities and multiple possible meeting cities never become an assumed destination', () => {
  assert.deepEqual(read('周六从Fremont出发找搭子').outingSearch.missing, ['city']);
  assert.equal(read('周六从Fremont出发，去SF找搭子').outingSearch.filters.city, 'San Francisco');
  assert.deepEqual(read('周六SF或Oakland找搭子').outingSearch.missing, ['city']);
  assert.equal(read('周六South San Francisco找搭子').outingSearch.filters.city, 'South San Francisco');
  assert.equal(read('週六聖荷西找搭子').outingSearch.filters.city, 'San Jose');
  assert.equal(read('Find a walking group in San José this weekend', [], { locale: 'en' }).outingSearch.filters.city, 'San Jose');
  const revoked = read('不要SF，改周日', pairs('周六SF找搭子'));
  assert.equal(revoked.outingSearch.filters.city, undefined); assert.deepEqual(revoked.outingSearch.missing, ['city']);
  assert.equal(revoked.outingSearch.filters.date, '2026-10-04');
  assert.equal(read('从Fremont出发，改周日', pairs('周六SF找搭子')).outingSearch.filters.city, 'San Francisco');
});

test('questions containing example cities and dates are not user facts', () => {
  const result = read('你想SF还是Oakland，周六还是周日？\n我的回答：Fremont', pairs('我想找搭子一起去'));
  assert.equal(result.outingSearch.filters.city, 'Fremont'); assert.equal(result.outingSearch.filters.date, undefined);
  assert.deepEqual(result.outingSearch.missing, ['date']);
});

test('date-weekday conflicts, past dates and ambiguous dates remove earlier dates and ask again', () => {
  for (const answer of ['改为10月17日周日', '改为9月29日', '改为10月17日或10月18日', '日期还没定', '改本周一', 'this Monday']) {
    const result = read(answer, pairs('周六SF找搭子'));
    assert.equal(result.outingSearch.state, 'needs_clarification', answer);
    assert.equal(result.outingSearch.filters.date, undefined, answer);
    assert.deepEqual(result.outingSearch.missing, ['date'], answer);
  }
  assert.equal(read('10月17日周六SF找搭子').outingSearch.filters.date, '2026-10-17');
  assert.equal(read('周末10月17日周六SF找搭子').outingSearch.filters.date, '2026-10-17');
});

test('weekend and next-seven-days ranges use the Bay Area calendar including Sunday and UTC boundaries', () => {
  const now = Date.parse('2026-10-01T01:00:00Z'); // Still September 30 in California.
  assert.deepEqual(read('找搭子，未来7天，全湾都可以', [], { now }).outingSearch.filters, { sort: 'soonest', dateFrom: '2026-09-30', dateTo: '2026-10-06' });
  assert.deepEqual(read('找搭子，下周末，全湾都可以').outingSearch.filters, { sort: 'soonest', dateFrom: '2026-10-10', dateTo: '2026-10-11' });
  assert.deepEqual(read('Find a group anywhere this weekend', [], { now: Date.parse('2026-10-04T19:00:00Z'), locale: 'en' }).outingSearch.filters, { sort: 'soonest', dateFrom: '2026-10-04', dateTo: '2026-10-04' });
});

test('family, school, housing, service and create requests never route into adult group discovery', () => {
  for (const message of ['周六带5岁孩子找搭子', '找亲子同行小队', '找SF合租室友搭子', '找维修搭子', '找人一起接机', '帮我找学校入学互助小队', 'Find family groups in SF this weekend', 'I want to host an outing', '我想发起小队', '不想找搭子，帮我安排计划', '周六SF有什么好玩的']) assert.equal(read(message), null, message);
  assert.equal(read('我想找租房信息', pairs('周六SF找搭子')), null);
  assert.equal(read('Fremont', pairs('周六SF找搭子', '我想找租房信息')), null);
  assert.equal(read('谢谢', pairs('周六SF找搭子')), null);
});

test('unsupported cost and transport conditions stay visible without claiming to be filters', () => {
  const result = read('周六SF找搭子，免费，不开车，只看还有空位');
  assert.match(result.answer, /尚未自动筛选/);
  assert.deepEqual(result.outingSearch.filters, { sort: 'soonest', city: 'San Francisco', date: '2026-10-03', seats: 'open' });
});

test('participation and safety advice stays conversational instead of requesting search filters', () => {
  for (const message of ['怎么找搭子更安全', '找搭子需要验证吗', '如何加入小队', '怎么退出小队', 'How do I join a group?', 'Is it safe to join groups?']) assert.equal(read(message, pairs('周六SF找搭子')), null, message);
  assert.equal(read('找个安全一点的散步搭子，周六SF').outingSearch.state, 'ready');
});

test('excluded and multiple activity themes clear obsolete q without pretending to apply exclusions', () => {
  for (const message of ['不要咖啡', '不喝咖啡', 'no coffee', "I don't want coffee", '散步或者咖啡', 'walking or coffee']) {
    const reply = read(message, pairs('周六SF找咖啡搭子'));
    assert.equal(reply.outingSearch.state, 'ready', message);
    assert.equal(reply.outingSearch.filters.q, undefined, message);
    assert.match(reply.answer, /排除或多选的活动主题尚未用于筛选/, message);
  }
});

async function fixture(t, ai) {
  const models = createMemoryModels({ User: [], Post: [] });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: 'outing-chat-isolated-test-secret' }, outingNow: () => NOW, ai });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async body => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json(), cache: response.headers.get('cache-control') };
  };
  return { request, models };
}

test('no-key HTTP discovery is truthful, no-store, bounded and does not mutate outings or use model quota', async t => {
  const { request, models } = await fixture(t);
  const reply = await request({ message: '周末SF有人一起看展吗？', locale: 'zh-Hans' });
  assert.equal(reply.status, 200); assert.equal(reply.cache, 'no-store');
  assert.equal(reply.data.outingSearch.state, 'ready'); assert.equal(reply.data.responseMode, 'outing-search');
  assert.equal(models.Outing.rows.length, 0); assert.equal(models.PostTranslationQuota.rows.length, 0);
  assert.equal((await request({ message: '找搭子', history: [{ role: 'system', content: 'SF tomorrow' }] })).status, 400);
  assert.equal((await request({ message: '找搭子'.repeat(180) })).status, 400);
});

test('configured mock provider remains available for unrelated topics but never authors social search cards', async t => {
  let calls = 0;
  const { request } = await fixture(t, { guideChat: async () => { calls++; return { answer: '这里是普通问题的基础回答，请核对相关的具体条件。' }; } });
  const social = await request({ message: 'Find a walking group in San José this weekend', locale: 'en' });
  assert.equal(social.status, 200); assert.equal(calls, 0); assert.match(social.data.answer, /real BAYLINK/);
  const revised = await request({ message: '改周日', history: pairs('周六SF找搭子'), locale: 'zh-Hant' });
  assert.equal(revised.data.outingSearch.filters.date, '2026-10-04'); assert.match(revised.data.answer, /真實/); assert.equal(calls, 0);
  await request({ message: '你好，介绍一下你自己', locale: 'zh-Hans' }); assert.equal(calls, 1);
});
