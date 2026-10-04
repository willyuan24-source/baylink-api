const test = require('node:test');
const assert = require('node:assert/strict');
const { buildChatWebRequest, isSearchReset } = require('../lib/guideWebSearch');
const { inferDestination, inferFilters, loadPlannerCatalog } = require('../lib/planner');
const { buildGuideLocalRecommendations } = require('../lib/guideLocalRecommendations');
const { searchScope } = require('../lib/bayAreaSearchScope');

const TODAY = '2026-10-04';
const ask = (message, options = {}) => buildChatWebRequest({ message, searchMode: 'smart', locale: 'zh-Hans', today: TODAY, ...options });
const history = (...messages) => messages.flatMap(content => [{ role: 'user', content }, { role: 'assistant', content: 'A previous answer is not source evidence.' }]);
const input = result => { assert.equal(result.search, true, JSON.stringify(result)); return result.input; };

test('the screenshot question in all three locales searches the entire California Bay Area on the Pacific date', () => {
  for (const [locale, message] of [
    ['zh-Hant', '今天有什麼活動，地方好去？'],
    ['zh-Hans', '今天有什么活动，地方好去？'],
    ['en', 'What is on today?'],
    ['en', 'Where should we go today?'],
  ]) {
    const row = input(ask(message, { locale }));
    assert.equal(row.locale, locale);
    assert.equal(row.date, TODAY);
    assert.equal(row.region, 'all');
    assert.equal(row.city, undefined, 'the default is not San Francisco city alone');
    assert.match(row.query, /San Francisco Bay Area, California, United States/);
    assert.match(row.query, /entire Bay Area; no city restriction/);
    assert.ok(row.query.includes(message));
  }
});

test('ordinary complete questions inherit the most recent valid public city and constraints, without raw history', () => {
  const row = input(ask('今天有什麼活動，地方好去？', {
    locale: 'zh-Hant', history: history('San Jose museums on October 6 under $80', 'Oakland museums on October 7 indoors under $30; private-note-marker'),
  }));
  assert.equal(row.city, 'Oakland');
  assert.equal(row.region, 'east-bay');
  assert.equal(row.date, TODAY, 'today overrides the prior date');
  assert.match(row.query, /indoor/);
  assert.match(row.query, /admission budget: USD 30/);
  assert.doesNotMatch(row.query, /private-note-marker|October 7|San Jose|previous answer/);
});

test('city aliases survive the actual query-builder to local-catalog path, including a city without events', async () => {
  const event = (id, city, region) => ({ id, title: `${city} event`, city, region, startDate: TODAY, endDate: TODAY,
    cost: 'free', costLabel: 'Free admission', officialUrl: `https://example.org/${id}`, planning: { admissionUsd: 0 } });
  const catalog = { version: 1, checkedAt: '2026-10-02', guides: [], places: [], events: [
    event('alameda', 'Alameda', 'east-bay'), event('san-jose', 'San Jose', 'south-bay'), event('oakland', 'Oakland', 'east-bay'),
  ] };
  for (const searchMode of ['smart', 'site']) for (const [message, city, ids] of [
    ['今天阿拉米達有什麼活動？', 'Alameda', ['alameda']],
    ['今天SanJose有什麼活動？', 'San Jose', ['san-jose']],
    ['今天 Belvedere 有什么活动？', 'Belvedere', []],
  ]) {
    const request = ask(message, { searchMode, locale: 'zh-Hant' });
    assert.equal(request.search, searchMode !== 'site');
    assert.equal(request.input.city, city, `${searchMode}: ${message}`);
    assert.doesNotMatch(request.input.query, /entire Bay Area; no city restriction/);
    assert.equal(searchScope(request.input, () => Date.parse(`${TODAY}T19:00:00Z`)).city, city);
    const result = await buildGuideLocalRecommendations({ message: request.input.query, searchContext: request.input, today: TODAY, locale: 'zh-Hant', catalog });
    assert.ok(result, `${city} must keep the catalog response path`);
    assert.equal(result.filters.city, city);
    assert.equal(result.filters.date, TODAY);
    assert.deepEqual(result.eventIds, ids, `${city} must never be filled with another city's events`);
    assert.deepEqual(result.sources.map(source => source.url), ids.map(id => `https://example.org/${id}`));
  }
});

test('current city and date override history, while a new region clears an inherited city', () => {
  const prior = history('Oakland museums October 7');
  const row = input(ask('San Jose events tomorrow', { history: prior, locale: 'en', searchContext: { city: 'Berkeley', date: '2026-10-09' } }));
  assert.equal(row.city, 'San Jose');
  assert.equal(row.region, 'south-bay');
  assert.equal(row.date, '2026-10-05');
  const region = input(ask('明天北湾有什么活动？', { history: prior }));
  assert.equal(region.region, 'north-bay');
  assert.equal(region.city, undefined);
  const all = input(ask('明天整个湾区都可以，不限城市，有什么活动？', { history: prior }));
  assert.equal(all.region, 'all');
  assert.equal(all.city, undefined);
});

test('current explicit UI context overrides inherited conditions before the current message', () => {
  const row = input(ask('What events are available?', {
    locale: 'en', history: history('Oakland events October 7'), searchContext: { city: 'San Jose', date: '2026-10-10' },
  }));
  assert.equal(row.city, 'San Jose');
  assert.equal(row.date, '2026-10-10');
});

test('an explicit restart discards old city, date, price and setting, including stale UI context', () => {
  for (const message of ['重新开始，今天有什么活动？', '重新開始，今天有什麼活動？', 'Start over. What is on today?', '请重新开始，今天有什么活动？', 'Please start over. What is on today?']) {
    assert.equal(isSearchReset(message), true, 'the server can reuse the same reset rule for its own history');
    const row = input(ask(message, { history: history('Oakland museums October 17 indoors under $30'), searchContext: { city: 'Berkeley', date: '2026-10-20' } }));
    assert.equal(row.region, 'all');
    assert.equal(row.city, undefined);
    assert.equal(row.date, TODAY);
    assert.doesNotMatch(row.query, /Oakland|Berkeley|museums|indoor|USD 30|2026-10-20/);
  }
  const later = input(ask('What events are there today?', { locale: 'en', history: history('Oakland museums October 17 indoors under $30', 'Start over. Berkeley events tomorrow') }));
  assert.equal(later.city, 'Berkeley');
  assert.doesNotMatch(later.query, /Oakland|indoor|USD 30/);
});

test('negative and quoted reset phrases preserve the public city, date and filters', () => {
  for (const message of [
    '不要重新开始，继续看 San Jose 有什么活动？', '不要重新開始，繼續看有什麼活動？',
    'Do not start over. What events are there?', '“重新开始”只是引用，继续看有什么活动？',
    '"Start over" is a quoted phrase. What events are there?', '重新开始是什么意思？有什么活动？',
  ]) {
    assert.equal(isSearchReset(message), false, message);
    const row = input(ask(message, { history: history('San Jose events October 7 indoors under $30') }));
    assert.equal(row.city, 'San Jose', message);
    assert.equal(row.date, '2026-10-07', message);
    assert.match(row.query, /indoor/);
    assert.match(row.query, /admission budget: USD 30/);
  }
});

test('assistant history and private user turns cannot supply web location, date or raw text', () => {
  const prior = history('Oakland museums October 7');
  prior.push(
    { role: 'assistant', content: 'Shanghai events October 20 SECRET_ASSISTANT_MARKER' },
    { role: 'user', content: 'San Jose events October 21, email private@example.com' },
    { role: 'user', content: 'Berkeley events October 22, call 650-555-1234' },
    { role: 'user', content: 'I live at 123 Main Street, Fremont, events October 23' },
  );
  const row = input(ask('What is on today?', { locale: 'en', history: prior }));
  assert.equal(row.city, 'Oakland');
  assert.equal(row.date, TODAY);
  assert.doesNotMatch(JSON.stringify(row), /SECRET|Shanghai|San Jose|Berkeley|Fremont|private@example|650-555|123 Main/);
  assert.equal(ask('My booking confirmation is 650-555-1234', { searchMode: 'web' }).status, 'not_applicable');
});

test('destination inference removes departure cities before regional inference', () => {
  const catalog = loadPlannerCatalog();
  const message = '明天从Fremont出发，有什么活动？';
  assert.equal(inferFilters(message, TODAY).region, 'east-bay', 'the generic filter parser alone sees the origin name');
  const destination = inferDestination(message, catalog);
  assert.deepEqual(destination.origins, ['Fremont']);
  assert.equal(inferFilters(destination.analysisMessage, TODAY).region, undefined);
  for (const text of [message, 'Leaving Fremont, what events are on tomorrow?', 'I live in Oakland. What events are on today?']) {
    const row = input(ask(text, { locale: 'en' }));
    assert.equal(row.city, undefined);
    assert.equal(row.region, 'all');
    assert.match(row.query, /departure only, not a destination restriction/);
  }
  const trip = input(ask('From Fremont to San Francisco, what events are on tomorrow?', { locale: 'en' }));
  assert.equal(trip.city, 'San Francisco');
  assert.equal(trip.region, 'sf');
  const inherited = input(ask('我从Fremont出发，今天有什么活动？', { history: history('San Jose events October 7') }));
  assert.equal(inherited.city, 'San Jose', 'changing a departure point does not change the selected destination');
  assert.equal(inherited.region, 'south-bay');
});

test('known out-of-area destinations receive a scope explanation instead of an unnoticed Bay Area rewrite', () => {
  for (const [locale, message] of [
    ['zh-Hans', '上海今天有什么活动？'], ['zh-Hant', '今天中國上海有什麼活動？'],
    ['en', 'What events are in Shanghai today?'], ['en', 'Seattle events tomorrow'], ['zh-Hans', '北京有什么景点？'], ['en', 'Shanghai restaurants today'],
  ]) {
    const result = ask(message, { locale, history: history('Oakland museums') });
    assert.equal(result.search, false);
    assert.equal(result.status, 'not_applicable');
    assert.ok(result.question);
    assert.match(result.question, /旧金山湾区|舊金山灣區|San Francisco Bay Area/);
    assert.equal(result.input, undefined);
  }
  assert.equal(ask('今天有什么活动？', { history: history('上海有什么活动？') }).search, false, 'an outside destination is not silently forgotten on a generic follow-up');
  assert.equal(ask('今天有什么活动？', { searchContext: { city: 'Shanghai' } }).search, false);
  assert.equal(input(ask('Oakland events today', { history: history('Shanghai events tomorrow'), locale: 'en' })).city, 'Oakland');
  assert.equal(input(ask('重新开始，今天有什么活动？', { history: history('上海有什么活动？') })).region, 'all');
  for (const searchMode of ['site', 'smart', 'web']) {
    const outside = ask('仅站内：上海今天有什么活动？', { searchMode });
    assert.equal(outside.search, false);
    assert.equal(outside.status, 'not_applicable');
    assert.match(outside.question, /旧金山湾区/);
    assert.equal(ask('今天有什么活动？', { searchMode, searchContext: { city: 'Shanghai' } }).search, false);
  }
  assert.ok(ask('今天有什么活动？', { searchMode: 'site', history: history('上海有什么活动？') }).question);
});

test('outside origin and cuisine references are not confused with an outside destination', () => {
  const travel = input(ask('从上海飞来San Francisco，今天有什么活动？'));
  assert.equal(travel.city, 'San Francisco');
  const food = input(ask('Find Shanghai dumplings in San Francisco', { locale: 'en', searchMode: 'web' }));
  assert.equal(food.city, 'San Francisco');
  assert.equal(input(ask('不要上海，今天Oakland有什么活动？')).city, 'Oakland');
  assert.equal(input(ask('旧金山中国城今天有什么活动？')).city, 'San Francisco');
  assert.equal(input(ask('San Francisco Sacramento Street cafes', { locale: 'en' })).city, 'San Francisco');
  assert.equal(input(ask('San Francisco museum at 123 Main Street hours', { locale: 'en' })).city, 'San Francisco', 'a public venue address is not an asserted private home address');
});

test('document origins, birthplaces and local names do not trigger an outside-destination refusal', () => {
  for (const message of ['中国驾照在加州怎么换证', '中國的駕照在加州如何換證', '上海出生孩子在San Jose入学', 'My child was born in Shanghai and needs school enrollment in San Jose']) {
    for (const searchMode of ['smart', 'site', 'web']) {
      const result = ask(message, { searchMode, school: /孩子|child/.test(message) });
      assert.equal(result.question, undefined, `${searchMode}: ${message}`);
    }
  }
  for (const message of ['Jack London Square Oakland events today', 'What cafes are near Jack London Square in Oakland?', 'San Francisco 上海菜 restaurants today']) {
    const row = input(ask(message, { locale: 'en' }));
    assert.equal(row.city, /Oakland/.test(message) ? 'Oakland' : 'San Francisco');
  }
  assert.ok(ask('我要去上海', { searchMode: 'site' }).question, 'an explicit outside destination is still refused without an events keyword');
  assert.ok(ask('What events are in London?', { locale: 'en' }).question, 'London itself remains outside the Bay Area');
});

test('site-only local discovery carries validated public city/date input without requesting web search', () => {
  const prior = history('Oakland museums October 7 indoors under $30');
  for (const [searchMode, message] of [['site', '有什么免费活动？'], ['smart', '只看站内指南，有什么免费活动？']]) {
    const result = ask(message, { searchMode, history: prior });
    assert.equal(result.search, false);
    assert.equal(result.status, 'not_requested');
    assert.equal(result.input.city, 'Oakland');
    assert.equal(result.input.region, 'east-bay');
    assert.equal(result.input.date, '2026-10-07');
    assert.match(result.input.query, /free admission only/);
    assert.doesNotMatch(result.input.query, /previous answer/);
  }
  const changed = ask('San Jose events tomorrow', { searchMode: 'site', history: prior, locale: 'en' });
  assert.equal(changed.search, false);
  assert.equal(changed.input.city, 'San Jose');
  assert.equal(changed.input.date, '2026-10-05');
  const fresh = ask('今天有什麼活動，地方好去？', { searchMode: 'site', locale: 'zh-Hant' });
  assert.equal(fresh.input.date, TODAY);
  assert.equal(fresh.input.region, 'all');
  assert.equal(fresh.input.city, undefined);
  assert.deepEqual(ask('总结这篇攻略', { searchMode: 'site', history: prior }), { search: false, status: 'not_requested' }, 'a plain article summary needs no invented outing scope');
});

test('operational and discovery queries default to today, while timeless information does not inherit a trip date', () => {
  for (const message of ['Oakland museum opening hours', 'San Francisco museums', '湾区有什么活动？']) assert.equal(input(ask(message)).date, TODAY);
  const timeless = input(ask('What is the history of Oakland museums?', { locale: 'en', history: history('San Jose museums October 9') }));
  assert.equal(timeless.city, 'Oakland');
  assert.equal(timeless.date, undefined);
  const howto = input(ask('How does Clipper work?', { searchMode: 'web', locale: 'en' }));
  assert.equal(howto.date, undefined);
  assert.equal(howto.region, 'all');
});

test('existing clarification, site-only, school, and service boundaries remain intact', () => {
  assert.ok(ask('Any more free ones?', { locale: 'en' }).question);
  const more = input(ask('Any more free ones?', { locale: 'en', history: history('Oakland museums October 7 indoors under $30') }));
  assert.equal(more.city, 'Oakland');
  assert.equal(more.date, '2026-10-07');
  assert.match(more.query, /museums|indoor/);
  assert.match(more.query, /free admission only/);
  assert.ok(ask('Oakland or Berkeley museums today', { locale: 'en' }).question);
  assert.equal(ask('今天有什么活动？', { searchMode: 'site' }).search, false);
  assert.equal(ask('根据站内指南整理湾区活动').search, false);
  assert.equal(ask('Find Bay Area schools', { school: true }).search, false);
  assert.equal(ask('Find Bay Area cleaning', { siteService: true }).search, false);
  assert.equal(ask('What is two plus two?', { history: history('Oakland museums') }).search, false);
});
