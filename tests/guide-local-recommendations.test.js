const test = require('node:test');
const assert = require('node:assert/strict');
const { buildGuideLocalRecommendations: build } = require('../lib/guideLocalRecommendations');
const { eventOccursOn } = require('../lib/planner');

const event = (id, overrides = {}) => ({ id, title: `${id} 活动`, city: 'San Francisco', region: 'sf', startDate: '2026-10-04', endDate: '2026-10-04', dateLabel: '2026-10-04 · 11:00–16:00', venue: 'Verified Hall', cost: 'free', costLabel: '免费入场；须预约，餐饮另付。', officialUrl: `https://example.org/${id}`, verifiedAt: '2026-10-02', planning: { admissionUsd: 0 }, ...overrides });
const place = (id, overrides = {}) => ({ id, title: `${id} 公园`, city: 'San Francisco', region: 'sf', category: 'attraction', cost: 'free', costLabel: '免费入场；交通另付。', officialUrl: `https://example.org/${id}`, planning: { admissionUsd: 0 }, ...overrides });
const fixture = (events = [], places = []) => ({ version: 1, checkedAt: '2026-10-02', events, places, guides: [] });
const ask = (message, catalog, extra = {}) => build({ message, today: '2026-10-04', catalog, ...extra });

test('Sunday never inherits Wednesday free admission; occurrence gaps and cancellations stay out', async () => {
  const catalog = fixture([
    event('sunday'),
    event('ybca-wednesday', { startDate: '2026-10-01', endDate: '2026-10-31', occurrenceDates: ['2026-10-07', '2026-10-14'], dateLabel: '每周三 11:00–20:00' }),
    event('uncertain-recurring', { startDate: '2026-10-01', endDate: '2026-10-31', dateLabel: '每周三 11:00–20:00' }),
    event('no-confirmed-session', { occurrenceDates: [] }),
    event('cancelled', { status: 'cancelled' }),
  ]);
  const answer = await ask('今天 SF 有什么免费活动？', catalog);
  assert.deepEqual(answer.eventIds, ['sunday']);
  assert.doesNotMatch(answer.answer, /Wednesday|周三|20:00|ybca/);
  assert.match(answer.answer, /须预约，餐饮另付/);
  assert.match(answer.answer, /不代表已即时确认/);
  assert.equal(answer.sources[0].url, 'https://example.org/sunday');
});

test('specific dates and tomorrow use the exact catalog occurrence, not the start/end envelope', async () => {
  const catalog = fixture([event('monday', { startDate: '2026-10-05', endDate: '2026-10-05' }), event('wednesday', { startDate: '2026-10-07', endDate: '2026-10-14', occurrenceDates: ['2026-10-07', '2026-10-14'] })]);
  assert.deepEqual((await ask('明天有什么活动？', catalog)).eventIds, ['monday']);
  assert.deepEqual((await ask('2026-10-07 events in SF', catalog, { locale: 'en' })).eventIds, ['wednesday']);
  assert.deepEqual((await ask('10月8日 SF 有什么活动？', catalog)).eventIds, []);
});

test('explicit cities, aliases, origins and empty known cities cannot broaden to another city', async () => {
  const catalog = fixture([event('sf'), event('sj', { city: 'San Jose', region: 'south-bay' }), event('alameda', { city: 'Alameda', region: 'east-bay' })]);
  for (const message of ['今天 San Jose 有什么活动？', '今天SanJose有什麼活動？', '今天聖荷西有什麼活動？', '今天從 SF 出發去 San Jose 有什麼活動？']) assert.deepEqual((await ask(message, catalog)).eventIds, ['sj'], message);
  assert.deepEqual((await ask('今天阿拉米達有什麼活動？', catalog)).eventIds, ['alameda']);
  const absent = await ask('今天 Belvedere 有什么活动？', catalog);
  assert.deepEqual(absent.eventIds, []);
  assert.equal(absent.filters.city, 'Belvedere');
  assert.match(absent.answer, /未找到.*不代表当地没有活动/s);
});

test('default and explicit Bay-wide requests retain all areas; stale UI context cannot override explicit city', async () => {
  const catalog = fixture([event('sf'), event('east', { city: 'Oakland', region: 'east-bay' }), event('north', { city: 'Novato', region: 'north-bay' })]);
  for (const message of ['今天有什么活动？', '今天从SF出发，全湾区都可以，有什么活动？']) {
    const answer = await ask(message, catalog);
    assert.equal(answer.filters.region, 'all');
    assert.equal(answer.filters.city, undefined);
    assert.equal(answer.eventIds.length, 3);
  }
  assert.deepEqual((await ask('今天 SF 有什么活动？', catalog, { searchContext: { city: 'Oakland', region: 'east-bay' } })).eventIds, ['sf']);
  assert.deepEqual((await ask('今天有什么活动？', catalog, { searchContext: { city: 'Oakland' } })).eventIds, ['east']);
});

test('free admission excludes unknown, discounted, paid and unverified eligibility prices', async () => {
  const catalog = fixture([
    event('free'), event('unknown', { cost: 'unknown', planning: { admissionUsd: null }, costLabel: '未公布票价' }),
    event('paid', { cost: 'paid', planning: { admissionUsd: 5 }, costLabel: '$5' }),
    event('child-discount', { cost: 'mixed', planning: { admissionUsd: 0 }, costLabel: '儿童免费，成人$10' }),
    event('members', { costLabel: '会员免费，普通入场$15' }),
    event('resident', { costLabel: '居民免费；需证件' }),
  ]);
  assert.deepEqual((await ask('今天 SF 免费活动', catalog)).eventIds, ['free']);
});

test('the Bay Area web prefix is regional; explicit SF and starting-city requests retain their scope', async () => {
  const catalog = fixture([event('sf'), event('east', { city: 'Fremont', region: 'east-bay' }), event('south', { city: 'San Jose', region: 'south-bay' })], [place('sf-place'), place('sj-place', { city: 'San Jose', region: 'south-bay' })]);
  const prefix = 'San Francisco Bay Area, California, United States. ';
  for (const query of [`${prefix}今天有什麼地方好去？`, `${prefix}from Fremont, things to do today`]) {
    const answer = await ask(query, catalog, { locale: 'zh-Hant' });
    assert.equal(answer.filters.region, 'all');
    assert.equal(answer.filters.city, undefined);
    assert.equal(answer.eventIds.length, 3);
    assert.equal(answer.placeIds.length, 2);
  }
  assert.deepEqual((await ask(`${prefix}SF 今天有什麼活動？`, catalog)).eventIds, ['sf']);
  assert.deepEqual((await ask(`${prefix}SanJose 今天有什麼活動？`, catalog)).eventIds, ['south']);
  const constrained = await ask(`${prefix}local events; San Jose; indoor; free admission only; conditions must be confirmed. 今天有什麼活動？`, fixture([event('sj', { city: 'San Jose', region: 'south-bay', planning: { admissionUsd: 0, setting: 'indoor' } }), event('outdoors', { city: 'San Jose', region: 'south-bay', planning: { admissionUsd: 0, setting: 'outdoor' } })]));
  assert.deepEqual(constrained.eventIds, ['sj']);
  assert.equal(constrained.filters.setting, 'indoor');
  assert.equal(constrained.filters.freeOnly, true);
});

test('permanent places are separately labeled, never asserted open today; closed schedule excluded', async () => {
  const catalog = fixture([], [place('unknown-hours'), place('closed-sunday', { planning: { admissionUsd: 0, schedule: { sourceUrl: 'https://example.org/hours', verifiedAt: '2026-10-02', weekly: { 0: [] } } } }), place('paid-place', { cost: 'paid', planning: { admissionUsd: 10 } })]);
  const answer = await ask('今天 SF 有什么免费好去处？', catalog);
  assert.deepEqual(answer.eventIds, []);
  assert.deepEqual(answer.placeIds, ['unknown-hours']);
  assert.match(answer.answer, /常设去处备选.*开放时间仍待官方确认/);
  assert.doesNotMatch(answer.answer, /今天开放|没有活动/);
});

test('unrelated, unsupported, undated and ambiguous questions return null', async () => {
  const catalog = fixture([event('sf')]);
  for (const message of ['今天上海有什么活动？', '今天 China Shanghai events', '我想租房', 'SF 有什么活动？', '总结这篇今天活动攻略', '今天和明天有哪些活动？', '今天SF和Oakland有哪些活动？', '2026-02-30 有什么活动？', '2026-10-01 有什么活动？', '今天免费手机怎么领？']) assert.equal(await ask(message, catalog), null, message);
  assert.equal(await ask('今天有什么活动？', catalog, { searchContext: { city: 'Shanghai' } }), null);
});

test('simplified, Traditional and English templates preserve exact source restrictions and optional translations', async () => {
  const row = event('one');
  for (const [locale, intro, note] of [['zh-Hans', /站内记录/, /没有新增网页查询/], ['zh-Hant', /站內記錄/, /沒有新增網頁查詢/], ['en', /published site records/, /no new web search/]]) {
    const answer = await ask('今天 SF 有什么活动？', fixture([row]), { locale });
    assert.match(answer.answer, intro);
    assert.match(answer.matchNote, note);
    assert.match(answer.answer, /须预约，餐饮另付/);
  }
  const english = await ask('Events in SF today', fixture([row]), { locale: 'en', translations: { 'one 活动': 'One Festival', '免费入场；须预约，餐饮另付。': 'Free admission; reservation required, food costs extra.' } });
  assert.match(english.answer, /One Festival/);
  assert.match(english.answer, /reservation required, food costs extra/);
  assert.equal(english.sources[0].title, 'One Festival');
});

test('filters retain age restrictions and indoor requirements through the existing planner', async () => {
  const catalog = fixture([event('kids', { category: 'family', planning: { admissionUsd: 0, setting: 'indoor', minAge: 3, maxAge: 8 } }), event('adult', { planning: { admissionUsd: 0, setting: 'indoor', minAge: 18 } }), event('outdoor', { category: 'family', planning: { admissionUsd: 0, setting: 'outdoor' } })]);
  const answer = await ask('今天 SF 带五岁孩子有什么免费室内活动？', catalog);
  assert.deepEqual(answer.eventIds, ['kids']);
});

test('date context enables short local discovery, but invalid catalogs never become invented answers', async () => {
  assert.deepEqual((await ask('SF 有什么活动？', fixture([event('sf')]), { searchContext: { date: '2026-10-04' } })).eventIds, ['sf']);
  assert.equal(await ask('今天有什么活动？', { version: 0 }), null);
  const answer = await ask('今天有什么活动？', fixture([event('unsafe', { officialUrl: 'https://user:password@example.org' })]));
  assert.deepEqual(answer.eventIds, []);
  assert.deepEqual(answer.sources, []);
});

test('production catalog Sunday SF and San Jose stay date/city grounded without any provider call', async () => {
  const catalog = require('../data/planner-catalog.json');
  const originalFetch = global.fetch;
  global.fetch = () => { throw new Error('No network allowed in local recommendations'); };
  try {
    for (const [message, city] of [['今天 SF 有什麼免費活動？', 'San Francisco'], ['今天 San Jose 有什麼活動？', 'San Jose']]) {
      const result = await ask(message, catalog, { locale: 'zh-Hant' });
      assert.ok(result.eventIds.length, message);
      assert.equal(result.sources.length, result.eventIds.length);
      for (const id of result.eventIds) {
        const row = catalog.events.find(row => row.id === id);
        assert.equal(row.city, city);
        assert.equal(eventOccursOn(row, '2026-10-04'), true);
      }
      assert.ok(!result.eventIds.includes('san-francisco-fleet-week-2026'));
      assert.ok(!result.eventIds.includes('ferry-plaza-farmers-market-2026-autumn'));
      assert.doesNotMatch(result.answer, /周三（今天）|今天.*没有.*活动/);
    }
  } finally { global.fetch = originalFetch; }
});
