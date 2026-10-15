// API-BB-5: dates families type, English asks against the Chinese catalog, and the other acceptance lines of
// the live check after API-BB-4B (10-15). Shipped data with a fixed day; no model, no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const { askedDateRange } = require('../lib/entityAliases');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const TODAY = '2026-10-14'; // Wednesday: this weekend is 10/17-18
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const stateOf = (message, today = TODAY) => resolveTaskState({ message, today, carry: true });
const evidence = (message, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: stateOf(message).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);

test('date spans: two days, the weekend of a day, the Nth weekend and a month', () => {
  const span = (message, today = TODAY) => { const value = askedDateRange(message, today); return value && [value.start, value.end]; };
  for (const [message, start, end] of [
    ['11月21日、22日有什么活动', '2026-11-21', '2026-11-22'], ['11月21日到22日', '2026-11-21', '2026-11-22'], ['11月21至22日', '2026-11-21', '2026-11-22'],
    ['11月21日到11月22日', '2026-11-21', '2026-11-22'], ['12月12日、13日', '2026-12-12', '2026-12-13'], ['November 21-22', '2026-11-21', '2026-11-22'],
    ['Nov 21 and 22', '2026-11-21', '2026-11-22'], ['11/21-22', '2026-11-21', '2026-11-22'], ['the weekend of December 5', '2026-12-05', '2026-12-06'],
    ['the December 5 weekend', '2026-12-05', '2026-12-06'], ['12月5日那个周末', '2026-12-05', '2026-12-06'], ['weekend of Dec 6', '2026-12-05', '2026-12-06'],
    ['weekend of December 3', '2026-12-05', '2026-12-06'], ['12月第一个周末', '2026-12-05', '2026-12-06'], ['十二月第二个周末', '2026-12-12', '2026-12-13'],
    ['11月最后一个周末', '2026-11-28', '2026-11-29'], ['first weekend of December', '2026-12-05', '2026-12-06'], ['last weekend of November', '2026-11-28', '2026-11-29'],
    ['12月有什么圣诞活动', '2026-12-01', '2026-12-31'], ['十二月份', '2026-12-01', '2026-12-31'], ['12月初', '2026-12-01', '2026-12-10'], ['12月底', '2026-12-21', '2026-12-31'],
    ['in December', '2026-12-01', '2026-12-31'], ['这个月有什么免费活动', '2026-10-14', '2026-10-31'], ['下个月', '2026-11-01', '2026-11-30'],
    ['1月有什么活动', '2027-01-01', '2027-01-31'], ['这周末', '2026-10-17', '2026-10-18'], ['下周末', '2026-10-24', '2026-10-25'],
  ]) assert.deepEqual(span(message), [start, end], message);
  // Not a span: one dated day, a baby's age in months, mooncakes, an age next to a date, a cup measure, "may" the verb.
  for (const message of ['12月5日东湾有什么适合孩子的活动', '3月大的宝宝可以去吗', '8月饼', '我们11月21日和22岁的儿子', '1/2 cup', 'in may we go', 'Oct 17, 2 adults']) assert.equal(span(message), null, message);
  // 12月中文活动 is December's Chinese-language events (中 is not 月中).
  assert.deepEqual(span('12月中文活动'), ['2026-12-01', '2026-12-31']);
  // 这周末 outranks a bare month in the same ask.
  assert.deepEqual(span('我1月回国，这周末带孩子去哪玩'), ['2026-10-17', '2026-10-18']);
});

test('task state: a span is one dateRange for an outing ask; a day plan still picks one day of two', () => {
  for (const [message, start, end] of [['11月21日、22日周末湾区有什么华人社区活动？', '2026-11-21', '2026-11-22'], ['12月第一个周末有什么亲子活动', '2026-12-05', '2026-12-06'],
    ['12月有什么圣诞活动', '2026-12-01', '2026-12-31'], ['周末带孩子去哪玩', '2026-10-17', '2026-10-18'], ['湾区周末有什么免费活动', '2026-10-17', '2026-10-18']]) {
    const { state, clarification } = stateOf(message);
    assert.equal(clarification, undefined, message);
    assert.equal(state.date, null, message);
    assert.deepEqual(state.dateRange, { start, end }, message);
  }
  assert.match(stateOf('11月21日、22日帮我排个旧金山一日游').clarification, /多个日期/);
  assert.deepEqual(stateOf('12月第一个周末帮我排个旧金山一日游').state.dateRange, { start: '2026-12-05', end: '2026-12-06' });
  // Weekends in general, a day already chosen in the conversation, and a past span.
  assert.equal(stateOf('周末一般去哪玩比较好').state.dateRange, undefined);
  const first = stateOf('下周末湾区有什么亲子活动').state;
  assert.deepEqual(resolveTaskState({ message: '周末有室内的吗', previous: first, today: TODAY, carry: true }).state.dateRange, { start: '2026-10-24', end: '2026-10-25' });
  assert.match(stateOf('October 5 or 6 family events').clarification, /已经过去/);
  // v1 (no carry) keeps its reading.
  assert.match(resolveTaskState({ message: '11月21日、22日周末湾区有什么华人社区活动？', today: TODAY }).clarification, /多个日期/);
});

test('English asks reach the Chinese catalog rows: L08 East Bay markets, a Pleasanton parade, Cantonese film', () => {
  const markets = evidence('Any farmers markets in the East Bay on Saturday morning?');
  for (const id of ['event:berkeley-downtown-saturday-farmers-market-2026', 'event:oakland-grand-lake-farmers-market-2026']) assert.ok(itemIds(markets).includes(id), itemIds(markets).join(', '));
  // The model sees the English name, not the Chinese title.
  const grandLake = markets.items.find(item => item.id === 'oakland-grand-lake-farmers-market-2026');
  assert.match(grandLake.title, /^Grand Lake Farmers Market/);
  assert.doesNotMatch(grandLake.title, /[㐀-鿿]/);
  assert.ok(itemIds(evidence('Any markets in the East Bay on Saturday?')).includes('event:berkeley-downtown-saturday-farmers-market-2026'));
  const parade = evidence('Are there any parades in Pleasanton on December 5?');
  assert.equal(itemIds(parade)[0], 'event:pleasanton-hometown-holiday-2026', itemIds(parade).join(', '));
  // "Are there any" is not a subject: no renter's checklist or doctor guide beside the parade.
  assert.ok(!parade.items.some(item => /move-in|doctor|uss-hornet/.test(item.id)), itemIds(parade).join(', '));
  assert.ok(itemIds(evidence('Any Cantonese film screenings in San Francisco on November 14?')).includes('event:sfpl-richmond-hk-film-hard-boiled-2026'));
  // A Chinese ask keeps the Chinese title.
  const zh = evidence('这周六东湾有什么农夫市集？');
  assert.match(zh.items.find(item => item.id === 'oakland-grand-lake-farmers-market-2026').title, /[㐀-鿿]/);
});

test('live L04: the streamed lead never shows a count, so the result does not correct it', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const { createPublicContext } = require('../lib/publicContext');
  const lead = 'No free museum days are listed for this weekend, but two free options are open that weekend [[e1]].';
  const answer = { lead, points: [{ text: 'SFMOMA public spaces are free [[e1]].', cardIds: [] }, { text: 'The Exploratorium has a free day later [[e2]].', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' };
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2', BAYBAY_STATE_SECRET: 'api-bb-5-isolated-secret-0123456789' },
    catalog: planner, guideCatalog: guides, englishGuideCatalog: guidesEn, isTest: true, now: () => Date.parse('2026-10-14T19:00:00Z'),
    ai: async (payload, options) => {
      const text = JSON.stringify(answer);
      if (options?.onText) for (let index = 0; index < text.length; index += 3) options.onText(text.slice(index, index + 3));
      return { model: 'claude-sonnet-5-5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] }] };
    } });
  const events = [];
  const result = await assistant.run({ message: 'Are there any free museum days in San Francisco this weekend?', locale: 'en', currentPath: '/en', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: '/en' }, currentPath: '/en', today: TODAY, locale: 'en' }), onDraft: event => events.push(event) });
  const drafted = events.filter(event => event.field === 'lead').map(event => event.text).join('');
  assert.ok(drafted.length > 20, drafted);
  assert.doesNotMatch(drafted, /\btwo\b/i);
  assert.doesNotMatch(result.lead, /\btwo\b/i);
  assert.equal(result.corrected, false);
});

test('area fit: a San Jose ask is not led by San Francisco museums; a BART day plan keeps places BART cannot reach behind', () => {
  const { railServes, railSystemsIn } = require('../lib/baybayTransit');
  const sanJose = evidence('我妈七十岁不会英文，住 San Jose，想找中文的老人活动和美术馆');
  const cityOf = item => item.city || item.row?.city || null;
  assert.ok(sanJose.items.filter(item => ['event', 'place'].includes(item.kind)).every(item => cityOf(item) === 'San Jose'), sanJose.items.map(item => `${item.id} ${cityOf(item)}`).join(', '));
  assert.ok(!itemIds(sanJose).some(id => /sfmoma|exploratorium/.test(id)));
  // San Francisco (or no city) still names its museums.
  assert.ok(itemIds(evidence('旧金山有什么免费博物馆')).includes('place:venue-sfmoma'));
  const bart = stateOf('帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家').state;
  assert.equal(bart.travelMode, 'transit');
  assert.ok(bart.preferences.includes('rail:bart'));
  const plan = buildFastEvidence({ query: '帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家', originalQuery: '帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家', state: bart, guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale: 'zh-Hans', audience: true });
  const rows = plan.candidates.map(row => ({ id: row.id, city: row.city }));
  assert.ok(rows.length >= 3, JSON.stringify(rows));
  for (const row of rows.slice(0, 6)) assert.ok(railServes(row.city, ['bart'], bart.date), JSON.stringify(row));
  assert.ok(!rows.some(row => /healdsburg|premium-outlets/.test(row.id)), JSON.stringify(rows));
  // The table: Livermore and Healdsburg have no BART station; Gilroy's Caltrain stop is weekday-only; driving clears the rail.
  assert.equal(railServes('Livermore', ['bart']), false); assert.equal(railServes('Healdsburg', ['bart', 'caltrain']), false);
  assert.equal(railServes('Gilroy', ['caltrain'], '2026-10-17'), false); assert.equal(railServes('Gilroy', ['caltrain'], '2026-10-16'), true);
  assert.deepEqual(railSystemsIn('不坐 BART，我们开车'), []);
  const drive = resolveTaskState({ message: '改成开车', previous: bart, today: TODAY, carry: true }).state;
  assert.ok(!drive.preferences.some(value => value.startsWith('rail:')), JSON.stringify(drive.preferences));
});
