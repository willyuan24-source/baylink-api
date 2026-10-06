const test = require('node:test');
const assert = require('node:assert/strict');
const { foodRequest, matchesFoodEvidence, foodEvidenceGap } = require('../lib/foodEvidence');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { selectConversationGuides } = require('../lib/guideConversation');
const { resolveTaskState, validateTaskState } = require('../lib/baybayState');

const TODAY = '2026-10-06';
const source = 'https://example.org/official-menu';
const guide = (slug, title, content) => ({ slug, title, content, url: `/guides/${slug}`, updatedAt: TODAY,
  sources: [{ title: 'Official menu', url: source }] });
const place = (id, title, summary, rest = {}) => ({ id, title, summary, category: 'food', region: 'sf', city: 'San Francisco',
  officialUrl: source, costLabel: 'Check the current menu and opening arrangements.', ...rest });
const catalog = (places = [], events = []) => ({ version: 1, checkedAt: TODAY, guides: [], places, events });
const search = (query, guideCatalog, supplied = catalog()) => buildSiteEvidence({ query, originalQuery: query,
  state: validateTaskState({}), guideCatalog, catalog: supplied, today: TODAY });

for (const query of ['湾区哪里饮茶', '灣區哪裡飲茶', '湾区点心推荐', '灣區點心推薦', 'Where can I get dim sum?', 'Dim-sum restaurants near me']) {
  test(`explicit food request retains its specific type: ${query}`, () => {
    assert.deepEqual(foodRequest(query), { kind: 'dim-sum' });
  });
}

test('general dining remains recognized without treating unrelated terms or negated/history/quoted mentions as requests', () => {
  for (const query of ['附近有什么好吃的', '灣區吃飯推薦', 'restaurants in San Francisco', 'Where should I eat out?']) {
    assert.deepEqual(foodRequest(query), { kind: 'dining' }, query);
  }
  for (const query of ['给朋友一点心意', '點心債券是什麼', 'What are dim sum bonds?', '点心机械在哪里买',
    '不想去饮茶，帮我找房', '不要点心，找博物馆', 'I am not looking for dim sum. Find a museum.',
    '之前问过饮茶，现在想看博物馆', 'What does the phrase "dim sum" mean?', '“點心”这个词怎么翻译',
    '餐厅租赁报税材料', '图书馆借书证和餐厅税务问题', '周六先看博物馆再吃饭', '飲茶後散步找人一起',
    'Find a museum and a restaurant for lunch']) assert.equal(foodRequest(query), null, query);
});

test('malformed optional source and plan fields do not throw or supply food proof', () => {
  const request = foodRequest('dim sum near me');
  for (const sources of [null, 'https://example.org/menu', {}, 42]) {
    assert.equal(matchesFoodEvidence({ title: 'Dim sum restaurant', summary: 'The menu lists dim sum.', sources, sourceUrls: sources, plan: sources }, request, 'place'), false);
    assert.equal(matchesFoodEvidence({ title: 'Dim sum restaurant', summary: 'The menu lists dim sum.', officialUrl: source, sources, sourceUrls: sources, plan: sources }, request, 'place'), true);
  }
});

test('specific type requires affirmative food facts and a real public source, rather than generic dining or nearby refreshments', () => {
  const request = foodRequest('哪里有点心');
  assert.equal(matchesFoodEvidence(place('restaurant-dim-sum', 'Example Restaurant', 'The official menu lists Cantonese dim sum.'), request, 'place'), true);
  assert.equal(matchesFoodEvidence(place('restaurant-cantonese', '粤式餐厅', '餐厅提供广式点心，当前菜单和营业安排需官方确认。'), request, 'place'), true);
  assert.equal(matchesFoodEvidence(place('restaurant-other', 'Seafood Restaurant', 'A seafood restaurant with indoor dining.'), request, 'place'), false);
  assert.equal(matchesFoodEvidence(place('restaurant-not-offered', 'Dim Sum Restaurant', 'Dim sum is not offered here.'), request, 'place'), false);
  assert.equal(matchesFoodEvidence(place('restaurant-pending', '餐厅', '点心待确认，请询问是否提供点心。'), request, 'place'), false);
  assert.equal(matchesFoodEvidence(place('restaurant-no-source', 'Restaurant', 'The menu lists dim sum.', { officialUrl: '' }), request, 'place'), false);
  assert.equal(matchesFoodEvidence(place('bookshop', 'Library Bookshop', 'There is a dim sum restaurant nearby.', { category: 'shopping' }), request, 'place'), false);
  assert.equal(matchesFoodEvidence({ title: 'Library Open House', summary: 'Enjoy refreshments and 点心.', officialUrl: source }, request, 'event'), false);
});

test('retrieval keeps type-specific sourced paragraphs and removes unrelated tax, housing and event cards in both paths', () => {
  const guides = [
    guide('tea', '湾区饮茶餐厅指南', `餐厅的官方菜单列出广式点心；费用与当前营业安排请向店家确认。\n${source}`),
    guide('tax', '湾区报税帮助从哪里开始', '报税前准备收入材料，不能把当地没有材料理解为没有服务。'),
    guide('housing', '湾区住哪里', '先看租房预算与通勤，附近好吃的东西不是房源可用性的证明。'),
  ];
  const supplied = catalog([
    place('restaurant-dim-sum', 'Cantonese Restaurant', 'The menu lists dim sum; current availability needs confirmation.'),
    place('restaurant-generic', 'Seafood Restaurant', 'Restaurant with seafood and indoor dining.'),
  ], [{ id: 'library', title: 'Library Open House', summary: '点心 and refreshments are offered after the talk.',
    city: 'San Francisco', region: 'sf', startDate: TODAY, endDate: TODAY, officialUrl: source, cost: 'free', costLabel: 'Free' }]);
  const before = JSON.stringify({ guides, supplied });
  for (const query of ['湾区哪里饮茶', '灣區點心推薦', 'Where can I get dim sum?']) {
    const result = search(query, guides, supplied);
    assert.ok(result.guides.length);
    assert.ok(result.guides.every(row => row.slug === 'tea'));
    assert.deepEqual(result.candidates.map(row => row.id), ['restaurant-dim-sum']);
    assert.equal(result.foodEvidence.status, 'matched');
    assert.ok(result.guides.every(row => row.verification === 'site-record' && row.verifiedLive === false));
    assert.deepEqual(selectConversationGuides(guides, query, 'other', '/', [], TODAY).map(row => row.slug), ['tea']);
  }
  assert.equal(JSON.stringify({ guides, supplied }), before, 'query precision never changes catalog facts or dates');
});

test('a distant food mention cannot lend a source or restaurant identity to an unrelated excerpt', () => {
  const guides = [guide('mixed', '湾区生活资料', `报税材料\n准备收入和身份证明。\n\n餐厅菜单\n这家餐厅官方菜单列出广式点心。\n${source}`)];
  const result = search('湾区哪里饮茶', guides);
  assert.ok(result.guides.length);
  assert.ok(result.guides.every(row => /广式点心/.test(row.text) && !/准备收入/.test(row.text)));
});

test('general dining retains published restaurants rather than library events and adjacent shops', () => {
  const supplied = catalog([
    place('restaurant-seafood', 'Pacific Seafood Restaurant', 'A seafood restaurant serving lunch and dinner.'),
    place('cafe-bakery', 'Example Bakery', 'The bakery offers bread, pastries and a cafe menu.'),
    place('shop', 'Example Bookshop', 'The bookshop is next to a restaurant.', { category: 'shopping' }),
  ], [{ id: 'recycling', title: 'Recycling open house', summary: 'Food costs extra; visit nearby restaurants.', city: 'San Francisco',
    region: 'sf', startDate: TODAY, endDate: TODAY, officialUrl: source, cost: 'free', costLabel: 'Free' }]);
  for (const query of ['附近有什么好吃的', '灣區吃飯推薦', 'restaurants near me']) {
    const result = search(query, [], supplied);
    assert.deepEqual(new Set(result.candidates.map(row => row.id)), new Set(['restaurant-seafood', 'cafe-bakery']));
    assert.equal(result.foodEvidence.status, 'matched');
  }
});

test('explicit article reading and non-food policy retrieval keep their existing scope', () => {
  const housing = guide('housing', '租房合同', '房源租约和押金要求。');
  assert.equal(selectConversationGuides([housing], '这篇文章为什么举饮茶例子', 'other', housing.url, [], TODAY)[0].slug, 'housing');
  const result = buildSiteEvidence({ query: '这篇文章里的饮茶例子', originalQuery: '这篇文章里的饮茶例子', state: validateTaskState({}),
    guideCatalog: [housing], catalog: catalog(), currentPath: housing.url, today: TODAY });
  assert.equal(result.guides[0].slug, 'housing');
  assert.equal(result.foodEvidence.status, 'needs-confirmation', 'an explicitly selected guide is context, not proof of a menu');
  assert.equal(search('湾区报税在哪里办理', [housing]).foodEvidence, undefined);
});

test('actual committed catalogs do not return unrelated records for tea/dim sum, while general restaurants remain reachable', () => {
  const guides = require('../data/guide-catalog.json'), supplied = require('../data/planner-catalog.json');
  for (const query of ['湾区哪里饮茶', '灣區點心推薦', 'Where can I get dim sum?']) {
    const result = buildSiteEvidence({ query, originalQuery: query, state: resolveTaskState({ message: query, today: TODAY, catalog: supplied }).state,
      guideCatalog: guides, catalog: supplied, today: TODAY });
    assert.ok(result.guides.every(row => matchesFoodEvidence(row, foodRequest(query))));
    assert.ok(result.candidates.every(row => matchesFoodEvidence(row, foodRequest(query), row.kind)));
    assert.ok(result.guides.every(row => !/tax|where-to-live|first-rental/.test(row.slug)));
    assert.ok(result.candidates.every(row => !/library|sfpl|state-of-city|recycling|bingo/.test(row.id)));
    if (!result.guides.length && !result.candidates.length) assert.equal(result.foodEvidence.status, 'needs-confirmation');
  }
  const dining = search('湾区吃饭推荐', guides, supplied);
  assert.ok(dining.candidates.some(row => row.id === 'restaurant-pacific-catch-mountain-view'
    || row.id === 'opening-yutori-palo-alto-restaurant' || row.id === 'restaurant-farmshop-marin'));
  assert.ok(dining.candidates.every(row => matchesFoodEvidence(row, { kind: 'dining' }, row.kind)));
});

test('a missing specific match exposes bounded three-language next steps without a site-wide absence or availability claim', () => {
  const result = search('哪里有点心', [], catalog([place('restaurant-generic', 'Restaurant', 'A seafood restaurant.')]));
  assert.deepEqual(result.foodEvidence, { kind: 'dim-sum', status: 'needs-confirmation', scope: 'retrieved-site-records' });
  assert.deepEqual(result.guides, []); assert.deepEqual(result.candidates, []);
  for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
    const note = foodEvidenceGap(result.foodEvidence, locale);
    assert.match(note, locale === 'en' ? /retrieved in this turn/ : /本[轮輪]/);
    assert.match(note, locale === 'en' ? /does not confirm|do not confirm/ : /不能[证證]明/);
    assert.match(note, locale === 'en' ? /Which city|named restaurant/ : /哪[个個]城市|哪家店/);
    assert.match(note, locale === 'en' ? /not a claim that no options exist/ : /不[表]示全站或[当當]地[没沒]有/);
  }
});
