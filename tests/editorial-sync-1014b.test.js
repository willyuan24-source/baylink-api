const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

// API-SYNC-3a from web c10a856b (CNT-HOTFIX-2, web PR #41, merged as web main 55f607e0 with the same tree): what the synced
// catalogs change for BayBay's fast evidence. Production loaders and the shipped data files with a fixed day; no model, no
// network. A later sync that changes one of these rows on purpose updates the pin from the web data, which is the source of truth.
const TODAY = '2026-10-14'; // Wednesday, so "this weekend" is 10/17-10/18
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const evidence = (message, locale = 'zh-Hans') => {
  const { state } = resolveTaskState({ message, today: TODAY, carry: true });
  return buildFastEvidence({ query: message, originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
};
const candidate = (result, id) => (result.candidates || []).find(row => row.id === id);
const listed = result => (result.candidates || []).map(row => `${row.id}(${row.cost})`).join(', ');

test('BORP: both official start times and the arrive-by-15:00 advice reach the evidence (H59)', () => {
  const id = 'berkeley-borp-adaptive-sports-expo-oct17-2026';
  for (const [message, locale] of [['10月17日伯克利 BORP 无障碍体育体验日的社区庆祝几点开始', 'zh-Hans'], ['What time does the BORP community celebration in Berkeley start on October 17?', 'en']]) {
    const result = evidence(message, locale);
    const row = candidate(result, id);
    assert.ok(row, `${message}: ${listed(result)}`);
    assert.equal(row.cost, 'free', message);
    assert.match(row.dateLabel, /社区庆祝 15:00 或 15:30 起，建议 15:00 前到/, message);
    assert.doesNotMatch(row.dateLabel, /社区庆祝 15:30–17:30/, message);
    const item = result.items.find(entry => entry.kind === 'event' && entry.id === id);
    assert.ok(item, message);
    assert.ok(item.text.includes('社区庆祝 15:00 或 15:30 起，建议 15:00 前到'), `${message}: ${item.text.slice(0, 200)}`);
  }
});

test('library programmes free by their system\'s policy become free candidates (H69)', () => {
  const millbrae = evidence('这周末 Millbrae 有什么免费的亲子活动');
  const storytime = candidate(millbrae, 'smcl-millbrae-chinese-storytime-oct-2026');
  assert.ok(storytime, listed(millbrae));
  assert.equal(storytime.cost, 'free');
  assert.match(storytime.costLabel, /^图书馆活动免费/);

  const marin = evidence('11月14日 Marin 有什么免费活动');
  for (const id of ['marin-bolinas-saturday-crafts-nov14-2026', 'marin-point-reyes-librito-concert-2026', 'marin-corte-madera-quiltmaking-talk-2026']) {
    assert.equal(candidate(marin, id)?.cost, 'free', `${id}: ${listed(marin)}`);
  }

  const english = evidence('Free library events in San Mateo County this weekend', 'en');
  assert.equal(candidate(english, 'smcl-millbrae-chinese-storytime-oct-2026')?.cost, 'free', listed(english));
});

test('SSA: "ten years of residence is not 40 work credits" reaches the evidence in zh and en', () => {
  const asks = [
    ['我在美国住满十年了，是不是就能领社安退休金？', 'zh-Hans', '在美国住满十年不等于有了 40 个积分'],
    ['社安退休金要多少个工作积分', 'zh-Hans', '在美国住满十年不等于有了 40 个积分'],
    ['I have lived in the US for ten years. Can I get Social Security retirement benefits?', 'en', 'ten years of living in the U.S. is not the same as 40 credits'],
  ];
  for (const [message, locale, line] of asks) {
    const items = evidence(message, locale).items.filter(item => /social-security/.test(item.id));
    assert.ok(items.length, message);
    assert.ok(items.some(item => (item.text || '').includes(line)), message);
  }
});

// Ranking gaps the 26 newly free programmes exposed (not caused by the sync), closed by API-BB-4B: a Chinese-language
// programme is not displaced by generic free events on a Chinese ask, and a county-scoped outing ask is that county's region.
test('a Chinese-community SF film stays a candidate for a free SF library ask on Saturday', () => {
  const result = evidence('这周六旧金山图书馆有什么免费活动');
  assert.ok(candidate(result, 'sfpl-richmond-hk-film-the-killer-2026'), listed(result));
});

test('a San Mateo County library ask ranks that county first', () => {
  const result = evidence('这周末圣马刁县图书馆有什么免费活动');
  const regions = (result.candidates || []).map(row => planner.events.find(event => event.id === row.id)?.region);
  assert.ok(candidate(result, 'san-bruno-dia-de-los-muertos-2026'), listed(result));
  const firstOther = regions.findIndex(region => region !== 'peninsula');
  assert.ok(regions.includes('peninsula') && (firstOther === -1 || !regions.slice(firstOther).includes('peninsula')), listed(result));
});
