const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides, guideSourceExcerpt } = require('../lib/guideConversation');
const published = require('../data/guide-catalog.json');

test('a named offer beyond 24,000 characters remains discoverable with bounded source context', () => {
  const source = 'https://example.test/harbor-rewards';
  const title = 'Harbor Rewards: a welcome drink with a $10 purchase';
  const guide = {
    slug: 'monthly-benefits', url: '/guides/monthly-benefits', title: 'Local benefits',
    summary: 'Published terms and sources.', keywords: [], categories: ['other'],
    content: `${'General information.\n\n'.repeat(1500)}${title}\nNew members only; registration and a $10 purchase required.\nOfficial source: ${source}`,
  };
  const unrelated = {
    slug: 'harbor-walk', url: '/guides/harbor-walk', title: 'Harbor walk',
    summary: 'Waterfront sightseeing.', keywords: [], categories: ['other'], content: 'Enjoy the harbor.',
  };
  assert.ok(guide.content.indexOf(title) > 24000);
  const selected = selectConversationGuides([unrelated, guide], 'Harbor Rewards welcome drink', 'other');
  assert.equal(selected[0].slug, guide.slug);
  const excerpt = guideSourceExcerpt(selected[0], 'Harbor Rewards welcome drink');
  assert.ok(excerpt.length <= 9000);
  assert.ok(excerpt.includes(title));
  assert.ok(excerpt.includes('registration and a $10 purchase required'));
  assert.ok(excerpt.includes(source));
});

test('all nine September refresh benefits are reachable by brand with their conditions and official source', () => {
  const cases = [
    ['Noah’s 免费咖啡', '会员线上买早餐，普通咖啡随单免费', '每单限一杯', 'https://www.noahs.com/free-coffee'],
    ['Ike’s 欢迎三明治', '新会员消费满 $10，解锁欢迎三明治', '最高抵 $18', 'https://www.ikessandwich.com/rewards/rewards-faq/'],
    ['Nothing Bundt Cakes 生日', '18+ 会员凭生日券，到店领个人 Bundtlet', '18 岁及以上', 'https://www.nothingbundtcakes.com/faqs/'],
    ['Jamba 新会员', '新会员冰沙半价，第二次指定食物半价', '各用一次', 'https://www.jamba.com/about/faq'],
    ['Caltrain 青少年票', '5–18 岁乘 Caltrain，全线单程 $1、日票 $2', '普通银行卡不会自动识别青少年资格', 'https://www.caltrain.com/fares'],
    ['SFMTA 免费长者 Muni', '合资格 SF 65+ 居民可申请免费 Muni，含缆车', '不是所有长者自动免费', 'https://www.sfmta.com/vi/node/12193'],
    ['Chase Center Muni', 'Chase Center 活动票，包含当天 Muni 乘车', '不含 cable cars、BART 或 Caltrain', 'https://www.sfmta.com/fares/your-chase-center-event-ticket-your-muni-fare'],
    ['South Novato The Shop', 'South Novato 免费手作空间，缝纫修车自己动手', '未满 18 岁由监护人签署', 'https://marinlibrary.org/the-shop/'],
    ['Marin City The Lab', 'Marin City 免费创作空间，学习 3D 打印与播客', '8 岁以下须监护人陪同', 'https://marinlibrary.org/the-lab/'],
  ];
  for (const [query, title, condition, source] of cases) {
    const selected = selectConversationGuides(published, query, 'other', '/', [], '2026-09-29');
    const guide = selected.find(item => item.slug === 'bay-area-freebies-deals-2026-10');
    assert.ok(guide, `Missing refreshed benefits guide for ${query}`);
    const excerpt = guideSourceExcerpt(guide, query);
    assert.ok(excerpt.length <= 9000, query);
    for (const expected of [title, condition, source]) assert.ok(excerpt.includes(expected), `${query}: missing ${expected}`);
  }
});

test('a named offer in an expired edition stays excluded from general discovery', () => {
  const archived = {
    slug: 'benefits-2026-08', url: '/guides/benefits-2026-08', title: 'Old benefits',
    editionMonth: '2026-08', categories: ['other'],
    content: `${'General information.\n\n'.repeat(1500)}Harbor Rewards: free drink\nExpired August 31.`,
  };
  assert.deepEqual(selectConversationGuides([archived], 'Harbor Rewards', 'other', '/', [], '2026-09-29'), []);
  assert.equal(selectConversationGuides([archived], '总结这篇 Harbor Rewards', 'other', archived.url, [], '2026-09-29')[0].slug, archived.slug);
});
