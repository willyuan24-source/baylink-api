const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides, guideSourceExcerpt } = require('../lib/guideConversation');
const catalogs = {
  zh: require('../data/guide-catalog.json'),
  en: require('../data/guide-catalog.en.json'),
};

// Exercise the complete exported production catalogs: a long benefit directory
// must preserve the requested offer's price, limitations and source together.
const cases = [
  {
    query: 'Lowe’s MyLowe’s Money Days',
    source: 'https://www.lowes.com/l/shop/mylowes-money-days',
    zh: ['10/10–11', '非保证获赠', '购买条件与奖品数量尚未公开核实'],
    en: ['Oct 10–11', 'prizes not guaranteed', 'purchase requirements and quantities still need checking'],
  },
  {
    query: 'Shake Shack SCARYGOOD',
    source: 'https://shakeshack.com/blog/our-food/scary-good-deals-are-back-this-october-at-shake-shack',
    zh: ['另买至少 $10', '10/12–18 送 Single Cheeseburger', '得来速、第三方和机场'],
    en: ['Spend $10 on other food or drinks', 'Oct 12–18: Single Cheeseburger', 'No stacking, drive-through, third-party'],
  },
  {
    query: 'Wendy’s Boo Books Frosty',
    source: 'https://www.wendys.com/adoption/frosty-boo-books',
    zh: ['券册售价 $1', '须先购券册', '12/31 前兑换'],
    en: ['Buy a $1 booklet', 'no additional purchase is needed when redeeming', 'by Dec 31'],
  },
  {
    query: 'Smashburger Kids Wednesdays',
    source: 'https://smashburger.com/kids-eat-free-details',
    zh: ['周三买完整成人套餐', '购买包含主食、配餐和饮品的成人套餐', '12 岁或以下', 'San Jose–Coleman'],
    en: ['Wednesdays: A full adult meal', 'Purchase an adult entrée, side and drink', '12 or under', 'San Jose–Coleman'],
  },
  {
    query: 'MOD Pizza KEF2026 Kids Meal',
    source: 'https://modpizza.com/kids-eat-free-deal/',
    zh: ['周日买常规披萨或沙拉', '每买一份 Regular-size', '12 岁及以下', '不适用电话或第三方订单'],
    en: ['Sundays: Buy a regular pizza or salad', 'Each regular-size pizza or salad purchased', '12 or under', 'No phone orders, third-party orders'],
  },
  {
    query: 'PetSmart Meet the Spooky Pets',
    source: 'https://www.prnewswire.com/news-releases/petsmart-celebrates-halloween-with-free-in-store-events-including-new-meet-the-spooky-pets-experience-302895172.html',
    zh: ['10/18', '不承诺免费领宠物或前 50 位手提袋', '10/17、25 的另一活动'],
    en: ['Oct 18', 'does not give away pets or promise the first-50 tote', 'Oct 17 and 25'],
  },
  {
    query: 'Dunkin Monday 4X points',
    source: 'https://news.dunkindonuts.com/news/dunkin-new-menu-september-2026',
    zh: ['先在 App 激活优惠', '每人每周一限一次', '这是购买饮品后的积分奖励'],
    en: ['must activate the offer', 'Once per member each Monday', 'rewards a drink purchase with points'],
  },
];

for (const [locale, catalog] of Object.entries(catalogs)) {
  for (const item of cases) {
    test(`${locale} October 5 offer retrieval keeps terms and source: ${item.query}`, () => {
      const selected = selectConversationGuides(catalog, item.query, 'other', '/', [], '2026-10-05');
      const excerpts = selected.map(guide => guideSourceExcerpt(guide, item.query));
      assert.ok(excerpts.length, 'No relevant published guide selected');
      assert.ok(excerpts.every(excerpt => excerpt.length <= 9000), 'Model excerpt exceeds its source budget');
      const expected = [...item[locale], item.source];
      assert.ok(excerpts.some(excerpt => expected.every(value => excerpt.includes(value))),
        `No single selected excerpt contains the offer constraints and official source: ${expected.join(' | ')}`);
    });
  }
}
