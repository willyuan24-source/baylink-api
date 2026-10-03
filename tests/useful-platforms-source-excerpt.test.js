const test = require('node:test');
const assert = require('node:assert/strict');
const { guideSourceExcerpt } = require('../lib/guideConversation');

const platforms = [
  ['Uber', 'uber'], ['Uber Eats', 'uber-eats'], ['Lyft', 'lyft'],
  ['Google Maps', 'google-maps'], ['Apple Maps', 'apple-maps'],
  ['Transit', 'transit'], ['511', '511'], ['Weee!', 'weee'],
  ['DoorDash', 'doordash'], ['Grubhub', 'grubhub'], ['Instacart', 'instacart'],
  ['Amazon Fresh', 'amazon-fresh'], ['Too Good To Go', 'too-good-to-go'],
  ['Yelp', 'yelp'], ['OpenTable', 'opentable'], ['Resy', 'resy'],
  ['Zillow', 'zillow'], ['Redfin', 'redfin'], ['Apartments.com', 'apartments-com'],
  ['Realtor.com', 'realtor-com'], ['Craigslist', 'craigslist'],
  ['Nextdoor', 'nextdoor'], ['Facebook Marketplace', 'facebook-marketplace'],
  ['OfferUp', 'offerup'], ['Buy Nothing', 'buy-nothing'], ['Slickdeals', 'slickdeals'],
  ['Rakuten', 'rakuten'], ['Flipp', 'flipp'], ['GasBuddy', 'gasbuddy'],
  ['DoTheBay', 'dothebay'], ['hoopla Digital', 'hoopla'], ['Watch Duty', 'watch-duty'],
  ['HungryPanda 熊猫外卖', 'hungrypanda'], ['Fantuan 饭团', 'fantuan'],
  ['Dealmoon 北美省钱快报', 'dealmoon'],
];

function fixture(language) {
  const records = platforms.map(([name, id]) => [
    `Platform: ${language === 'en' ? name.replace(/ [\u3400-\u9fff]+$/, '') : name} | ${id}`,
    'Category: food community housing deals transport | app-web',
    (language === 'en'
      ? 'Compare app coverage, fees, terms and membership conditions before use. '
      : '使用前核对平台覆盖、费用与会员条件；app coverage fees terms membership。').repeat(7),
    // Body mentions must not establish the identity of this record.
    'Other services mentioned for context: Uber, Uber Eats, HungryPanda, Fantuan, Dealmoon.',
    `Limitations: ${id}: delivery fees, account eligibility and address availability still apply.`,
    `Official sources: https://example.test/${id}/official`,
    `Conditions: https://example.test/${id}/terms`,
    'Verified: 2026-10-02',
  ].join('\n'));
  return {
    records,
    guide: {
      slug: 'bay-area-useful-apps-platforms-guide',
      content: ['Use official platform sources and compare the final cost.', ...records,
        'General advice: check account eligibility, platform fees and address coverage.'].join('\n\n'),
    },
  };
}

const selectedIds = excerpt => [...excerpt.matchAll(/^Platform: [^\r\n|]+ \| ([^\r\n]+)$/gm)].map(match => match[1]);
const recordFor = (records, id) => records.find(record => record.startsWith('Platform: ') && record.split('\n')[0].endsWith(` | ${id}`));

for (const language of ['zh', 'en']) {
  test(`${language}: every named platform preserves complete limitations and sources`, () => {
    const { guide, records } = fixture(language);
    assert.ok(guide.content.length > 9000);
    assert.ok(guide.content.indexOf(records.at(-1)) > 20000);
    for (const [name, id] of platforms) {
      for (const query of [`${name} app coverage fees terms membership`, `请问 ${id} 怎么用，有什么费用和限制？`]) {
        const excerpt = guideSourceExcerpt(guide, query);
        assert.ok(excerpt.includes(recordFor(records, id)), `${query}: whole platform record`);
        assert.deepEqual(selectedIds(excerpt), [id], `${query}: no neighboring or body-mentioned platform`);
        assert.ok(excerpt.length <= 9000);
      }
    }
  });

  test(`${language}: Chinese, spacing, punctuation and known misspellings resolve aliases`, () => {
    const { guide, records } = fixture(language);
    for (const [query, id] of [
      ['熊猫外卖', 'hungrypanda'], ['熊貓外賣', 'hungrypanda'],
      ['hungry panada 外卖费用', 'hungrypanda'], ['Hungry Panda', 'hungrypanda'],
      ['HUNGRYPANADA', 'hungrypanda'], ['饭团外卖', 'fantuan'], ['飯團', 'fantuan'],
      ['Fantuan Delivery', 'fantuan'], ['北美省钱快报', 'dealmoon'],
      ['省錢快報', 'dealmoon'], ['Uber   Eats', 'uber-eats'], ['UberEats外卖', 'uber-eats'],
      ['Ｕｂｅｒ Ｅａｔｓ', 'uber-eats'], ['Weee!', 'weee'], ['BuyNothing', 'buy-nothing'],
      ['谷歌地图', 'google-maps'], ['蘋果地圖', 'apple-maps'],
      ['FB Marketplace', 'facebook-marketplace'], ['Do The Bay', 'dothebay'],
    ]) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(excerpt.includes(recordFor(records, id)), query);
      assert.deepEqual(selectedIds(excerpt), [id], query);
    }
  });

  test(`${language}: longest names distinguish Uber from Uber Eats and comparisons retain all named platforms`, () => {
    const { guide, records } = fixture(language);
    assert.deepEqual(selectedIds(guideSourceExcerpt(guide, 'Uber Eats fees')), ['uber-eats']);
    assert.deepEqual(selectedIds(guideSourceExcerpt(guide, 'Uber fees')), ['uber']);
    for (const [query, ids] of [
      ['Compare Uber and Uber Eats fees', ['uber', 'uber-eats']],
      ['Uber Eats 和 Uber 怎么选', ['uber', 'uber-eats']],
      ['hungry panada、饭团和北美省钱快报对比费用', ['hungrypanda', 'fantuan', 'dealmoon']],
      ['Compare Apartments.com and Realtor.com housing apps', ['apartments-com', 'realtor-com']],
    ]) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.deepEqual(selectedIds(excerpt), ids);
      for (const id of ids) assert.ok(excerpt.includes(recordFor(records, id)));
      assert.ok(excerpt.length <= 9000);
    }
  });

  test(`${language}: generic requests keep whole records and do not infer aliases from substrings`, () => {
    const { guide, records } = fixture(language);
    for (const query of ['app coverage fees terms membership', 'UberX app fees', 'transitional app fees', 'call 15110 for app fees']) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(selectedIds(excerpt).length > 1, query);
      for (const id of selectedIds(excerpt)) assert.ok(excerpt.includes(recordFor(records, id)), `${query}: ${id} not truncated`);
      assert.ok(excerpt.length <= 9000);
    }
  });
}

test('short platform directories still isolate an explicitly named platform; generic short content stays unchanged', () => {
  const records = [
    'Platform: Uber | uber\nRide limitations.\nhttps://example.test/uber/terms',
    'Platform: Uber Eats | uber-eats\nFood limitations.\nhttps://example.test/eats/terms',
  ];
  const guide = { content: `Intro.\n\n${records.join('\n\n')}` };
  assert.ok(guide.content.length < 9000);
  const excerpt = guideSourceExcerpt(guide, 'Uber Eats 怎么用');
  assert.ok(excerpt.includes(records[1]));
  assert.deepEqual(selectedIds(excerpt), ['uber-eats']);
  assert.equal(guideSourceExcerpt(guide, '有哪些平台？'), guide.content);
});

test('large surrounding advice cannot consume a named record budget and CRLF records remain intact', () => {
  const target = ['Platform: Fantuan 饭团 | fantuan', 'Fee and coverage conditions. '.repeat(170),
    'https://example.test/fantuan/official', 'https://example.test/fantuan/terms'].join('\r\n');
  const unrelated = `Platform: Uber Eats | uber-eats\r\n${'app fees coverage '.repeat(320)}\r\nhttps://example.test/eats/terms`;
  const guide = { content: `Intro.\r\n\r\n${unrelated}\r\n\r\n${'Fantuan app fees coverage advice. '.repeat(180)}\r\n\r\n${target}` };
  const excerpt = guideSourceExcerpt(guide, '饭团 app fees coverage');
  assert.ok(excerpt.includes(target));
  assert.ok(!excerpt.includes('https://example.test/eats/terms'));
  assert.ok(excerpt.length <= 9000);
});

test('records that exceed the available budget are never emitted as fragments', () => {
  const target = `Platform: OfferUp | offerup\n${'Terms and important conditions. '.repeat(310)}\nhttps://example.test/last-source`;
  const excerpt = guideSourceExcerpt({ content: `Intro.\n\n${target}` }, 'OfferUp');
  assert.ok(excerpt.length <= 9000);
  assert.ok(!excerpt.includes('Platform: OfferUp'));
  assert.ok(!excerpt.includes('Terms and important conditions.'));
});

test('ordinary guides with passing platform names retain the existing behavior', () => {
  const content = 'Food apps: compare Uber Eats and Fantuan.\n\nCheck the final total.';
  assert.equal(guideSourceExcerpt({ content }, 'Fantuan'), content);
});

const catalogQueries = {
  'google-maps': '谷歌地图 离线导航',
  'apple-maps': '苹果地图 公交路线',
  'transit-app': 'Transit App Royale arrival predictions',
  clipper: 'Clipper 手机钱包 实体卡',
  'bart-official': 'BART 车站停车 怎么支付',
  'caltrain-website': 'Caltrain mobile ticket retirement',
  '511-sf-bay': '511 出行提醒',
  uber: '优步 机场接送',
  lyft: 'Lyft airport pickup',
  waymo: 'Waymo service area',
  parkmobile: 'ParkMobile parking zone',
  'hotspot-parking': 'HotSpot Parking parking fees',
  paybyphone: 'PayByPhone parking location',
  spothero: 'SpotHero reservation conditions',
  'bay-wheels': 'Lyft Bike dock return',
  fastrak: 'FasTrak express lane tolls',
  'uber-eats': 'UberEats外卖 会员配送费',
  doordash: 'Door Dash delivery fees',
  grubhub: 'Grub Hub membership',
  hungrypanda: 'hungry panada 配送范围',
  fantuan: '飯團外賣 会员费',
  weee: 'Weee! 买菜起送条件',
  instacart: 'Instacart grocery substitutions',
  'amazon-fresh': 'Amazon Fresh address availability',
  'too-good-to-go': 'TooGoodToGo pickup window',
  yelp: 'Yelp reviews sponsored listings',
  opentable: 'Open Table reservation cancellation',
  resy: 'Resy restaurant booking',
  zillow: 'Zillow Zestimate estimates',
  redfin: 'Redfin 房源估值',
  'apartments-com': 'Apartments.com rental application fees',
  'realtor-com': 'Realtor.com rental listing verification',
  craigslist: 'Craigslist 二手交易面交',
  nextdoor: 'Next Door neighborhood account',
  'facebook-marketplace': 'FB Marketplace local pickup',
  offerup: 'OfferUp 买卖见面',
  'buy-nothing': 'BuyNothing 赠送物品',
  dealmoon: '北美省钱快报 优惠码',
  slickdeals: 'Slick Deals deal alerts',
  rakuten: 'Rakuten cashback timing',
  flipp: 'Flipp weekly grocery ads',
  gasbuddy: 'Gas Buddy price freshness',
  funcheap: 'Funcheap event availability',
  dothebay: 'Do The Bay local events',
  eventbrite: 'Eventbrite event ticket refund',
  meetup: 'Meetup group membership fee',
  libby: 'Libby 图书馆电子书',
  hoopla: 'hoopla Digital library availability',
  'watch-duty': 'WatchDuty wildfire alerts',
  airnow: 'AirNow 空气质量',
  myshake: 'MyShake earthquake notifications',
  kqed: 'KQED local news',
  'sf-standard': 'SF Standard news subscription',
};

for (const [language, catalog] of [
  ['zh', require('../data/guide-catalog.json')],
  ['en', require('../data/guide-catalog.en.json')],
]) {
  const guide = catalog.find(item => item.slug === 'bay-area-useful-apps-platforms-guide');
  const records = String(guide?.content || '').split(/\n\s*\n/).filter(record => record.startsWith('Platform: '));

  test(`${language} actual catalog: all 53 identities resolve by name, ID and practical query with complete sources`, () => {
    assert.ok(guide, 'platform guide is exported');
    assert.equal(records.length, 53);
    assert.deepEqual(selectedIds(records.join('\n\n')).sort(), Object.keys(catalogQueries).sort());
    for (const record of records) {
      const [, name, id] = record.match(/^Platform: ([^\r\n|]+) \| ([^\r\n]+)\r?\n/);
      // Validate the actual exporter contract, including the limitations before
      // and the sources after the main text, rather than fixture-only IDs.
      assert.match(record, /\nCheck: /, `${id}: limitations exported`);
      assert.match(record, /\nhttps:\/\//, `${id}: official sources exported`);
      assert.match(record, /\n2026-10-02$/, `${id}: verification date exported`);
      for (const query of [name, `${id} fees coverage official sources`, catalogQueries[id]]) {
        const excerpt = guideSourceExcerpt(guide, query);
        assert.ok(excerpt.includes(record), `${language}/${id}/${query}: complete actual record`);
        assert.deepEqual(selectedIds(excerpt), [id], `${language}/${id}/${query}: only the requested platform`);
        assert.ok(excerpt.length <= 9000, `${language}/${id}: excerpt budget`);
      }
    }
  });

  test(`${language} actual catalog: overlapping transport names and multilingual comparisons preserve every selected source`, () => {
    for (const [query, ids] of [
      ['Uber Eats versus Uber', ['uber', 'uber-eats']],
      ['Bay Wheels dock locations', ['bay-wheels']],
      ['Compare Lyft Bike and Lyft', ['lyft', 'bay-wheels']],
      ['BART versus Caltrain', ['bart-official', 'caltrain-website']],
      ['熊猫外卖、饭团、北美省钱快报有什么区别？', ['hungrypanda', 'fantuan', 'dealmoon']],
      ['Google Maps 与 Apple Maps 有哪些限制', ['google-maps', 'apple-maps']],
      ['Compare Zillow, Redfin, Apartments.com and Realtor.com', ['zillow', 'redfin', 'apartments-com', 'realtor-com']],
    ]) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.deepEqual(selectedIds(excerpt), ids, query);
      for (const id of ids) assert.ok(excerpt.includes(recordFor(records, id)), `${query}: ${id} sources retained`);
      assert.ok(excerpt.length <= 9000, query);
    }
  });

  test(`${language} actual catalog: broad keyword requests respect the budget without cutting any emitted record`, () => {
    for (const query of [language === 'zh' ? '外卖 配送 会员 费用' : 'food delivery membership fees', 'grocery delivery fees membership coverage', 'events tickets library news']) {
      const excerpt = guideSourceExcerpt(guide, query);
      const ids = selectedIds(excerpt);
      assert.ok(ids.length > 0, query);
      for (const id of ids) assert.ok(excerpt.includes(recordFor(records, id)), `${query}: ${id} record intact`);
      assert.ok(excerpt.length <= 9000, query);
    }
  });
}
