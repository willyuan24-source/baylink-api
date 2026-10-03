const test = require('node:test');
const assert = require('node:assert/strict');
const { guideSourceExcerpt } = require('../lib/guideConversation');

// The published directory's 32 names and metadata, with deterministic text so
// regressions do not depend on another checkout or future editorial changes.
const venues = [
  ['San Francisco Premium Outlets', 'Livermore | East Bay | outlet'],
  ['Great Mall', 'Milpitas | South Bay | outlet'],
  ['Gilroy Premium Outlets', 'Gilroy | South Bay | outlet'],
  ['Napa Premium Outlets', 'Napa | North Bay | outlet'],
  ['Petaluma Village Premium Outlets', 'Petaluma | North Bay | outlet'],
  ['Vacaville Premium Outlets', 'Vacaville | North Bay | outlet'],
  ['Westfield Valley Fair', 'Santa Clara | South Bay | mall'],
  ['Santana Row', 'San Jose | South Bay | lifestyle'],
  ['Stanford Shopping Center', 'Palo Alto | Peninsula | mall'],
  ['Hillsdale Shopping Center', 'San Mateo | Peninsula | mall'],
  ['Stonestown Galleria', 'San Francisco | San Francisco | mall'],
  ['Serramonte Center', 'Daly City | Peninsula | mall'],
  ['Westgate Center', 'San Jose | South Bay | mall'],
  ['The Pruneyard', 'Campbell | South Bay | lifestyle'],
  ['Town & Country Village', 'Palo Alto | Peninsula | lifestyle'],
  ['Union Square', 'San Francisco | San Francisco | district'],
  ['Japantown / Japan Center', 'San Francisco | San Francisco | district'],
  ['Fillmore Street', 'San Francisco | San Francisco | district'],
  ['Broadway Plaza', 'Walnut Creek | East Bay | lifestyle'],
  ['Stoneridge Shopping Center', 'Pleasanton | East Bay | mall'],
  ['Sunvalley Shopping Center', 'Concord | East Bay | mall'],
  ['Bay Street Emeryville', 'Emeryville | East Bay | lifestyle'],
  ['Pacific Commons', 'Fremont | East Bay | lifestyle'],
  ['City Center Bishop Ranch', 'San Ramon | East Bay | lifestyle'],
  ['Fourth Street Berkeley', 'Berkeley | East Bay | district'],
  ['South Shore Center', 'Alameda | East Bay | lifestyle'],
  ['Southland Mall', 'Hayward | East Bay | mall'],
  ['The Village at Corte Madera', 'Corte Madera | North Bay | lifestyle'],
  ['Town Center Corte Madera', 'Corte Madera | North Bay | lifestyle'],
  ['Coddingtown', 'Santa Rosa | North Bay | mall'],
  ['Santa Rosa Plaza', 'Santa Rosa | North Bay | mall'],
  ['Solano Town Center', 'Fairfield | North Bay | mall'],
];

function shoppingFixture(language) {
  const records = venues.map(([name, metadata], index) => [name, metadata,
    `${index + 1} Example Street`,
    (language === 'en'
      ? 'Check shopping stores hours transport parking directions returns and outlet policies before visiting. '
      : '购物出发前核对门店、交通、停车和退货条件；shopping stores hours transport parking directions returns outlet。').repeat(6),
    language === 'en' ? 'Parking validation applies only where posted; confirm the return trip.' : '停车验证以现场条件为准，并提前确认回程。',
    `https://example.test/venue-${index}/stores`,
    `https://example.test/venue-${index}/visit`,
    '2026-10-02',
  ].join('\n'));
  return { records, guide: { content: ['Compare total cost before shopping.', ...records,
    'General shopping advice: verify parking, directions and return conditions.'].join('\n\n') } };
}

for (const language of ['zh', 'en']) {
  test(`${language}: all 32 named shopping records remain complete under generic and mixed queries`, () => {
    const { guide, records } = shoppingFixture(language);
    assert.ok(guide.content.length > 9000);
    assert.ok(guide.content.indexOf(records.at(-1)) > 20000);
    for (const [index, [name]] of venues.entries()) {
      for (const query of [
        `${name} shopping parking directions`,
        `请问 ${name} 怎么去 parking 停车 购物 路线`,
        `${name} stores hours transport parking directions shopping returns outlet`,
      ]) {
        const excerpt = guideSourceExcerpt(guide, query);
        assert.ok(excerpt.length <= 9000, query);
        assert.ok(excerpt.includes(records[index]), `${query}: preserve the complete venue, conditions and links`);
        assert.ok(!records.some((record, other) => other !== index && excerpt.includes(record)), `${query}: exclude other venues`);
      }
    }
  });

  test(`${language}: known shopping aliases identify a venue while city-only queries stay broad`, () => {
    const { guide, records } = shoppingFixture(language);
    for (const [alias, name] of [
      ['Valley Fair', 'Westfield Valley Fair'],
      ['Stanford', 'Stanford Shopping Center'],
      ['Livermore outlets', 'San Francisco Premium Outlets'],
      ['Livermore 奥特莱斯', 'San Francisco Premium Outlets'],
      ['Japan Center', 'Japantown / Japan Center'],
    ]) {
      const excerpt = guideSourceExcerpt(guide, `${alias} shopping 停车 directions`);
      const index = venues.findIndex(([venue]) => venue === name);
      assert.ok(excerpt.includes(records[index]), alias);
      assert.equal(records.filter(record => excerpt.includes(record)).length, 1, alias);
    }
    for (const query of ['San Francisco shopping parking', 'Santa Rosa shopping parking', 'Livermore shopping parking']) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(records.filter(record => excerpt.includes(record)).length > 1, `${query}: city is not an alias for one venue`);
    }
  });

  test(`${language}: explicit comparisons retain both complete late records`, () => {
    const { guide, records } = shoppingFixture(language);
    const excerpt = guideSourceExcerpt(guide, 'Compare Santa Rosa Plaza and Solano Town Center shopping parking directions');
    assert.ok(excerpt.includes(records[30]));
    assert.ok(excerpt.includes(records[31]));
    assert.equal(records.filter(record => excerpt.includes(record)).length, 2);
    assert.ok(excerpt.length <= 9000);
  });
}

test('a large neighboring shopping record cannot consume a named venue budget', () => {
  const target = `Solano Town Center\nFairfield | North Bay | mall\n${'Specific parking restrictions and directions. '.repeat(60)}\nhttps://example.test/target`;
  const neighbor = `Santa Rosa Plaza\nSanta Rosa | North Bay | mall\n${'shopping parking directions '.repeat(240)}\nhttps://example.test/unrelated`;
  const guide = { content: `Shopping advice.\n\n${neighbor}\n\n${target}\n\n${'Check current conditions. '.repeat(100)}` };
  assert.ok(guide.content.length > 9000);
  const excerpt = guideSourceExcerpt(guide, 'Solano Town Center shopping parking directions');
  assert.ok(excerpt.includes(target));
  assert.ok(!excerpt.includes('https://example.test/unrelated'));
  assert.ok(excerpt.length <= 9000);
});

test('venue names use full boundaries and longest-name matching, not names found in descriptions', () => {
  const base = 'Great Mall\nMilpitas | South Bay | outlet\nParking conditions.\nhttps://example.test/base';
  const annex = 'Great Mall Annex\nSan Jose | South Bay | mall\nThis is separate from Great Mall.\nhttps://example.test/annex';
  const guide = { content: `Shopping advice.\n\n${base}\n\n${annex}\n\n${'General parking shopping directions. '.repeat(270)}` };
  const excerpt = guideSourceExcerpt(guide, 'Great Mall Annex shopping parking directions');
  assert.ok(excerpt.includes(annex));
  assert.ok(!excerpt.includes(base));
  const comparison = guideSourceExcerpt(guide, 'Compare Great Mall and Great Mall Annex parking');
  assert.ok(comparison.includes(base));
  assert.ok(comparison.includes(annex));
});
