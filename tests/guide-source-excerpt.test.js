const test = require('node:test');
const assert = require('node:assert/strict');
const { guideSourceExcerpt } = require('../lib/guideConversation');

const catalogs = {
  zh: require('../data/guide-catalog.json'),
  en: require('../data/guide-catalog.en.json'),
};
const directory = language => catalogs[language].find(guide => guide.slug === 'bay-area-city-utilities-internet-phone-directory');
const cityRecord = (guide, county, city) => {
  const record = guide.content.split(/\n\s*\n/).find(block => block.startsWith(`${county}\n${city}\n`));
  assert.ok(record, `Published directory must contain ${county}/${city}`);
  return record;
};

for (const language of ['zh', 'en']) {
  test(`${language}: later city contacts survive generic utility terms and the source budget`, () => {
    const guide = directory(language);
    const rioVista = cityRecord(guide, 'Solano', 'Rio Vista');
    const vallejo = cityRecord(guide, 'Solano', 'Vallejo');
    assert.ok(guide.content.indexOf(rioVista) > 24000);
    assert.ok(guide.content.indexOf(vallejo) > 24000);
    for (const [query, record, phone, url] of [
      ['Rio Vista water utility contact', rioVista, '707-374-6451', 'https://www.riovistacity.com/finance/page/i-am-owner-0'],
      ['请帮我找 Rio Vista 水电开户 water utility electricity garbage internet moving service contact 电话', rioVista, '707-374-6451', 'https://mdrr.com/rio-vista/'],
      ['Vallejo 水费开户 water utility contact', vallejo, '707-648-4345', 'https://www.vallejo.gov/our_city/departments_divisions/water_department'],
    ]) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(excerpt.length <= 9000, query);
      assert.ok(excerpt.includes(record), `${query}: preserve the full city record, including provider conditions`);
      assert.ok(excerpt.includes(phone), query);
      assert.ok(excerpt.includes(url), query);
      assert.doesNotMatch(excerpt, /(?:^|\n)Solano\n(?:Fairfield|Suisun City|Vacaville)\n/, 'adjacent cities are not context for this address');
      assert.doesNotMatch(excerpt, /(?:^|\n)San Francisco\nSan Francisco\n/, 'the introduction must not leak the first city record');
    }
  });

  test(`${language}: complete city names and aliases distinguish overlapping municipalities`, () => {
    const guide = directory(language);
    const sf = cityRecord(guide, 'San Francisco', 'San Francisco');
    const southSf = cityRecord(guide, 'San Mateo', 'South San Francisco');
    const paloAlto = cityRecord(guide, 'Santa Clara', 'Palo Alto');
    const eastPaloAlto = cityRecord(guide, 'San Mateo', 'East Palo Alto');
    for (const [query, wanted, excluded] of [
      ['South   San Francisco water utility contact', southSf, sf],
      ['南旧金山 water 开户', southSf, sf],
      ['SF water utility contact', sf, southSf],
      ['旧金山 水电客服电话', sf, southSf],
      ['Palo Alto water utility contact', paloAlto, eastPaloAlto],
      ['帕洛阿尔托 水电开户', paloAlto, eastPaloAlto],
      ['East Palo Alto 水费 utility contact', eastPaloAlto, paloAlto],
      ['East PA water utility contact', eastPaloAlto, paloAlto],
      ['东帕洛阿尔托 water 联系方式', eastPaloAlto, paloAlto],
    ]) {
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(excerpt.length <= 9000, query);
      assert.ok(excerpt.includes(wanted), `${query}: missing the requested city's complete contacts`);
      assert.ok(!excerpt.includes(excluded), `${query}: included contacts from a different city`);
    }
  });

  test(`${language}: explicit comparisons keep both cities and named carrier contacts remain available`, () => {
    const guide = directory(language);
    const excerpt = guideSourceExcerpt(guide, 'Compare Palo Alto and East Palo Alto water utility contacts');
    assert.ok(excerpt.includes(cityRecord(guide, 'Santa Clara', 'Palo Alto')));
    assert.ok(excerpt.includes(cityRecord(guide, 'San Mateo', 'East Palo Alto')));
    assert.ok(excerpt.length <= 9000);
    const carrier = guideSourceExcerpt(guide, 'Rio Vista Verizon Wireless phone contact');
    assert.ok(carrier.includes(cityRecord(guide, 'Solano', 'Rio Vista')));
    assert.match(carrier, /Verizon Wireless\n800-922-0204\n/);
    assert.ok(carrier.includes('https://www.verizon.com/support/contact-us'));
    assert.ok(carrier.length <= 9000);
  });
}

test('a large neighboring city cannot consume the budget ahead of the requested city', () => {
  const target = 'Solano\nRio Vista\nWater: Example municipal water\n707-000-0001\nContact: https://example.test/rio-vista';
  const unrelated = `Solano\nFairfield\nWater: Other provider\n${'water utility contact electricity garbage internet '.repeat(160)}`;
  const guide = { content: `Moving checklist: confirm the full address.\n\n${unrelated}\n\n${target}\n\n${'General advice. '.repeat(300)}` };
  assert.ok(guide.content.length > 9000);
  const excerpt = guideSourceExcerpt(guide, 'Rio Vista water utility contact electricity garbage internet');
  assert.ok(excerpt.includes(target));
  assert.ok(!excerpt.includes('Water: Other provider'));
  assert.ok(excerpt.includes('Moving checklist: confirm the full address.'));
  assert.ok(excerpt.length <= 9000);
});
