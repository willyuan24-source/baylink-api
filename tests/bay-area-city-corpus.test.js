const test = require('node:test');
const assert = require('node:assert/strict');
const aliases = require('../data/city-search-aliases.json');
const { loadPlannerCatalog } = require('../lib/planner');
const { mentionedCities, normalizeCityMentions } = require('../lib/bayAreaSearchScope');

// Independent previous algorithm, exercised against both published language
// catalogs so a faster scan cannot silently weaken any geographic constraint.
const catalog = loadPlannerCatalog();
const cities = new Map(Object.entries(aliases).map(([city, names]) => [city, new Set([city, city.replace(/\s+/g, ''), ...names, ...(city === 'San Jose' ? ['San José'] : [])])]));
for (const row of [...catalog.events, ...catalog.places]) for (const city of String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/)) {
  if (city && !/bay area|湾区|灣區/i.test(city) && !cities.has(city)) cities.set(city, new Set([city]));
}
const matchers = [...cities].flatMap(([city, names]) => [...names].map(name => ({ city, pattern: new RegExp(`${/^[a-z]/i.test(name) ? '(?<![a-z])' : ''}${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${/[a-z]$/i.test(name) ? '(?![a-z])' : ''}`, 'giu') })));
function previous(value) {
  let text = String(value || '').replace(/San Francisco Bay Area|旧金山湾区|舊金山灣區/gi, ' Bay Area ');
  const matches = matchers.flatMap(({ city, pattern }) => [...text.matchAll(pattern)].map(match => ({ city, start: match.index, end: match.index + match[0].length })));
  const found = [...new Map(matches.filter(item => !matches.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start)).map(item => [`${item.start}:${item.end}`, item])).values()];
  const names = [...new Set(found.map(item => item.city))];
  for (const item of found.sort((a, b) => b.start - a.start)) text = text.slice(0, item.start) + item.city + text.slice(item.end);
  return { names, text };
}

test('single-scan city matching preserves both complete editorial catalogs and Unicode boundaries', () => {
  const guides = [...require('../data/guide-catalog.json'), ...require('../data/guide-catalog.en.json')];
  const texts = [...guides.map(guide => `${guide.title}\n${guide.content}`),
    ...[...cities.values()].map(names => [...names].join('')),
    'ſan Joſé and ſan Joſe; Kensington and Kensington; Oaklandſ and ſOakland; SFPL SMCL SF; South San Francisco San Francisco East Palo Alto Palo Alto',
  ];
  for (const text of texts) {
    const expected = previous(text);
    assert.deepEqual(mentionedCities(text), expected.names, text.slice(0, 180));
    assert.equal(normalizeCityMentions(text), expected.text, text.slice(0, 180));
  }
});
