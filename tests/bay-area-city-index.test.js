const test = require('node:test');
const assert = require('node:assert/strict');
const aliases = require('../data/city-search-aliases.json');
const { loadPlannerCatalog } = require('../lib/planner');
const { canonicalCity, mentionedCities, normalizeCityMentions } = require('../lib/bayAreaSearchScope');

// Retain the previous matching semantics as an independent compatibility oracle:
// dictionary order, Latin boundaries, nested city names and Unicode accents all
// affect the geography guard, not merely search relevance.
const normalize = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
const cities = new Map(Object.entries(aliases).map(([city, names]) => [city, new Set([city, city.replace(/\s+/g, ''), ...names, ...(city === 'San Jose' ? ['San José'] : [])])]));
const catalog = loadPlannerCatalog();
for (const row of [...catalog.events, ...catalog.places]) for (const city of String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/)) {
  if (city && !/bay area|湾区|灣區/i.test(city) && !cities.has(city)) cities.set(city, new Set([city]));
}
function prior(text) {
  text = String(text || '').replace(/San Francisco Bay Area|旧金山湾区|舊金山灣區/gi, ' Bay Area ');
  const matches = [];
  for (const [city, names] of cities) for (const name of names) {
    const pattern = new RegExp(`${/^[a-z]/i.test(name) ? '(?<![a-z])' : ''}${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${/[a-z]$/i.test(name) ? '(?![a-z])' : ''}`, 'giu');
    for (const match of text.matchAll(pattern)) matches.push({ city, start: match.index, end: match.index + match[0].length });
  }
  const found = [...new Map(matches.filter(item => !matches.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start)).map(item => [`${item.start}:${item.end}`, item])).values()];
  const names = [...new Set(found.map(item => item.city))];
  for (const item of found.sort((a, b) => b.start - a.start)) text = text.slice(0, item.start) + item.city + text.slice(item.end);
  return { names, text };
}

test('compiled city lookup preserves every published alias and first-match precedence', () => {
  for (const [, names] of cities) for (const name of names) {
    const expected = [...cities].find(([, values]) => [...values].some(value => normalize(value) === normalize(name)))?.[0] || null;
    assert.equal(canonicalCity(` ${name.toUpperCase()} `), expected, name);
  }
  for (const value of [null, undefined, '', 'New York', 'Fremont Library Illinois', 'NotSanJose']) assert.equal(canonicalCity(value), null);
});

test('compiled city matchers retain longest-name and boundary behavior across repeated multilingual queries', () => {
  const examples = [
    '从South San Francisco去San Francisco，之后回SouthSanFrancisco。',
    'East Palo Alto / Palo Alto / San José / SANTACLARA',
    '舊金山灣區、旧金山湾区和San Francisco Bay Area不是單一城市。',
    'NotSanJose Fremontish myOaklandname；Fremont BART station。',
    '我住佛利蒙，比较SFPL和San Mateo County Libraries，排除圣荷西。',
    ...[...cities.values()].map(names => [...names].join(' · ')),
  ];
  for (let repeat = 0; repeat < 3; repeat++) for (const text of examples) {
    const expected = prior(text);
    assert.deepEqual(mentionedCities(text), expected.names, text);
    assert.equal(normalizeCityMentions(text), expected.text, text);
  }
});
