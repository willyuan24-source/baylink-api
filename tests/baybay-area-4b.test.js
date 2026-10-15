// H73 (audit 10-13, BB-1013-10), API-BB-4B: the asker's area. A stated home city with no
// destination ranks nearer records first; an outing ask with no area gets a spread and one short
// question; a record the answer itself rules out is not shown as a card. $0, fixtures only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog, createPublicContext } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const { turnRules, dropExcludedCards } = require('../lib/baybayQuality');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const TODAY = '2026-10-14';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const stateOf = message => resolveTaskState({ message, today: TODAY, carry: true }).state;
const regionOf = id => planner.events.find(row => row.id === id)?.region ?? planner.places.find(row => row.id === id)?.region;

test('a Fremont family with no destination gets East Bay records first (nearest by county and region)', () => {
  const message = 'We live in Fremont with a 3-year-old. Anything fun and free this Sunday?';
  const state = stateOf(message);
  assert.equal(state.goal, 'discover');
  assert.equal(state.origin, 'Fremont');
  assert.equal(state.city, null);
  const result = buildFastEvidence({ query: message, originalQuery: message, state, guideCatalog: guidesEn, catalog: planner, discoveries, today: TODAY, locale: 'en', audience: true });
  const regions = result.candidates.map(row => regionOf(row.id));
  assert.ok(regions.length >= 2, JSON.stringify(result.candidates.map(row => row.id)));
  assert.equal(regions[0], 'east-bay', JSON.stringify(result.candidates.map(row => row.id)));
  const firstOther = regions.findIndex(region => region !== 'east-bay');
  assert.ok(firstOther === -1 || !regions.slice(firstOther).includes('east-bay'), `East Bay first: ${regions}`);
  assert.ok(!result.candidates.some(row => row.id === 'sf-sunday-streets-excelsior-oct18-2026') || regions.indexOf('sf') > regions.lastIndexOf('east-bay'));
});

test('area rules: a home city asks for nearest first; an outing ask with no area asks one short question; a named city needs neither', () => {
  const fremont = turnRules({ message: 'We live in Fremont with a 3-year-old. Anything fun and free this Sunday?', state: stateOf('We live in Fremont with a 3-year-old. Anything fun and free this Sunday?') }).join('\n');
  assert.match(fremont, /starts from "Fremont"/);
  assert.match(fremont, /nearest to it first/);
  const nowhere = turnRules({ message: '这周末带 5 岁孩子去哪玩比较好？', state: stateOf('这周末带 5 岁孩子去哪玩比较好？') }).join('\n');
  assert.match(nowhere, /No area is known/);
  assert.match(nowhere, /one short question which area/);
  const city = turnRules({ message: '这周末带 5 岁孩子在 Berkeley 去哪玩？', state: stateOf('这周末带 5 岁孩子在 Berkeley 去哪玩？') }).join('\n');
  assert.doesNotMatch(city, /No area is known|starts from/);
  // "有什么好玩的" is an outing ask; with a county it is that county's region.
  const marin = stateOf('马林县周末有什么好玩的');
  assert.equal(marin.goal, 'discover'); assert.equal(marin.region, 'north-bay');
});

// Review 10-14: "what to do / where to go" is an outing only in an outing frame; how-to questions
// and a yes/no question about one place are not discover asks.
const NOT_DISCOVER = ['What to do when the power goes out?', 'What to do if my car gets towed in San Francisco?', 'What to do after a car accident in San Jose?',
  'What to do if I lose my green card?', 'Exploratorium 好玩吗？', 'Exploratorium 好不好玩？', 'What to do with my old couch in San Jose?',
  'Where to go for a flu shot in Oakland this weekend?', '周六去哪里办驾照？',
  // Review round 3: taking a thing somewhere is an errand.
  'Where should I take my car for repairs in Oakland this Saturday?', 'Where can I take my old laptop for recycling this weekend?'];
const DISCOVER = ['我们住在 San Jose，这周六带孩子去哪儿玩好？', '我家在 Fremont，周日带 3 岁孩子去哪儿？', 'We live in San Jose. What can we do with kids this Saturday?',
  'What to do in San Jose this weekend?', 'Where should we take my parents this weekend?', 'What to do with kids in Oakland?', '这周末湾区有什么好玩的？', 'Anything fun this Sunday?',
  'Where should we take the kids this Saturday?', 'Where can we take our dog this Sunday?'];

test('outing goal: how-to and yes/no phrasings are not discover; outing phrasings are', () => {
  for (const message of NOT_DISCOVER) assert.notEqual(stateOf(message).goal, 'discover', message);
  for (const message of DISCOVER) assert.equal(stateOf(message).goal, 'discover', message);
});

test('L-AREA-2 and a Fremont 去哪儿 ask: the first candidates are in the home county or region', () => {
  const COUNTY_OF = { 'San Jose': 'south-bay', Fremont: 'east-bay' };
  for (const [message, locale] of [['我们住在 San Jose，这周六带孩子去哪儿玩好？', 'zh-Hans'], ['我家在 Fremont，周日带 3 岁孩子去哪儿？', 'zh-Hans'], ['We live in San Jose. What can we do with kids this Saturday?', 'en']]) {
    const state = stateOf(message);
    assert.equal(state.goal, 'discover', message);
    const result = buildFastEvidence({ query: message, originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
    const regions = result.candidates.slice(0, 3).map(row => regionOf(row.id));
    assert.ok(regions.length >= 2 && regions.every(region => region === COUNTY_OF[state.origin]), `${message}: ${JSON.stringify(result.candidates.map(row => [row.id, regionOf(row.id)]))}`);
    assert.match(turnRules({ message, state }).join('\n'), new RegExp(`starts from "${state.origin}"`), message);
  }
});

test('a point that rules its own record out keeps its words but loses its card', () => {
  const draft = { lead: 'L', points: [{ text: 'Coyote Hills is free [[e2]].', cardIds: ['e2'] }, { text: "Randall Museum is closed Sundays, so it won't work [[e8]].", cardIds: ['e8'] }], candidateIds: ['e2', 'e8'] };
  const sunday = dropExcludedCards(draft, { date: '2026-10-18' });
  assert.deepEqual(sunday.refs, ['e8']);
  assert.deepEqual(sunday.draft.points.map(point => point.cardIds), [['e2'], []]);
  assert.match(sunday.draft.points[1].text, /closed Sundays/);
  assert.deepEqual(sunday.draft.candidateIds, ['e2']);
  // "Closed Mondays" on a Sunday ask is a note, not an exclusion; nor is a plain "周一闭馆，周日开放".
  assert.deepEqual(dropExcludedCards({ lead: 'L', points: [{ text: 'Open Sunday; closed Mondays [[e3]].', cardIds: ['e3'] }, { text: '周一闭馆，周日开放 [[e4]]', cardIds: ['e4'] }], candidateIds: [] }, { date: '2026-10-18' }).refs, []);
  assert.deepEqual(dropExcludedCards({ lead: 'L', points: [{ text: 'Randall 周日闭馆，所以这天去不了 [[e8]]。', cardIds: ['e8'] }], candidateIds: ['e8'] }, { date: '2026-10-18' }).refs, ['e8']);
});

test('only a self-exclusion of the record drops its card (review 10-14 negatives and positives)', () => {
  const dropped = (text, date, titles = {}) => dropExcludedCards({ lead: 'L', points: [{ text: `${text} [[e1]]`, cardIds: ['e1'] }], candidateIds: ['e1'] }, { date, titleOf: ref => titles[ref] || null }).refs.length > 0;
  const SUNDAY = '2026-10-18', MONDAY = '2026-10-19';
  for (const text of ["You can't go wrong with Coyote Hills on a Sunday", "Strollers won't work on the upper trail, so bring a carrier", 'Parking is not an option on Sundays, take BART',
    '周六人多，所以不适合推婴儿车，建议周日上午去', 'Closed Sundays in winter only; open this Sunday', "Children under 3 can't go on the rides, but the petting zoo at Ardenwood is free",
    'Street parking does not work well on Sundays; take BART from Fremont', 'Free admission does not work with online tickets, so walk up',
    'Skip this one if you want something quieter; otherwise it is the best fit', '如果下雨，户外部分这天不适合，可以改去室内展区', '这天去不了的话，下周六还有一场', '周日游船不开放，湖边步道照常',
    // Review round 3: a qualified clause or a following "but" is about one part of the visit.
    "So it won't be open late, but it's perfect for a morning visit", "The trail is short, so it won't fit a full day; pair it with the farm next door",
    'It is not an option for strollers on the upper loop, but the lower loop is flat']) {
    assert.equal(dropped(text, SUNDAY, { e1: 'Ardenwood Historic Farm' }), false, text);
  }
  assert.equal(dropped('Lake Elizabeth is free to walk around; the boat rental is closed Mondays', MONDAY, { e1: 'Lake Elizabeth' }), false, 'a part of the visit beside a free statement');
  assert.equal(dropped('The boat rental is closed Mondays', MONDAY, { e1: 'Lake Elizabeth' }), false, 'a part of the visit');
  for (const [text, titles] of [["Randall Museum is closed Sundays, so it won't work", {}], ['Randall Museum is closed Sundays.', { e1: 'Randall Museum' }], ['The museum is closed on Sundays.', {}],
    ['Closed Sundays.', {}], ['它周日不开放。', {}], ['Randall 周日闭馆，所以这天去不了。', {}], ['Sunday hours were cut, so this one is not an option.', {}], ['周日闭馆。', {}],
    ["It's closed this Sunday, so skip it", {}], ["The museum is being renovated, so it won't work this Sunday.", {}]]) {
    assert.equal(dropped(text, SUNDAY, titles), true, text);
  }
});

test('end to end: the ruled-out record is not among the final cards', async () => {
  const englishGuides = require('../data/guide-catalog.en.json');
  const publicContext = createPublicContext({ guideCatalog: guides });
  let refs = null;
  const answer = context => ({ lead: 'Two nearby free options.', points: [{ text: `Option one [[${refs[0]}]].`, cardIds: [refs[0]] }, { text: `The museum is closed Sundays, so it won't work [[${refs[1]}]].`, cardIds: [refs[1]] }], candidateIds: [], followups: [], coverage: [], gap: '' });
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2', BAYBAY_STATE_SECRET: 'api-bb-4b-area-secret-0123456789abc' },
    guideCatalog: guides, englishGuideCatalog: englishGuides, now: () => Date.parse('2026-10-14T19:00:00Z'), isTest: false,
    Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) },
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body);
      const user = JSON.parse(body.messages.find(message => message.role === 'user').content.find?.(block => block.type === 'text')?.text ?? body.messages.find(message => message.role === 'user').content);
      const entities = user.evidence.filter(item => ['event', 'place', 'offer', 'opening'].includes(item.kind));
      refs = [entities[0].ref, entities[1].ref];
      const reply = { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text: JSON.stringify(answer(user)) }] };
      return { ok: true, status: 200, json: async () => reply, clone() { return this; }, text: async () => JSON.stringify(reply) };
    } });
  const result = await assistant.run({ message: 'We live in Fremont with a 3-year-old. Anything fun and free this Sunday?', locale: 'en', currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale: 'en' }) });
  assert.ok(result.research.warnings.includes('answer_excluded_card_dropped'), JSON.stringify(result.research.warnings));
  assert.equal(result.localMatches.length, 1, JSON.stringify(result.localMatches.map(card => card.id)));
});
