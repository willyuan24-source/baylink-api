const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createPublicContext } = require('../lib/publicContext');
const { loadPlannerCatalog } = require('../lib/planner');

const DAY = '2026-10-06', NOW = Date.parse(`${DAY}T19:00:00Z`);
const final = (answer, candidateIds = []) => ({ status: 'completed', model: 'final-card-fixture', output: [{ type: 'message', role: 'assistant',
  content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds, followups: [] }) }] }] });
const invoke = (name, args) => ({ status: 'completed', output: [{ type: 'function_call', name, call_id: `final-cards-${name}`, arguments: JSON.stringify(args) }] });
const event = (id, extra = {}) => ({ id, title: `San Francisco walk event ${id}`, summary: 'A published San Francisco walking outing.',
  city: 'San Francisco', region: 'sf', startDate: '2026-10-10', endDate: '2026-10-10', officialUrl: `https://example.org/events/${id}`,
  cost: 'free', audience: [], plan: [], ...extra });
const place = id => ({ id, title: `Public Park ${id}`, summary: 'A San Francisco outdoor park for walks.', city: 'San Francisco', region: 'sf',
  officialUrl: `https://example.org/parks/${id}`, guideSlug: `park-${id}`, cost: 'free', durationMinutes: 60 });
const catalog = (events = [], places = []) => ({ version: 1, checkedAt: DAY, events, places, guides: [] });
const options = extra => ({ config: { JWT_SECRET: 'isolated-final-card-fixture-secret' }, catalog: catalog(), guideCatalog: [], isTest: true, now: () => NOW,
  webSearch: async () => { throw new Error('External requests are forbidden in final-card tests'); }, ...extra });
const publicCards = result => result.localMatches.map(({ kind, id }) => `${kind}:${id}`);

test('the real walk question drops initial concert/festival cards after citing the two actual walk guides', async () => {
  const guideCatalog = require('../data/guide-catalog.json');
  const initialCards = [];
  let calls = 0;
  const assistant = createBayBayAssistant(options({ catalog: loadPlannerCatalog(), guideCatalog, ai: async payload => {
    if (!calls++) return invoke('search_site', { query: 'Presidio Tunnel Tops Chinatown North Beach walk' });
    const toolResult = payload.input.find(row => row.type === 'function_call_output');
    const context = JSON.parse(toolResult ? toolResult.output : payload.input[0].content);
    const refs = ['/guides/presidio-picnic-day-guide', '/guides/sf-chinatown-north-beach-walk-guide']
      .map(url => (context.sources || context.evidence).find(source => source.url === url));
    assert.ok(refs.every(Boolean));
    return final(`Presidio Tunnel Tops and Chinatown to North Beach are two site-record walk options. Confirm opening arrangements and any venue fees. [[${refs[0].id}]] [[${refs[1].id}]]`);
  } }));
  const result = await assistant.run({ message: '旧金山适合周末散步的两个站内去处，分别是什么？请给资料来源，并把没有核实的开放时间和费用说清楚。',
    searchMode: 'site', locale: 'zh-Hans', onQuickCard: cards => initialCards.push(...cards) });
  assert.equal(calls, 2); assert.equal(result.degraded, false, JSON.stringify(result.research.warnings));
  assert.ok(initialCards.some(card => card.id === 'sf-journey-final-frontier-november-2026'));
  assert.ok(initialCards.some(card => /presidio/.test(card.id)));
  assert.deepEqual(result.localMatches, []);
  assert.deepEqual(result.sources.map(source => source.url), ['/guides/presidio-picnic-day-guide', '/guides/sf-chinatown-north-beach-walk-guide']);
});

test('actual final citations and valid selected identities keep the matching event cards only', async () => {
  const events = [event('a'), event('b'), event('c')];
  for (const useSelection of [false, true]) {
    const assistant = createBayBayAssistant(options({ catalog: catalog(events), ai: async payload => {
      const context = JSON.parse(payload.input[0].content);
      const source = context.evidence.find(row => row.url === events[1].officialUrl);
      assert.ok(source);
      return useSelection ? final('Option b is a catalog lead; its current arrangements need confirmation.', ['b', 'origin', 'invented-id'])
        : final(`The published walk event b is a lead; confirm its current arrangements. [[${source.id}]]`);
    } }));
    const result = await assistant.run({ message: 'San Francisco walking options', locale: 'en', searchMode: 'site' });
    assert.deepEqual(publicCards(result), ['event:b']); assert.equal(result.degraded, false);
  }
});

test('a shared institution source or shared guide URL cannot support every event/place card', async () => {
  const shared = 'https://example.org/institution';
  const events = [event('a', { officialUrl: shared }), event('b', { officialUrl: shared }), event('c')];
  const assistant = createBayBayAssistant(options({ catalog: catalog(events), ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    return final(`The institution publishes general information; no particular event has been selected. [[${context.evidence.find(row => row.url === shared).id}]]`);
  } }));
  assert.deepEqual((await assistant.run({ message: 'San Francisco walking options', locale: 'en', searchMode: 'site' })).localMatches, []);

  const guide = { slug: 'shared-parks', title: 'San Francisco parks', url: '/guides/shared-parks', content: 'San Francisco park walking options require individual venue confirmation.', updatedAt: DAY };
  const sharedPlaces = [place('a'), place('b')].map(row => ({ ...row, guideSlug: guide.slug }));
  const placesAssistant = createBayBayAssistant(options({ catalog: catalog([], sharedPlaces), guideCatalog: [guide], ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    return final(`This guide describes parks in general, rather than selecting a specific venue. [[${context.evidence.find(row => row.url === guide.url).id}]]`);
  } }));
  assert.deepEqual((await placesAssistant.run({ message: 'San Francisco park walking options', locale: 'en', searchMode: 'site' })).localMatches, []);
});

test('final plan stops control cards even when a rejected initial stop is cited', async () => {
  let calls = 0;
  const places = [place('a'), place('b'), place('c')];
  const assistant = createBayBayAssistant(options({ catalog: catalog([], places), ai: async payload => {
    if (!calls++) return invoke('create_plan', { candidateIds: ['a', 'b', 'c'] });
    const context = JSON.parse(payload.input[0].content);
    const rejected = context.evidence.find(row => row.url === places[2].officialUrl);
    return final(`Keep the first two parks; the third park is not in the final route. [[${rejected.id}]]`, ['a', 'b']);
  } }));
  const result = await assistant.run({ message: '2026-10-10 San Francisco 安排一天', locale: 'en', searchMode: 'site' });
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['a', 'b']);
  assert.deepEqual(publicCards(result), ['guide:park-a', 'guide:park-b']);
});

test('an actually cited current guide remains a card without treating unrelated selected context as a recommendation', async () => {
  const guide = { slug: 'walk-notes', title: 'Walking notes', url: '/guides/walk-notes', content: 'The published walking notes recommend checking the venue schedule.', updatedAt: DAY };
  const ref = { kind: 'guide', id: guide.slug, title: guide.title, url: guide.url, summary: guide.content };
  const unrelated = { kind: 'event', id: 'other-meeting', title: 'Other meeting', url: '/events/other-meeting', temporalStatus: 'current' };
  const pageContext = { contextReferences: [ref, unrelated], contextUsed: { references: [{ kind: 'guide', id: ref.id }, { kind: 'event', id: unrelated.id }], notices: [] } };
  const assistant = createBayBayAssistant(options({ guideCatalog: [guide], ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    return final(`Use this guide's published notes, with current schedules still unverified. [[${context.evidence.find(row => row.url === guide.url).id}]]`);
  } }));
  const result = await assistant.run({ message: 'Explain this walking guide', currentPath: guide.url, pageContext, locale: 'en', searchMode: 'site' });
  assert.deepEqual(result.localMatches, [ref]); assert.deepEqual(result.nextSteps, []);
  assert.deepEqual(result.contextReferences, pageContext.contextReferences); assert.deepEqual(result.contextUsed, pageContext.contextUsed);
  assert.ok(result.evidence.some(row => row.url.endsWith(unrelated.url)));
});

test('without a model draft, fallback retains the resolved public context and initial reference cards', async () => {
  const events = [event('a'), event('b')], inputCatalog = catalog(events);
  const pageContext = createPublicContext({ catalog: inputCatalog }).resolve({ currentPath: '/events/a', today: DAY, locale: 'en' });
  const frames = [];
  const assistant = createBayBayAssistant(options({ catalog: inputCatalog }));
  const result = await assistant.run({ message: 'San Francisco walking options', pageContext, locale: 'en', searchMode: 'site', onQuickCard: cards => frames.push(cards) });
  assert.equal(result.degraded, true); assert.deepEqual(result.localMatches, frames[0]);
  assert.deepEqual(result.contextReferences, pageContext.contextReferences); assert.deepEqual(result.contextUsed, pageContext.contextUsed);
  assert.equal(result.nextSteps[0].references[0].id, 'a');
});

test('a destination-count clarification keeps the original public cards without invoking synthesis', async () => {
  const frames = [];
  let calls = 0;
  const assistant = createBayBayAssistant(options({ catalog: catalog([], [place('a'), place('b'), place('c')]),
    ai: async () => { calls++; throw new Error('A clarification must not invoke the model'); } }));
  const result = await assistant.run({ message: '2026-10-10 San Francisco 安排一天，想去 Public Park a、Public Park b、Public Park c，最多2站',
    locale: 'zh-Hans', searchMode: 'site', onQuickCard: cards => frames.push(cards) });
  assert.equal(calls, 0); assert.equal(result.assistantPlan, undefined); assert.match(result.answer, /指定的地点超过/);
  assert.equal(frames[0].length, 3); assert.deepEqual(result.localMatches, frames[0]);
});
