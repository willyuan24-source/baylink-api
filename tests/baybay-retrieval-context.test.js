const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { resolveTaskState } = require('../lib/baybayState');
const { loadPlannerCatalog } = require('../lib/planner');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const guideCatalog = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const TODAY = '2026-10-04';
const QUESTION = '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。';
const notes = [
  ['SFPL：Kanopy 与 Discover & Go 资格分别核对', '加州居民可免费申请 SFPL 卡', 'https://sfpl.org/research-learn/elibrary/bay-beats-movies-tv'],
  ['SMCL：Kanopy 每月额度与馆票是两套条件', '每月 30 tickets', 'https://smcl.org/resources-types/evideos/'],
  ['AC Library：先分清实体卡、eCard 与影音入口', '本次未找到 AC 卡适用的 Kanopy 官方入口', 'https://aclibrary.org/movies-tv/'],
];

test('the real resolved multi-service question retains all scoped notes despite an inferred arts topic', () => {
  const { state } = resolveTaskState({ message: QUESTION, catalog, today: TODAY });
  assert.equal(state.goal, 'information'); assert.equal(state.city, null); assert.equal(state.origin, 'Fremont');
  const result = buildSiteEvidence({ query: QUESTION, state, guideCatalog, catalog, today: TODAY });
  assert.ok(result.guides.length <= 8);
  for (const [heading, fact, url] of notes) {
    const paragraph = result.guides.find(row => row.sectionHeading === heading);
    assert.ok(paragraph, heading); assert.ok(paragraph.text.includes(fact), fact);
    assert.equal(paragraph.sourceUrls[0].url, url);
    assert.equal(paragraph.verifiedLive, false); assert.equal(paragraph.verification, 'site-record');
    assert.ok(paragraph.requestedTopics.includes('films'));
  }
  const allText = result.guides.map(row => row.text).join('\n');
  assert.match(allText, /10 页黑白/); assert.match(allText, /每天最多 25 页/);
  assert.match(allText, /上述馆票限制不能直接套到影音或打印/);
  const withoutBroadTopic = buildSiteEvidence({ query: QUESTION, state: { ...state, topic: null }, guideCatalog, catalog, today: TODAY });
  assert.deepEqual(result.guides.map(row => row.evidenceId), withoutBroadTopic.guides.map(row => row.evidenceId));
  // Locale rewriting translates “Library/Libraries” inside institution names.
  // The original query must still identify those providers for facet coverage.
  const localized = buildSiteEvidence({ query: normalizeGuideQuery(QUESTION), originalQuery: QUESTION, state, guideCatalog, catalog, today: TODAY });
  for (const [heading] of notes) assert.ok(localized.guides.some(row => row.sectionHeading === heading), heading);
});

test('the actual first model payload retains the separate card, film and pass qualification paragraphs', async () => {
  let first;
  const assistant = createBayBayAssistant({
    config: { JWT_SECRET: 'retrieval-context-test-secret-only' }, guideCatalog, catalog, isTest: true,
    now: () => Date.parse('2026-10-04T19:00:00Z'),
    ai: async payload => {
      const context = JSON.parse(payload.input[0].content); first ||= context;
      return { status: 'completed', model: 'retrieval-context-fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({
        answer: `各服务的资格需分开核对；这里是站内资料快照。 [[${context.evidence.find(row => row.kind === 'guide').id}]]`, candidateIds: [], followups: [],
      }) }] }] };
    },
    webSearch: async () => { throw new Error('This test must never call the network'); },
  });
  await assistant.run({ message: QUESTION, locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(first.state.city, null);
  const text = first.evidence.filter(row => row.kind === 'guide').map(row => row.text).join('\n');
  for (const [heading, fact] of notes) { assert.ok(text.includes(heading), heading); assert.ok(text.includes(fact), fact); }
  assert.match(text, /10 页黑白/); assert.match(text, /每天最多 25 页/);
  assert.match(text, /上述馆票限制不能直接套到影音或打印/);
});

test('explicit multi-topic retrieval takes precedence without dropping topic context from short follow-ups', () => {
  const empty = { version: 1, checkedAt: TODAY, events: [], places: [], guides: [] };
  const localGuides = [
    { slug: 'arts', title: 'Bay Area arts information', content: 'Museum ticket prices and opening hours depend on the exhibition. Arts visitors should consult the gallery before planning a visit.' },
    { slug: 'water', title: 'Bay Area water information', content: 'Water utility opening hours and fees depend on the service office. Water account customers should consult their supplier before visiting.' },
  ];
  const retrieve = (query, topic) => buildSiteEvidence({ query, state: { goal: 'information', topic }, guideCatalog: localGuides, catalog: empty, today: TODAY }).guides;
  const question = 'Compare ticket prices, opening hours and public transit for these services.';
  assert.deepEqual(retrieve(question, 'arts').map(row => row.evidenceId), retrieve(question, null).map(row => row.evidenceId));
  assert.equal(retrieve('What else?', 'arts')[0]?.slug, 'arts');
  assert.equal(retrieve('What else?', null).length, 0);
});
