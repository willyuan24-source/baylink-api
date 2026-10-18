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
// API-SYNC-3g (web #48): the library starter guide's new pass paragraph ("旧金山 · SFPL Discover & Go …", with Marin's and
// San Mateo County's passes) now takes the slot of the perks guide's scoped SFPL note. SFPL's facts stay in the eight rows
// through the October edition's SFPL Kanopy card (a CA resident can get a free SFPL card; the Kanopy entry) and the
// pass rules (SFPL needs SF residents); keeping the scoped note itself is the TODO below.
const SFPL_SCOPED_NOTE = 'SFPL：Kanopy 与 Discover & Go 资格分别核对';
const notes = [
  ['SFPL · KANOPY：用 SFPL 图书证，在家免费看片', '加州居民可免费办 SFPL 卡', 'https://sfpl.org/research-learn/elibrary/bay-beats-movies-tv'],
  ['SMCL：Kanopy 每月额度与馆票是两套条件', '每月 30 tickets', 'https://smcl.org/resources-types/evideos/'],
  ['AC Library：先分清实体卡、eCard 与影音入口', 'AC Library 官网没有列出 AC 卡可用的 Kanopy 入口', 'https://aclibrary.org/movies-tv/'],
];
const SFPL_PASSES = /SFPL 需 SF 居民/;

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
  assert.match(allText, SFPL_PASSES);
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
  assert.match(text, SFPL_PASSES);
});

// API-BB-9 (API-SYNC-3g follow-up): on web #48's catalog the library starter guide's pass paragraph ("旧金山 · SFPL
// Discover & Go：旧金山市县居民…") outranks the perks guide's scoped SFPL note for this Fremont ask. Its scope now names
// SFPL (the place label before the acronym is not the institution), so the SF-residence restriction belongs to SFPL's
// pass statement only, and the October edition's SFPL Kanopy card keeps "加州居民可免费办 SFPL 卡" in the rows.
test('the multi-service question keeps an SFPL pass statement that limits SF residence to passes, and the open SFPL card rule', () => {
  const { evidenceScopes } = require('../lib/baybayBenefitScope');
  const { state } = resolveTaskState({ message: QUESTION, catalog, today: TODAY });
  const result = buildSiteEvidence({ query: QUESTION, state, guideCatalog, catalog, today: TODAY });
  const scopes = evidenceScopes(result.guides, { sources: new Map() });
  const passes = scopes.find(scope => scope.entityKey === 'sfpl' && /Discover & Go/.test(scope.heading) && /旧金山市县居民/.test(scope.text));
  assert.ok(passes, scopes.map(scope => `${scope.entity} | ${scope.heading.slice(0, 40)}`).join(' || '));
  assert.ok(scopes.some(scope => scope.entityKey === 'sfpl' && scope.text.includes('加州居民可免费办 SFPL 卡')));
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

test('the full new-resident DMV question reaches the initial model with distinct deadlines, documents and official entries', async () => {
  const cases = [
    ['zh-Hans', '假设我是刚从外州搬到 Fremont 的成年人，已有有效外州驾照和一辆外州登记的自用车。请分别说明加州驾照、车辆登记、地址更新的办理期限、所需材料和官方入口。只给已查到的规则，不确定的资格或例外要明确说明，不要把这三件事的期限混在一起。', ['最多再用外州驾照开 10 天', '20 天内办加州登记', '已有加州 DMV 记录', '还没有加州驾照或 ID', 'REG 343', 'REG 31', '不是到达当天自动起算']],
    ['en', 'Assume I am an adult who just moved from another state to Fremont, with a valid out-of-state driver license and a personal vehicle registered in that state. Explain California driver license, vehicle registration and address change deadlines, required documents and official entry points separately. Give only sourced rules and identify uncertain eligibility or exceptions; do not mix these three deadlines.', ['at most 10 days', 'within 20 days', 'already have a California DMV record', 'no California license or ID yet', 'REG 343', 'REG 31', 'not simply the day you arrived']],
  ];
  for (const [locale, message, expected] of cases) {
    let first;
    const assistant = createBayBayAssistant({
      config: { JWT_SECRET: 'dmv-retrieval-test-secret-only' }, catalog, guideCatalog, englishGuideCatalog: require('../data/guide-catalog.en.json'), isTest: true,
      now: () => Date.parse('2026-10-04T19:00:00Z'),
      ai: async payload => {
        first ||= JSON.parse(payload.input[0].content);
        return { status: 'completed', model: 'dmv-context-fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: 'Refer to the separately sourced rules.', candidateIds: [], followups: [] }) }] }] };
      },
      webSearch: async () => { throw new Error('This test must never call the network'); },
    });
    await assistant.run({ message, locale, searchMode: 'site' });
    const text = [...first.evidence.map(row => row.text || ''), ...(first.sourceScopes || []).map(row => row.text)].join('\n');
    for (const value of expected) assert.ok(text.includes(value), `${locale}: ${value}`);
    const urls = first.evidence.map(row => row.url);
    // The 10-12 driver guide names Vehicle Code 12505(c) in the text and lists it in its sources; the paragraph no longer links it inline.
    assert.ok(text.includes(locale === 'en' ? 'California Vehicle Code 12505(c)' : '加州车辆法 12505(c)'), `${locale}: 12505(c)`);
    for (const url of ['https://www.dmv.ca.gov/portal/driver-education-and-safety/special-interest-driver-guides/new-to-california', 'https://www.dmv.ca.gov/portal/online-change-of-address-coa-system']) assert.ok(urls.includes(url), `${locale}: ${url}`);
  }
});
