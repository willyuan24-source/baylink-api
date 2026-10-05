const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { createEvidenceStore } = require('../lib/baybayTools');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const guideCatalog = require('../data/guide-catalog.json');
const englishGuideCatalog = require('../data/guide-catalog.en.json');
const catalog = require('../data/planner-catalog.json');
const search = (message, state) => buildSiteEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state, guideCatalog, catalog, today: '2026-10-05' });

test('the first site retrieval includes dated eligibility through the venue official reference without guessing the nickname identity', () => {
  const result = search('11月11日木头公园是不是谁都免费？我爸妈从国内来旅游，我们还要订停车吗？', { goal: 'information', date: '2026-11-11' });
  const passage = result.guides.find(row => /11\/11 Muir Woods/.test(row.text));
  assert.ok(passage, 'the first retrieval must not depend on a model deciding to issue a second query');
  assert.match(passage.text, /仅适用于美国公民及居民/);
  assert.match(passage.text, /停车或接驳车仍需预约并付费/);
  assert.ok(passage.sourceUrls.some(source => source.url === 'https://www.nps.gov/muwo/planyourvisit/fees.htm'));
  assert.equal(passage.verifiedLive, false);
  assert.ok(result.guides.length <= 8);
});

test('the two-city visitor comparison keeps both cities own places and the nearby boundary label', () => {
  const result = search('Belvedere跟Tiburon有啥值得看的？各给点，不要把附近地方都说成在城里。', { goal: 'information', city: null, region: 'all' });
  const text = result.guides.map(row => row.text).join('\n');
  for (const expected of ['City guide: Belvedere', 'China Cabin [city]', 'Belvedere Community Park [city]', 'Angel Island State Park [nearby]', '它不在 Belvedere 市内', 'City guide: Tiburon', 'Railroad & Ferry Depot Museum [city]', 'Blackie’s Pasture / Old Rail Trail [city]']) assert.ok(text.includes(expected), expected);
  assert.ok(result.guides.length <= 8);
  assert.ok(result.guides.every(row => row.verifiedLive === false));
});

test('dated candidate admission labels are citable editorial snapshots even when a family total cannot be computed', () => {
  const result = search('11月7、8号在北湾，带5岁孩子想看看自然，别推酒庄。Sugarloaf那边有合适的吗？', { goal: 'information', region: 'north-bay', date: null, childAges: [5] });
  const store = createEvidenceStore(result);
  const event = store.candidates.get('november-north-sugarloaf-public-star-party-2026');
  assert.ok(event);
  const source = [...store.sources.values()].find(row => row.url === 'https://sugarloafpark.org/event/public-star-party-46');
  assert.ok(source);
  for (const expected of ['成人$15', '5岁及以下免费', '$10/车停车', '11/7', '19:00–22:00']) assert.ok(source.text.includes(expected), expected);
  assert.equal(source.verification, 'catalog');
  assert.equal(source.verifiedLive, false);
  assert.equal(source.checkedAt, '2026-10-05');
  assert.equal(event.admissionFacts.knownTotalUsd, null, 'publishing price tiers must not invent party size or a computed total');
  assert.equal(event.admissionFacts.basis, 'catalog');
});

test('the Dixon and Rio Vista family-waterfront comparison retains concrete land-based places and limits', () => {
  const result = search('Dixon和Rio Vista哪儿适合带娃在水边转转？不想钓鱼，也别给我已经结束的节。', { goal: 'information', city: null, region: 'all' });
  const text = result.guides.map(row => row.text).join('\n');
  for (const expected of ['City guide: Dixon', 'Hall Memorial Park [city]', 'Jepson Prairie Preserve [nearby]', 'City guide: Rio Vista', 'Waterfront Promenade [city]', 'North Front Street', 'Bruning Park [city]', '300 California Street', '县方明确禁止游泳']) assert.ok(text.includes(expected), expected);
  const river = result.guides.find(row => row.text.includes('Waterfront Promenade [city]'));
  assert.ok(river.sourceUrls.some(source => source.url === 'https://www.riovistacity.com/parksrec'));
  assert.match(river.text, /公共陆上散步点，不代表相邻码头、船坡与水域都可随意使用/);
  assert.equal(river.verifiedLive, false);
  assert.ok(result.guides.length <= 8);
});

test('the English directory tail remains searchable with city ownership and river-access limits', () => {
  const query = 'Compare Dixon and Rio Vista for a short waterfront walk with a child. No fishing or already-ended festivals.';
  const result = buildSiteEvidence({ query, originalQuery: query, state: { goal: 'information', city: null, region: 'all' }, guideCatalog: englishGuideCatalog, catalog, today: '2026-10-05' });
  const text = result.guides.map(row => row.text).join('\n');
  for (const expected of ['City guide: Dixon', 'Hall Memorial Park [city]', 'Jepson Prairie Preserve [nearby]', 'City guide: Rio Vista', 'Waterfront Promenade [city]', 'North Front Street', 'Bruning Park [city]', '300 California Street', 'county prohibits swimming']) assert.ok(text.includes(expected), expected);
  assert.match(text, /does not imply unrestricted use of neighboring docks, launch ramps or water/);
  assert.ok(result.guides.length <= 8);
  assert.ok(result.guides.every(row => row.verifiedLive === false));
});

test('the initial model context receives the missing eligibility, both city scopes and the complete known price tiers', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const questions = [
    ['11月11日木头公园是不是谁都免费？我爸妈从国内来旅游，我们还要订停车吗？', ['仅适用于美国公民及居民', '停车或接驳车仍需预约并付费']],
    ['Belvedere跟Tiburon有啥值得看的？各给点，不要把附近地方都说成在城里。', ['China Cabin [city]', 'Belvedere Community Park [city]', '它不在 Belvedere 市内', 'Railroad & Ferry Depot Museum [city]']],
    ['Dixon和Rio Vista哪儿适合带娃在水边转转？不想钓鱼，也别给我已经结束的节。', ['Hall Memorial Park [city]', 'Jepson Prairie Preserve [nearby]', 'Waterfront Promenade [city]', 'Bruning Park [city]']],
    ['Compare Dixon and Rio Vista for a short waterfront walk with a child. No fishing or already-ended festivals.', ['City guide: Dixon', 'Hall Memorial Park [city]', 'City guide: Rio Vista', 'Waterfront Promenade [city]', 'Bruning Park [city]', 'county prohibits swimming'], 'en'],
    ['11月7、8号在北湾，带5岁孩子想看看自然，别推酒庄。Sugarloaf那边有合适的吗？', ['成人$15', '5岁及以下免费', '$10/车停车']],
  ];
  for (const [message, expected, locale = 'zh-Hans'] of questions) {
    let first;
    const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'local-completeness-test-only' }, catalog, guideCatalog, englishGuideCatalog, isTest: true,
      now: () => Date.parse('2026-10-05T19:00:00Z'),
      ai: async payload => {
        first ||= JSON.parse(payload.input[0].content);
        return { status: 'completed', model: 'local-context-fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '这里使用站内资料快照。', candidateIds: [], followups: [] }) }] }] };
      },
      webSearch: async () => { throw new Error('This local context test must not call external services'); },
    });
    await assistant.run({ message, searchMode: 'site', locale });
    assert.ok(first);
    const text = [...first.evidence, ...first.sourceScopes].map(row => row.text || '').join('\n');
    for (const value of expected) assert.ok(text.includes(value), `${message}: ${value}`);
    for (const scope of first.sourceScopes) assert.ok(scope.sourceIds.some(id => first.evidence.some(source => source.id === id)), 'each scoped record retains a visible citable guide');
    assert.ok(first.sourceScopes.every(scope => scope.basis === 'site-snapshot'));
  }
});
