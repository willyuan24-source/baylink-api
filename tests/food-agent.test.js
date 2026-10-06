const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createPublicContext } = require('../lib/publicContext');
const { foodEvidenceGap } = require('../lib/foodEvidence');
const NOW = Date.parse('2026-10-06T19:00:00Z');
const DAY = '2026-10-06';
const MENU = 'https://example.org/restaurant/menu';
const final = answer => ({ status: 'completed', model: 'food-evidence-fixture', output: [{ type: 'message', role: 'assistant',
  content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
const invoke = query => ({ status: 'completed', output: [{ type: 'function_call', name: 'search_site', call_id: 'food-site-call', arguments: JSON.stringify({ query }) }] });
const restaurant = (id, summary) => ({ id, title: id === 'restaurant-dim-sum' ? 'Example Dim Sum Restaurant' : 'Example Seafood Restaurant',
  summary, category: 'food', city: 'San Francisco', region: 'sf', officialUrl: MENU, costLabel: 'Menu prices need confirmation.' });
const catalog = places => ({ version: 1, checkedAt: DAY, places, events: [], guides: [] });
const options = extra => ({ config: { JWT_SECRET: 'isolated-food-evidence-fixture-secret' }, catalog: catalog([]), guideCatalog: [], isTest: true, now: () => NOW, ...extra });

for (const [locale, message, gap] of [
  ['zh-Hans', '湾区哪里饮茶', /本轮取得的站内记录尚未确证.*饮茶／点心/],
  ['zh-Hant', '灣區哪裡飲茶', /本輪取得的站內記錄尚未確證.*飲茶／點心/],
  ['en', 'Where can I get dim sum?', /records retrieved in this turn do not establish a tea\/dim-sum option/],
]) {
  test(`${locale}: a site-only type gap gives honest next steps without a model, provider or unrelated card`, async () => {
    let calls = 0;
    const forbidden = async () => { calls++; throw new Error('Unexpected external/model call'); };
    const assistant = createBayBayAssistant(options({ catalog: catalog([restaurant('restaurant-generic', 'A seafood restaurant with indoor dining.')]),
      ai: forbidden, webSearch: forbidden, sourceFetch: forbidden, fetchImpl: forbidden }));
    const result = await assistant.run({ message, locale, searchMode: 'site' });
    assert.match(result.answer, gap); assert.equal(calls, 0); assert.equal(result.degraded, false);
    assert.equal(result.responseMode, 'assistant'); assert.equal(result.retrieval.webStatus, 'not_requested');
    assert.deepEqual(result.localMatches, []); assert.deepEqual(result.suggestedGuides, []);
    assert.deepEqual(result.matchingPosts, []); assert.deepEqual(result.interactiveCards, []);
    assert.ok(result.assistantSessionToken); assert.ok(result.research.warnings.includes('food_evidence_unconfirmed'));
    assert.ok(!result.research.warnings.includes('model_unavailable_or_capacity'));
    assert.match(result.answer, locale === 'en' ? /not a claim that no options exist/ : /不表示全站或[当當]地[没沒]有/);
    assert.match(result.answer, locale === 'en' ? /Which city or named restaurant/ : /哪[个個]城市或哪家店/);
  });
}

test('a genuinely matched type keeps synthesis/citations and distinguishes the menu record from current availability', async () => {
  let payloadContext, modelCalls = 0;
  const assistant = createBayBayAssistant(options({ catalog: catalog([restaurant('restaurant-dim-sum', 'The published menu lists Cantonese dim sum.')]),
    ai: async payload => {
      modelCalls++; payloadContext = JSON.parse(payload.input[0].content);
      assert.match(payload.instructions, /generic restaurant.*cannot establish tea\/dim-sum/);
      const source = payloadContext.evidence.find(row => row.url === MENU);
      return final(`The published menu record lists dim sum; confirm the current menu and opening arrangements with the venue. [[${source.id}]]`);
    } }));
  const result = await assistant.run({ message: 'Where can I get dim sum?', locale: 'en', searchMode: 'site' });
  assert.ok(modelCalls > 0); assert.equal(result.degraded, false);
  assert.deepEqual(payloadContext.foodEvidenceRequirement, { kind: 'dim-sum', status: 'matched', scope: 'retrieved-site-records',
    unverified: ['current-menu', 'opening-hours', 'availability'] });
  assert.match(result.answer, /published menu record lists dim sum/); assert.equal(result.sources[0].url, MENU);
  assert.ok(!result.research.warnings.includes('food_evidence_unconfirmed'));
});

test('a successful live-web lookup is retained when the site has no established type-specific match', async () => {
  let modelCalls = 0, webCalls = 0;
  const assistant = createBayBayAssistant(options({ webSearch: async () => {
    webCalls++; return { answer: 'An official menu describes dim sum; current availability needs checking.',
      sources: [{ title: 'Official menu', url: MENU }], candidates: [], checkedAt: new Date(NOW).toISOString() };
  }, ai: async payload => {
    modelCalls++; const context = JSON.parse(payload.input[0].content);
    assert.equal(context.foodEvidenceRequirement.status, 'needs-confirmation');
    const source = context.evidence.find(row => row.kind === 'web');
    return final(`This web result is a lead to the official dim-sum menu; current service still needs confirmation. [[${source.id}]]`);
  } }));
  const result = await assistant.run({ message: 'Where can I get dim sum?', locale: 'en', searchMode: 'web' });
  assert.equal(webCalls, 1); assert.ok(modelCalls > 0); assert.equal(result.retrieval.webStatus, 'completed');
  assert.equal(result.retrieval.scope, 'site+web'); assert.equal(result.sources[0].url, MENU);
  assert.match(result.answer, /web result is a lead/); assert.ok(!result.research.warnings.includes('food_evidence_unconfirmed'));
});

test('a model search_site query cannot silently replace a dim-sum requirement with generic restaurants', async () => {
  let rounds = 0;
  const assistant = createBayBayAssistant(options({ catalog: catalog([
    restaurant('restaurant-dim-sum', 'The restaurant menu lists dim sum.'), restaurant('restaurant-generic', 'A seafood restaurant.'),
  ]), ai: async payload => {
    if (!rounds++) return invoke('restaurants in San Francisco');
    const result = JSON.parse(payload.input.find(row => row.type === 'function_call_output').output);
    assert.deepEqual(result.candidates.map(row => row.id), ['restaurant-dim-sum']);
    return final(`Check the published menu and current service with the venue. [[${result.sources.find(row => row.url === MENU).id}]]`);
  } }));
  const result = await assistant.run({ message: 'Where can I get dim sum?', locale: 'en', searchMode: 'site' });
  assert.equal(rounds, 2); assert.ok(result.research.steps.some(step => step.tool === 'search_site' && step.status === 'completed'));
});

test('an unrelated explicitly selected article stays page context without becoming food proof', async () => {
  const housing = { slug: 'housing', title: 'Rental lease', content: 'Read the rent and deposit terms.', url: '/guides/housing',
    updatedAt: DAY, sources: [{ title: 'Rental authority', url: 'https://example.org/rental' }] };
  const ref = { kind: 'guide', id: housing.slug, title: housing.title, url: housing.url, summary: housing.content };
  let calls = 0;
  const assistant = createBayBayAssistant(options({ guideCatalog: [housing], ai: async () => { calls++; return final('Wrong menu proof.'); } }));
  const result = await assistant.run({ message: 'Does this article establish dim sum service?', locale: 'en', searchMode: 'site',
    currentPath: housing.url, pageContext: { contextReferences: [ref], contextUsed: { references: [ref], notices: [] } } });
  assert.equal(calls, 0); assert.match(result.answer, /do not establish a tea\/dim-sum option/);
  assert.deepEqual(result.contextReferences, [ref]); assert.ok(result.evidence.some(row => /\/guides\/housing$/.test(row.url)));
  assert.deepEqual(result.localMatches, []); assert.deepEqual(result.contextUsed.references, [ref]);
});

for (const [locale, message] of [
  ['zh-Hans', '湾区哪里饮茶'], ['zh-Hant', '灣區哪裡飲茶'], ['en', 'Where can I get dim sum?'],
]) {
  test(`${locale}: real senior-guide page context stays evidence without final or streamed dining cards`, async () => {
    const guides = require('../data/guide-catalog.json');
    const englishGuides = require('../data/guide-catalog.en.json');
    const currentPath = '/guides/bay-area-chinese-senior-services-referral-guide';
    const pageContext = createPublicContext({ catalog: catalog([]), guideCatalog: guides, englishGuideCatalog: englishGuides })
      .resolve({ currentPath, today: DAY, locale });
    assert.equal(pageContext.contextReferences.length, 1);
    const frames = [];
    let calls = 0;
    const forbidden = async () => { calls++; throw new Error('Unexpected external/model call'); };
    const assistant = createBayBayAssistant(options({ guideCatalog: guides, englishGuideCatalog: englishGuides,
      ai: forbidden, webSearch: forbidden, sourceFetch: forbidden, fetchImpl: forbidden }));
    const result = await assistant.run({ message, locale, searchMode: 'site', currentPath, pageContext,
      onQuickCard: cards => { frames.push(cards); return Promise.resolve(); } });
    assert.equal(calls, 0); assert.equal(result.answer, foodEvidenceGap({ kind: 'dim-sum' }, locale));
    assert.equal(result.degraded, false); assert.deepEqual(frames, [[]]);
    assert.deepEqual(result.localMatches, []); assert.deepEqual(result.suggestedGuides, []);
    assert.deepEqual(result.matchingPosts, []); assert.deepEqual(result.interactiveCards, []); assert.deepEqual(result.nextSteps, []);
    assert.deepEqual(result.contextReferences, pageContext.contextReferences); assert.deepEqual(result.contextUsed, pageContext.contextUsed);
    assert.ok(result.evidence.some(row => row.url.endsWith(currentPath)));
  });
}

test('matched dining paragraphs retain their selected guide card, while unrelated selected context does not', async () => {
  const dining = { slug: 'dim-sum-menu', title: 'Dim Sum Restaurant menu', url: '/guides/dim-sum-menu',
    content: 'The restaurant menu lists Cantonese dim sum.', updatedAt: DAY, sources: [{ title: 'Official menu', url: MENU }] };
  const ref = { kind: 'guide', id: dining.slug, title: dining.title, url: dining.url, summary: dining.content };
  const unrelated = { kind: 'event', id: 'community-meeting', title: 'Community meeting', url: '/events/community-meeting', temporalStatus: 'current' };
  const pageContext = { contextReferences: [ref, unrelated], contextUsed: { references: [ref, unrelated], notices: [] } };
  const frames = [];
  const assistant = createBayBayAssistant(options({ guideCatalog: [dining], ai: async payload => {
    const context = JSON.parse(payload.input[0].content);
    assert.equal(context.foodEvidenceRequirement.status, 'matched');
    return final(`Check the published menu and current service with the venue. [[${context.evidence.find(row => row.kind === 'guide').id}]]`);
  } }));
  const result = await assistant.run({ message: 'Where can I get dim sum?', locale: 'en', searchMode: 'site', currentPath: dining.url, pageContext,
    onQuickCard: cards => frames.push(cards) });
  assert.equal(result.degraded, false); assert.deepEqual(frames, [[ref]]); assert.deepEqual(result.localMatches, [ref]);
  assert.deepEqual(result.contextReferences, [ref, unrelated]); assert.deepEqual(result.contextUsed, pageContext.contextUsed);
  assert.deepEqual(result.nextSteps, []);
});

test('a mixed museum/food request and a non-food question preserve the ordinary response envelope and sourced article', async () => {
  const museum = { slug: 'museum', title: 'Museum and lunch', content: 'Visit the museum. A nearby restaurant is a separate lunch option.',
    url: '/guides/museum', updatedAt: DAY, sources: [{ title: 'Museum visitor guide', url: 'https://example.org/museum' }] };
  const ref = { kind: 'guide', id: museum.slug, title: museum.title, url: museum.url, summary: museum.content };
  const pageContext = { contextReferences: [ref], contextUsed: { references: [ref], notices: [] } };
  for (const message of ['Find a museum and a restaurant for lunch', 'Museum visitor information']) {
    let modelCalls = 0;
    const frames = [];
    const assistant = createBayBayAssistant(options({ guideCatalog: [museum], ai: async payload => {
      modelCalls++; const context = JSON.parse(payload.input[0].content);
      assert.equal(context.foodEvidenceRequirement, undefined);
      return final(`Use the visitor guide and check its published conditions. [[${context.evidence.find(row => row.kind === 'guide').id}]]`);
    } }));
    const result = await assistant.run({ message, locale: 'en', searchMode: 'site', currentPath: museum.url, pageContext,
      onQuickCard: cards => frames.push(cards) });
    assert.ok(modelCalls); assert.equal(result.sources[0].url, museum.url);
    assert.deepEqual(frames, [[ref]]); assert.deepEqual(result.localMatches, [ref]);
    assert.deepEqual(result.contextReferences, [ref]); assert.deepEqual(result.contextUsed, pageContext.contextUsed);
    for (const key of ['suggestedActions', 'interactiveCards', 'contextReferences', 'nextSteps']) assert.ok(Array.isArray(result[key]), key);
    assert.ok(!result.research.warnings.includes('food_evidence_unconfirmed'));
  }
});

test('food words cannot intercept an emergency or professional-service boundary', async () => {
  let calls = 0;
  const assistant = createBayBayAssistant(options({ ai: async () => { calls++; throw new Error('Safety must return before model'); } }));
  const emergency = await assistant.run({ message: 'I have chest pain and cannot breathe after eating dim sum.', locale: 'en', searchMode: 'site' });
  assert.equal(emergency.safetyRoute, 'emergency'); assert.match(emergency.answer, /911/);
  const professional = await assistant.run({ message: '餐厅报税应该准备什么材料', locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(professional.safetyRoute, 'professional'); assert.equal(calls, 0);
});
