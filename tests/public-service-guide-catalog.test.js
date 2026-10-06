const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides, guideSourceExcerpt } = require('../lib/guideConversation');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const zh = require('../data/guide-catalog.json');
const en = require('../data/guide-catalog.en.json');
const planner = require('../data/planner-catalog.json');
const TODAY = '2026-10-06';
const NOW = Date.parse(`${TODAY}T19:00:00Z`);
const PUBLIC_SERVICE_SLUGS = [
  'bay-area-medicare-hicap-medi-cal-guide',
  'california-tenant-deposit-rights-help-guide',
  'bay-area-free-tax-help-vita-calfile-guide',
  'bay-area-social-security-retirement-preparation-guide',
  'bay-area-naturalization-official-path-guide',
];
const CASES = [
  {
    slug: 'bay-area-social-security-retirement-preparation-guide',
    officialUrl: 'https://www.ssa.gov/prepare/get-benefits-estimate',
    queries: {
      'zh-Hans': 'SSA 社会保障退休福利工作积分、个人估算与免费口译准备',
      'zh-Hant': 'SSA 社會保障退休福利工作積分、個人估算與免費口譯準備',
      en: 'SSA Social Security retirement work credits, personal estimates and free interpreter preparation',
    },
    facts: { zh: '并非在美国住满十年自动取得', en: 'living in the United States for ten years does not automatically earn them' },
  },
  {
    slug: 'bay-area-naturalization-official-path-guide',
    officialUrl: 'https://www.uscis.gov/n-400',
    queries: {
      'zh-Hans': 'USCIS N-400 入籍准备、考试版本与官方法律服务入口',
      'zh-Hant': 'USCIS N-400 入籍準備、考試版本與官方法律服務入口',
      en: 'USCIS N-400 naturalization preparation, test version and official legal services',
    },
    facts: { zh: '年龄与年限要同时满足', en: 'Both age and resident years must be met' },
  },
];

test('builtin Chinese, English and planner catalogs contain the same 134 guides and all five public-service additions', () => {
  for (const [name, rows] of [['Chinese', zh], ['English', en], ['planner', planner.guides]]) {
    assert.equal(rows.length, 134, `${name}: published guide count`);
    assert.equal(new Set(rows.map(row => row.slug)).size, 134, `${name}: guide IDs must be unique`);
    for (const slug of PUBLIC_SERVICE_SLUGS) assert.ok(rows.some(row => row.slug === slug), `${name}: ${slug}`);
  }
  assert.deepEqual(en.map(row => row.slug).sort(), zh.map(row => row.slug).sort());
  assert.deepEqual(planner.guides.map(row => row.slug).sort(), zh.map(row => row.slug).sort());
  for (const item of CASES) {
    for (const rows of [zh, en]) {
      const guide = rows.find(row => row.slug === item.slug);
      assert.equal(guide.url, `/guides/${item.slug}`);
      assert.ok(guide.sources.some(source => source.url === item.officialUrl), `${item.slug}: canonical official entry`);
    }
  }
});

for (const item of CASES) {
  for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
    test(`${locale} retrieves the actual ${item.slug} with its conditions and official source`, () => {
      const rows = locale === 'en' ? en : zh;
      const query = normalizeGuideQuery(item.queries[locale]);
      const selected = selectConversationGuides(rows, query, 'other', '/', [], TODAY);
      const guide = selected.find(row => row.slug === item.slug);
      assert.ok(guide, `Published guide missing from retrieval: ${item.slug}`);
      const excerpt = guideSourceExcerpt(guide, query);
      assert.ok(excerpt.length <= 9000);
      assert.ok(excerpt.includes(item.officialUrl), 'the excerpt must preserve the official entry');
      assert.ok(excerpt.includes(item.facts[locale === 'en' ? 'en' : 'zh']), 'eligibility caveats must travel with the guide');
    });
  }
}

async function fixture(t) {
  const inputs = [];
  const app = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-public-service-guide-fixture', OPENAI_API_KEY: 'fixture-only-no-real-provider-key' },
    models: createMemoryModels(),
    // Keep the Chinese catalog implicit to exercise the server's real builtin
    // file. Test mode requires explicitly supplying the actual English catalog.
    guideCatalogEn: en,
    plannerNow: () => NOW,
    ai: { guideChat: async () => { throw new Error('No legacy paid provider is allowed in this fixture'); }, baybay: async payload => {
      const input = JSON.parse(payload.input[0].content);
      inputs.push(input);
      const source = input.evidence.find(row => row.kind === 'guide');
      assert.ok(source, 'the fake provider must receive published guide evidence');
      return { status: 'completed', model: 'public-service-guide-fixture', output: [{ type: 'message', role: 'assistant', content: [{
        type: 'output_text', text: JSON.stringify({ answer: `Review this guide's official preparation steps. [[${source.id}]]`, candidateIds: [], followups: [] }),
      }] }] };
    } },
    baybayFetch: async () => { throw new Error('No network or paid provider is allowed in this fixture'); },
    baybaySourceFetch: async () => { throw new Error('No live source request is allowed in this fixture'); },
  });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  return { inputs, ask: async body => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assistantVersion: 2, searchMode: 'site', ...body }),
    });
    return { status: response.status, body: await response.json() };
  } };
}

for (const item of CASES) {
  for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
    for (const selection of ['currentPath', 'explicit-reference']) {
      test(`${locale} Ask BayBay resolves ${item.slug} from ${selection} and passes its real source to the fake provider`, async t => {
        const f = await fixture(t);
        const guide = (locale === 'en' ? en : zh).find(row => row.slug === item.slug);
        const result = await f.ask({
          locale,
          message: locale === 'en' ? 'Summarize this guide and its official preparation steps.' : locale === 'zh-Hant' ? '總結這篇攻略，列出先核對的準備步驟與官方入口。' : '总结这篇攻略，列出先核对的准备步骤与官方入口。',
          context: { currentPath: guide.url, ...(selection === 'explicit-reference' ? { references: [{ kind: 'guide', id: item.slug, title: 'FORGED CLIENT TITLE' }] } : {}) },
        });
        assert.equal(result.status, 200, JSON.stringify(result.body));
        assert.ok(f.inputs.length > 0, 'a real model request must be captured by the fake provider');
        assert.deepEqual(result.body.contextUsed.references, [{ kind: 'guide', id: item.slug }]);
        const reference = result.body.contextReferences.find(row => row.kind === 'guide' && row.id === item.slug);
        assert.ok(reference, 'the selected guide must resolve from the builtin catalog');
        assert.equal(reference.title, guide.title);
        assert.equal(reference.url, guide.url);
        assert.equal(result.body.contextUsed.notices.length, 0, 'the synchronized guide is published');
        const input = f.inputs[0];
        const pageSource = input.evidence.find(row => row.kind === 'guide' && row.url === `https://www.baylink.us${guide.url}` && row.text.includes(item.slug));
        assert.ok(pageSource, 'the first provider payload must include the canonical current-page guide');
        assert.ok(pageSource.text.includes(guide.title));
        assert.ok(pageSource.text.includes(guide.summary));
        const sourceText = [...input.evidence.map(row => `${row.url || ''}\n${row.text || ''}`), ...(input.sourceScopes || []).map(row => row.text || '')].join('\n');
        assert.ok(sourceText.includes(item.officialUrl), 'the actual provider payload must carry this guide\'s official source');
        const officialSource = input.evidence.find(row => row.url === item.officialUrl);
        assert.ok(officialSource, 'published reference URLs must be registered as model-readable sources');
        assert.equal(officialSource.kind, 'web');
        assert.equal(officialSource.verification, 'catalog', 'a published official link is not a live page read');
        assert.notEqual(officialSource.verifiedLive, true);
        assert.doesNotMatch(JSON.stringify(input), /FORGED CLIENT TITLE/);
      });
    }
  }
}

test('public benefit and tax questions can include free agency interpreters without becoming hired translation searches', () => {
  for (const [slug, query] of [
    [PUBLIC_SERVICE_SLUGS[0], 'Medicare HICAP 医保咨询是否提供免费中文口译'],
    [PUBLIC_SERVICE_SLUGS[2], 'VITA IRS 报税准备和免费口译帮助'],
    [PUBLIC_SERVICE_SLUGS[3], 'SSA 自雇工作记录、退休福利和免费口译'],
    [PUBLIC_SERVICE_SLUGS[0], 'Medicare HICAP consultation and free interpreters'],
    [PUBLIC_SERVICE_SLUGS[2], 'VITA IRS tax preparation and free interpreters'],
    [PUBLIC_SERVICE_SLUGS[3], 'SSA 工作记录和无需付费口译帮助'],
    [PUBLIC_SERVICE_SLUGS[3], 'SSA 免費口譯，不必付費口譯'],
    [PUBLIC_SERVICE_SLUGS[0], 'Medicare HICAP free interpreters, no paid interpreter needed'],
  ]) {
    const rows = /[\u3400-\u9fff]/.test(query) ? zh : en;
    const selected = selectConversationGuides(rows, normalizeGuideQuery(query), 'other', '/', [], TODAY);
    assert.ok(selected.some(row => row.slug === slug), query);
  }
});

test('explicitly hiring or paying for an interpreter still selects translation-service guidance', () => {
  const service = { slug: 'translation-service', url: '/guides/translation-service', title: 'Translation service request 翻译服务', categories: ['translation'], summary: 'Hire an interpreter with a clear quote.', content: '找付费口译员陪同 SSA 办理。Hire a paid interpreter for SSA appointments with a budget and price quote.' };
  for (const query of [
    '我要雇一位口译员陪我去 SSA，预算100美元',
    'Hire a paid interpreter for a SSA appointment with a price quote',
    'SSA 有免费口译吗？我还是想找付费口译员陪同',
  ]) {
    const rows = /[\u3400-\u9fff]/.test(query) ? zh : en;
    const selected = selectConversationGuides([...rows, service], normalizeGuideQuery(query), 'translation', '/', [], TODAY);
    assert.ok(selected.some(row => row.slug === service.slug), query);
    assert.ok(selected.every(row => (row.categories || []).includes('translation')), 'hired-service questions must retain translation-service guidance');
    assert.ok(selected.every(row => !PUBLIC_SERVICE_SLUGS.includes(row.slug)), 'free public-agency guides must not replace the explicit hired-service request');
  }
});

const scopedCatalog = { version: 1, checkedAt: TODAY, events: [], places: [], guides: [] };
const scopedGuides = [
  { slug: 'physical', url: '/guides/physical', title: 'Physical-page garden guide', content: 'A garden visitor should confirm flower displays with the park before visiting.', sources: [{ title: 'Garden reference', url: 'https://garden.example.test/visits' }] },
  { slug: 'selected', url: '/guides/selected', title: 'Selected application guide', content: 'Applications require checking the current form edition and retaining official notices.', sources: [{ title: 'Application reference', url: 'https://application.example.test/forms' }] },
  { slug: 'transit', url: '/guides/transit', title: 'BART transit guide', content: 'BART riders should check the transit timetable and fare before travel.', sources: [{ title: 'Transit reference', url: 'https://transit.example.test/bart' }] },
];
const scopedEvidence = options => buildSiteEvidence({ guideCatalog: scopedGuides, catalog: scopedCatalog, state: { goal: 'information' }, today: TODAY, ...options });

test('an explicit article selection overrides the physical page and survives zero matching keywords', () => {
  const result = scopedEvidence({ query: '总结这篇', currentPath: '/guides/physical', selectedGuideUrls: ['/guides/selected'] });
  assert.ok(result.guides.length > 0);
  assert.ok(result.guides.every(row => row.slug === 'selected'));
  assert.ok(result.guides.some(row => row.text.includes('current form edition')));
  assert.ok(result.guides.every(row => row.sourceUrls.every(source => source.url === 'https://application.example.test/forms')));
  assert.ok(result.guides.every(row => row.verification === 'site-record' && row.verifiedLive === false));
});

test('an explicit cleared article selection does not restore physical-page priority', () => {
  const cleared = scopedEvidence({ query: '总结这篇', currentPath: '/guides/physical', selectedGuideUrls: [] });
  const withoutPage = scopedEvidence({ query: '总结这篇', currentPath: '/', selectedGuideUrls: [] });
  assert.deepEqual(cleared.guides.map(row => row.evidenceId), withoutPage.guides.map(row => row.evidenceId));
});

test('ordinary topic queries retain global retrieval despite an open or selected unrelated article', () => {
  const result = scopedEvidence({ query: 'BART transit timetable and fare', currentPath: '/guides/physical', selectedGuideUrls: ['/guides/selected'] });
  assert.ok(result.guides.length > 0);
  assert.ok(result.guides.every(row => row.slug === 'transit'));
});

for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
  test(`${locale} explicit guide references override a different current guide in the actual provider payload`, async t => {
    const f = await fixture(t);
    const target = CASES[1], physical = CASES[0];
    const result = await f.ask({
      locale,
      message: locale === 'en' ? 'Summarize this guide and its official preparation steps.' : locale === 'zh-Hant' ? '總結這篇攻略。' : '总结这篇攻略。',
      context: { currentPath: `/guides/${physical.slug}`, references: [{ kind: 'guide', id: target.slug }] },
    });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.contextUsed.references, [{ kind: 'guide', id: target.slug }]);
    const input = f.inputs[0];
    assert.ok(input.evidence.some(row => row.url === target.officialUrl));
    assert.ok(!input.evidence.some(row => row.url === physical.officialUrl), 'the physical page must not supply another guide\'s official references');
    const bodies = input.evidence.filter(row => row.kind === 'guide' && row.url.startsWith('/guides/'));
    assert.ok(bodies.length > 0);
    assert.ok(bodies.every(row => row.url === `/guides/${target.slug}`));
  });
}
