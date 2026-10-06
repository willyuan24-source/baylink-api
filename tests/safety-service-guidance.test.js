const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const zh = require('../data/guide-catalog.json');
const english = require('../data/guide-catalog.en.json');
const MEDICARE = 'bay-area-medicare-hicap-medi-cal-guide';
const TAX = 'bay-area-free-tax-help-vita-calfile-guide';
const HICAP_URL = 'https://www.aging.ca.gov/Programs_and_Services/Medicare_Counseling/';
const VITA_URL = 'https://www.irs.gov/individuals/free-tax-return-preparation-for-qualifying-taxpayers';
const FTB_URL = 'https://www.ftb.ca.gov/file/ways-to-file/online/index.html';

async function fixture(t, overrides = {}) {
  const models = createMemoryModels();
  const attempts = { providers: 0, quota: 0, external: 0 };
  const forbiddenProvider = async () => { attempts.providers++; throw new Error('Paid provider must not run'); };
  models.AiGovernance.updateOne = models.AiGovernance.findOneAndUpdate = async () => {
    attempts.quota++; throw new Error('Quota storage is offline in this fixture');
  };
  const application = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-safety-service-guidance-fixture', AI_DAILY_REQUEST_LIMIT: 0 },
    models, guideCatalogEn: english, ...overrides,
    ai: { baybay: forbiddenProvider, guideChat: forbiddenProvider, postAssist: forbiddenProvider,
      outingDraft: forbiddenProvider, planner: { recommend: forbiddenProvider } },
    baybayFetch: async () => { attempts.external++; throw new Error('External provider request prohibited'); },
    baybaySourceFetch: async () => { attempts.external++; throw new Error('External source request prohibited'); },
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return { attempts, models, ask: async (body, path = '/api/ai/guide-chat') => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, headers: response.headers, data: await response.json() };
  } };
}

const CASES = [
  { name: 'broad Medicare', slug: MEDICARE, topic: 'medicare', queries: {
    'zh-Hans': '父母的 Medicare 怎么开始了解？', 'zh-Hant': '父母的 Medicare 怎麼開始了解？', en: 'Where should I start with Medicare for my parents?',
  } },
  { name: 'HICAP without a Medicare keyword', slug: MEDICARE, topic: 'medicare', queries: {
    'zh-Hans': 'HICAP 在哪里，咨询前准备什么？', 'zh-Hant': 'HICAP 在哪裡，諮詢前準備什麼？', en: 'Where is HICAP and what should I prepare?',
  } },
  { name: 'broad insurance', slug: MEDICARE, topic: 'insurance', queries: {
    'zh-Hans': '医保从哪里开始了解？', 'zh-Hant': '醫保從哪裡開始了解？', en: 'Where should I start with health insurance?',
  } },
  { name: 'Medi-Cal without a translated insurance keyword', slug: MEDICARE, topic: 'insurance', queries: {
    'zh-Hans': 'Medi-Cal 续保应该找哪里？', 'zh-Hant': 'Medi-Cal 續保應該找哪裡？', en: 'Where do I start with Medi-Cal renewal?',
  } },
  { name: 'broad tax preparation', slug: TAX, topic: 'tax', queries: {
    'zh-Hans': '湾区报税帮助从哪里开始找？', 'zh-Hant': '灣區報稅幫助從哪裡開始找？', en: 'How do I find tax help in the Bay Area?',
  } },
  { name: 'tax-program names without broad tax words', slug: TAX, topic: 'tax', queries: {
    'zh-Hans': ['VITA 怎么预约？', 'TCE 需要准备什么？', 'CalFile 从哪里开始？'],
    'zh-Hant': ['VITA 怎麼預約？', 'TCE 需要準備什麼？', 'CalFile 從哪裡開始？'],
    en: ['How do I book VITA?', 'What should I bring to TCE?', 'Where do I start with CalFile?'],
  } },
];

for (const example of CASES) for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
  test(`${locale}: HTTP safety response gives the published guide and official preparation for ${example.name}`, async t => {
    const f = await fixture(t);
    for (const message of [example.queries[locale]].flat()) {
      // An unrelated current page must not replace the actual requested topic.
      const result = await f.ask({ message, locale, assistantVersion: 2, stream: true,
        context: { currentPath: '/guides/bay-area-rental-scam-guide' } });
      assert.equal(result.status, 200, message);
      assert.match(result.headers.get('content-type'), /application\/json/);
      assert.equal(result.data.safetyRoute, 'professional');
      assert.equal(result.data.safetyTopic, example.topic);
      assert.equal(result.data.responseMode, 'safety');
      assert.deepEqual(result.data.suggestedGuides.map(row => row.slug), [example.slug]);
      const guide = result.data.suggestedGuides[0];
      assert.equal(guide.url, zh.find(row => row.slug === example.slug).url);
      if (locale === 'en') {
        assert.equal(guide.title, english.find(row => row.slug === example.slug).title);
        assert.doesNotMatch(result.data.answer + guide.title, /[\u3400-\u9fff]/u);
        assert.match(result.data.answer, /not a live source check/);
      } else if (locale === 'zh-Hant') {
        assert.doesNotMatch(guide.title, /咨询|准备|报税/u);
        assert.match(result.data.answer, /不是本次即時網頁核驗/u);
      } else assert.match(result.data.answer, /不是本次即时网页核验/u);
      if (example.slug === MEDICARE) {
        assert.ok(result.data.sources.some(row => row.url === HICAP_URL));
        assert.ok(result.data.sources.some(row => row.url === 'https://www.dhcs.ca.gov/medi-cal/'));
        assert.match(result.data.answer, /1-800-434-0222/);
        assert.match(result.data.answer, /医生|醫生|doctors/);
        assert.match(result.data.answer, /药物|藥物|medication/);
        assert.match(result.data.answer, /不是对你个人资格的判定|不是對你個人資格的判定|does not determine your eligibility/);
      } else {
        assert.ok(result.data.sources.some(row => row.url === VITA_URL));
        assert.ok(result.data.sources.some(row => row.url === FTB_URL));
        assert.match(result.data.answer, /800-906-9887/);
        assert.match(result.data.answer, /表格|forms/);
        assert.match(result.data.answer, /不代表现在开门|不代表現在開門|does not guarantee that a site is open/);
        assert.match(result.data.answer, /联邦免费不代表州申报也免费|聯邦免費不代表州申報也免費|free federal filing does not guarantee free state filing/);
      }
      assert.deepEqual(result.data.matchingPosts, []);
      assert.deepEqual(result.data.interactiveCards, []);
    }
    assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
    assert.equal(f.models.AiGovernance.rows.length, 0);
  });
}

test('HTTP mixed Medicare and VITA questions preserve both real guides without making personal determinations or echoing identifiers', async t => {
  const f = await fixture(t);
  for (const [locale, message] of [
    ['zh-Hans', 'Medicare 和 VITA 都想了解。我的号码 123-45-6789，保证我符合资格吗？'],
    ['zh-Hant', 'Medicare 和 VITA 都想了解。我的號碼 123-45-6789，保證我符合資格嗎？'],
    ['en', 'Medicare and VITA: my ID is 123-45-6789. Can you guarantee I qualify?'],
  ]) {
    const { status, data } = await f.ask({ message, locale });
    assert.equal(status, 200); assert.equal(data.safetyRoute, 'professional');
    assert.deepEqual(data.suggestedGuides.map(row => row.slug).sort(), [MEDICARE, TAX].sort());
    assert.ok(data.sources.some(row => row.url === HICAP_URL) && data.sources.some(row => row.url === VITA_URL));
    assert.match(data.answer, /个人判定应由|個人判定應由|For a personal determination/);
    assert.match(data.answer, /不要|请勿|請勿|Do not|Avoid/);
    assert.doesNotMatch(JSON.stringify(data), /123-45-6789|you qualify|你已符合|你一定符合/);
  }
  assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
});

test('HTTP current emergency wins over Medicare and tax guidance on every guarded AI entry before providers or quota', async t => {
  const f = await fixture(t);
  for (const path of ['/api/ai/guide-chat', '/api/planner/recommend', '/api/ai/post-assist', '/api/ai/outing-draft']) {
    for (const [locale, message] of [
      ['zh-Hans', 'Medicare 和报税先不管，我现在胸痛不能呼吸'],
      ['zh-Hant', 'Medicare 和報稅先不管，我現在胸痛不能呼吸'],
      ['en', 'Medicare and tax filing can wait; I have chest pain and cannot breathe now'],
    ]) {
      const { status, data } = await f.ask({ message, intent: message, locale }, path);
      assert.equal(status, 200); assert.equal(data.safetyRoute, 'emergency');
      assert.match(data.answer, /911/); assert.match(data.answer, /988/); assert.match(data.answer, /1-800-222-1222/);
      assert.deepEqual(data.suggestedGuides, []);
      assert.ok(!data.sources.some(row => row.url === HICAP_URL || row.url === VITA_URL));
    }
  }
  assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
});

test('HTTP immigration, diagnosis and legal questions keep professional boundaries rather than generated personal advice', async t => {
  const f = await fixture(t);
  for (const message of ['Do I qualify for a green card?', 'Give me a medical diagnosis and prescription', 'Can you give legal advice about eviction?']) {
    const { status, data } = await f.ask({ message, locale: 'en' });
    assert.equal(status, 200); assert.equal(data.safetyRoute, 'professional');
    assert.match(data.answer, /qualified professional|official service/);
    assert.match(data.answer, /Avoid sharing full IDs/);
    assert.deepEqual(data.suggestedGuides, []);
  }
  assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
});

test('HTTP safety responses do not invent a guide missing from the application catalog', async t => {
  const f = await fixture(t, { guideCatalog: [] });
  for (const [locale, message] of [['zh-Hans', '医保和报税'], ['zh-Hant', '醫保和報稅'], ['en', 'HICAP and VITA']]) {
    const { status, data } = await f.ask({ message, locale });
    assert.equal(status, 200); assert.deepEqual(data.suggestedGuides, []);
    assert.ok(data.sources.some(row => row.url === HICAP_URL) && data.sources.some(row => row.url === VITA_URL));
  }
  assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
});

test('HTTP English safety presentation cannot override canonical guide URLs or fall back to Chinese titles', async t => {
  const f = await fixture(t, { guideCatalogEn: [
    { ...english.find(row => row.slug === MEDICARE), url: 'https://evil.invalid/guide' },
    { ...english.find(row => row.slug === TAX), title: '未翻译标题', url: 'https://evil.invalid/tax' },
  ] });
  const { data } = await f.ask({ message: 'HICAP and VITA', locale: 'en' });
  assert.deepEqual(data.suggestedGuides.map(row => row.url), ['/guides/' + MEDICARE, '/guides/' + TAX]);
  assert.doesNotMatch(JSON.stringify(data), /evil\.invalid|未翻译|[\u3400-\u9fff]/u);
  assert.deepEqual(f.attempts, { providers: 0, quota: 0, external: 0 });
});
