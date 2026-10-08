// The page the user is viewing reaches the model as the first input field and
// as top-priority evidence with the fixed citation id "page" (BBLIVE-04, B1/B2).
// Deterministic: a fake provider records the payload; no paid model is called.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createPublicContext } = require('../lib/publicContext');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { resolveTaskState } = require('../lib/baybayState');
const catalog = require('../data/planner-catalog.json');
const guideCatalog = require('../data/guide-catalog.json');
const englishGuideCatalog = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-08T17:00:00Z');
const TODAY = '2026-10-08';
const FLEET = '/events/san-francisco-fleet-week-2026';
const SENIOR = '/guides/bay-area-chinese-senior-services-referral-guide';
const context = createPublicContext({ catalog, guideCatalog, englishGuideCatalog });
const final = answer => ({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });

function assistant(reply) {
  const payloads = [];
  const run = createBayBayAssistant({ config: { JWT_SECRET: 'isolated-page-context-fixture', BAYBAY_STATE_SECRET: 'isolated-page-context-state' },
    catalog, guideCatalog, englishGuideCatalog, isTest: true, now: () => NOW,
    ai: async payload => { payloads.push(payload); return final(reply(JSON.parse(payload.input[0].content), payload)); } });
  return { payloads, ask: (message, currentPath, locale = 'zh-Hans') => run.run({ message, locale, searchMode: 'site', currentPath,
    pageContext: context.resolve({ context: {}, currentPath, today: TODAY, locale }) }) };
}

test('B1: on the Fleet Week page "这个活动" is the current page, first in the input and citable as [[page]]', async () => {
  const f = assistant(input => `适合，但先看航空展时段和陡梯限制。[[page]]`);
  const result = await f.ask('这个活动适合带70岁的爸妈去吗？', FLEET);
  assert.equal(f.payloads.length, 1);
  const input = JSON.parse(f.payloads[0].input[0].content);
  // currentPage is the first field the model reads.
  assert.equal(Object.keys(input)[0], 'currentPage');
  const page = input.currentPage;
  assert.equal(page.id, 'page'); assert.equal(page.kind, 'event');
  assert.match(page.title, /Fleet Week/);
  assert.equal(page.url, `https://www.baylink.us${FLEET}`);
  assert.equal(page.dates, '10月4日（周日） 至 10月12日（周一）', 'dates carry their weekday');
  assert.equal(page.temporalStatus, 'current'); assert.equal(page.temporalLabel, '进行中');
  assert.match(page.venue, /Pier 27/); assert.ok(page.details.length > 0); assert.ok(page.summary.length <= 400);
  // The frozen rule lives in the instructions; the page record leads the evidence.
  assert.match(f.payloads[0].instructions, /If the user says 这个\/這個\/这里\/這裡\/这家\/這家\/这场\/這場\/它\/this\/here\/it without naming something else, they mean currentPage/);
  assert.match(f.payloads[0].instructions, /never ask which item they mean/);
  assert.equal(input.evidence[0].id, 'page');
  assert.equal(input.evidence[0].url, `https://www.baylink.us${FLEET}`);
  assert.match(input.evidence[0].text, /10月4日（周日）/);
  // [[page]] renders as an ordinary numbered citation to the page.
  assert.equal(result.responseMode, 'assistant'); assert.equal(result.degraded, false);
  assert.equal(result.answer, '适合，但先看航空展时段和陡梯限制。[1]');
  assert.equal(result.sources[0].url, `https://www.baylink.us${FLEET}`);
  assert.doesNotMatch(result.answer, /哪一个|哪個/);
});

test('the page rule is frozen text: identical with and without a page, so the system prefix stays cacheable', async () => {
  const f = assistant(() => '好的。');
  await f.ask('这个活动适合带70岁的爸妈去吗？', FLEET);
  await f.ask('这个周末旧金山有什么免费活动？', '/');
  const rule = /currentPage, when present, is the BAYLINK page the user is viewing\.[^\n]*call 911\./;
  const [withPage, withoutPage] = f.payloads.map(payload => payload.instructions.match(rule)?.[0]);
  assert.ok(withPage); assert.equal(withPage, withoutPage);
  assert.equal(JSON.parse(f.payloads[1].input[0].content).currentPage, undefined, 'no page, no currentPage field');
});

test('a coverage or candidate reference to "page" resolves to the real page evidence', async () => {
  const f = assistant(() => '见页面。[[page]]');
  const result = await f.ask('这个活动几点开始？', FLEET);
  const pageEvidence = result.evidence.find(row => row.url === `https://www.baylink.us${FLEET}`);
  assert.ok(pageEvidence, 'the page record is public evidence');
  assert.match(pageEvidence.id, /^s-/, 'the public evidence keeps its stable store id');
  assert.equal(result.sources.length, 1);
});

test('a past event page tells the model it has ended (still there? -> ended, not "which one")', async () => {
  const f = assistant(() => '这个活动已在 10 月 4 日结束。[[page]]');
  const result = await f.ask('这个还有吗？', '/events/santana-row-glass-pumpkin-2026');
  const page = JSON.parse(f.payloads[0].input[0].content).currentPage;
  assert.equal(page.temporalStatus, 'past'); assert.equal(page.temporalLabel, '已结束');
  assert.equal(page.dates, '10月2日（周五） 至 10月4日（周日）');
  assert.match(f.payloads[0].instructions, /If currentPage\.temporalStatus is past or inactive, say so plainly/);
  assert.equal(result.sources[0].url, 'https://www.baylink.us/events/santana-row-glass-pumpkin-2026');
});

test('zh-Hant and English page cards carry localized weekdays and no Chinese date label in English', async () => {
  for (const [locale, dates] of [['zh-Hant', '10月4日（週日） 至 10月12日（週一）'], ['en', 'Sun, Oct 4 – Mon, Oct 12']]) {
    const f = assistant(() => locale === 'en' ? 'Yes. [[page]]' : '可以。[[page]]');
    await f.ask(locale === 'en' ? 'Is this good for my 70-year-old parents?' : '這個活動適合帶 70 歲的爸媽去嗎？', FLEET, locale);
    const page = JSON.parse(f.payloads[0].input[0].content).currentPage;
    assert.equal(page.dates, dates, locale);
    if (locale === 'en') { assert.equal(page.scheduleLabel, undefined); assert.equal(page.temporalLabel, 'ongoing'); }
  }
});

test('B2: on the senior-services guide, "第一步该打哪个电话" brings the county AAA numbers, including 408-350-3200', async () => {
  const f = assistant(input => {
    const guide = input.evidence.find(row => row.kind === 'guide' && /408-350-3200/.test(row.text));
    return guide ? `San Jose 属于 Santa Clara 县，先打县老龄服务 408-350-3200。[[${guide.id}]]` : '没有找到电话。';
  });
  const result = await f.ask('我妈在 San Jose，第一步该打哪个电话？', SENIOR);
  const input = JSON.parse(f.payloads[0].input[0].content);
  assert.ok(input.evidence.some(row => row.kind === 'guide' && row.text.includes('408-350-3200')), 'the guide paragraph with the Santa Clara number is evidence');
  assert.equal(input.currentPage.kind, 'guide');
  assert.match(result.answer, /408-350-3200/);
  assert.ok(result.sources.some(row => row.url === SENIOR));
});

test('the current guide is boosted, not exclusive: unrelated questions keep global retrieval', () => {
  const evidence = (message, extra) => buildSiteEvidence({ query: message, originalQuery: message, state: resolveTaskState({ message, today: TODAY, catalog }).state,
    guideCatalog, catalog, today: TODAY, currentPath: SENIOR, selectedGuideUrls: [SENIOR], ...extra });
  const phone = evidence('我妈在 San Jose，第一步该打哪个电话？');
  // At most three boosted paragraphs from the open guide; other guides still compete.
  assert.ok(phone.guides.filter(row => row.url === SENIOR).length <= 3);
  assert.ok(phone.guides.some(row => row.url !== SENIOR));
  assert.ok(phone.guides.some(row => row.text.includes('408-350-3200')));
  // Without the page the same question does not find that paragraph (the B2 failure).
  const withoutPage = evidence('我妈在 San Jose，第一步该打哪个电话？', { currentPath: '/', selectedGuideUrls: [] });
  assert.ok(!withoutPage.guides.some(row => row.text.includes('408-350-3200')));
  // A question that shares no words with the open guide is not polluted by it.
  const unrelated = evidence('BART transit timetable and fare');
  assert.ok(!unrelated.guides.some(row => row.url === SENIOR));
});

test('a professional topic boosts its pillar guide even when another guide is open', async () => {
  const f = assistant(input => {
    const pillar = input.evidence.find(row => row.kind === 'guide' && row.url === '/guides/bay-area-medicare-hicap-medi-cal-guide');
    return pillar ? `A 是住院保险，B 是门诊保险；先找 HICAP。[[${pillar.id}]]` : '没有资料。';
  });
  const result = await f.ask('我爸65岁了，Medicare A和B有什么区别？', '/guides/bay-area-rental-scam-guide');
  const input = JSON.parse(f.payloads[0].input[0].content);
  assert.ok(input.evidence.some(row => row.url === '/guides/bay-area-medicare-hicap-medi-cal-guide'), 'the pillar guide is evidence');
  assert.equal(result.safetyRoute, 'professional'); assert.equal(result.safetyTopic, 'medicare');
  assert.equal(result.suggestedGuides[0].slug, 'bay-area-medicare-hicap-medi-cal-guide');
});
