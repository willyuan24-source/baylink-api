// API-BB-10: fixes from the #58 live check (10-17). Every test is offline ($0): Anthropic is a fixture that answers
// with the live drafts, on the shipped data with a fixed day.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { repairBenefitCoverage } = require('../lib/baybayBenefitScope');
const { loadPlannerCatalog } = require('../lib/planner');

const NOW = Date.parse('2026-10-18T01:45:00Z'); // Sat 2026-10-17 18:45 PDT, the live check
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', BAYBAY_ENGINE: 'v2' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const message = content => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content, usage: { input_tokens: 40, output_tokens: 60 } });
const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
/** One live question through the v2 fast path; `draft(evidence, ref)` builds the model's JSON from the evidence it was sent. */
async function ask(question, draft, { locale = 'zh-Hans', history = [], assistantSessionToken } = {}) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: base, guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body);
      const context = JSON.parse(body.messages[0].content[0].text);
      sent.push(context);
      const ref = test => context.evidence.find(test)?.ref;
      return reply(message([{ type: 'text', text: JSON.stringify({ lead: '', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...draft(context.evidence, ref) }) }]));
    } });
  const response = await assistant.run({ message: question, locale, currentPath: '/', history, searchMode: 'site', webAccess: { allowed: false }, ...(assistantSessionToken ? { assistantSessionToken } : {}) });
  return { response, sent };
}
const coverageItem = (response, id) => response.answerCoverage.items.find(item => item.id === id);
const coverageSources = (response, id) => coverageItem(response, id).sourceIds.map(sourceId => response.evidence.find(row => row.id === sourceId));

// ---------------------------------------------------------------- 1. SFPL card + Kanopy from Fremont (live Q3)

const Q3 = {
  'zh-Hans': { question: '我住 Fremont，可以办 SFPL 借书证和用 Kanopy 吗？', lead: '可以办 SFPL 卡，Kanopy 要看你的卡是否有效绑定，Fremont 居民可先到馆办卡。',
    points: ['加州居民可免费办 SFPL 卡，首次领卡需到馆核验照片证件。', 'Kanopy 需有效 SFPL 图书证并绑定卡号，不是无限次观看。', '你住 Fremont，本地 AC Library 的卡不能直接套用 SFPL 的 Kanopy 权益。'],
    kanopy: '持有效 SFPL 图书证并完成 Kanopy 绑定即可免费观看，非无限次，每月额度以登录页为准。', card: '加州居民可免费办 SFPL 卡，首次领卡需到馆核验照片证件。' },
  'zh-Hant': { question: '我住 Fremont，可以辦 SFPL 借書證和用 Kanopy 嗎？', lead: '可以辦 SFPL 卡，Kanopy 要看你的卡是否有效綁定，Fremont 居民可先到館辦卡。',
    points: ['加州居民可免費辦 SFPL 卡，首次領卡需到館核驗照片證件。', 'Kanopy 需有效 SFPL 圖書證並綁定卡號，不是無限次觀看。', '你住 Fremont，本地 AC Library 的卡不能直接套用 SFPL 的 Kanopy 權益。'],
    kanopy: '持有效 SFPL 圖書證並完成 Kanopy 綁定即可免費觀看，非無限次，每月額度以登入頁為準。', card: '加州居民可免費辦 SFPL 卡，首次領卡需到館核驗照片證件。' },
  en: { question: 'I live in Fremont. Can I get an SFPL library card and use Kanopy?', lead: 'Yes: California residents can get an SFPL card, then link it to Kanopy.',
    points: ['California residents can get a free SFPL card; the first pickup needs photo ID at a branch.', 'Kanopy needs a valid SFPL card linked to your account, and viewing is limited.', 'Your AC Library card from Fremont does not carry SFPL’s Kanopy access.'],
    kanopy: 'A valid SFPL card linked to Kanopy gives free streaming, with monthly limits shown at sign-in.', card: 'California residents can get a free SFPL card and must show photo ID at a branch to collect it.' },
};
const q3Draft = copy => (evidence, ref) => {
  const kanopy = ref(row => /sfpl-kanopy-streaming/.test(row.url || '') || /SFPL 图书证，在家免费看片|SFPL 圖書證，在家免費看片|Stream films at home|Kanopy/.test(row.title || '') && row.kind === 'offer');
  const perks = ref(row => row.kind === 'guide' && /湾区免费生活清单|灣區免費生活清單|everyday free|Free Bay Area/i.test(row.title || ''));
  assert.ok(kanopy, 'the Kanopy record is in the evidence'); assert.ok(perks, 'the perks guide is in the evidence');
  return { lead: copy.lead, points: [{ text: `${copy.points[0]}[[${kanopy}]]`, cardIds: [] }, { text: `${copy.points[1]}[[${perks}]]`, cardIds: [kanopy] }, { text: `${copy.points[2]}[[${perks}]]`, cardIds: [] }],
    coverage: [{ id: 'kanopy', status: 'answered', summary: copy.kanopy, sourceIds: [perks, kanopy] }, { id: 'card_eligibility', status: 'answered', summary: copy.card, sourceIds: [kanopy] }] };
};

for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
  test(`${locale}: a cited, correct SFPL card + Kanopy answer is not degraded and its card item cites the Kanopy record`, async () => {
    const { response } = await ask(Q3[locale].question, q3Draft(Q3[locale]), { locale });
    assert.equal(response.degraded, false);
    assert.ok(!response.research.warnings.includes('answer_benefit_scope_corrected'), response.research.warnings.join());
    assert.equal(response.answerCoverage.status, 'complete');
    assert.equal(coverageItem(response, 'card_eligibility').status, 'answered');
    for (const id of ['kanopy', 'card_eligibility']) {
      for (const source of coverageSources(response, id)) {
        assert.ok(source, `${id}: every coverage id has its public evidence row`);
        assert.doesNotMatch(`${source.title} ${source.url}`, /radon|氡|省钱攻略|省錢攻略|freebies-deals/i, `${id}: ${source.title}`);
      }
    }
    assert.ok(coverageSources(response, 'card_eligibility').some(source => /sfpl-kanopy-streaming/.test(source.url)));
    assert.equal(response.points.length, 3);
    assert.ok(response.points.every(point => /\[\d\]/.test(point.text)), 'every point keeps its citation');
  });
}

test('a real SFPL residency error is still repaired, and the repair never cites the radon-detector loan', () => {
  // The scopes the live Q3 turn read (work/probe-q3.cjs), cut to the SFPL ones the repair groups.
  const scopes = [
    { entity: 'SFPL', entityKey: 'sfpl', heading: 'SFPL · KANOPY：用 SFPL 图书证，在家免费看片', sourceIds: ['perks', 'kanopy-official'],
      text: '五区日常福利，按条件慢慢挑\nSFPL · KANOPY：用 SFPL 图书证，在家免费看片\n长期资源 · 片库与观看额度依账户显示\n须有有效 SFPL 图书证并完成 Kanopy 账户绑定；加州居民可免费办 SFPL 卡，首次领卡需到馆核验照片证件。不是无限次观看。' },
    { entity: 'SFPL', entityKey: 'sfpl', heading: '旧金山 · SFPL Discover & Go：旧金山市县居民用借书证号和 PIN 登录 sfpl.discoverandgo.net，预约博物馆、科学馆、动物园和剧院的门票', sourceIds: ['starter'],
      text: '用图书馆卡借博物馆票和公园通行证\n旧金山 · SFPL Discover & Go：旧金山市县居民用借书证号和 PIN 登录 sfpl.discoverandgo.net，预约博物馆、科学馆、动物园和剧院的门票；同时最多 2 个预约，最多提前 3 个月。' },
    { entity: 'SFPL', entityKey: 'sfpl', heading: 'SAN FRANCISCO PUBLIC LIBRARY：SFPL 图书证可免费借氡探测器', sourceIds: ['october', 'radon'],
      text: '十月有效优惠与后续预告\nSAN FRANCISCO PUBLIC LIBRARY：SFPL 图书证可免费借氡探测器\n常设借用 · 最长 21 天\n持 SFPL 图书证借用，可在线预约；设备先到先得，最长借期 21 天，用后须归还。\n图书馆 2026 年新增的家用设备服务，所有分馆均可办理，归还可到任一分馆。' },
  ];
  const good = { status: 'complete', items: [{ id: 'card_eligibility', status: 'answered', summary: '加州居民可免费办 SFPL 卡，首次领卡需到馆核验照片证件。', sourceIds: ['kanopy'] },
    { id: 'kanopy', status: 'answered', summary: '加州居民可免费办 SFPL 卡，绑定后即可用 Kanopy 看片。', sourceIds: ['kanopy'] }] };
  assert.equal(repairBenefitCoverage(good, scopes, 'zh-Hans').changed, false);
  const bad = { status: 'complete', items: [{ id: 'card_eligibility', status: 'answered', summary: 'SFPL 要求旧金山居民才能办卡。', sourceIds: ['kanopy'] }] };
  const repaired = repairBenefitCoverage(bad, scopes, 'zh-Hans');
  assert.equal(repaired.changed, true);
  const item = repaired.coverage.items[0];
  assert.match(item.summary, /加州居民可免费办 SFPL 卡/);
  assert.doesNotMatch(item.summary, /氡|设备|旧金山居民才能/);
  assert.ok(!item.sourceIds.includes('radon') && !item.sourceIds.includes('october'), item.sourceIds.join());
  assert.deepEqual(item.sourceIds, ['perks', 'kanopy-official']);
});

// ---------------------------------------------------------------- 4. "这周末 10/24" is Sat 10/24 and Sun 10/25 (live Q5)

const { resolveTaskState } = require('../lib/baybayState');
const stateOf = (message, previous) => resolveTaskState({ message, today: '2026-10-17', catalog, carry: true, ...(previous ? { previous } : {}) });

test('a weekend word beside a written Saturday or Sunday is that whole weekend, in zh-Hans, zh-Hant and en', () => {
  for (const message of ['这周末 10/24 带娃去哪', '這週末 10/24 帶娃去哪', '这周末10月24日带娃去哪', '10/24 这个周末带孩子去哪玩', '10月24号周末带娃去哪玩', '周末 10/25 带娃去哪',
    'This weekend (10/24), where can we go with the kids?', 'Oct 24 weekend events for kids']) {
    const { state } = stateOf(message);
    assert.deepEqual(state.dateRange, { start: '2026-10-24', end: '2026-10-25' }, message);
    assert.equal(state.date, null, message);
  }
  // A weekday beside 周末 and a date without 周末 keep their one day; a bare 这周末 is still this weekend.
  assert.equal(stateOf('这周末 10/23 带娃去哪').state.date, '2026-10-23');
  assert.equal(stateOf('10/24 带娃去哪').state.date, '2026-10-24');
  assert.deepEqual(stateOf('这周末带娃去哪').state.dateRange, { start: '2026-10-17', end: '2026-10-18' });
  // A one-day plan keeps the day it writes out.
  const plan = stateOf('帮我安排这周末 10/24 带娃一日游').state;
  assert.equal(plan.goal, 'day-plan'); assert.equal(plan.date, '2026-10-24');
});

test('review round 1: full-width separators, a second date and a time of day beside "周末 10/24"', () => {
  // Chinese keyboards type full-width punctuation: the span still covers the written day.
  for (const message of ['这周末（10/24）带娃去哪', '周末（10/24）有什么活动', '这周末，10/24，带娃去哪', '这周末：10/24 带娃去哪',
    // The weekend's other day offered beside it is the same span.
    '周末 10/24 还是 10/25 去比较好', '这周末 10/24 或 10/25 带娃', '10/24 还是 10/25 周末去哪', '这周末 10/24、10/25 带娃去哪']) {
    const { state } = stateOf(message);
    assert.deepEqual(state.dateRange, { start: '2026-10-24', end: '2026-10-25' }, message); assert.equal(state.date, null, message);
  }
  // Another date outside that weekend: the ask names several days, as before this lane (no silent 10/31).
  for (const message of ['周末 10/24 或 10/31 都行，去哪玩', 'weekend 10/24 or 10/31, where to go']) {
    const result = stateOf(message);
    assert.equal(result.state.date, null, message); assert.equal(result.state.dateRange, undefined, message); assert.match(result.clarification || '', /多个日期/, message);
  }
  assert.deepEqual(stateOf('这周末 10/24，下周末 10/31 都可以').state.dateRange, { start: '2026-10-24', end: '2026-10-25' });
  // The weekend's other day asked on its own is that day ("这周末 10/24 去 SJMA，10/25 去哪").
  assert.equal(stateOf('这周末 10/24 去 SJMA，10/25 去哪').state.date, '2026-10-25');
  // A clock time or part of the day right after the date asks about that one day.
  for (const message of ['这周末 10/24 下午3点有什么', '周末 10/24 晚上有什么演出']) assert.equal(stateOf(message).state.date, '2026-10-24', message);
});

test('review round 2: a weekday written beside the date is part of the span, never this week\'s Saturday or Sunday', () => {
  // "10月24日（周六）" is how Chinese dates are often written; the weekday left over was read as this Saturday (10/17).
  for (const message of ['这周末 10月24日（周六）带娃去哪', '这周末 10/24（周六）带娃去哪', '这周末 10/24 周六 带娃去哪', '这周末 10月24日 星期六 带娃去哪',
    '這週末 10/24（週六）帶娃去哪', 'This weekend (10/24, Saturday), where to go?', 'weekend 10/24 (Sat) kids', '这周末 10/25（周日）带娃去哪', '这周末 10/25 星期天去哪',
    '这周末 10/24（六）带娃去哪', '这周末 10/24（周六）或 10/25（周日）带娃', '10/24（周六）还是 10/25 周末去哪', 'weekend Oct 24, Sat., kids']) {
    const { state } = stateOf(message);
    assert.deepEqual(state.dateRange, { start: '2026-10-24', end: '2026-10-25' }, message); assert.equal(state.date, null, message);
  }
  // A weekday that does not match the date still asks to confirm (as before this lane); a part of the day after the weekday,
  // or a weekday written before the date, keeps the one written day.
  for (const message of ['这周末 10/24（周日）去哪', 'weekend 10/24 (Sun) kids']) {
    const result = stateOf(message);
    assert.notEqual(result.state.date, '2026-10-18', message); assert.match(result.clarification || '', /星期不一致/, message);
  }
  for (const message of ['这周末 10/24 周六上午有什么', '这周末 10/24 (周六) 下午有什么', '这周末 周六 10/24 带娃去哪', '帮我安排这周末 10/24（周六）带娃一日游']) {
    assert.equal(stateOf(message).state.date, '2026-10-24', message);
  }
  // A weekday, today or tomorrow elsewhere in the ask is not folded into the span: the ask reads as it did before this lane
  // (the written-day span never hands the leftover word the whole date).
  const before = { '这周末 10/24，周六或周日都行': undefined, '这周末 10/24 带娃去哪，周六有雨吗': /多个日期/, '这周末 10/24 还是明天': undefined, '这周末 10/24，周日去公园': /星期不一致/ };
  for (const [message, clarification] of Object.entries(before)) {
    const result = stateOf(message);
    assert.equal(result.state.date, null, message);
    if (clarification) assert.match(result.clarification || '', clarification, message);
  }
});

// ---------------------------------------------------------------- 5. home city vs the service's city (live Q3)

test('a library service asked from home keeps the home city as the origin and does not move the scope to the institution\'s city', () => {
  for (const message of [Q3['zh-Hans'].question, Q3['zh-Hant'].question, Q3.en.question]) {
    const { state, clarification } = stateOf(message);
    assert.equal(state.origin, 'Fremont', message);
    assert.equal(state.city, null, message); assert.equal(state.region, null, message);
    assert.equal(clarification, undefined, message);
  }
  // A trip to the library's city is still a destination, and a plain SFPL question is still about SF.
  assert.equal(stateOf('我住 Fremont，想去旧金山图书馆办卡').state.city, 'San Francisco');
  assert.equal(stateOf('SFPL 借书证怎么办？').state.city, 'San Francisco');
});

test('after the Fremont SFPL question, a follow-up is not scoped to San Francisco', async () => {
  const first = await ask(Q3['zh-Hans'].question, q3Draft(Q3['zh-Hans']));
  assert.equal(first.response.taskState.origin, 'Fremont');
  assert.equal(first.response.taskState.city, null);
  const { state } = stateOf('那这周末附近有什么免费亲子活动？', first.response.taskState);
  assert.notEqual(state.city, 'San Francisco'); assert.notEqual(state.region, 'sf');
  assert.equal(state.origin, 'Fremont');
});

// ---------------------------------------------------------------- 6. the editor's 10/24–25 picks on the live Q5 ask

test('with the synced picks file, "这周末 10/24 带娃去哪" leads with the editor\'s 10/24–25 picks (fixture = WEB-PICKS-EXPORT)', () => {
  const path = require('path');
  const { buildFastEvidence } = require('../lib/baybayEvidence');
  const { normalizeGuideQuery } = require('../lib/guideLocale');
  const { loadDiscoveryCatalog } = require('../lib/publicContext');
  const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
  const message = '这周末 10/24 带娃去哪';
  const candidateIds = () => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state: stateOf(message).state,
    guideCatalog: guides, catalog, discoveries, today: '2026-10-17', locale: 'zh-Hans', audience: true }).candidates.map(row => row.id);
  const before = process.env.BAYLINK_WEEKEND_PICKS_FILE;
  let withPicks, without;
  try {
    process.env.BAYLINK_WEEKEND_PICKS_FILE = path.join(__dirname, 'fixtures', 'missing-weekend-picks.json');
    without = candidateIds();
    process.env.BAYLINK_WEEKEND_PICKS_FILE = path.join(__dirname, 'fixtures', 'weekend-picks-web.json');
    withPicks = candidateIds();
  } finally { if (before === undefined) delete process.env.BAYLINK_WEEKEND_PICKS_FILE; else process.env.BAYLINK_WEEKEND_PICKS_FILE = before; }
  const PICKS = ['r2-petaluma-lumafest-20261024', 'menlo-park-halloween-hoopla-2026', 'sfpl-chinatown-creative-saturdays-fall-2026', 'acl-cherryland-chinese-storytimes-oct24-2026', 'san-jose-sjma-dia-muertos-community-2026'];
  const shown = withPicks.slice(0, 8);
  // The live answer (no file) had 1 of the 5; with the file at least 4 of them are among the first 8 candidates.
  assert.ok(PICKS.filter(id => shown.includes(id)).length >= 4, shown.join());
  assert.ok(PICKS.filter(id => without.slice(0, 8).includes(id)).length < PICKS.filter(id => shown.includes(id)).length);
});

test('a point with an event\'s child prices keeps the adult tier its record lists (zh-Hans, zh-Hant, en)', () => {
  const { adultTierRepair } = require('../lib/baybayQuality');
  const events = require('../data/planner-catalog.json').events;
  const costOf = id => events.find(row => row.id === id).costLabel;
  assert.match(costOf('alameda-haunted-house-2026'), /18\+ \$8/);
  // Review round 1: the tier is its own sentence after the point's text, before the trailing marker, in the answer's locale,
  // although the evidence cost is the Chinese planner label in every locale.
  const cases = [
    ['zh-Hans', 'alameda-haunted-house-2026', 'Alameda 青少年鬼屋 14:00–21:00，0–3 岁免费，4–14 岁 $5。[[e7]]', 'Alameda 青少年鬼屋 14:00–21:00，0–3 岁免费，4–14 岁 $5。18+ 成人 $8。[[e7]]'],
    ['zh-Hant', 'alameda-haunted-house-2026', 'Alameda 青少年鬼屋 14:00–21:00，0–3 歲免費，4–14 歲 $5 [[e7]]', 'Alameda 青少年鬼屋 14:00–21:00，0–3 歲免費，4–14 歲 $5。18+ 成人 $8。 [[e7]]'],
    ['en', 'alameda-haunted-house-2026', 'Alameda teen haunted house, 2–9 pm: free under 4, ages 4–14 $5. [[e7]]', 'Alameda teen haunted house, 2–9 pm: free under 4, ages 4–14 $5. Adults 18+: $8. [[e7]]'],
    ['en', 'sfzoo-zoolights-2026', 'ZooLights runs nightly; kids $21. [[e7]]', 'ZooLights runs nightly; kids $21. Adults: $30. [[e7]]'],
    ['en', 'pleasanton-pumpkins-after-dark-2026', 'Pumpkins After Dark: ages 4–17 $22.80, under 4 free [[e7]]', 'Pumpkins After Dark: ages 4–17 $22.80, under 4 free. Adults 18+: $28.80. [[e7]]'],
    ['zh-Hans', 'pleasanton-pumpkins-after-dark-2026', '南瓜夜：4–17 岁 $22.80，3 岁及以下免费。[[e7]]', '南瓜夜：4–17 岁 $22.80，3 岁及以下免费。18+ 成人 $28.80。[[e7]]'],
  ];
  for (const [locale, id, text, expected] of cases) {
    const result = adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: ref => ref === 'e7' ? costOf(id) : null, locale });
    assert.equal(result.repaired, true, `${locale} ${id}`); assert.equal(result.draft.points[0].text, expected, `${locale} ${id}`);
    assert.doesNotMatch(locale === 'en' ? result.draft.points[0].text : '', /[成岁歲]/);
  }
  // Left alone: a point that already gives the range or an adult price (not $80 for $8), a point without child prices, another
  // record, and a cost line with two price periods (Dickens: early-bird adult $40 vs regular $50 from 11/1).
  const alameda = costOf('alameda-haunted-house-2026');
  for (const text of ['门票 $5–$8 [[e7]]', '4–14 岁 $5，成人 $8 [[e7]]', '4–14 岁 $5，18+ $9 [[e7]]', 'Alameda 鬼屋周五至周日开放 [[e7]]', 'Michaels 免费手作 [[e1]]']) {
    assert.equal(adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: ref => ref === 'e7' ? alameda : null }).repaired, false, text);
  }
  assert.equal(adultTierRepair({ points: [{ text: '4–14 岁 $5，停车 $80 [[e7]]', cardIds: [] }] }, { costOf: () => alameda }).repaired, true);
  for (const text of ['11/1 起普通票 5–12 岁 $30。[[e7]]', '早鸟票 5–12 岁 $25。[[e7]]', 'Regular tickets from Nov 1: ages 5–12 $30. [[e7]]']) {
    assert.equal(adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => costOf('dickens-christmas-fair-2026'), locale: /[a-z]/i.test(text[0]) ? 'en' : 'zh-Hans' }).repaired, false, text);
  }
});

test('review round 1: a streamed point continued by the adult tier is not marked corrected', () => {
  const { adultTierRepair } = require('../lib/baybayQuality');
  const { draftCorrected } = require('../lib/baybayProgress');
  const cost = require('../data/planner-catalog.json').events.find(row => row.id === 'alameda-haunted-house-2026').costLabel;
  for (const [locale, streamed] of [['zh-Hans', 'Alameda 青少年鬼屋 0–3 岁免费，4–14 岁 $5。'], ['en', 'Alameda teen haunted house: free under 4, ages 4–14 $5.']]) {
    const { draft } = adultTierRepair({ points: [{ text: `${streamed}[[e7]]`, cardIds: [] }] }, { costOf: () => cost, locale });
    const final = draft.points[0].text.replace('[[e7]]', '[3]');
    assert.notEqual(final, `${streamed}[3]`);
    assert.equal(draftCorrected({ lead: '', points: [streamed] }, { lead: '', points: [{ text: final }] }), false, locale);
  }
});

// ---------------------------------------------------------------- 3. the CHSA registration page is a link (live Q2)

const Q2 = {
  'zh-Hant': ['11月15日 CHSA 台灣華人尋根講座怎麼報名？', '可依主辦方傳單的報名頁 LoveBoatAlumni.org/roots2026 報名，10月15日起已開放。', 'CHSA 活動頁上的報名短連結目前會跳到無關網頁，請改用傳單上的報名頁 LoveBoatAlumni.org/roots2026。'],
  'zh-Hans': ['11月15日 CHSA 台湾华人寻根讲座怎么报名？', '可按主办方传单的报名页 LoveBoatAlumni.org/roots2026 报名，10月15日起已开放。', 'CHSA 活动页上的报名短链接现在会跳到无关网页，请改用传单上的报名页 LoveBoatAlumni.org/roots2026。'],
  en: ['How do I register for the CHSA roots seminar on November 15?', 'Register on the flyer’s page, LoveBoatAlumni.org/roots2026; sign-up opened Oct 15.', 'The short link on CHSA’s event page goes to an unrelated page, so use LoveBoatAlumni.org/roots2026 from the flyer.'],
};
for (const locale of ['zh-Hant', 'zh-Hans', 'en']) {
  test(`${locale}: the registration page the CHSA record writes out is a link in the lead and the point; an address no record gives stays text`, async () => {
    const [question, lead, point] = Q2[locale];
    const { response, sent } = await ask(question, (evidence, ref) => {
      const chsa = ref(row => /chsa-taiwanese-chinese-roots-seminar-2026/.test(row.page || '') || /寻根|尋根|Roots/i.test(row.title || ''));
      assert.ok(chsa, 'the CHSA record is in the evidence');
      return { lead: `${lead}[[${chsa}]]`, points: [{ text: `${point}[[${chsa}]]`, cardIds: [chsa] }, { text: `也可看 example.org/roots 的介绍。[[${chsa}]]`, cardIds: [] }], candidateIds: [chsa] };
    }, { locale });
    assert.ok(sent[0].evidence.some(row => /LoveBoatAlumni\.org\/roots2026/.test(row.text || '')), 'the record text the model read has the page');
    const link = '[LoveBoatAlumni.org/roots2026](https://LoveBoatAlumni.org/roots2026)';
    assert.ok(response.lead.includes(link), response.lead);
    assert.ok(response.points[0].text.includes(link), response.points[0].text);
    assert.doesNotMatch(response.points[1].text, /\]\(https?:/);
    assert.ok(response.points[1].text.includes('example.org/roots'));
    assert.notEqual(response.corrected, true);
  });
}

test('a streamed draft that showed the address as text is continued, not corrected, by the linked result', () => {
  const { draftCorrected } = require('../lib/baybayProgress');
  assert.equal(draftCorrected({ lead: '报名页是 LoveBoatAlumni.org/roots2026', points: [] }, { lead: '报名页是 [LoveBoatAlumni.org/roots2026](https://LoveBoatAlumni.org/roots2026)。[1]', points: [] }), false);
});
