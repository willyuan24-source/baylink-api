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
// The API-BB-10 fallback (review round 6) put features back to main 8eec008; their tests stay here as todo for follow-up lane API-BB-11.
const HOME_CITY_TODO = 'API-BB-10 fallback: the home-city library reading is main 8eec008 again; follow-up lane API-BB-11';
const WEEKEND_DAY_TODO = 'API-BB-10 fallback: the weekend-day span ("这周末 10/24" as Sat + Sun) is main 8eec008 again; follow-up lane API-BB-11';
const ADULT_TIER_TODO = 'API-BB-10 fallback: the adult price tier repair is removed, as on main 8eec008; follow-up lane API-BB-11';

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
  // The scopes the live 10-17 Q3 turn read, cut to the SFPL ones the repair groups.
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

test('a weekend word beside a written Saturday or Sunday is that whole weekend, in zh-Hans, zh-Hant and en', { todo: WEEKEND_DAY_TODO }, () => {
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

test('review round 1: full-width separators, a second date and a time of day beside "周末 10/24"', { todo: WEEKEND_DAY_TODO }, () => {
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
  // Review round 4: the weekend's other day written apart ("这周末 10/24 去 SJMA，10/25 去哪") is read as on main; the span never
  // hands the leftover day the whole date (it could be the busy day, see review round 4 below).
  assert.deepEqual(resolveTaskState({ message: '这周末 10/24 去 SJMA，10/25 去哪', today: '2026-10-22', catalog, carry: true }).state.dateRange, { start: '2026-10-24', end: '2026-10-25' });
  // A clock time or part of the day right after the date asks about that one day.
  for (const message of ['这周末 10/24 下午3点有什么', '周末 10/24 晚上有什么演出']) assert.equal(stateOf(message).state.date, '2026-10-24', message);
});

test('review round 2: a weekday written beside the date is part of the span, never this week\'s Saturday or Sunday', { todo: WEEKEND_DAY_TODO }, () => {
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

test('a library service asked from home keeps the home city as the origin and does not move the scope to the institution\'s city', { todo: HOME_CITY_TODO }, () => {
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

test('after the Fremont SFPL question, a follow-up is not scoped to San Francisco', { todo: HOME_CITY_TODO }, async () => {
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

test('a point with an event\'s child prices keeps the adult tier its record lists (zh-Hans, zh-Hant, en)', { todo: ADULT_TIER_TODO }, () => {
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
    // Review round 2: a floor price keeps its 起 / from.
    ['zh-Hans', 'sf-botanical-lightscape-2026', '植物园灯光夜：5–17 岁 $20 起，4 岁及以下免费。[[e7]]', '植物园灯光夜：5–17 岁 $20 起，4 岁及以下免费。成人 $32 起。[[e7]]'],
    ['en', 'sf-botanical-lightscape-2026', 'Botanical Garden Lightscape: ages 5–17 from $20, under 5 free. [[e7]]', 'Botanical Garden Lightscape: ages 5–17 from $20, under 5 free. Adults: from $32. [[e7]]'],
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
  // Review round 5 (allowlist grammar): Pumpkins After Dark's line ends in a parking fee with a payment condition ("停车 $15（只收
  // 刷卡和手机支付）"), a segment that is not an age band, so its points are left alone.
  assert.match(costOf('pleasanton-pumpkins-after-dark-2026'), /停车 \$15（只收刷卡和手机支付）/);
  for (const [locale, text] of [['en', 'Pumpkins After Dark: ages 4–17 $22.80, under 4 free [[e7]]'], ['zh-Hans', '南瓜夜：4–17 岁 $22.80，3 岁及以下免费。[[e7]]']]) {
    assert.equal(adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => costOf('pleasanton-pumpkins-after-dark-2026'), locale }).repaired, false, text);
  }
  for (const text of ['11/1 起普通票 5–12 岁 $30。[[e7]]', '早鸟票 5–12 岁 $25。[[e7]]', 'Regular tickets from Nov 1: ages 5–12 $30. [[e7]]']) {
    assert.equal(adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => costOf('dickens-christmas-fair-2026'), locale: /[a-z]/i.test(text[0]) ? 'en' : 'zh-Hans' }).repaired, false, text);
  }
  // Review round 2: a price that holds only before a deadline (camp harmony: "11/15 中午前报名 … 成人 $130 起") would lose the
  // condition in a separate sentence, so it is left alone.
  assert.match(costOf('sffmc-camp-harmony-2026-27'), /中午前报名.*成人 \$130 起/);
  for (const [locale, text] of [['zh-Hans', '和谐营：11/15 中午前报名 3–12 岁 $65 起。[[e7]]'], ['en', 'Camp Harmony: register by Nov 15 noon, ages 3–12 from $65. [[e7]]']]) {
    assert.equal(adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => costOf('sffmc-camp-harmony-2026-27'), locale }).repaired, false, text);
  }
});

test('review round 1: a streamed point continued by the adult tier is not marked corrected', { todo: ADULT_TIER_TODO }, () => {
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

// ---------------------------------------------------------------- review round 3: the reviewers' regression cases

const stateOn = (message, { today = '2026-10-17', previous, searchContext } = {}) => resolveTaskState({ message, today, catalog, carry: true, ...(previous ? { previous } : {}), ...(searchContext ? { searchContext } : {}) });
const askedDateRangeOf = message => require('../lib/entityAliases').askedDateRange(message, '2026-10-17');
const WEEKEND_1024 = { start: '2026-10-24', end: '2026-10-25' };

test('review round 3: a typed weekend day beats the web date bar\'s day and a carried day outside it, in zh-Hans, zh-Hant and en', { todo: WEEKEND_DAY_TODO }, () => {
  for (const today of ['2026-10-17', '2026-10-22']) {
    for (const [message, date] of [['这周末 10/25 周日带娃去哪', '2026-10-24'], ['weekend 10/25 (Sun) with kids', '2026-10-24'], ['这周末 10/24 带娃去哪', '2026-10-25'], ['這週末 10/24 帶娃去哪', '2026-10-24']]) {
      const { state } = stateOn(message, { today, searchContext: { date } });
      assert.deepEqual(state.dateRange, WEEKEND_1024, `${today} ${message} (date bar ${date})`); assert.equal(state.date, null, `${today} ${message}`);
    }
    const { state } = stateOn('这周末 10/24 带娃去哪', { today, previous: { goal: 'discover', date: '2026-10-18' } });
    assert.deepEqual(state.dateRange, WEEKEND_1024, `${today} carried 10/18`); assert.equal(state.date, null);
  }
});

test('review round 3: a follow-up inside the weekend it carries keeps the day the user typed, and both written days are the weekend', { todo: WEEKEND_DAY_TODO }, () => {
  const day = date => ({ goal: 'discover', date });
  for (const today of ['2026-10-17', '2026-10-22']) {
    for (const [message, previous, date] of [['这个周末 10/25 周日带娃去哪', day('2026-10-24'), '2026-10-25'], ['這個週末 10/25 週日帶娃去哪', day('2026-10-24'), '2026-10-25'],
      ['This weekend Oct 25 (Sunday) where to go', day('2026-10-24'), '2026-10-25'], ['那这周末 10/25 呢', day('2026-10-24'), '2026-10-25'], ['这周末 10/24 带娃去哪', day('2026-10-25'), '2026-10-24'],
      ['this weekend 10/24 (Sat) then?', day('2026-10-25'), '2026-10-24'], ['這週末 10/24 週六呢', day('2026-10-25'), '2026-10-24'],
      ['这周末 10/25 周日呢', { goal: 'discover', dateRange: WEEKEND_1024 }, '2026-10-25']]) {
      const { state } = stateOn(message, { today, previous });
      assert.equal(state.date, date, `${today} ${message}`); assert.equal(state.dateRange, undefined, `${today} ${message}`);
    }
    for (const message of ['周末 10/24 跟 10/25 都行', 'weekend Oct 24-25 kids', '这周末 10/24（周六）和 10/25（周日）带娃去哪']) {
      const { state } = stateOn(message, { today, previous: day('2026-10-24') });
      assert.deepEqual(state.dateRange, WEEKEND_1024, `${today} ${message}`); assert.equal(state.date, null, `${today} ${message}`);
    }
  }
});

test('review round 3: a date labelled last / past / previous weekend or 上周末 never becomes the asked weekend', { todo: WEEKEND_DAY_TODO }, () => {
  for (const [today, weekend] of [['2026-10-17', { start: '2026-10-17', end: '2026-10-18' }], ['2026-10-22', WEEKEND_1024]]) {
    for (const message of ['Last weekend (Oct 10) we went to the zoo, what about this weekend?', 'last weekend, Oct 10, was rainy; what about this weekend?', 'Past weekend (Oct 10) was busy, this weekend free',
      'previous weekend (Oct 10) was fun; this weekend?']) {
      assert.deepEqual(stateOn(message, { today }).state.dateRange, weekend, `${today} ${message}`);
    }
  }
  // zh: the past weekend's date is not the span (main read the one date 10/10 and asks whether that is meant).
  for (const message of ['上周末 10/10 去了动物园，这周末去哪', '上個週末（10/10）去過了，這週末還有別的嗎', '上週末 10/10 去過了，這週末去哪', '上一个周末 10/10 去过了，这周末去哪']) {
    const span = askedDateRangeOf(message);
    assert.ok(!span || span.start !== '2026-10-10', message);
    assert.notDeepEqual(stateOn(message).state.dateRange, { start: '2026-10-10', end: '2026-10-11' }, message);
  }
});

test('review round 3: one-day wording and times keep one day; a written year is honoured', { todo: WEEKEND_DAY_TODO }, () => {
  for (const message of ['这周末 10/24 周六有空，去哪玩', '这周末 10/24 周六一天，带娃去哪', '这周末 10/24 当天往返去哪', '这周末 10/24 一整天带娃去哪', '这周末 10/24，周六只有半天', '這週末 10/24 週六有空',
    '這週末 10/24 週六一天就好', 'weekend 10/24, Saturday only', 'weekend 10/24 Saturday only, kids', 'weekend 10/24, one day only', 'this weekend 10/24, the whole day',
    '这周末 10/24 早晨去爬山', '这周末 10/24 午后去哪', '这周末 10/24 凌晨看流星', '周末 10/24 半夜有什么', '周末 10/24 下班后去哪', 'weekend 10/24 at noon', 'weekend 10/24 for dinner',
    '这周末 10/24 带娃 10:30 出发', '这周末 10/24 带娃去哪，下午三点出发', '這週末 10/24 帶娃，下午三點出發', 'weekend 10/24 Saturday, back by 5pm', '这周末 10/24 白天带娃去哪',
    '这周末 10/24，周六去公园']) {
    for (const today of ['2026-10-17', '2026-10-22']) {
      const { state } = stateOn(message, { today });
      assert.equal(state.date, '2026-10-24', `${today} ${message}`); assert.equal(state.dateRange, undefined, `${today} ${message}`);
    }
  }
  for (const [message, range] of [['2027年10月24日周末去哪', { start: '2027-10-23', end: '2027-10-24' }], ['weekend Oct 24, 2027', { start: '2027-10-23', end: '2027-10-24' }],
    ['这周末 2027年10月23日 去哪', { start: '2027-10-23', end: '2027-10-24' }]]) {
    assert.deepEqual(stateOn(message).state.dateRange, range, message);
  }
  // Review round 4: a weekend that has already ended is read as on main (the written day, with main's past-date handling).
  assert.equal(stateOn('2025年10月25日周末去了哪').state.date, '2025-10-25');
  // A departure time main reads as no date stays so (no weekend span either).
  assert.equal(stateOn('weekend Oct 24 leaving at 10:30').state.dateRange, undefined);
  // A holiday's own weekend and a deadline before the weekend keep the written day, as on main.
  assert.equal(stateOn('感恩节周末 11/28 去哪').state.date, '2026-11-28');
  assert.equal(stateOn('报名截止 10/24 周末前').state.date, '2026-10-24');
});

test('review round 3: weekday words inside ordinary words do not reject the span, and a rejected span never falls back to this weekend', { todo: WEEKEND_DAY_TODO }, () => {
  for (const today of ['2026-10-17', '2026-10-22']) {
    for (const message of ['the sun is out this weekend 10/24', '这周末 10/24 每周一次的亲子课', '这周末 10/24 每周三次的游泳课停了，去哪', 'we sat at home last time; weekend 10/24 ideas?', 'weekend 10/24 sat or sun']) {
      const { state } = stateOn(message, { today });
      assert.deepEqual(state.dateRange, WEEKEND_1024, `${today} ${message}`); assert.equal(state.date, null, `${today} ${message}`);
    }
  }
  // On Saturday 10/17 the written 10/24 is not this weekend: no 10/17-18 span when the weekend-day reading steps aside.
  for (const message of ['这周末 10/24 周六周日都行', 'This weekend 10/24 - Saturday or Sunday is fine', '这周末 10/24 或者 11/1 都可以', '这周末 10/24 周日带娃去哪']) {
    const { state } = stateOn(message);
    assert.notDeepEqual(state.dateRange, { start: '2026-10-17', end: '2026-10-18' }, message);
    assert.notEqual(state.date, '2026-10-18', message);
  }
});

test('review round 3: a museum-pass clause after a ； stays the pass\'s rule (shipped SMCL and SFPL sections, zh + en)', () => {
  for (const [locale, file, marker, kanopyClaim, cardClaim, leak] of [
    ['en', 'guide-catalog.en.json', 'SMCL: Kanopy allowances', 'SMCL Kanopy gives 30 tickets a month, but eCards are excluded.', 'SMCL eCards are excluded; apply for a physical card.', /two active reservations/],
    ['zh-Hans', 'guide-catalog.json', 'SMCL：Kanopy 每月额度', 'SMCL 的 Kanopy 每月 30 tickets，但 eCard 不适用。', 'SMCL 的 eCard 不适用，需到馆申请图书证。', /最多同时保留两笔预约/]]) {
    const guide = require(`../data/${file}`).find(row => row.slug === 'bay-area-everyday-free-perks');
    const at = guide.content.indexOf(marker);
    const text = guide.content.slice(at, guide.content.indexOf('\n\n', at));
    const scopes = [{ id: 'smcl', heading: text.split('\n')[0], entity: 'SMCL', entityKey: 'smcl', text, sourceIds: ['s'] }];
    for (const [id, summary] of [['kanopy', kanopyClaim], ['card_eligibility', cardClaim]]) {
      const out = repairBenefitCoverage({ status: 'complete', items: [{ id, label: id, status: 'answered', summary, sourceIds: ['s'] }] }, scopes, locale, new Map());
      assert.equal(out.changed, true, `${locale} ${id}`); assert.equal(out.coverage.items[0].status, 'unknown', `${locale} ${id}`);
      assert.doesNotMatch(out.coverage.items[0].summary, leak, `${locale} ${id}`);
    }
  }
  // The shipped SFPL Discover & Go paragraph: its reservation limit and the Bay Area Discovery Museum pass never become printing
  // statements in a repaired SFPL printing item.
  const starter = require('../data/guide-catalog.json').find(row => row.slug === 'bay-area-library-starter-guide');
  const paragraph = starter.content.split(/\n\n+/).find(part => part.startsWith('旧金山 · SFPL Discover & Go'));
  assert.match(paragraph, /同时最多 2 个预约/);
  const scopes = [{ id: 'starter', heading: paragraph.split('\n')[0], entity: 'SFPL', entityKey: 'sfpl', text: `用图书馆卡借博物馆票和公园通行证\n${paragraph}`, sourceIds: [] }];
  const out = repairBenefitCoverage({ status: 'complete', items: [{ id: 'printing', label: 'printing', status: 'answered', summary: 'SFPL 免费打印需旧金山市县居民。', sourceIds: [] }] }, scopes, 'zh-Hans', new Map());
  assert.equal(out.changed, true);
  assert.doesNotMatch(out.coverage.items[0].summary, /同时最多 2 个预约|Bay Area Discovery Museum/);
});

test('review round 6: a pass, printing or Kanopy clause that needs a card first is not a card rule, so a false card claim is still repaired (zh-Hans, zh-Hant, en)', () => {
  // The verify's made-up scopes: each clause names another service and only requires holding the card. Main repairs the false card
  // claim from the card scope; round 5 added the clause as a card rule with the service's residence or age rule and kept the claim.
  const cardScope = { id: 'card', heading: 'SFPL：办卡', entity: 'SFPL', entityKey: 'sfpl', text: '图书馆\nSFPL：办卡\n加州居民可免费办 SFPL 卡。', sourceIds: ['card'] };
  for (const [locale, heading, sentence, claim] of [
    ['zh-Hans', 'SFPL · Discover & Go：用借书证预约博物馆门票', 'SFPL Discover & Go：限旧金山市县居民，须年满 18 岁并已办 SFPL 卡；每次最多 2 张票。', 'SFPL 办卡需旧金山居民。'],
    ['zh-Hans', 'SFPL · Discover & Go：用借书证预约博物馆门票', 'SFPL Discover & Go：限旧金山市县居民，须年满 18 岁并已办 SFPL 卡；每次最多 2 张票。', 'SFPL 办卡须年满 18 岁。'],
    ['zh-Hans', 'SFPL · 打印：每天免费打印', '免费打印仅限旧金山居民，需先办理图书证；每天 10 页。', 'SFPL 办卡需旧金山居民。'],
    ['zh-Hans', 'SFPL · KANOPY：在家看片', 'Kanopy 仅限年满 18 岁的旧金山居民，需先领卡；每月 10 部。', 'SFPL 办卡须年满 18 岁。'],
    ['zh-Hant', 'SFPL · Discover & Go：用借書證預約博物館門票', 'SFPL Discover & Go：限舊金山市縣居民，須年滿 18 歲並已辦 SFPL 卡；每次最多 2 張票。', 'SFPL 辦卡須年滿 18 歲。'],
    ['zh-Hant', 'SFPL · KANOPY：在家看片', 'Kanopy 僅限年滿 18 歲的居民，需先領卡；每月 10 部。', 'SFPL 辦卡須年滿 18 歲。'],
    ['en', 'SFPL · Discover & Go: museum passes', 'SFPL Discover & Go is for San Francisco residents age 18+ who get a library card first; two tickets per visit.', 'SFPL cards are only for San Francisco residents.']]) {
    const scopes = [{ id: 's1', heading, entity: 'SFPL', entityKey: 'sfpl', text: `福利\n${heading}\n${sentence}`, sourceIds: ['src'] }, cardScope];
    const out = repairBenefitCoverage({ status: 'complete', items: [{ id: 'card_eligibility', status: 'answered', summary: claim, sourceIds: ['x'] }] }, scopes, locale);
    assert.equal(out.changed, true, `${locale} ${sentence} :: ${claim}`);
    assert.equal(out.coverage.items[0].status, 'unknown', `${locale} ${sentence}`);
    assert.deepEqual(out.coverage.items[0].sourceIds, ['card'], `${locale} ${sentence}`);
  }
  // The live Q3 card clause after a Kanopy rule is still a card rule of its own (see "a real SFPL residency error is still repaired").
});

// ---------------------------------------------------------------- review round 7: never worse than main on made-up scope text
// A sentence that states a restriction is classified exactly as on main 8eec008 (TOPICS, with its heading fallback); a ；-clause is
// a card rule only when the allowlist grammar reads it whole (who + can + get the LIBRARY card + how to collect it).
const r7Repair = (id, claim, scopes, locale) => repairBenefitCoverage({ status: 'complete', items: [{ id, status: 'answered', summary: claim, sourceIds: ['x'] }] }, scopes, locale);

test('review round 7: a card section whose heading names the card, or an en plural "library cards", keeps a correct card claim (zh-Hans, zh-Hant, en)', () => {
  for (const [locale, entity, heading, sentence, claim] of [
    ['zh-Hans', 'SMCL', 'SMCL：半岛图书证', '限 San Mateo County 居民，年满 16 岁。线上申请后到馆领取。', 'SMCL 办卡限 San Mateo County 居民。'],
    ['zh-Hans', 'SMCL', 'SMCL：半岛图书证', '限 San Mateo County 居民，年满 16 岁。线上申请后到馆领取。', 'SMCL 的图书证须年满 16 岁。'],
    ['zh-Hans', 'ACL', 'AC Library：图书证', '仅限 Alameda County 居民；13 岁以下需家长陪同。', 'AC Library 办卡仅限 Alameda County 居民。'],
    ['zh-Hant', 'SMCL', 'SMCL：半島圖書證', '限 San Mateo County 居民，年滿 16 歲。', 'SMCL 辦卡限 San Mateo County 居民。'],
    ['zh-Hant', 'ACL', 'AC Library：圖書證', '僅限 Alameda County 居民。', 'AC Library 辦卡僅限 Alameda County 居民。'],
    ['en', 'SMCL', 'SMCL: Library cards', 'Only San Mateo County residents age 16+ qualify.', 'SMCL library cards are only for San Mateo County residents.'],
    ['en', 'ACL', 'AC Library: library cards', 'Library cards are only for Alameda County residents.', 'AC Library cards are only for Alameda County residents.'],
    ['en', 'SJPL', 'SJPL: Library card', 'You must be a California resident age 13+.', 'SJPL library cards require California residents age 13+.'],
    ['en', 'ACL', 'AC Library: cards', 'Library cards are free for Alameda County residents.', 'AC Library library cards are free for Alameda County residents.']]) {
    const scopes = [{ id: 's1', heading, entity, entityKey: entity.toLowerCase(), text: `图书馆\n${heading}\n${sentence}`, sourceIds: ['src'] }];
    const out = r7Repair('card_eligibility', claim, scopes, locale);
    assert.equal(out.changed, false, `${locale} ${heading} :: ${claim}`);
    assert.equal(out.coverage.items[0].status, 'answered', `${locale} ${heading} :: ${claim}`);
    assert.equal(out.coverage.status, 'complete');
  }
  // A false Kanopy claim built from the same card section is still repaired from it.
  const scopes = [{ id: 's1', heading: 'SMCL：半岛图书证', entity: 'SMCL', entityKey: 'smcl', text: '图书馆\nSMCL：半岛图书证\n限 San Mateo County 居民，年满 16 岁。', sourceIds: ['src'] }];
  const out = r7Repair('kanopy', 'SMCL 的 Kanopy 限 San Mateo County 居民。', scopes, 'zh-Hans');
  assert.equal(out.changed, true); assert.equal(out.coverage.items[0].status, 'unknown');
  assert.match(out.coverage.items[0].summary, /限 San Mateo County 居民，年满 16 岁/);
});

test('review round 7: card-rule wordings (办证, 借书证, plural library cards, getting a card) keep a correct card claim, as on main (zh-Hans, zh-Hant, en)', () => {
  const han = /[一-鿿]/;
  const wordings = ['加州居民持有效证件即可到馆办证。', '加州居民可免费办理图书证。', '凡居住在加州者均可免费申请借书证。', '加州居民可免費辦理借書證。', '辦證需帶有照片的證件，加州居民免費。',
    'Library cards are free for California residents.', 'Library cards are available to California residents age 13 and older.', 'Getting a card: bring photo ID; California residents only.',
    'California residents qualify for a free library card.', 'Residents of California are eligible for library cards.'];
  // Under a heading that is not about the card, main reads 办证 / 借書證 / "Getting a card" as no card rule; that stays main's reading.
  const mainReadsCard = sentence => !/办证|辦證|借書證|Getting a card/.test(sentence);
  for (const heading of ['SFPL · Library card', 'SFPL：图书证', 'SFPL：服务说明']) {
    for (const sentence of wordings.filter(sentence => heading !== 'SFPL：服务说明' || mainReadsCard(sentence))) {
      const scopes = [{ entity: 'SFPL', entityKey: 'sfpl', heading, text: `${heading}\n${sentence} 另有打印服务，每页 $0.15，仅限旧金山居民。`, sourceIds: ['g1'] }];
      const claim = han.test(sentence) ? '加州居民可免费办 SFPL 卡。' : 'California residents can get a free SFPL card.';
      const out = r7Repair('card_eligibility', claim, scopes, han.test(sentence) ? 'zh-Hans' : 'en');
      assert.equal(out.changed, false, `${heading} :: ${sentence}`);
      assert.equal(out.coverage.items[0].status, 'answered', `${heading} :: ${sentence}`);
    }
  }
});

test('review round 7: a clause about a tool card, a parking card or a LinkedIn card is never a library-card rule, so a false card claim is repaired (zh-Hans, zh-Hant, en)', () => {
  for (const [locale, entity, heading, sentence, claim] of [
    ['zh-Hans', 'BPL', 'BERKELEY PUBLIC LIBRARY：工具馆', '一次最多 10 件；Berkeley 居民到工具馆领卡后可借。', 'BPL 办卡仅限 Berkeley 居民。'],
    ['zh-Hant', 'BPL', 'BERKELEY PUBLIC LIBRARY：工具館', '一次最多 10 件；Berkeley 居民到工具館領卡後可借。', 'BPL 辦卡僅限 Berkeley 居民。'],
    ['en', 'OPL', 'OAKLAND PUBLIC LIBRARY: Tool lending', 'Tool loans are free; Oakland residents age 18+ can get a tool card at any branch.', 'OPL library cards are only for Oakland residents.'],
    ['en', 'BPL', 'BERKELEY PUBLIC LIBRARY: Tool Library', 'Up to 10 items at a time; Berkeley residents sign up for a tool borrower card in person.', 'BPL library cards are only for Berkeley residents.'],
    ['en', 'MCFL', 'MCFL: State park passes', 'Passes lend for 7 days; Marin County residents can get a parking card at a branch.', 'MCFL library cards are only for Marin County residents.'],
    ['zh-Hans', 'SFPL', 'SFPL · LINKEDIN LEARNING', '课程免费；旧金山居民可申请 LinkedIn 卡。', 'SFPL 办卡仅限旧金山居民。']]) {
    const key = entity.toLowerCase();
    const scopes = [{ id: 's1', heading, entity, entityKey: key, text: `福利\n${heading}\n${sentence}`, sourceIds: ['src'] },
      { id: 's2', heading: `${entity}：办卡`, entity, entityKey: key, text: `图书馆\n${entity}：办卡\n加州居民可免费办卡。`, sourceIds: ['card'] }];
    const out = r7Repair('card_eligibility', claim, scopes, locale);
    assert.equal(out.changed, true, `${locale} ${sentence}`);
    assert.equal(out.coverage.items[0].status, 'unknown', `${locale} ${sentence}`);
    assert.deepEqual(out.coverage.items[0].sourceIds, ['card'], `${locale} ${sentence}`);
  }
});

test('review round 7: a Kanopy, printing or Discover & Go clause that uses the card after getting it is the service\'s rule, so a false card claim is repaired (zh-Hans, zh-Hant, en)', () => {
  const cardScope = { id: 's2', heading: 'SFPL：办卡', entity: 'SFPL', entityKey: 'sfpl', text: '图书馆\nSFPL：办卡\n加州居民可免费办 SFPL 卡。', sourceIds: ['card'] };
  for (const [locale, heading, sentence, claim] of [
    ['zh-Hans', 'SFPL · KANOPY：在家看片', 'Kanopy 每月 10 部；仅限旧金山居民办卡后使用。', 'SFPL 办卡仅限旧金山居民。'],
    ['zh-Hans', 'SFPL · KANOPY：在家看片', 'Kanopy 每月 10 部；年满 18 岁的读者办卡后即可登录。', 'SFPL 办卡须年满 18 岁。'],
    ['zh-Hans', 'SFPL · KANOPY：在家看片', 'Kanopy 每月 10 部；旧金山居民办 SFPL 卡后即可登录。', 'SFPL 办卡仅限旧金山居民。'],
    ['zh-Hans', 'SFPL · 打印：每天免费打印', '每天免费打印 10 页；旧金山居民办卡后即可享有。', 'SFPL 办卡仅限旧金山居民。'],
    ['zh-Hant', 'SFPL · KANOPY：在家看片', 'Kanopy 每月 10 部；僅限舊金山居民辦卡後使用。', 'SFPL 辦卡僅限舊金山居民。'],
    ['en', 'SFPL · KANOPY: Stream at home', 'Kanopy gives 10 films a month; San Francisco residents can get a library card and log in.', 'SFPL library cards are only for San Francisco residents.'],
    ['en', 'SFPL · Discover & Go', 'Two tickets per visit; residents age 18+ can sign up for a library card and reserve.', 'You must be 18+ to get an SFPL library card; age 18+ only.']]) {
    const scopes = [{ id: 's1', heading, entity: 'SFPL', entityKey: 'sfpl', text: `福利\n${heading}\n${sentence}`, sourceIds: ['src'] }, cardScope];
    const out = r7Repair('card_eligibility', claim, scopes, locale);
    assert.equal(out.changed, true, `${locale} ${sentence}`);
    assert.equal(out.coverage.items[0].status, 'unknown', `${locale} ${sentence}`);
    assert.deepEqual(out.coverage.items[0].sourceIds, ['card'], `${locale} ${sentence}`);
  }
});

test('review round 7: the live Q3 clause in other wordings (需持有效证件, 申请借书证, 办证, library cards) is a card rule, so the correct claim is not degraded (zh-Hans, zh-Hant, en)', () => {
  const kanopyHead = 'SFPL · KANOPY：用 SFPL 图书证，在家免费看片';
  const radon = { entity: 'SAN FRANCISCO PUBLIC LIBRARY', entityKey: 'sfpl', heading: 'SAN FRANCISCO PUBLIC LIBRARY：SFPL 图书证可免费借氡探测器',
    text: 'SAN FRANCISCO PUBLIC LIBRARY：SFPL 图书证可免费借氡探测器\n持 SFPL 图书证借用，可在线预约；设备先到先得，最长借期 21 天，用后须归还。', sourceIds: ['radon'] };
  // The pass rule that owns the San Francisco residence the false claims borrow (the live Q3 turn's Discover & Go paragraph).
  const passes = { entity: 'SFPL', entityKey: 'sfpl', heading: '旧金山 · SFPL Discover & Go：旧金山市县居民用借书证号和 PIN 登录', sourceIds: ['starter'],
    text: '用图书馆卡借博物馆票和公园通行证\n旧金山 · SFPL Discover & Go：旧金山市县居民用借书证号和 PIN 登录 sfpl.discoverandgo.net，预约博物馆门票；同时最多 2 个预约。' };
  for (const [locale, rule, tail, good, bad] of [
    ['zh-Hans', '须有有效 SFPL 图书证并完成 Kanopy 账户绑定', '加州居民可免费办 SFPL 卡，需持有效证件到馆办理。', '加州居民可免费办 SFPL 卡。', 'SFPL 要求旧金山居民才能办卡。'],
    ['zh-Hans', '须有有效 SFPL 图书证并完成 Kanopy 账户绑定', '加州居民可免费申请 SFPL 借书证。', '加州居民可免费办 SFPL 卡。', 'SFPL 要求旧金山居民才能办卡。'],
    ['zh-Hans', '须有有效 SFPL 图书证并完成 Kanopy 账户绑定', '加州居民均可免费办证。', '加州居民可免费办 SFPL 卡。', 'SFPL 要求旧金山居民才能办卡。'],
    ['zh-Hans', '须有有效 SFPL 图书证并完成 Kanopy 账户绑定', '加州居民可免费办理图书证，须先在线申请再到馆领取。', '加州居民可免费办 SFPL 卡。', 'SFPL 要求旧金山居民才能办卡。'],
    ['zh-Hant', '須有有效 SFPL 圖書證並完成 Kanopy 帳戶綁定', '加州居民可免費辦 SFPL 卡，需持有效證件到館辦理。', '加州居民可免費辦 SFPL 卡。', 'SFPL 要求舊金山居民才能辦卡。'],
    ['zh-Hant', '須有有效 SFPL 圖書證並完成 Kanopy 帳戶綁定', '加州居民均可免費辦證。', '加州居民可免費辦 SFPL 卡。', 'SFPL 要求舊金山居民才能辦卡。'],
    ['en', 'Requires a valid SFPL card linked to Kanopy', 'library cards are free for California residents.', 'California residents can get a free SFPL card.', 'SFPL cards are only for San Francisco residents.'],
    ['en', 'Requires a valid SFPL card linked to Kanopy', 'California residents can get a free SFPL card with photo ID at a branch.', 'California residents can get a free SFPL card.', 'SFPL cards are only for San Francisco residents.']]) {
    const kanopy = { entity: 'SFPL', entityKey: 'sfpl', heading: kanopyHead, text: `${kanopyHead}\n${rule}；${tail}`, sourceIds: ['kanopy'] };
    const kept = r7Repair('card_eligibility', good, [radon, kanopy, passes], locale);
    assert.equal(kept.changed, false, `${locale} ${tail}`);
    assert.equal(kept.coverage.items[0].status, 'answered', `${locale} ${tail}`);
    const repaired = r7Repair('card_eligibility', bad, [radon, kanopy, passes], locale).coverage.items[0];
    assert.equal(repaired.status, 'unknown', `${locale} ${tail}`);
    assert.ok(repaired.summary.includes(tail.replace(/[。.]$/, '')), `${locale} ${tail} :: ${repaired.summary}`);
    assert.doesNotMatch(repaired.summary, /氡|设备/, `${locale} ${tail}`);
    assert.deepEqual(repaired.sourceIds, ['kanopy'], `${locale} ${tail}`);
  }
  // A card the reader must already hold (持 + card) is still a prerequisite, never how to get one.
  const held = { entity: 'SFPL', entityKey: 'sfpl', heading: kanopyHead, text: `${kanopyHead}\nKanopy 每月 10 部；旧金山居民持有效 SFPL 图书证即可登录。`, sourceIds: ['kanopy'] };
  const card = { id: 'card', heading: 'SFPL：办卡', entity: 'SFPL', entityKey: 'sfpl', text: '图书馆\nSFPL：办卡\n加州居民可免费办 SFPL 卡。', sourceIds: ['card'] };
  const out = r7Repair('card_eligibility', 'SFPL 办卡仅限旧金山居民。', [held, card], 'zh-Hans');
  assert.equal(out.changed, true); assert.deepEqual(out.coverage.items[0].sourceIds, ['card']);
});

test('review round 7: a card repair left with no card statement cites what main cites, never the pass rule it repairs (shipped SCL sections)', () => {
  // The shipped Sonoma County Library parking-pass and Discover & Go paragraphs. On main the parking-pass line is the card's only
  // statement; it is restriction-free and not a card rule, so the repair falls back to main's statements rather than the
  // direct scopes (the Discover & Go heading names 图书证, and its Sonoma residence and age 15 rule is what the claim borrowed).
  const paragraphs = require('../data/guide-catalog.json').find(row => row.slug === 'bay-area-freebies-deals-2026-11').content.split(/\n\n+/)
    .filter(part => /^SONOMA COUNTY LIBRARY：(?:Sonoma 图书馆借停车证|北湾图书证也能借)/.test(part));
  assert.equal(paragraphs.length, 2);
  const scopes = paragraphs.map((text, index) => ({ id: `scl-${index}`, heading: text.split('\n')[0], entity: 'SONOMA COUNTY LIBRARY', entityKey: 'scl', text: `福利\n${text}`, sourceIds: [`scl-${index}`] }));
  const out = r7Repair('card_eligibility', 'SONOMA COUNTY LIBRARY 的图书证：Sonoma County 居民、年满 15 岁，持正式图书证和 PIN。', scopes, 'zh-Hans');
  assert.equal(out.changed, true); assert.equal(out.coverage.items[0].status, 'unknown');
  assert.match(out.coverage.items[0].summary, /区域公园日间停车证/);
  assert.doesNotMatch(out.coverage.items[0].summary, /年满 15 岁|Discover & Go/);
});

test('review round 3: the adult tier is added only from a cost line with no condition anywhere', { todo: ADULT_TIER_TODO }, () => {
  const { adultTierRepair } = require('../lib/baybayQuality');
  const events = require('../data/planner-catalog.json').events;
  const costOf = id => events.find(row => row.id === id).costLabel;
  const tier = (cost, text, locale = 'zh-Hans') => adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => cost, locale });
  // Rio Vista: a reference price for derby entry, the final price on the ticket page; ZooLights: a member discount.
  assert.match(costOf('rio-vista-bass-derby-2026'), /参考/);
  for (const [id, text] of [['rio-vista-bass-derby-2026', '钓鱼赛：儿童 $10。[[e7]]'], ['sfzoo-zoolights-2026', 'ZooLights 儿童 $21。[[e7]]']]) {
    assert.equal(tier(costOf(id), text).repaired, false, id); assert.equal(tier(costOf(id), text.replace('儿童', 'kids'), 'en').repaired, false, id);
  }
  for (const cost of ['平日成人 $20、儿童 $10', '成人 $30+、儿童 $15', '成人 $30 左右，儿童 $15', '成人 $20+$3.18手续费、儿童 $10', '网购成人 $25、儿童 $12', '成人约 $25、儿童 $12',
    '成人 $25、儿童 $12；会员免费', '居民成人 $10、儿童 $5', '成人 $25（周末）、儿童 $12', 'Adults $25, kids $12 online']) {
    assert.equal(tier(cost, `活动：儿童 $${cost.match(/(?:儿童|kids) \$(\d+)/)[1]}。[[e7]]`).repaired, false, cost);
  }
  // A note that another age band's price is not listed says nothing about the adult price (the live Q5 Alameda row).
  assert.match(costOf('alameda-haunted-house-2026'), /15–17 岁费用未注明，待核实/);
  assert.equal(tier(costOf('alameda-haunted-house-2026'), '鬼屋：4–14 岁 $5。[[e7]]').draft.points[0].text, '鬼屋：4–14 岁 $5。18+ 成人 $8。[[e7]]');
  // en: a point ending in a Chinese full stop gets no extra period; an adult price written as $8.00 is already given.
  assert.equal(tier(costOf('alameda-haunted-house-2026'), 'Haunted house: ages 4–14 $5。[[e7]]', 'en').draft.points[0].text, 'Haunted house: ages 4–14 $5。 Adults 18+: $8.[[e7]]');
  assert.equal(tier(costOf('alameda-haunted-house-2026'), 'Ages 4–14 $5, everyone else $8.00 [[e7]]', 'en').repaired, false);
});

test('review round 3: a branch\'s hours or address asked from home stays on the library\'s city; a card or service ask does not', { todo: HOME_CITY_TODO }, () => {
  for (const message of ['我住 Fremont，SFPL 总馆在哪里？', '我住 Fremont，SFPL 的 Mission Bay 分馆周末几点开门？', 'I live in Fremont. What time does SFPL Main Library open on Sunday?', 'I live in Fremont. Where is SFPL Main Library?',
    '我住 Fremont，旧金山图书馆有什么亲子活动', '我住 Fremont，想去 SFPL 总馆借书']) {
    const { state } = stateOf(message);
    assert.equal(state.city, 'San Francisco', message); assert.equal(state.origin, 'Fremont', message);
  }
  for (const [message, home] of [['I live in Oakland. Can I use SFPL Discover & Go?', 'Oakland'], ['我住 Fremont，SFPL 可以免费打印吗', 'Fremont'], ['我住 Oakland，SFPL 的 eCard 能用 Kanopy 吗', 'Oakland']]) {
    const { state } = stateOf(message);
    assert.equal(state.city, null, message); assert.equal(state.origin, home, message);
  }
});

// ---------------------------------------------------------------- review round 4 (verify of 4fccff6): narrowed to main's reading

test('review round 4: a follow-up that drops the carried weekend for this or next weekend replaces the carried day (zh-Hans, zh-Hant, en)', { todo: WEEKEND_DAY_TODO }, () => {
  const day = date => ({ goal: 'discover', date });
  for (const [today, weekend] of [['2026-10-17', { start: '2026-10-17', end: '2026-10-18' }], ['2026-10-22', WEEKEND_1024]]) {
    for (const message of ['10/31 那个周末有事了，这周末呢', '10/31 那個週末沒空了，這週末有什麼', 'The 10/31 weekend is out, what about this weekend?', 'weekend 10/31 no longer works, this weekend instead',
      '万圣节周末 10/31 有事，这周末去哪', 'Halloween weekend 10/31 we are away; this weekend?', '10/31 那个周末有事，这周末帮我排一天']) {
      const { state } = stateOn(message, { today, previous: day('2026-10-31') });
      assert.deepEqual(state.dateRange, weekend, `${today} ${message}`); assert.equal(state.date, null, `${today} ${message}`);
    }
  }
  for (const message of ['10/24 那个周末有事，下周末呢', 'weekend 10/24 is out; what about next weekend?', '10/24 那個週末不行，下週末呢']) {
    const { state } = stateOn(message, { today: '2026-10-22', previous: day('2026-10-24') });
    assert.deepEqual(state.dateRange, { start: '2026-10-31', end: '2026-11-01' }, message); assert.equal(state.date, null, message);
  }
  // weekendDay: false (a follow-up inside the carried weekend, a day plan, a holiday's own weekend) is main's reading exactly.
  const { askedDateRange } = require('../lib/entityAliases');
  assert.deepEqual(askedDateRange('10/31 那个周末有事了，这周末呢', '2026-10-17', { weekendDay: false }), { start: '2026-10-17', end: '2026-10-18', kind: 'weekend' });
});

test('review round 4: a past weekend\'s date beside 周末 / weekend is a side remark when the ask names this weekend', { todo: WEEKEND_DAY_TODO }, () => {
  for (const [today, weekend] of [['2026-10-17', { start: '2026-10-17', end: '2026-10-18' }], ['2026-10-22', WEEKEND_1024]]) {
    for (const message of ['That weekend, Oct 10, was rainy. What about this weekend?', 'The prior weekend (Oct 10) we hiked; this weekend?', 'We went to the zoo on the weekend, Oct 10. This weekend?',
      'Weekend (Oct 10) was rainy, so this weekend?', 'Our weekend, Oct 10, was busy; this weekend?']) {
      assert.deepEqual(stateOn(message, { today }).state.dateRange, weekend, `${today} ${message}`);
    }
    // zh wording ZH_NOT_LAST does not list reads 10/10 as main does; never the 10/10-11 weekend.
    for (const message of ['上周的周末 10/10 去了动物园，这周末去哪', '10/10 那个周末去过了，这周末呢', '前個週末 10/10 去過了，這週末呢']) {
      assert.notDeepEqual(stateOn(message, { today }).state.dateRange, { start: '2026-10-10', end: '2026-10-11' }, `${today} ${message}`);
    }
  }
});

test('review round 4: the weekend\'s other day written apart is read as on main, never as the only (busy) day', { todo: WEEKEND_DAY_TODO }, () => {
  for (const message of ['这周末 10/24，10/25 都行', '這週末 10/24，10/25 都可以', '这周末 10/24 / 10/25 都行', '这周末 10/24 10/25 都可以',
    '这周末 10/24 有空，10/25 要加班', '这周末 10/24 带娃，10/25 休息', '這週末 10/24 帶娃，10/25 要上班', 'This weekend 10/24, but 10/25 we are busy', '这周末 10/25 带娃，10/24 有事']) {
    const { state } = stateOn(message, { today: '2026-10-22' });
    assert.deepEqual(state.dateRange, WEEKEND_1024, message); assert.equal(state.date, null, message);
    for (const searchContext of [undefined, { date: '2026-10-31' }]) {
      const result = stateOn(message, { searchContext }).state;
      assert.ok(!['2026-10-24', '2026-10-25'].includes(result.date), `10-17 ${message} ${result.date}`);
    }
  }
  // The date bar on the free day keeps it, with main's "pick one day" note.
  const hinted = stateOn('这周末 10/24 带娃出去，10/25 还要上中文学校', { today: '2026-10-22', searchContext: { date: '2026-10-24' } });
  assert.equal(hinted.state.date, '2026-10-24'); assert.match(hinted.clarification || '', /多个日期/);
});

test('review round 4: more one-day wording keeps the one day, and a typed two-day span still beats the date bar as on main', { todo: WEEKEND_DAY_TODO }, () => {
  for (const message of ['这周末 10/24 周六那天去哪', '这周末 10/24 带娃，晚饭前回来', '这周末 10/24 带娃去哪，天黑前回家', '这周末 10/24 早去早回', '这周末 10/24 出去玩几个小时',
    '這週末 10/24 帶娃，晚飯前回來', 'weekend 10/24, just a few hours out', 'weekend 10/24, sunrise hike?', 'weekend 10/24, back before dark']) {
    for (const today of ['2026-10-17', '2026-10-22']) {
      const { state } = stateOn(message, { today });
      assert.equal(state.date, '2026-10-24', `${today} ${message}`); assert.equal(state.dateRange, undefined, `${today} ${message}`);
    }
  }
  for (const [message, date, typed] of [['12月5日，6日都可以，去哪', '2026-10-24', '2026-12-05'], ['12月5日，6日哪天都行', '2026-10-25', '2026-12-05'], ['11月21日，22日都可以，带娃去哪', '2026-10-31', '2026-11-21']]) {
    assert.equal(stateOn(message, { searchContext: { date } }).state.date, typed, message);
  }
});

test('review round 4: after a home-city card question, asking where a library is or when it opens is about the library\'s city again', { todo: HOME_CITY_TODO }, () => {
  for (const [first, followups] of [[Q3['zh-Hans'].question, ['SFPL 总馆在哪里？', 'SFPL 总馆几点开门？', '那 SFPL 总馆周末开吗']],
    [Q3['zh-Hant'].question, ['SFPL 總館在哪裡？', '那 SFPL 總館週末開嗎']], [Q3.en.question, ['What time does SFPL Main Library open on Sunday?', 'Where is the SFPL Main Library?']]]) {
    const home = stateOf(first).state;
    assert.equal(home.city, null, first); assert.equal(home.origin, 'Fremont', first);
    for (const followup of followups) {
      const { state } = stateOf(followup, home);
      assert.equal(state.city, 'San Francisco', `${first} -> ${followup}`); assert.equal(state.region, 'sf', `${first} -> ${followup}`); assert.equal(state.origin, 'Fremont', `${first} -> ${followup}`);
      // …and the next general follow-up stays there, as on main.
      assert.equal(stateOf('附近有什么吃的', state).state.city, 'San Francisco', `${followup} -> 附近有什么吃的`);
    }
    // A general follow-up after the card question is still not scoped to San Francisco.
    assert.notEqual(stateOf('那这周末附近有什么免费亲子活动？', home).state.city, 'San Francisco', first);
  }
});

test('review round 4: the adult tier is never added to a point that cites two records, talks about the parents, or has a date, tax or overlapping-band note', { todo: ADULT_TIER_TODO }, () => {
  const { adultTierRepair } = require('../lib/baybayQuality');
  const events = require('../data/planner-catalog.json').events;
  const alameda = events.find(row => row.id === 'alameda-haunted-house-2026').costLabel;
  const costs = { e7: alameda, e6: '展览免费开放。' };
  const tier = (text, locale = 'zh-Hans', costOf = ref => costs[ref] ?? null) => adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf, locale });
  // The live Q5 evidence: Alameda (e7) and the free Emeryville art show (e6) in one point, interleaved or with trailing markers.
  for (const [locale, text] of [
    ['zh-Hans', 'Alameda 青少年鬼屋 4–14 岁 $5 [[e7]]；Emeryville 艺术展闭幕周末，免费入场 [[e6]]'], ['zh-Hans', 'Alameda 青少年鬼屋 4–14 岁 $5；Emeryville 艺术展闭幕周末免费。[[e7]][[e6]]'],
    ['zh-Hant', 'Alameda 青少年鬼屋 4–14 歲 $5 [[e7]]；Emeryville 藝術展閉幕週末，免費入場 [[e6]]'], ['zh-Hant', 'Alameda 青少年鬼屋 4–14 歲 $5；Emeryville 藝術展閉幕週末免費。[[e7]][[e6]]'],
    ['en', 'Alameda teen haunted house: ages 4–14 $5 [[e7]]; the Emeryville art show closes this weekend, free [[e6]]'], ['en', 'Alameda haunted house, ages 4–14 $5; the Emeryville art show is free. [[e7]][[e6]]']]) {
    const result = tier(text, locale);
    assert.equal(result.repaired, false, text); assert.equal(result.draft.points[0].text, text);
  }
  // The same record cited twice is still one record.
  assert.equal(tier('Alameda 鬼屋 4–14 岁 $5 [[e7]]，周六开放 [[e7]]').repaired, true);
  // The point talks about the accompanying adults itself.
  for (const [locale, text] of [['zh-Hans', '鬼屋：4–14 岁 $5，家长陪同免费 [[e7]]'], ['zh-Hant', '鬼屋：4–14 歲 $5，家長陪同 [[e7]]'], ['en', 'Kids 4–14 $5; parents get in free. [[e7]]']]) {
    assert.equal(tier(text, locale).repaired, false, text);
  }
  // A date-dependent or tax note, or an unlisted band that reaches 18, conditions the whole line.
  for (const cost of ['成人 $8，4–14 岁 $5（视日期而定）', '成人 $8，4–14 岁 $5，价格依日期调整', '成人 $8 (+tax)，4–14 岁 $5', '成人 $8（含税），4–14 岁 $5', '成人 $8，4–14 岁 $5；15–20 岁费用待核实']) {
    assert.equal(tier('活动：4–14 岁 $5。[[e7]]', 'zh-Hans', () => cost).repaired, false, cost);
  }
  assert.equal(tier('活动：4–14 岁 $5。[[e7]]', 'zh-Hans', () => '成人 $8，4–14 岁 $5；15–17 岁费用待核实').repaired, true);
});
// ---------------------------------------------------------------- review round 5 (verify2 of 34927987e): inverted rules

test('review round 5: a written day that has passed, or a weekend already under way, is read as on main (zh-Hans, zh-Hant, en)', { todo: WEEKEND_DAY_TODO }, () => {
  // Asked on Sunday 10/25: Saturday 10/24 has passed. Main's reading, with main's past-date clarification (no Sat..Sun range
  // that starts yesterday, and the live Q5 ask never answers with yesterday's offers).
  for (const message of ['这周末 10/24 带娃去哪', '这周末 10/24 周六去哪', '這週末 10/24 有什麼活動', 'weekend 10/24 events']) {
    for (const extra of [{}, { searchContext: { date: '2026-10-25' } }, { previous: { goal: 'discover', date: '2026-10-31' } }]) {
      const result = stateOn(message, { today: '2026-10-25', ...extra });
      assert.equal(result.state.date, '2026-10-24', message); assert.equal(result.state.dateRange, undefined, message);
      assert.match(result.clarification || '', /已经过去/, message);
    }
  }
  // The written Sunday asked on that Sunday is today, one day, as on main.
  for (const [today, message] of [['2026-10-25', '这周末 10/25 周日带娃去哪'], ['2026-10-25', '這週末 10/25（週日）帶小孩去哪'], ['2026-10-25', 'this weekend 10/25 kids events'],
    ['2026-10-18', '这周末 10/18 带娃去哪'], ['2026-10-18', '這週末 10/18（週日）帶小孩去哪'], ['2026-10-18', 'this weekend 10/18 kids events']]) {
    const result = stateOn(message, { today });
    assert.equal(result.state.date, today, message); assert.equal(result.state.dateRange, undefined, message); assert.equal(result.clarification, undefined, message);
  }
  // On the Saturday itself the weekend still holds both days.
  for (const message of ['这周末 10/24 带娃去哪', '這週末 10/25 帶娃去哪', 'weekend 10/24 events']) {
    assert.deepEqual(stateOn(message, { today: '2026-10-24' }).state.dateRange, WEEKEND_1024, message);
  }
});

test('review round 5: the weekend\'s other day written as a day of the month or as the next day keeps main\'s one day', { todo: WEEKEND_DAY_TODO }, () => {
  for (const today of ['2026-10-17', '2026-10-22']) {
    for (const [message, date] of [['这周末 10/24 出去玩，25号在家休息', '2026-10-24'], ['这周末 10/24 带娃，第二天要上中文课', '2026-10-24'], ['这周末 10/24 去玩，隔天休息', '2026-10-24'],
      ['这周末 10/24 出门，次日在家', '2026-10-24'], ['這週末 10/24 出去，25號要上班', '2026-10-24'], ['這週末 10/24 帶娃，隔天在家', '2026-10-24'], ['weekend 10/24 out with kids, the 25th we rest', '2026-10-24'],
      ['weekend 10/24, the next day is soccer', '2026-10-24'], ['这周末 10/25 带娃，24号有事', '2026-10-25']]) {
      for (const extra of [{}, { searchContext: { date: '2026-10-31' } }, { previous: { goal: 'discover', date: '2026-10-31' } }]) {
        const { state } = stateOn(message, { today, ...extra });
        assert.equal(state.date, date, `${today} ${message}`); assert.equal(state.dateRange, undefined, `${today} ${message}`);
      }
    }
  }
  // An alternative written as 明日 or "tmrw" is not dropped into the weekend span either.
  for (const message of ['這週末 10/24 還是明日比較好', 'weekend 10/24, or tmrw?']) assert.equal(stateOn(message).state.dateRange, undefined, message);
});

test('review round 5: whatever the planner itself reads as a time keeps the one day, with or without a word list entry', { todo: WEEKEND_DAY_TODO }, () => {
  for (const message of ['这周末 10/24 当晚有什么演出', '这周末 10/24 一大早出发去海边', '这周末 10/24 一点钟出发，带娃去哪', '这周末 10/24 晚饭去哪吃', '这周末 10/24 夜间有什么活动', '这周末 10/24 午饭后去哪',
    '这周末 10/24 早饭吃什么', '这周末 10/24 宵夜去哪', '这周末 10/24 晚间有烟火吗', '這週末 10/24 晚餐去哪吃', '這週末 10/24 當晚去哪', '這週末 10/24 一大早去爬山', '這週末 10/24 早餐去哪吃',
    'weekend 10/24 midnight movie?', 'weekend 10/24 at dawn, birdwatching spots', 'weekend 10/24, just for the day, where to go', 'weekend 10/24, out from 2 to 5', 'this weekend 10/24, sundown hikes?',
    // Read only by the planner's own parsers (the outing length), no list entry.
    '这周末 10/24 带娃出去玩两小时', '這週末 10/24 帶娃出去玩兩小時']) {
    for (const today of ['2026-10-17', '2026-10-22']) {
      const { state } = stateOn(message, { today });
      assert.equal(state.date, '2026-10-24', `${today} ${message}`); assert.equal(state.dateRange, undefined, `${today} ${message}`);
    }
  }
  // Yesterday, which no list names, is another day too: never the weekend span.
  for (const message of ['这周末 10/24 带娃去哪，昨天去过动物园了', 'weekend 10/24 with kids, we went to the zoo yesterday']) assert.equal(stateOn(message).state.dateRange, undefined, message);
  // The rule is askedDateRange's otherTemporal: any time the caller reads in the rest of the ask leaves the span.
  const { askedDateRange } = require('../lib/entityAliases');
  assert.equal(askedDateRange('这周末 10/24 带娃去哪', '2026-10-17', { otherTemporal: () => false }).day, '2026-10-24');
  assert.equal(askedDateRange('这周末 10/24 带娃去哪', '2026-10-17', { otherTemporal: rest => /带娃/.test(rest) })?.day, undefined);
  // Still the weekend: nothing else in the ask names a time (the Sunset District is a place, not a sunset; 1号公路 is a road).
  for (const message of ['这周末 10/24 带娃去哪', '這週末 10/24 帶娃去哪', 'weekend 10/24 with kids', '这周末 10/24 去 Sunset District 带娃', 'weekend 10/24 kids, Outer Sunset?',
    '这周末 10/24 走 1号公路 带娃去哪', '這週末 10/24 走一號公路去海邊']) {
    assert.deepEqual(stateOn(message).state.dateRange, WEEKEND_1024, message);
  }
});

test('review round 5: a carried day the ask writes beside 周末 / weekend is kept, never this weekend\'s 10/17-18', { todo: WEEKEND_DAY_TODO }, () => {
  for (const previous of [{ goal: 'discover', date: '2026-10-24' }, { goal: 'information', date: '2026-10-24', city: 'San Francisco' }, { goal: 'day-plan', date: '2026-10-24' }]) {
    for (const message of ['这周末 10/24 周六带娃去哪', '这周末 10/24 室内去哪', '這週末 10/24 有什麼免費活動', 'This weekend: 10/24. Ideas?', 'this weekend Oct 24 (Sat) with kids']) {
      const { state } = stateOn(message, { previous });
      assert.equal(state.date, '2026-10-24', `${previous.goal} ${message}`); assert.equal(state.dateRange, undefined, `${previous.goal} ${message}`);
    }
  }
  assert.equal(stateOn('这个周末 10/25 周日带娃去哪', { previous: { goal: 'discover', date: '2026-10-25' } }).state.date, '2026-10-25');
  // A carried day the ask only mentions apart from 周末 still gives way to this weekend, as on main.
  assert.deepEqual(stateOn('10/24 那天有事，这周末呢', { previous: { goal: 'discover', date: '2026-10-24' } }).state.dateRange, { start: '2026-10-17', end: '2026-10-18' });
});

test('review round 5: after a home-city card question, any follow-up that names the library and is not a card or service ask is about the library\'s city', { todo: HOME_CITY_TODO }, () => {
  const followups = ['SFPL 总馆怎么走？', 'SFPL 总馆什么时候开？', 'SFPL 总馆在什么地方', 'SFPL 总馆的位置', 'SFPL 总馆周末开放吗', 'SFPL 总馆离 BART 近吗', 'SFPL 总馆几号线', 'SFPL 总馆附近有什么吃的',
    'SFPL 總館附近有什麼好吃的', 'SFPL 總館怎麼走', 'SFPL Main Library location?', 'Any good food near SFPL Main Library?', 'What else is around SFPL Main?', 'SFPL 总馆在哪？能办卡吗'];
  for (const first of [Q3['zh-Hans'].question, Q3['zh-Hant'].question, Q3.en.question]) {
    const home = stateOf(first).state;
    assert.equal(home.city, null, first); assert.equal(home.origin, 'Fremont', first);
    for (const followup of followups) {
      const { state } = stateOf(followup, home);
      assert.equal(state.city, 'San Francisco', `${first} -> ${followup}`); assert.equal(state.region, 'sf', `${first} -> ${followup}`); assert.equal(state.origin, 'Fremont', `${first} -> ${followup}`);
    }
    // "How far is SFPL Main from BART?" reads BART as the start, as on main; the city is the library's.
    assert.equal(stateOf('How far is SFPL Main from BART?', home).state.city, 'San Francisco');
    // The card or service follow-up stays home; a general one is still ordered by nearness to home.
    for (const followup of ['SFPL 借书证怎么办？', '附近有什么吃的', '那这周末附近有什么免费亲子活动？']) {
      const { state } = stateOf(followup, home);
      assert.equal(state.city, null, `${first} -> ${followup}`); assert.equal(state.origin, 'Fremont', `${first} -> ${followup}`);
    }
  }
});

test('review round 5: a first turn that asks the way or the hours beside the card question keeps the library\'s city', { todo: HOME_CITY_TODO }, () => {
  for (const message of ['我住 Fremont，SFPL 总馆怎么走？能办卡吗', '我住 Fremont，SFPL 总馆什么时候开，可以办借书证吗', '我住 Fremont，可以办 SFPL 卡吗？总馆在什么地方', '我住 Fremont，想办 SFPL 卡，总馆周末开放吗',
    '我住 Fremont，SFPL 总馆离 BART 近吗？能办卡吗', '我住 Fremont，SFPL 總館怎麼走？能辦卡嗎', 'I live in Oakland. SFPL Main Library location for a library card?', 'I live in Fremont. How do I get to SFPL Main to get a library card?',
    'I live in Fremont, can I get an SFPL card at the Main Library and where is it?']) {
    assert.equal(stateOf(message).state.city, 'San Francisco', message);
  }
  // The service as the only question, with greetings around it, is still asked from home.
  for (const message of ['你好，我住 Fremont，可以办 SFPL 卡吗？谢谢', '我住 Fremont，可以辦 SFPL 借書證嗎？', 'Hi! I live in Fremont. Can I get an SFPL card? Thanks.']) {
    const { state } = stateOf(message);
    assert.equal(state.city, null, message); assert.equal(state.origin, 'Fremont', message);
  }
});

test('review round 5: card question -> "SFPL 总馆怎么走？" -> "附近有什么吃的" stays in San Francisco on turns 2 and 3 (v2 fast path)', { todo: HOME_CITY_TODO }, async () => {
  const first = await ask(Q3['zh-Hans'].question, q3Draft(Q3['zh-Hans']));
  assert.equal(first.response.taskState.city, null); assert.equal(first.response.taskState.origin, 'Fremont');
  const history = [{ role: 'user', content: Q3['zh-Hans'].question }, { role: 'assistant', content: first.response.answer || '好的。' }];
  const second = await ask('SFPL 总馆怎么走？', () => ({ lead: '好的。' }), { history: [...history], assistantSessionToken: first.response.assistantSessionToken });
  assert.equal(second.response.taskState.city, 'San Francisco'); assert.equal(second.response.taskState.origin, 'Fremont');
  history.push({ role: 'user', content: 'SFPL 总馆怎么走？' }, { role: 'assistant', content: second.response.answer || '好的。' });
  const third = await ask('附近有什么吃的', () => ({ lead: '好的。' }), { history: [...history], assistantSessionToken: second.response.assistantSessionToken });
  assert.equal(third.response.taskState.city, 'San Francisco');
  assert.ok(third.sent.length, 'the third turn asked the model with evidence');
  assert.ok(!third.sent[0].evidence.some(row => /@(?:Emeryville|Santa Clara|Oakland)\b/.test(`${row.title}@${row.city || ''}`)), 'no East Bay or South Bay evidence on turn 3');
});

test('review round 5: the adult tier comes only from a cost line the allowlist grammar reads whole (zh-Hans, zh-Hant, en)', { todo: ADULT_TIER_TODO }, () => {
  const { adultTierRepair } = require('../lib/baybayQuality');
  const tier = (cost, text, locale = 'zh-Hans') => { const result = adultTierRepair({ points: [{ text, cardIds: [] }] }, { costOf: () => cost, locale }); return result.repaired ? result.draft.points[0].text : null; };
  // Every segment an age band with a price, a free band, or a below-18 unlisted note (optionally after a source lead).
  assert.equal(tier('0–3 岁免费，4–14 岁 $5，18+ $8', '鬼屋 4–14 岁 $5 [[e7]]'), '鬼屋 4–14 岁 $5。18+ 成人 $8。 [[e7]]');
  assert.equal(tier('成人 $12，3–12 岁 $6', '3–12 歲 $6 [[e7]]', 'zh-Hant'), '3–12 歲 $6。成人 $12。 [[e7]]');
  assert.equal(tier('Adults (18+) $12, ages 4–17 $6, under 4 free', 'Ages 4–17 $6 [[e7]]', 'en'), 'Ages 4–17 $6. Adults 18+: $12. [[e7]]');
  assert.equal(tier('官网列 成人 $12、儿童 $6；15–17 岁费用未注明，待核实', '活动：儿童 $6。[[e7]]'), '活动：儿童 $6。成人 $12。[[e7]]');
  // Anything else in the line leaves the point alone: parking, a member note, a band above the children that is not the adult
  // band, two adult prices, free adults, a note that reaches 18, a price period, an unknown lead.
  for (const cost of ['成人 $12，3–12 岁 $6，停车 $10', '成人 $12，3–12 岁 $6，会员免费', '成人 $12，13 岁以上 $8，3–12 岁 $6', '成人 $12，成人 $15，3–12 岁 $6', '成人免费，3–12 岁 $6',
    '成人 $12，3–12 岁 $6；13–20 岁费用未注明', '早鸟 成人 $12，3–12 岁 $6', '门票：成人 $12，3–12 岁 $6', '18 岁及以下 $6，成人 $12', 'Adults $12, kids $6 online', '成人 $12 起至 $20，3–12 岁 $6']) {
    for (const [locale, text] of [['zh-Hans', '活动 3–12 岁 $6 [[e7]]'], ['zh-Hant', '活動 3–12 歲 $6 [[e7]]'], ['en', 'Ages 3–12 $6 [[e7]]']]) {
      assert.equal(tier(cost, text, locale), null, `${locale} ${cost}`);
    }
  }
  // Still skipped: a point citing two records, or talking about the parents.
  assert.equal(tier('成人 $12，3–12 岁 $6', '3–12 岁 $6 [[e7]]；另一处免费 [[e6]]'), null);
  for (const [locale, text] of [['zh-Hans', '3–12 岁 $6，父母陪同 [[e7]]'], ['zh-Hant', '3–12 歲 $6，家長陪同 [[e7]]'], ['en', 'Ages 3–12 $6; guardians stay with kids [[e7]]']]) assert.equal(tier('成人 $12，3–12 岁 $6', text, locale), null, text);
});
