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
