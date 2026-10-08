// G12 / ENGINE-03 / ENGINE-04 regression set. Deterministic, $0: no model call.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const member = require('./support/member-session');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { safetyResponse, emergencyResponse, professionalTopics } = require('../lib/safetyRouting');
const catalog = require('../data/planner-catalog.json');
const guideCatalog = require('../data/guide-catalog.json');

// The 30 G12 cases: 10 must route (professional guard or emergency card),
// 20 must reach BayBay as ordinary questions. Every ENGINE-03 probe sentence
// is included; "移民" alone and "医疗" alone are life stages and places.
const MUST_ROUTE = [
  ['我爸65岁了，Medicare A和B有什么区别？', 'professional', 'medicare'],
  ['Medi-Cal 的牙科能看吗', 'professional', 'insurance'],
  ['今年报税季什么时候开始？有没有免费报税的地方？', 'professional', 'tax'],
  ['房东要驱逐我，我该怎么办', 'professional', 'legal'],
  ['绿卡面试要准备什么', 'professional', 'immigration'],
  ['移民律师怎么找比较靠谱？', 'professional', 'immigration'],
  ['我刚交了移民递件，多久会有消息？', 'professional', 'immigration'],
  ['医疗报告上的诊断看不懂，这个处方药该不该吃？', 'professional', 'medical'],
  ['我爸突然说话不清楚，半边身子没力气', 'emergency', 'stroke'],
  ["My dad suddenly can't speak and his face is drooping", 'emergency', 'stroke'],
];
const MUST_NOT_ROUTE = [
  '我是新移民，刚到湾区第一周要办什么？',
  '新移民第一周要办哪些事？',
  '周六想带刚移民来的爸妈去旧金山玩一天',
  '给新移民家庭的免费活动有哪些',
  '我是新移民，湾区有什么免费英语课？',
  '刚移民过来，怎么办Clipper长者卡？',
  'What should a new immigrant do first in San Jose?',
  '附近哪里有中文的医疗服务诊所？',
  '有没有中文的医疗翻译志愿者活动',
  '帮我写一条出租帖：两房一厅，近医疗中心',
  '没有牙科保险哪里看牙便宜',
  'Social Security 退休金怎么申请',
  '我是新移民，想办加州身份证要带什么？',
  '移民来湾区五年了，周末想带孩子去哪玩？',
  '去日本旅游需要签证吗？',
  '这家医疗中心附近有停车场吗？',
  '老人医疗陪诊志愿者在哪里报名？',
  '我妈中风后在康复，有适合她的中文活动吗？',
  '这个周末 Costco 大出血，值得去吗？',
  '孩子眼皮一直抽搐，要看哪个科？',
];

test('G12 regression: exactly 10 must-route and 20 must-not-route cases', () => {
  assert.equal(MUST_ROUTE.length, 10); assert.equal(MUST_NOT_ROUTE.length, 20);
  for (const [message, route, topic] of MUST_ROUTE) {
    const result = safetyResponse(message, /[㐀-鿿]/u.test(message) ? 'zh-Hans' : 'en');
    assert.equal(result?.safetyRoute, route, message);
    assert.equal(route === 'emergency' ? result.emergencyTopic : result.safetyTopic, topic, message);
    assert.equal(result.safety.kind, route, message);
  }
  for (const message of MUST_NOT_ROUTE) {
    assert.equal(safetyResponse(message), null, message);
    assert.deepEqual(professionalTopics(message), [], message);
  }
});

// ENGINE-04 emergency lexicon in three languages, by topic.
const EMERGENCIES = {
  stroke: [['zh-Hans', '我爸突然说话不清楚，半边身子没力气，怎么办'], ['zh-Hans', '我妈嘴歪了，好像中风了'], ['zh-Hant', '我爸突然說話不清楚，半邊身子沒力氣'],
    ['en', 'I think my mom is having a stroke'], ['en', 'His face is drooping and his speech is slurred']],
  unconscious: [['zh-Hans', '我妈晕倒了叫不醒'], ['zh-Hans', '奶奶突然昏迷了'], ['zh-Hant', '我媽暈倒了叫不醒'], ['en', 'My grandpa is unconscious'], ['en', "She passed out and won't wake up"]],
  breathing: [['zh-Hans', '他没有呼吸了'], ['en', 'The baby is not breathing']],
  bleeding: [['zh-Hans', '流了很多血止不住'], ['zh-Hans', '我爸摔倒后大出血'], ['zh-Hant', '傷口血流不止'], ['en', 'My son is bleeding heavily and it will not stop'], ['en', 'Severe bleeding from a cut']],
  anaphylaxis: [['zh-Hans', '孩子过敏喉咙肿了'], ['zh-Hant', '孩子過敏嘴唇腫了'], ['zh-Hans', '吃了花生后严重过敏反应'], ['en', 'My throat is swelling after eating peanuts'], ['en', 'She is having anaphylaxis']],
  cardiac: [['zh-Hans', '心脏病发作怎么办'], ['zh-Hans', '我爸有心脏病发作的症状'], ['zh-Hant', '我爸好像心臟病發作'], ['en', 'I think my husband is having a heart attack']],
  seizure: [['zh-Hans', '孩子突然全身抽搐'], ['zh-Hant', '他癲癇發作了'], ['en', 'My son is having a seizure']],
  ingestion: [['zh-Hans', '孩子误吞了电池'], ['zh-Hans', '宝宝吞了一个纽扣电池'], ['zh-Hant', '孩子誤吞了磁鐵'], ['en', 'My toddler swallowed a button battery'], ['en', 'He swallowed two magnets']],
};
const FIRST_SENTENCE = { 'zh-Hans': '请立即拨打 911。', 'zh-Hant': '請立即撥打 911。', en: 'Call 911 now.' };

for (const [topic, cases] of Object.entries(EMERGENCIES)) {
  test(`emergency lexicon: ${topic} routes to a 911-first card with a tel:911 action in every language`, () => {
    for (const [locale, message] of cases) {
      const result = emergencyResponse(message, locale);
      assert.equal(result?.safetyRoute, 'emergency', message);
      assert.equal(result.emergencyTopic, topic, message);
      assert.ok(result.answer.startsWith(FIRST_SENTENCE[locale]), `${message}: ${result.answer}`);
      assert.match(result.answer, /1-800-222-1222/); assert.match(result.answer, /988/);
      assert.equal(result.safety.kind, 'emergency');
      assert.deepEqual(result.safety.actions[0], { id: 'call-911', label: { 'zh-Hans': '拨打 911', 'zh-Hant': '撥打 911', en: 'Call 911' }[locale], href: 'tel:911', primary: true });
      assert.ok(result.safety.actions.some(action => action.href === 'tel:+18002221222'));
      assert.ok(result.safety.actions.some(action => action.href === 'tel:988'));
      assert.equal(result.safety.hideFollowups, true); assert.equal(result.safety.hideFeedback, true);
      assert.deepEqual(result.followups, []); assert.deepEqual(result.suggestedGuides, []);
      assert.equal(result.degraded, false);
    }
  });
}

test('emergency lexicon does not fire on denials, history, slang or ordinary site questions', () => {
  for (const message of [
    '孩子没有误吞电池', '我妈以前晕倒过，现在好了', '我没有呼吸困难', 'BayBay 没反应了怎么办', '他没反应过来', '电池回收点在哪里？',
    '商家大出血促销', '他们家这次大出血', '心脏病发作前有什么征兆？以前听过讲座', 'What are the signs of a heart attack?', '孩子口齿不清要看语言治疗吗？',
    'What is unconscious bias training?', 'They passed out flyers at the fair', 'The website is not responding',
    'Where can I recycle batteries?', 'Stroke rehabilitation classes for seniors', 'Translate: my face is drooping',
  ]) assert.equal(emergencyResponse(message), null, message);
});

test('BayBay keeps a guarded model answer for professional topics: guard rules, pillar guide, contact and no interception', async () => {
  const payloads = [];
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'isolated-guard-fixture', BAYBAY_STATE_SECRET: 'isolated-guard-state' }, catalog, guideCatalog, isTest: true, now: () => Date.parse('2026-10-08T17:00:00Z'),
    ai: async payload => {
      payloads.push(payload);
      const input = JSON.parse(payload.input[0].content);
      const pillar = input.evidence.find(row => row.url === '/guides/bay-area-medicare-hicap-medi-cal-guide');
      // The fake model forgets the HICAP phone number on purpose.
      return { status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text',
        text: JSON.stringify({ answer: `Part A 主要是住院，Part B 主要是门诊；具体选择请找免费咨询。[[${pillar.id}]]`, candidateIds: [], followups: [] }) }] }] };
    } });
  const result = await assistant.run({ message: '我爸65岁了，Medicare A和B有什么区别？', locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(payloads.length, 1, 'the professional question reaches the model');
  const instructions = payloads[0].instructions;
  assert.match(instructions, /Professional-topic guard \(medicare\)/);
  assert.match(instructions, /never a refusal or a one-line redirect/);
  assert.match(instructions, /Do not decide this person's individual eligibility/);
  assert.match(instructions, /HICAP 免费 Medicare 咨询 1-800-434-0222/);
  assert.match(instructions, /tell the user not to send them/);
  assert.equal(result.responseMode, 'assistant'); assert.equal(result.degraded, false);
  assert.equal(result.safetyRoute, 'professional'); assert.equal(result.safetyTopic, 'medicare');
  // The model's explanation stays; the resource card's phone is appended once.
  assert.match(result.answer, /^Part A 主要是住院/);
  assert.match(result.answer, /官方联系：HICAP 免费 Medicare 咨询 1-800-434-0222 \[\d\]/);
  assert.equal(result.answer.match(/1-800-434-0222/g).length, 1);
  assert.ok(result.safety.resources.some(row => row.href === 'tel:+18004340222'));
  assert.equal(result.suggestedGuides[0].slug, 'bay-area-medicare-hicap-medi-cal-guide');
  // USCIS is the immigration contact; there is no phone to append.
  const immigration = safetyResponse('绿卡面试要准备什么').safety;
  assert.ok(immigration.resources.some(row => row.url === 'https://www.uscis.gov/'));
  assert.equal(immigration.guides[0].slug, 'bay-area-naturalization-official-path-guide');
  // VITA is the tax contact.
  assert.ok(safetyResponse('有没有免费报税的地方').safety.resources.some(row => row.phone === '800-906-9887' && row.href === 'tel:+18009069887'));
});

async function helperFixture(t) {
  const calls = { postAssist: 0, guide: 0, planner: 0 };
  const draft = { title: 'Room for rent', description: 'Two-bedroom apartment near a medical center. Contact for viewing times.', category: 'rent', type: 'provider', area: '', budget: '', timeInfo: '', quickTags: [], safetyTip: '', coverSuggestion: '' };
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: member.SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-claude' },
    models: createMemoryModels({ User: [member.user] }),
    postAssistFetch: async () => { calls.postAssist++; return { ok: true, json: async () => ({ type: 'message', model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(draft) }] }) }; },
    ai: { guideChat: async () => { calls.guide++; throw new Error('No legacy provider'); }, planner: { recommend: async () => { calls.planner++; throw new Error('No planner provider'); } } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const post = async (path, body, headers = {}) => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  return { calls, post };
}

test('post assist only runs the emergency check: rent near a medical center and a tax-service post are ordinary drafts', async t => {
  const f = await helperFixture(t);
  for (const intent of ['帮我写一条出租帖：两房一厅，近医疗中心', '我提供报税服务，帮我写一条服务帖']) {
    const result = await f.post('/api/ai/post-assist', { intent, language: 'zh' }, member.headers());
    assert.equal(result.status, 200, intent); assert.equal(result.data.safetyRoute, undefined, intent); assert.ok(result.data.draft, intent);
  }
  assert.equal(f.calls.postAssist, 2);
  const emergency = await f.post('/api/ai/post-assist', { intent: '帮我写个帖子，我现在胸口很痛喘不过气', language: 'zh' }, member.headers());
  assert.equal(emergency.data.safetyRoute, 'emergency'); assert.ok(emergency.data.answer.startsWith('请立即拨打 911。'));
  assert.equal(f.calls.postAssist, 2, 'the emergency never reaches the helper');
});

test('legacy guide chat and the planner keep the deterministic professional template', async t => {
  const f = await helperFixture(t);
  const legacy = await f.post('/api/ai/guide-chat', { message: '绿卡面试要准备什么', locale: 'zh-Hans' });
  assert.equal(legacy.data.safetyRoute, 'professional'); assert.equal(legacy.data.responseMode, 'safety'); assert.equal(legacy.data.safety.topic, 'immigration');
  const planner = await f.post('/api/planner/recommend', { intent: '带爸妈去问 Medicare 怎么选', locale: 'zh-Hans' });
  assert.equal(planner.data.safetyRoute, 'professional'); assert.equal(planner.data.safetyTopic, 'medicare');
  // A narrowed topic is no longer intercepted on the legacy path either.
  const outing = await f.post('/api/ai/guide-chat', { message: '周六想带刚移民来的爸妈去旧金山玩一天', locale: 'zh-Hans' });
  assert.notEqual(outing.data.safetyRoute, 'professional');
  assert.equal(f.calls.planner, 0);
});
