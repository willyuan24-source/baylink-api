const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { planPostSearch } = require('../lib/baybaySearch');
const { buildChatWebRequest } = require('../lib/guideWebSearch');
const { needsSourceFacts } = require('../lib/plannerWebFacts');
const { requestSearch } = require('../lib/plannerWebSearch');
const { resolveTaskState } = require('../lib/baybayState');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { loadPlannerCatalog } = require('../lib/planner');
const { isSchoolRequest } = require('../lib/guideConversation');
const guideCatalog = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const NOW = Date.parse('2026-10-05T19:00:00Z');
const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
const official = { title: 'Official district enrollment', url: 'https://fremontunified.org/enrollment/' };
function cited(text, source = official) {
  const content = `${text} [official]`;
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: content, annotations: [{ type: 'url_citation', ...source, start_index: content.indexOf('[official]'), end_index: content.length }] }] }] };
}
async function fixture(t, options = {}) {
  const calls = { agent: [], guide: [], web: [] };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'public-routing-fixture-only' }, models: createMemoryModels(), plannerNow: () => NOW,
    ai: { guideChat: async payload => { calls.guide.push(payload); return { answer: '城市不等于学区，请自行到学区官方地址工具核对；无需在聊天中提交孩子身份或住址。' }; },
      baybay: async payload => {
        calls.agent.push(payload);
        const context = JSON.parse(payload.input[0].content);
        const source = context.evidence.find(row => row.kind === 'guide') || context.evidence[0];
        return { status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: options.agentAnswer || `城市不等于学区；请按年级和目标学年核对官方规则，不能由城市猜具体学校。${source ? ` [[${source.id}]]` : ''}`, candidateIds: [], followups: [] }) }] }] };
      },
      plannerWebSearch: async payload => { calls.web.push(payload); if (options.error) throw options.error; return cited('Check the district enrollment page for the requested academic year; an application does not guarantee school assignment.'); },
      plannerWebExtract: async () => assert.fail('public rules must not invoke visitor extraction'),
    }, plannerWebLookup: lookup });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const ask = async body => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json(); assert.equal(response.status, 200, JSON.stringify(data)); return data;
  };
  return { calls, ask };
}

test('public enrollment is eligible for web while school years are not coerced into outing dates', () => {
  for (const searchMode of ['smart', 'web', 'site']) {
    const result = buildChatWebRequest({ message: 'Fremont Unified 2027–28 TK 入学年龄与报名时间', school: true, searchMode, locale: 'zh-Hans', today: '2026-10-05', searchContext: { date: '2026-10-10' } });
    assert.equal(result.search, searchMode !== 'site'); assert.equal(result.input.date, undefined);
    assert.match(result.input.query, /2027–28 TK/); assert.doesNotMatch(result.input.query, /admission budget/);
  }
  for (const message of ['My child is named Example Child, which Fremont school?', '孩子名字叫示例，在哪个小学报名？', 'Fremont school for 123 Example Street', '孩子出生日期：2020-03-04，如何入学？', 'School enrollment for private@example.test',
    '孩子叫示例宝宝，2020年3月4日出生，Sunnyvale 入学怎么办？', 'My son Example Child was born on March 4, 2020. How do I enroll him in Fremont school?',
    '孩子2020年3月4日出生，Fremont 怎么入学？', 'My son was born on 03/04/2020. What Fremont school enrollment rules apply?', 'My son Example Child needs school enrollment in Fremont.']) {
    const result = buildChatWebRequest({ message, school: true, searchMode: 'web', locale: 'en', today: '2026-10-05' });
    assert.equal(result.search, false, message); assert.equal(result.status, 'not_applicable'); assert.equal(result.input, undefined);
  }
  const followup = buildChatWebRequest({ message: 'Fremont 呢？', school: true, searchMode: 'web', locale: 'zh-Hans', today: '2026-10-05', history: [{ role: 'user', content: 'School enrollment at 123 Example Street' }] });
  assert.equal(followup.search, true); assert.doesNotMatch(followup.input.query, /123|Example Street/);
  for (const message of ['孩子6岁，明年一年级，Fremont 入学材料有哪些？', 'My son is six and starts first grade in 2027. What are Fremont enrollment requirements?', 'For 2027 enrollment, does the official rule say children born on or before September 1, 2021 qualify?']) {
    const result = buildChatWebRequest({ message, school: true, searchMode: 'web', locale: 'en', today: '2026-10-05' });
    assert.equal(result.search, true, message); assert.ok(result.input);
  }
});

test('entity mentions alone do not turn a statement into research or a ticket followup into education', () => {
  assert.equal(isSchoolRequest('Recheck child admission. Keep the order and places; do not change the itinerary.'), false);
  assert.equal(isSchoolRequest('College admission requirements'), true);
  const fresh = resolveTaskState({ message: 'Can I use SFPL library card in San Francisco?', today: '2026-10-05', catalog });
  assert.equal(fresh.state.city, 'San Francisco');
  for (const searchMode of ['smart', 'site']) {
    const context = { searchMode, locale: 'zh-Hans', today: '2026-10-05', history: [{ role: 'user', content: 'San Jose events tomorrow' }] };
    assert.deepEqual(buildChatWebRequest({ ...context, message: '明天我要考驾照' }), { search: false, status: 'not_requested' });
    const asked = buildChatWebRequest({ ...context, message: '明天考驾照需要带什么材料？' });
    assert.equal(asked.search, searchMode === 'smart'); assert.ok(asked.input); assert.equal(asked.input.date, undefined);
    assert.doesNotMatch(asked.input.query, /San Jose|events/);
  }
});

test('v2 school questions reach the assistant with appropriate regional school guides and no old outing plan', async t => {
  const { ask, calls } = await fixture(t);
  const message = '原来住 Sunnyvale，准备搬到 Cupertino。孩子一年级，2027–28 学年入学要怎么核对学区？不要按城市猜学校。';
  const result = await ask({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans', history: [{ role: 'user', content: '在旧金山安排一天行程' }, { role: 'assistant', content: '请先确认出发时间。' }] });
  assert.equal(result.responseMode, 'assistant'); assert.equal(result.taskState.goal, 'information'); assert.equal(result.assistantPlan, undefined);
  assert.equal(calls.guide.length, 0); assert.equal(calls.web.length, 0); assert.ok(calls.agent.length);
  const first = JSON.parse(calls.agent[0].input[0].content);
  assert.equal(first.message, message); assert.match(calls.agent[0].instructions, /city is not a school district/);
  const guides = first.evidence.filter(row => row.kind === 'guide');
  assert.ok(guides.some(row => /south-bay-school-district-enrollment-guide/.test(row.url)));
  assert.ok(guides.every(row => /school-(?:district|enrollment)/.test(row.url)));
  assert.equal(first.candidates.length, 0); assert.match(guides.map(row => row.text).join('\n'), /Cupertino|Sunnyvale/);
});

test('the exact school boundary question is information about two cities, not a destination-choice clarification', async t => {
  const message = '住 Sunnyvale 是不是就能去 Cupertino 的学校？孩子明年上一年级。';
  const resolved = resolveTaskState({ message, today: '2026-10-05', catalog });
  assert.equal(resolved.state.goal, 'information'); assert.equal(resolved.clarification, undefined);
  assert.equal(resolved.state.city, null); assert.equal(resolved.state.partySize, null); assert.deepEqual(resolved.state.childAges, []);
  const { ask, calls } = await fixture(t);
  const result = await ask({ message, assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans' });
  assert.equal(result.responseMode, 'assistant'); assert.ok(calls.agent.length); assert.equal(result.assistantPlan, undefined);
  assert.doesNotMatch(result.answer, /选择一个目的城市/);
  const context = JSON.parse(calls.agent[0].input[0].content);
  assert.equal(context.message, message);
  const guides = context.evidence.filter(row => row.kind === 'guide');
  assert.ok(guides.some(row => /south-bay-school-district-enrollment-guide/.test(row.url)));
  const text = guides.map(row => row.text).join('\n');
  assert.match(text, /Sunnyvale/); assert.match(text, /Cupertino/);
  assert.match(calls.agent[0].instructions, /Preserve each requested city, grade and academic year/);
});

test('school web research uses official cited results in v2 and legacy without sending private school details', async t => {
  const { ask, calls } = await fixture(t);
  for (const assistantVersion of [undefined, 2]) {
    const before = calls.web.length;
    const result = await ask({ message: 'Fremont Unified 2027–28 TK 入学年龄与报名时间，请查官方', assistantVersion, searchMode: 'web', locale: 'zh-Hans' });
    assert.equal(calls.web.length, before + 1); assert.equal(result.retrieval.webStatus, 'completed');
    assert.ok(result.sources?.length); assert.match(calls.web.at(-1).instructions, /school year/);
  }
  const before = calls.web.length, agentBefore = calls.agent.length;
  for (const message of ['My child is named Example Child; we live at 123 Example Street, Fremont. Which school?', '孩子叫示例宝宝，2020年3月4日出生，Sunnyvale 入学怎么办？', 'My son Example Child was born on March 4, 2020. How do I enroll him in Fremont school?']) {
    const privateResult = await ask({ message, assistantVersion: 2, searchMode: 'web', locale: 'en' });
    assert.equal(calls.web.length, before); assert.equal(calls.agent.length, agentBefore);
    assert.equal(privateResult.retrieval.webStatus, 'not_applicable');
  }
});

test('public tenant/repair rules bypass posts while actual housing and service requests retain post matching', async t => {
  for (const [message, category] of [['Fremont 租房有哪些租客权益？', 'rent'], ['Find Oakland rent control rules', 'rent'], ['有哪些 San Jose 维修许可要求？', 'repair']]) assert.equal(planPostSearch(message, category), null, message);
  for (const [message, category] of [['找 Fremont 房源', 'rent'], ['Find Oakland apartments available now', 'rent'], ['找 Sunnyvale 维修水管服务', 'repair'], ['Find Bay Area cleaning', 'cleaning']]) assert.ok(planPostSearch(message, category)?.query, message);
  const { ask, calls } = await fixture(t);
  const result = await ask({ message: 'Fremont 租房有哪些租客权益？', assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans' });
  assert.equal(result.responseMode, 'assistant'); assert.ok(calls.agent.length); assert.deepEqual(result.matchingPosts, []);
});

test('non-visitor fees and opening questions preserve service facts instead of admission templates', async () => {
  for (const query of ['PG&E electricity prices', 'library printing prices', 'DMV office hours and vehicle registration fees', 'school admission dates', 'ACWD water rates and office hours', '图书馆打印价格与开放时间', 'San Jose house cleaning prices', 'Oakland apartment rental prices']) {
    assert.equal(needsSourceFacts({ query }), false, query);
    let instructions;
    const fact = 'The program fee is $0.15 per black-and-white page; eligibility must be checked for this specific service.';
    const result = await requestSearch({ query, locale: 'en', date: '2026-10-10' }, { isTest: true, lookup, ai: async payload => { instructions = payload.instructions; return cited(fact); }, extractAi: async () => assert.fail('no visitor extraction'), sourceFetch: async () => assert.fail('no visitor page formatting') });
    assert.equal(result.answer, `${fact} [1]`); assert.equal(result.sources[0].url, official.url); assert.deepEqual(result.candidates, []);
    assert.match(instructions, /fee units/); assert.doesNotMatch(result.answer, /Admission details|last entry|ticket availability/);
  }
  for (const query of ['museum hours and admission', 'Oakland 博物馆门票和营业时间', 'SFMOMA周三开馆吗']) assert.equal(needsSourceFacts({ query }), true, query);
});

test('legacy web failures expose only normalized safe failure codes', async t => {
  for (const [code, expected] of [['web_daily_limit', 'web_daily_limit'], ['web_rate_limit', 'web_rate_limit'], ['private-provider-code', 'web_provider_unavailable']]) {
    const { ask } = await fixture(t, { error: Object.assign(new Error('PRIVATE upstream details'), { code }) });
    const result = await ask({ message: 'Fremont school enrollment rules', searchMode: 'web', locale: 'en' });
    assert.equal(result.retrieval.failureCode, expected); assert.equal(result.retrieval.webStatus, 'unavailable');
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE|private-provider-code/);
  }
});

test('v2 retains the legacy protection against invented regional school districts', async t => {
  const { ask } = await fixture(t, { agentAnswer: 'Apply to the Peninsula School District for first grade.' });
  const result = await ask({ message: 'San Mateo first grade school enrollment', assistantVersion: 2, searchMode: 'site', locale: 'en' });
  assert.equal(result.degraded, true); assert.ok(result.research.warnings.includes('answer_school_authority_rejected'));
  assert.doesNotMatch(result.answer, /Peninsula School District/); assert.match(result.answer, /city is not a school district/);
  assert.ok(result.sources.length);
});

test('the real library chain preserves Fremont and recalls AC card/film facts, not housing advice', () => {
  const initial = '刚搬到Fremont，图书馆卡网上办行不行？能顺便免费打印吗？';
  let state = resolveTaskState({ message: initial, today: '2026-10-05', catalog }).state;
  const first = buildSiteEvidence({ query: initial, originalQuery: initial, state, guideCatalog, catalog, today: '2026-10-05' });
  assert.ok(first.guides.some(row => /AC Library：网上申请/.test(row.sectionHeading)));
  assert.ok(first.guides.some(row => /实体 Library Card/.test(row.text) && /10 页黑白/.test(row.text)));
  state = resolveTaskState({ message: '今天只打印12页黑白', previous: state, today: '2026-10-05', catalog }).state;
  const message = '那 Kanopy也能看？一定要再办 SF的卡吗？';
  state = resolveTaskState({ message, previous: state, today: '2026-10-05', catalog }).state;
  assert.equal(state.goal, 'newcomer'); assert.equal(state.city, 'Fremont'); assert.equal(state.region, 'east-bay');
  const followup = buildSiteEvidence({ query: message, originalQuery: message, state, guideCatalog, catalog, today: '2026-10-05' });
  const ac = followup.guides.find(row => /AC Library：先分清/.test(row.sectionHeading));
  assert.ok(ac); assert.match(ac.text, /hoopla/); assert.match(ac.text, /未找到 AC 卡适用的 Kanopy/);
  assert.ok(ac.sourceUrls.some(source => source.url === 'https://aclibrary.org/movies-tv/'));
  assert.ok(followup.guides.some(row => /SFPL：Kanopy/.test(row.sectionHeading)));
  assert.ok(followup.guides.every(row => !/rent|rental|housing/.test(row.slug)));
  assert.ok(followup.guides.length <= 8);
  for (const next of ['我准备搬到 San Francisco，图书馆卡怎么申请？', '那就去 San Francisco 图书馆办卡', 'I am moving to San Francisco; how do I get a library card?', '搬到 San Francisco 后请比较 SFPL 和 AC Library 图书证资格']) {
    assert.equal(resolveTaskState({ message: next, previous: state, today: '2026-10-05', catalog }).state.city, 'San Francisco', next);
  }
});
