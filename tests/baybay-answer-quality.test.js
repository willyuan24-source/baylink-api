const test = require('node:test');
const assert = require('node:assert/strict');
const { requestChecklist, coverageFor, checklistAnswer, admissionConflict, sourcedPlanSummary, needsExtendedSynthesis, directSiteAnswer } = require('../lib/baybayAnswerQuality');
const { createStageTimer, boundedOperation } = require('../lib/baybayTiming');
const { createBayBayAssistant } = require('../lib/baybayAgent');

const NOW = Date.parse('2026-10-04T19:00:00Z');
const libraryQuestion = '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。';
const final = value => ({ status: 'completed', model: 'fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ candidateIds: [], followups: [], ...value }) }] }] });
const calls = rows => ({ status: 'completed', output: rows.map(([name, args], index) => ({ type: 'function_call', name, call_id: `call-${index}`, arguments: JSON.stringify(args) })) });
const base = extra => ({ config: { JWT_SECRET: 'quality-fixture-signing-key' }, isTest: true, now: () => NOW, catalog: { version: 1, checkedAt: '2026-10-04', places: [], events: [], guides: [] }, ...extra });
const libraryGuide = { slug: 'library-fixture', title: '图书馆服务资格比较', summary: 'Library service eligibility', keywords: ['Kanopy', '图书馆', '打印'], content: '打印服务\n\n站内记录区分打印、Kanopy 和借博物馆门票。不同发卡馆的居住地、年龄、eCard 与正式卡规则各自适用，不能把一张卡的借阅权限用于另一馆。此测试站内段落不代表实时官方核验。', updatedAt: '2026-10-04' };

test('the audited library prompt preserves each requested subject without inventing eligibility', () => {
  const checklist = requestChecklist(libraryQuestion, 'zh-Hans');
  assert.equal(checklist.complex, true);
  assert.deepEqual(checklist.items.map(item => item.id), ['printing', 'kanopy', 'museum_passes', 'card_eligibility', 'official_entries']);
  assert.ok(requestChecklist(libraryQuestion, 'en').items.every(item => !/[\u3400-\u9fff]/.test(item.label)));
  const coverage = coverageFor({ checklist, draft: { coverage: [{ id: 'kanopy', status: 'answered', summary: 'Everyone is eligible.', sourceIds: ['invented'] }] }, sources: new Map(), locale: 'en' });
  assert.equal(coverage.status, 'partial');
  assert.ok(coverage.items.every(item => item.status === 'unknown'));
  assert.doesNotMatch(JSON.stringify(coverage), /Everyone is eligible|invented/);
  const answer = checklistAnswer('Recorded rules differ.', coverage, checklist);
  assert.match(answer, /Kanopy/); assert.match(answer, /打印/);
  assert.equal(requestChecklist('Hello, tell me a joke.', 'en').assessmentScope, 'unassessed');
});

test('three source reads end research with a substantive cited answer for every library topic', async t => {
  const start = Date.now(); let elapsed = 0, rounds = 0, reads = 0;
  t.mock.method(Date, 'now', () => start + elapsed);
  const events = [], payloads = [];
  const urls = ['https://www.sfpl.org/kanopy', 'https://smcl.org/printing', 'https://aclibrary.org/passes'];
  const facts = [
    'Kanopy fixture: use the participating library account, not any Bay Area library card. Its current film allowance requires checking.',
    'Printing fixture: a separate participating library account is required. The catalog printing allowance is a snapshot, not a current entitlement.',
    'Museum passes fixture: residence, age and physical card eligibility apply separately at the issuing library. An eCard alone does not establish eligibility.',
  ];
  const assistant = createBayBayAssistant(base({ guideCatalog: [libraryGuide],
    webSearch: async () => { elapsed += 30; return { answer: 'Three official source leads.', sources: urls.map((url, i) => ({ title: `Library official ${i}`, url })), candidates: [] }; },
    sourceFetch: async source => { reads++; elapsed += 12; return { text: facts[urls.indexOf(source.url)] }; },
    ai: async payload => {
      payloads.push(payload); elapsed += 20;
      const context = JSON.parse(payload.input[0].content);
      if (++rounds === 1) {
        const refs = urls.map(url => context.evidence.find(source => source.url === url).id);
        return calls([...refs.map(sourceId => ['read_source', { sourceId }]), ['read_source', { sourceId: refs[0] }]]);
      }
      assert.deepEqual(payload.tools, []);
      assert.match(payload.instructions, /Return the final JSON now/);
      assert.doesNotMatch(payload.instructions, /Keep the answer within six|Keep answer under 1400/);
      assert.equal(context.researchBudget.readsRemaining, 0);
      for (const fact of facts) assert.ok(context.evidence.some(source => source.text === fact));
      const summaryByTopic = {
        printing: '打印：站内额度是收录快照；须按该发卡馆的账户要求领取。',
        kanopy: 'Kanopy：需使用参与馆的账户，不能用任意湾区卡；当前观看额度尚需核对。',
        museum_passes: '馆票：发卡馆有单独的居住地和年龄条件；eCard 不足以证明资格。',
        card_eligibility: '各馆的居住地、年龄和正式卡要求分开判断，不能互相套用。',
        official_entries: '所列三个官方入口分别对应影片、打印和馆票规则。',
      };
      return final({ answer: '这些服务的发卡馆条件不同，先按现有卡与另办卡区分。', coverage: context.requestChecklist.map((item, index) => ({ id: item.id, status: index === 1 ? 'unknown' : 'answered', summary: summaryByTopic[item.id], sourceIds: [context.evidence.find(source => source.url === urls[index % 3]).id] })) });
    },
  }));
  const result = await assistant.run({ message: libraryQuestion, searchMode: 'smart', onProgress: event => events.push(event) });
  assert.equal(rounds, 2); assert.equal(reads, 3); assert.equal(result.degraded, false);
  assert.equal(result.answerCoverage.status, 'partial');
  assert.match(result.answer, /打印：站内额度/); assert.match(result.answer, /Kanopy：需使用/); assert.match(result.answer, /eCard 不足以/);
  assert.ok(result.answerCoverage.items.every(item => item.sourceIds.every(id => result.evidence.some(source => source.id === id))));
  assert.equal(result.research.timings.searchMs, 30); assert.equal(result.research.timings.readMs, 36);
  assert.equal(result.research.timings.modelMs, 20); assert.equal(result.research.timings.finalMs, 20);
  assert.equal(result.research.timings.totalMs, 106);
  assert.ok(events.some(event => event.phase === 'sources' && event.status === 'completed'));
  assert.ok(events.some(event => event.phase === 'answer' && event.status === 'running'));
  assert.ok(events.every(event => Object.keys(event).sort().join(',') === 'phase,status'));
  assert.doesNotMatch(JSON.stringify(result.research.timings), /Fremont|Library|https|signing/);
});

test('simple site eligibility starts final synthesis directly, still uses model evidence and tolerates broken progress listeners', async () => {
  let rounds = 0;
  const guide = { ...libraryGuide, content: 'Kanopy 使用条件\n\n这是一份记录账户资格与影片观看条件的站内资料。当前已收录的是特定参与图书馆的卡种限制，并不表示所有图书证均可使用；个人持卡资格和观看额度需要按自己的发卡馆核对。' };
  const assistant = createBayBayAssistant(base({ guideCatalog: [guide], ai: async payload => {
    rounds++; assert.deepEqual(payload.tools, []);
    const context = JSON.parse(payload.input[0].content);
    assert.ok(context.evidence.some(source => source.text.includes('并不表示所有图书证均可使用')));
    return final({ answer: '这份站内资料不能证明你的个人使用资格，请先说明发卡馆。', coverage: [{ id: 'kanopy', status: 'needs_user_input', summary: '请说明图书证的发卡馆，才能判断此卡能否使用。', sourceIds: [] }] });
  } }));
  const result = await assistant.run({ message: '我可以用 Kanopy 吗？', searchMode: 'site', onProgress: () => { throw new Error('UI disappeared'); } });
  assert.equal(rounds, 1); assert.equal(result.degraded, false);
  assert.equal(result.answerCoverage.items[0].status, 'needs_user_input');
  assert.equal(result.retrieval.webStatus, 'not_requested');
});

test('failed research still receives a reserved tool-free final synthesis attempt', async () => {
  let rounds = 0;
  const assistant = createBayBayAssistant(base({ guideCatalog: [libraryGuide], ai: async payload => {
    if (++rounds === 1) throw new Error('Research model timeout');
    assert.deepEqual(payload.tools, []);
    assert.match(payload.instructions, /Research is complete/);
    return final({ answer: '现有站内记录能够区分服务，但最新额度尚未核对。', coverage: [] });
  } }));
  const result = await assistant.run({ message: libraryQuestion, searchMode: 'site' });
  assert.equal(rounds, 2); assert.equal(result.degraded, false);
  assert.ok(result.research.warnings.includes('final_synthesis_recovered'));
  assert.equal(result.research.modelResponses[0].status, 'failed');
  assert.equal(result.answerCoverage.items.length, 5);
});

test('quota errors fail closed before any model call and remain observable without identifiers', async () => {
  let models = 0;
  const assistant = createBayBayAssistant(base({ Quota: { updateOne: async () => { throw new Error('private database endpoint'); } }, ai: async () => { models++; return final({ answer: 'No.' }); } }));
  const result = await assistant.run({ message: '图书馆资料', searchMode: 'site' });
  assert.equal(models, 0); assert.equal(result.degraded, true);
  assert.ok(result.research.warnings.includes('quota_unavailable'));
  assert.ok(Number.isFinite(result.research.timings.quotaMs));
  assert.doesNotMatch(JSON.stringify(result.research), /private database endpoint/);
});

test('timings are exclusive aggregated stages and bounded operations terminate a stalled dependency', async t => {
  const began = Date.now(); let elapsed = 0;
  t.mock.method(Date, 'now', () => began + elapsed);
  const timer = createStageTimer(began);
  timer.sync('stateMs', () => { elapsed += 7; });
  await timer.measure('quotaMs', async () => { elapsed += 9; });
  elapsed += 4;
  const result = timer.snapshot();
  assert.equal(result.stateMs, 7); assert.equal(result.quotaMs, 9); assert.equal(result.otherMs, 4); assert.equal(result.totalMs, 20);
  assert.ok(Object.values(result).every(value => Number.isFinite(value) && value >= 0));
  await assert.rejects(boundedOperation(() => new Promise(() => {}), 5, 'fixture_timeout'), { code: 'fixture_timeout' });
});

test('an answered status cannot hide an explicitly unresolved summary, while known facts stay visible', () => {
  const checklist = requestChecklist(libraryQuestion);
  const sources = new Map([['source', { id: 'source' }]]);
  for (const summary of ['此项尚未确认。', '门票尚未核实。', 'This item is unconfirmed.', 'The current amount still needs verification.']) {
    const coverage = coverageFor({ checklist, sources, locale: 'zh-Hans', draft: { coverage: checklist.items.map(item => ({ id: item.id, status: 'answered', summary, sourceIds: ['source'] })) } });
    assert.equal(coverage.status, 'partial', summary);
    assert.ok(coverage.items.every(item => item.status === 'unknown'));
  }
  const mixed = '已知此馆要求正式卡；当前库存尚未确认。';
  const result = coverageFor({ checklist, sources, draft: { coverage: [{ id: 'museum_passes', status: 'answered', summary: mixed, sourceIds: ['source'] }] } });
  assert.equal(result.items.find(item => item.id === 'museum_passes').summary, mixed);
  assert.deepEqual(result.items.find(item => item.id === 'museum_passes').sourceIds, ['source']);
});

test('only a conflicting collective total is rejected, not a free venue or child-only/per-person/conditional claim', () => {
  const plan = { budget: { knownTotalUsd: 109.85 }, stops: [
    { title: 'Exploratorium · 日间科学探索馆', admissionFacts: { knownTotalUsd: 109.85 } },
    { title: '渔人码头与 PIER 39', admissionFacts: { knownTotalUsd: 0 } },
  ] };
  for (const sentence of ['Exploratorium 两位成人和孩子的门票合计是 $0，全部免费。', '全家门票合计 $80。', 'Family admission total: $0.', '全程费用合计 $100。']) assert.ok(admissionConflict(sentence, plan), sentence);
  for (const sentence of ['Pier 39 门票合计 $0，全部免费。', 'Exploratorium 每位成人门票合计 $39.95。', '儿童门票合计 $0。', '两位成人门票合计 $79.90。', '如果符合图书馆票条件，全家门票合计 $0。', '全家门票合计不是 $0。', '全家门票合计 $109.85。', 'Pier 39 is free; family admission total is $109.85.']) assert.equal(admissionConflict(sentence, plan), null, sentence);
});

test('the real strict waterfront query replaces an unsupported free total with the same structured cost as its plan', async () => {
  const message = '请规划 2026 年 10 月 10 日的旧金山路线，严格按 Ferry Building → Exploratorium → Pier 39 的顺序，不加其他景点。2 位成人和 1 名 5 岁孩子，10:00 从 Ferry Building 出发，17:00 在 Pier 39 结束，只步行或公交，全家总预算 $120 包括门票、交通和午餐。请核对三处的营业安排、孩子票价与路线时长；预算不够或没有查到的内容请直接说明，不要当作免费或已确认。';
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'quality-cost-conflict-secret' }, isTest: true, now: () => NOW,
    ai: async payload => { const context = JSON.parse(payload.input[0].content); const sourceId = context.candidates.find(candidate => candidate.id === 'venue-exploratorium-daytime').sourceIds[0];
      return final({ answer: `Exploratorium 两位成人和孩子的门票合计是 $0，全部免费。 [[${sourceId}]]`, candidateIds: ['venue-exploratorium-daytime', 'pier39'] }); },
  });
  const result = await assistant.run({ message, searchMode: 'site' });
  assert.equal(result.assistantPlan.budget.knownTotalUsd, 109.85);
  assert.equal(result.degraded, true); assert.ok(result.research.warnings.includes('answer_admission_conflict'));
  assert.match(result.answer, /门票小计：\$109\.85/);
  assert.doesNotMatch(result.answer, /两位成人和孩子的门票合计是 \$0|全部免费/);
  assert.match(result.answer, /不是已确认的结账价或全程总价/);
  assert.ok(result.sources.length > 0);
});

test('the actual DMV and constrained family prompts retain their missed request subjects', () => {
  const cases = require('../scripts/baybay-quality-cases.json').cases;
  const dmv = cases.find(item => item.id === 'dmv-new-resident');
  assert.deepEqual(requestChecklist(dmv.request.message).items.map(item => item.id), dmv.assertions.coverageIds);
  const plan = requestChecklist(cases.find(item => item.id === 'strict-sf-family-plan').request.message);
  assert.deepEqual(plan.items.map(item => item.id), ['hours', 'admission', 'transport', 'budget']);
  assert.equal(plan.complex, true);
  assert.equal(needsExtendedSynthesis({ complex: false }, { goal: 'day-plan', partySize: 3, childAges: [5], budget: 120 }), true);
  assert.equal(needsExtendedSynthesis({ complex: false }, { goal: 'information', partySize: 3, childAges: [5], budget: 120 }), false);
  for (const message of ['地址更新', '更新地址', '地址變更', 'address update']) assert.ok(requestChecklist(message).items.some(item => item.id === 'address_change'));
});

test('a live-shaped fallback with no plan citations is replaced by sourced card facts and stays degraded', async t => {
  const question = require('../scripts/baybay-quality-cases.json').cases.find(item => item.id === 'strict-sf-family-plan').request.message;
  const models = [], phases = [], timeouts = [], schedule = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => { timeouts.push(delay); return schedule(callback, delay, ...args); });
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'missing-citation-secret', OPENAI_API_KEY: 'fixture-only' }, now: () => NOW,
    Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) },
    fetchImpl: async (_url, init) => {
      const payload = JSON.parse(init.body); models.push(payload.model);
      assert.deepEqual(payload.tools, []); // Existing named site plan needs synthesis, not repeated research.
      assert.match(payload.instructions, /Research is complete/);
      if (models.length === 1) throw new Error('AI request timed out');
      return { ok: true, json: async () => ({ ...final({ answer: '2026年10月10日，Exploratorium开放时间是10:00至17:00，成人39.95美元，5岁孩子29.95美元，全家门票合计109.85美元。具体交通待确认。', candidateIds: ['venue-exploratorium-daytime', 'pier39'], coverage: [] }), model: 'gpt-4.1-mini' }) };
    },
  });
  const result = await assistant.run({ message: question, searchMode: 'site', onProgress: event => phases.push(event) });
  assert.deepEqual(models, ['gpt-6.1-sol', 'gpt-4.1-mini']);
  assert.ok(timeouts.includes(28000)); assert.ok(timeouts.every(timeout => timeout <= 28000));
  assert.equal(result.degraded, true); assert.ok(result.research.warnings.includes('answer_plan_citations_repaired'));
  assert.equal(result.answerCoverage.status, 'partial');
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39']);
  assert.match(result.answer, /成人 2 × \$39\.95/); assert.match(result.answer, /5 岁儿童 1 × \$29\.95/);
  assert.match(result.answer, /已知门票小计：\$109\.85/);
  assert.match(result.answer, /10:00–17:00/); assert.match(result.answer, /所选日期是否照常开放仍待确认/);
  assert.match(result.answer, /站内快照/); assert.match(result.answer, /不是已确认的结账价或全程总价/);
  assert.doesNotMatch(result.answer, /2026年10月10日，Exploratorium开放时间是/);
  assert.ok(result.sources.some(source => source.url === 'https://www.exploratorium.edu/visit'));
  assert.ok(result.sources.some(source => /pier39\.com/.test(source.url)));
  assert.ok(result.answerCoverage.items.flatMap(row => row.sourceIds).every(id => result.evidence.some(source => source.id === id)));
  assert.ok(phases.some(event => event.phase === 'answer' && event.status === 'completed'));
  assert.equal(result.retrieval.webStatus, 'not_requested');
});

test('a sourced plan answer is preserved while fake markers or unrelated guide citations cannot repair its claims', async () => {
  for (const kind of ['valid', 'fake', 'unrelated']) {
    const assistant = createBayBayAssistant(base({ guideCatalog: [libraryGuide], catalog: { version: 1, checkedAt: '2026-10-04', events: [], guides: [], places: [{ id: 'park', title: 'Fixture Park', city: 'Fremont', officialUrl: 'https://example.org/park', cost: 'unknown' }] },
      ai: async payload => { const context = JSON.parse(payload.input[0].content); const ref = kind === 'valid' ? context.candidates.find(row => row.id === 'park').sourceIds[0] : kind === 'unrelated' ? context.evidence.find(row => row.kind === 'guide')?.id : 'made-up';
        return final({ answer: `Fixture Park 的具体时段待确认。 [[${ref}]] [1]`, candidateIds: ['park'] }); },
    }));
    const result = await assistant.run({ message: '2026-10-10 Fremont 安排一天去 Fixture Park，顺便参考图书馆 Kanopy 打印资料', searchMode: 'site' });
    assert.equal(result.degraded, kind !== 'valid', kind);
    assert.equal(result.sources.length, 1, kind);
    assert.equal(result.sources[0].url, 'https://example.org/park', kind);
    if (kind !== 'valid') assert.ok(result.research.warnings.includes('answer_plan_citations_repaired'));
  }
});

test('no-source plan records cannot invent a citation or expose unsourced dollar amounts', () => {
  const summary = sourcedPlanSummary({ stops: [{ title: 'Unknown venue', sourceIds: ['fake'], admissionFacts: { knownTotalUsd: 99, sourceIds: ['fake'], breakdown: [{ category: 'adult', unitUsd: 99, quantity: 1 }] } }] }, new Map(), 'en');
  assert.deepEqual(summary.sourceIds, []); assert.doesNotMatch(summary.answer, /\$99|\[\[|recorded subtotal/);
  assert.match(summary.answer, /no sourced admission subtotal/);
});

test('live casual family fallback puts the incomplete total before scoped free access and preserves the paid reference', () => {
  const sources = new Map([
    ['museum', { id: 'museum', url: 'https://www.exploratorium.edu/visit' }],
    ['pier', { id: 'pier', url: 'https://www.pier39.com/frequently-asked-questions' }],
  ]);
  const publicScope = 'Public pedestrian areas and open sea-lion viewing areas only. Aquarium, cruises, rides, food, shopping, luggage storage, parking and transport are excluded and must be priced separately. The snapshot does not confirm opening or access on a future date.';
  const plan = { stops: [
    { title: 'Exploratorium', sourceIds: ['museum'], admissionFacts: { status: 'partial', basis: 'catalog-snapshot', knownTotalUsd: null, knownPerPersonUsd: 39.95, partySize: null, childAges: [5], breakdown: [], sourceIds: ['museum'], sourceUrl: sources.get('museum').url, checkedAt: '2026-10-02', note: 'Regular daytime general admission only. After Dark and optional purchases are not included.' } },
    { title: 'PIER 39', sourceIds: ['pier'], admissionFacts: { status: 'partial', basis: 'catalog-snapshot', knownTotalUsd: 0, knownPerPersonUsd: 0, partySize: null, childAges: [5], breakdown: [], sourceIds: ['pier'], sourceUrl: sources.get('pier').url + '/', checkedAt: '2026-10-04', note: publicScope } },
  ] };
  const before = JSON.stringify(plan);
  for (const [locale, gap, known, scope] of [
    ['zh-Hans', '完整门票小计还不能计算', '仅已知门票小计：$0.00', '免费只适用于来源写明的范围'],
    ['zh-Hant', '完整門票小計還不能計算', '僅已知門票小計：$0.00', '免費只適用於來源寫明的範圍'],
  ]) {
    const summary = sourcedPlanSummary(plan, sources, locale);
    assert.ok(summary.answer.indexOf(gap) < summary.answer.indexOf('$'), locale);
    assert.ok(summary.sections.admission.startsWith(gap), locale);
    assert.ok(summary.sections.budget.includes(known), locale);
    assert.match(summary.answer, /\$39\.95/);
    assert.ok(summary.answer.includes(scope), locale);
    assert.doesNotMatch(summary.answer, /Public pedestrian|Regular daytime|adult 1|成人 1|儿童.*39\.95|兒童.*39\.95/);
    assert.deepEqual(summary.sourceIds, ['museum', 'pier']);
    assert.match(summary.answer, /2026-10-02/);
  }
  const english = sourcedPlanSummary(plan, sources, 'en');
  assert.match(english.sections.budget, /^The complete admission subtotal cannot be calculated yet\. Known portions only: \$0\.00/);
  assert.ok(english.answer.includes(publicScope));
  assert.match(english.answer, /recorded applicable per-person reference \$39\.95/);
  assert.equal(JSON.stringify(plan), before, 'the detailed source scope remains intact in plan facts');
});

test('fallback keeps sourced adult and child tiers when the overall party total is unavailable', () => {
  const sources = new Map([['museum', { id: 'museum', url: 'https://example.org/museum' }]]);
  const summary = sourcedPlanSummary({ stops: [{ title: 'Museum', sourceIds: ['museum'], admissionFacts: {
    status: 'partial', basis: 'page-read', knownTotalUsd: null, knownPerPersonUsd: 40, sourceIds: ['museum'], sourceUrl: 'https://example.org/museum', checkedAt: '2026-10-05',
    breakdown: [{ category: 'adult', unitUsd: 40 }, { category: 'child', age: 5, unitUsd: 20, quantity: 1 }], note: '普通日间入场；特别体验另收费。',
  } }] }, sources);
  assert.match(summary.answer, /成人 \$40\.00；5 岁儿童 1 × \$20\.00/);
  assert.match(summary.answer, /仍需确认人数及各人的适用票档/);
  assert.match(summary.answer, /普通日间入场；特别体验另收费。/);
  assert.match(summary.answer, /已读官方记录 · 2026-10-05/);
  assert.doesNotMatch(summary.answer, /\$60\.00|已知门票小计：/);
});

test('complete sourced subtotals keep their numbers while mismatched price sources cannot expose a per-person price', () => {
  const sources = new Map([['venue', { id: 'venue', url: 'https://example.org/venue' }]]);
  const priced = { title: 'Venue', sourceIds: ['venue'], admissionFacts: { status: 'complete', knownTotalUsd: 50, knownPerPersonUsd: 25, sourceIds: ['venue'], sourceUrl: 'https://example.org/venue', breakdown: [{ category: 'adult', unitUsd: 25, quantity: 2 }] } };
  const complete = sourcedPlanSummary({ stops: [priced] }, sources, 'en');
  assert.match(complete.sections.budget, /^Recorded admission subtotal: \$50\.00/);
  assert.doesNotMatch(complete.answer, /cannot be calculated|Known portions only/);
  const mismatched = sourcedPlanSummary({ stops: [{ ...priced, admissionFacts: { ...priced.admissionFacts, knownTotalUsd: null, sourceUrl: 'https://example.org/other' } }] }, sources, 'en');
  assert.doesNotMatch(mismatched.answer, /\$25|\$50/);
  assert.match(mismatched.answer, /no sourced admission subtotal/);
});

test('official entry links reuse cited institutions before filling the cap with one institution', () => {
  const sources = new Map(['ac-print', 'ac-card', 'ac-film', 'sf-card', 'sm-film'].map(id => [id, { id, title: id, url: `https://${id.startsWith('ac') ? 'aclibrary.org' : id.startsWith('sf') ? 'sfpl.org' : 'smcl.org'}/${id}` }]));
  const coverage = coverageFor({ checklist: requestChecklist(libraryQuestion), sources, locale: 'en', draft: { coverage: [
    { id: 'kanopy', status: 'unknown', summary: 'The film allowance still needs checking.', sourceIds: ['sm-film'] },
    { id: 'official_entries', status: 'answered', summary: 'Official links.', sourceIds: ['ac-print', 'ac-card', 'ac-film', 'sf-card'] },
  ] } });
  assert.deepEqual(coverage.items.find(item => item.id === 'official_entries').sourceIds, ['ac-print', 'sf-card', 'sm-film', 'ac-card']);
  assert.ok(coverage.items.every(item => item.sourceIds.length <= 4));
});

test('signed acknowledgements and save instructions are not replaced with old admission facts', async () => {
  const query = require('../scripts/baybay-quality-cases.json').cases.find(item => item.id === 'strict-sf-family-plan').request.message;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'interaction-followup-secret' }, isTest: true, now: () => NOW,
    ai: async payload => {
      const context = JSON.parse(payload.input[0].content);
      const reference = context.candidates.find(candidate => candidate.id === 'venue-exploratorium-daytime').sourceIds[0];
      return final({ answer: context.message === query ? `门票使用站内记录，所选日期仍待确认。 [[${reference}]]` : context.message === '谢谢' ? '不客气，祝你们出行顺利。' : '你可以先保留这段对话，之后继续查看这份安排。', candidateIds: [] });
    },
  });
  const first = await assistant.run({ message: query, searchMode: 'site' });
  for (const message of ['谢谢', '怎么保存这份安排', 'How can I save this itinerary?']) {
    const response = await assistant.run({ message, searchMode: 'site', sessionToken: first.assistantSessionToken });
    assert.deepEqual(response.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39']);
    assert.equal(response.degraded, false, message); assert.doesNotMatch(response.answer, /门票小计|缺少行程来源引用/);
    assert.ok(!response.research.warnings.includes('answer_plan_citations_repaired'));
  }
  const factual = await assistant.run({ message: '谢谢，另外5岁孩子的门票多少？', searchMode: 'site', sessionToken: first.assistantSessionToken });
  assert.equal(factual.degraded, true); assert.ok(factual.research.warnings.includes('answer_plan_citations_repaired'));
});

test('the real supplied DMV question starts a 28-second site final with exceptions and document distinctions intact', async t => {
  const message = require('../scripts/baybay-quality-cases.json').cases.find(item => item.id === 'dmv-new-resident').request.message;
  const deadlines = [], schedule = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => { deadlines.push(delay); return schedule(callback, delay, ...args); });
  for (const searchMode of ['site', 'smart']) {
    const payloads = []; deadlines.length = 0;
    const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'complex-site-final-secret' }, isTest: true, now: () => NOW,
      guideCatalog: require('../data/guide-catalog.json'),
      webSearch: async () => { throw new Error('No external research is needed by this fixture'); },
      ai: async payload => { payloads.push(payload); return final({ answer: '按三个业务分别解释已有规则，未确认的个人例外仍需核对。', coverage: [] }); },
    });
    const response = await assistant.run({ message, searchMode });
    assert.equal(payloads.length, 1);
    const payload = payloads[0], context = JSON.parse(payload.input[0].content);
    assert.equal(context.state.goal, 'newcomer');
    const text = [...context.evidence.map(source => source.text || ''), ...context.sourceScopes.map(source => source.text)].join('\n');
    for (const fact of ['继续驾驶最多 10 天', '成为居民后受雇从事驾驶，须先取得加州驾照', '不能把这理解成只要 10 天内提交申请或约到 DMV', '普通非 REAL ID 的住址清单至少需一份合格文件，REAL ID 另需两份', '材料未齐时，仍应按期提交申请和应缴费用', '已有加州 DMV 记录', 'REG 343', 'REG 31']) assert.ok(text.includes(fact), fact);
    assert.ok(context.evidence.some(source => source.url.includes('sectionNum=12505.')));
    assert.match(payload.instructions, /triggering event, qualifying status, action required and exceptions/);
    assert.match(payload.instructions, /distinct document categories, required counts/);
    if (searchMode === 'site') {
      assert.deepEqual(payload.tools, []); assert.match(payload.instructions, /Research is complete/);
      assert.ok(deadlines.includes(28000));
      assert.equal(response.research.modelResponses[0].phase, 'final');
      assert.equal(response.retrieval.webStatus, 'not_requested');
    } else {
      assert.ok(payload.tools.some(tool => tool.name === 'read_source'));
      assert.ok(deadlines.includes(18000));
      assert.equal(response.research.modelResponses[0].phase, 'research');
    }
  }
});

test('complex site synthesis requires sourced coverage rather than merely a long or partial guide', () => {
  const checklist = requestChecklist('比较打印、Kanopy 和博物馆门票，并给官方入口');
  const state = { goal: 'information' }, message = 'Compare the supplied services.';
  const text = '打印服务与 Kanopy 的资格彼此独立，需要按各自的图书馆服务条件核对。'.repeat(12);
  const guides = [{ text, sourceUrls: [{ url: 'https://library.example/printing' }] }, { text, sourceUrls: [{ url: 'https://library.example/films' }] }];
  assert.equal(directSiteAnswer({ message, checklist, state, site: { guides } }), false, 'museum-pass evidence is missing');
  const all = guides.map(guide => ({ ...guide, text: `${guide.text} Discover & Go 博物馆门票有单独要求。` }));
  assert.equal(directSiteAnswer({ message, checklist, state, site: { guides: all } }), true);
  assert.equal(directSiteAnswer({ message, checklist, state, site: { guides: all.map(guide => ({ ...guide, sourceUrls: [] })) } }), false);
  assert.equal(directSiteAnswer({ message, checklist, state: { goal: 'day-plan' }, site: { guides: all } }), false);
});
