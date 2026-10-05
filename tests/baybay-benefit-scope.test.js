const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { coverageFor, checklistAnswer, requestChecklist, normalExcerpt } = require('../lib/baybayAnswerQuality');
const { repairBenefitCoverage } = require('../lib/baybayBenefitScope');
const NOW = Date.parse('2026-10-04T19:00:00Z');
const prompt = '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。';
const final = value => ({ model: 'fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '重复的长篇正文。'.repeat(150), candidateIds: [], followups: [], ...value }) }] }] });

test('normal answer excerpts preserve service headings and resolve known official URLs without dangling link text', () => {
  assert.equal(normalExcerpt('官方入口：\n完整条件。', 200), '官方入口：\n完整条件。');
  const sources = new Map([['cards', { id: 'cards', title: 'SFPL 申请图书证', url: 'https://sfpl.org/cards' }], ['film', { id: 'film', title: 'SFPL Kanopy 入口', url: 'https://sfpl.org/kanopy' }]]);
  const checklist = requestChecklist(prompt);
  const coverage = coverageFor({ checklist, sources, draft: { coverage: [{ id: 'official_entries', status: 'answered', summary: '官方入口：https://sfpl.org/cards 和 [影片](https://sfpl.org/kanopy)', sourceIds: [] }] } });
  const entries = coverage.items.find(item => item.id === 'official_entries');
  assert.equal(entries.status, 'answered'); assert.deepEqual(entries.sourceIds, ['cards', 'film']);
  assert.equal(entries.summary, 'SFPL 申请图书证；SFPL Kanopy 入口');
  const rendered = checklistAnswer('重复的长篇正文。'.repeat(150), coverage, checklist);
  assert.doesNotMatch(rendered, /重复的长篇正文|入口：和|https:/);
  assert.match(rendered, /SFPL 申请图书证；SFPL Kanopy 入口/);
});

test('fresh service-specific official evidence supersedes a snapshot; an ambiguous new rule stays a conflict', () => {
  const scopes = [{ id: 'scope-old', heading: 'SMCL：Kanopy 与馆票分别核对', entity: 'SMCL', entityKey: 'smcl', text: 'SMCL：Kanopy 与馆票分别核对\nDiscover & Go 馆票要求年满16岁。', sourceIds: ['snapshot'] }];
  const sources = new Map([['snapshot', { id: 'snapshot', url: 'https://smcl.org/old-rules', verification: 'catalog' }], ['fresh', { id: 'fresh', url: 'https://smcl.org/printing', title: 'SMCL printing rules', verification: 'page-read', text: 'SMCL printing now requires age 16 and older.' }]]);
  const coverage = { status: 'complete', items: [{ id: 'printing', label: 'Printing', status: 'answered', summary: 'SMCL printing requires age 16 and older.', sourceIds: ['fresh'] }] };
  const accepted = repairBenefitCoverage(coverage, scopes, 'en', sources);
  assert.equal(accepted.changed, false); assert.deepEqual(accepted.coverage, coverage);
  sources.get('fresh').text = 'SMCL printing now has new eligibility rules. Please contact the branch for details.';
  const conflict = repairBenefitCoverage(coverage, scopes, 'en', sources);
  assert.equal(conflict.changed, true); assert.equal(conflict.coverage.items[0].status, 'unknown');
  assert.match(conflict.coverage.items[0].summary, /Current read-page evidence/);
  assert.doesNotMatch(conflict.coverage.items[0].summary, /Discover & Go|馆票/);
  assert.deepEqual(conflict.coverage.items[0].sourceIds, ['fresh']);
});

test('current AC printing snapshots own their eCard exclusion without inheriting museum-pass age rules', () => {
  for (const locale of ['zh-Hans', 'en']) {
    const catalog = require(locale === 'en' ? '../data/guide-catalog.en.json' : '../data/guide-catalog.json');
    const guide = catalog.find(row => row.slug === 'bay-area-everyday-free-perks');
    const text = guide.content.split('\n\n').find(row => row.startsWith('ALAMEDA COUNTY LIBRARY：'));
    const scopes = [
      { entity: 'AC Library', entityKey: 'acl', heading: text.split('\n')[0], text, sourceIds: ['print'] },
      { entity: 'AC Library', entityKey: 'acl', heading: 'AC Library: Discover & Go', text: 'AC Library: Discover & Go\nDiscover & Go requires age 15 and older; eCard not eligible.', sourceIds: ['passes'] },
    ];
    const summary = locale === 'en'
      ? 'AC Library physical cardholders receive 10 free black-and-white pages per day. eCard not eligible for the free allowance.'
      : 'AC Library 实体卡用户每天可免费打印10页黑白文件，eCard不适用。';
    const coverage = { status: 'complete', items: [{ id: 'printing', status: 'answered', summary, sourceIds: ['print'] }] };
    const accepted = repairBenefitCoverage(coverage, scopes, locale);
    assert.equal(accepted.changed, false, locale);
    assert.deepEqual(accepted.coverage, coverage);
    const invalid = { ...coverage, items: [{ ...coverage.items[0], summary: `${summary} AC Library printing requires age 15 and older.` }] };
    const corrected = repairBenefitCoverage(invalid, scopes, locale);
    assert.equal(corrected.changed, true, locale);
    assert.equal(corrected.coverage.items[0].status, 'unknown');
    assert.doesNotMatch(corrected.coverage.items[0].summary, /requires age 15 and older/);
  }
});

test('the live Fremont online-card and free-printing question preserves correctly scoped eligibility', async () => {
  let context;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'printing-scope-fixture-only' }, guideCatalog: require('../data/guide-catalog.json'), isTest: true, now: () => NOW,
    ai: async payload => {
      context = JSON.parse(payload.input[0].content);
      const source = context.evidence.find(row => row.url === '/guides/bay-area-everyday-free-perks');
      assert.ok(source);
      return final({ answer: `可以网上申请，但免费打印须有实体卡；只有 eCard 或无卡访客不享免费额度。[[${source.id}]]`, coverage: [
        { id: 'printing', status: 'answered', summary: 'AC Library 实体卡用户每天可免费打印10页黑白文件，eCard不适用；超额黑白每页 $0.15，彩印每页 $0.35，不含复印。', sourceIds: [source.id] },
        { id: 'card_eligibility', status: 'answered', summary: 'Fremont 居民可网上申请 eCard，设置 PIN 后使用 eLibrary，有效五年；免费打印须转实体卡，到馆出示姓名及当前加州地址证明。', sourceIds: [source.id] },
      ] });
    },
  });
  const response = await assistant.run({ message: '刚搬到 Fremont，图书馆卡网上办行不行？能顺便免费打印吗？', searchMode: 'site' });
  assert.ok(context.sourceScopes.some(scope => /eCard 或无卡访客不享免费额度/.test(scope.text)));
  assert.equal(response.degraded, false);
  assert.ok(!response.research.warnings.includes('answer_benefit_scope_corrected'));
  assert.equal(response.answerCoverage.items.find(item => item.id === 'printing').status, 'answered');
  assert.match(response.answerCoverage.items.find(item => item.id === 'printing').summary, /实体卡.*eCard不适用/);
  assert.ok(response.sources.some(source => source.url === '/guides/bay-area-everyday-free-perks'));
});

test('the actual bad library response is repaired from original scoped source paragraphs instead of spreading pass eligibility', async () => {
  let context;
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'scoped-benefit-test-key' }, guideCatalog: require('../data/guide-catalog.json'), isTest: true, now: () => NOW,
    ai: async payload => {
      context = JSON.parse(payload.input[0].content);
      const refs = context.evidence.filter(source => source.kind === 'guide').map(source => source.id).slice(0, 2);
      return final({ coverage: [
        { id: 'printing', status: 'answered', summary: 'Alameda County Library 持实体卡用户可每天免费打印10页黑白，eCard不适用。SMCL要求县居民、16岁及以上才能打印。', sourceIds: refs },
        { id: 'kanopy', status: 'answered', summary: 'SFPL需旧金山居民且持实体卡才能使用Kanopy。AC Library图书证不包含Kanopy权益。', sourceIds: refs },
        { id: 'museum_passes', status: 'answered', summary: '各馆 Discover & Go 需要分别核对居住地与卡种。', sourceIds: refs },
        { id: 'card_eligibility', status: 'answered', summary: 'AC Library图书证要求居住在Alameda County，持实体卡，年龄15岁及以上。SFPL要求旧金山居民，持实体卡。SMCL要求San Mateo County居民，持实体卡，年龄16岁及以上。', sourceIds: refs },
        { id: 'official_entries', status: 'answered', summary: 'https://sfpl.org/welcome-new-cardholders/kiosk-application 和 https://smcl.org/printanywhere/', sourceIds: [] },
      ] });
    },
  });
  const response = await assistant.run({ message: prompt, searchMode: 'site' });
  assert.ok(context.sourceScopes.some(scope => scope.text.includes('每月 30 tickets')));
  assert.ok(context.sourceScopes.some(scope => scope.text.includes('加州居民可免费申请 SFPL 卡')));
  assert.ok(context.sourceScopes.every(scope => scope.heading && scope.sourceIds.every(id => context.evidence.some(source => source.id === id))));
  assert.equal(response.degraded, true); assert.ok(response.research.warnings.includes('answer_benefit_scope_corrected'));
  assert.equal(response.answerCoverage.status, 'partial');
  const summaries = Object.fromEntries(response.answerCoverage.items.map(item => [item.id, item.summary]));
  assert.match(summaries.printing, /10 页|10页/); assert.match(summaries.printing, /25 页|25页/);
  assert.doesNotMatch(summaries.printing, /16岁及以上才能打印/);
  // The updated AC printing source explicitly excludes eCards; only the
  // unrelated SMCL museum-pass restriction needs correction here.
  assert.match(summaries.printing, /Alameda County Library.*eCard不适用/);
  assert.match(summaries.kanopy, /加州居民可免费申请 SFPL 卡/);
  assert.match(summaries.kanopy, /未找到 AC 卡适用的 Kanopy 官方入口/);
  assert.doesNotMatch(summaries.kanopy, /SFPL需旧金山居民|图书证不包含Kanopy权益/);
  assert.match(summaries.card_eligibility, /在加州居住、工作或就学者可申请免费实体卡/);
  assert.doesNotMatch(summaries.card_eligibility, /年龄15岁及以上|年龄16岁及以上|SFPL要求旧金山居民/);
  assert.doesNotMatch(response.answer, /重复的长篇正文|入口： 和/);
});
