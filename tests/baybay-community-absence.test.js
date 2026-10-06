const test = require('node:test');
const assert = require('node:assert/strict');
const { guardCommunityAbsence } = require('../lib/baybayCommunityAbsence');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const NOW = Date.parse('2026-10-06T19:00:00Z');
const catalog = { version: 1, checkedAt: '2026-10-06', events: [], places: [], guides: [] };
const config = { NODE_ENV: 'test', JWT_SECRET: 'isolated-community-absence-fixture-secret' };
const final = answer => ({ status: 'completed', model: 'fixture-only', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
const cases = [
  { locale: 'zh-Hans', rental: '站内没有 Sunnyvale 房源。', service: '本站暂无清洁服务帖子。', outing: '站内没有符合条件的小队。', pending: /本轮尚未检索/, zero: /本次.*查询没有匹配/, unavailable: /查询未能完成/ },
  { locale: 'zh-Hant', rental: '站內沒有 Sunnyvale 房源。', service: '本站暫無清潔服務帖子。', outing: '站內沒有符合條件的小隊。', pending: /本輪尚未檢索/, zero: /本次.*查詢沒有匹配/, unavailable: /查詢未能完成/ },
  { locale: 'en', rental: 'There are no rental posts in Sunnyvale.', service: 'There are no cleaning service providers on the site.', outing: 'There are no public outings in Sunnyvale.', pending: /have not queried/, zero: /query returned no matches/, unavailable: /query could not be completed/ },
];

for (const row of cases) {
  for (const domain of ['rental', 'service', 'outing']) {
    test(`${row.locale}: unqueried ${domain} absence is an explicit gap with real public next steps`, () => {
      const result = guardCommunityAbsence({ answer: row[domain], locale: row.locale });
      assert.equal(result.changed, true); assert.match(result.answer, row.pending);
      assert.equal(result.warning, 'community_absence_unverified');
      assert.equal(result.suggestedActions[0].url, domain === 'outing' ? '/together' : domain === 'rental' ? '/category/rent' : '/category/cleaning');
      assert.equal(result.suggestedActions[0].type, domain === 'outing' ? 'guide' : 'category');
      if (domain !== 'outing') assert.ok(result.suggestedActions.some(action => action.type === 'post' && action.postType === 'client'));
    });
  }
  test(`${row.locale}: completed zero results remain scoped to the actual query`, () => {
    const result = guardCommunityAbsence({ answer: row.rental, locale: row.locale, searches: { posts: { status: 'completed', matchingCount: 0 } } });
    assert.match(result.answer, row.zero); assert.doesNotMatch(result.answer, row.pending);
    assert.match(result.answer, /不代表全站|does not establish that the whole site/);
  });
  test(`${row.locale}: unavailable retrieval is not mistaken for zero matches`, () => {
    const result = guardCommunityAbsence({ answer: row.service, locale: row.locale, searches: { posts: { status: 'unavailable' } } });
    assert.match(result.answer, row.unavailable); assert.doesNotMatch(result.answer, row.zero);
  });
  test(`${row.locale}: direct v2 assembly does not mistake its guide search for a housing-post query`, async () => {
    const assistant = createBayBayAssistant({ config, catalog, guideCatalog: [], isTest: true, now: () => NOW, ai: async () => final(row.rental) });
    const result = await assistant.run({ message: 'Sunnyvale 有 Studio 吗？', locale: row.locale, searchMode: 'site' });
    assert.match(result.answer, row.pending); assert.equal(result.degraded, true);
    assert.ok(result.research.warnings.includes('community_absence_unverified'));
    assert.equal(result.matchingPosts.length, 0); assert.equal(result.sources.length, 0);
    assert.ok(result.research.steps.some(step => step.tool === 'search_site'));
    assert.equal(result.suggestedActions[0].url, '/category/rent');
  });
}

test('positive community records and normal sourced policy exclusions are retained exactly', () => {
  for (const answer of [
    '找到 2 条 Sunnyvale 房源帖子，请按详情核对。', '已有 2 支公开小队。', 'The site has three cleaning service posts.',
    'Original Medicare does not cover most routine dental services. [[official]]',
    'Original Medicare 通常不报销常规牙科服务；没有保险时请核对诊所报价。[[official]]',
    '该医保计划没有清洁服务；请按保险条款核对。[[official]]',
    'There are no cleaning services included in this health plan. [[official]]',
    '这家诊所没有水管师傅。[[official]]',
    '没有书面租约时，请先了解租客权益，不要假定押金可以扣除。[[tenant-guide]]',
    '这不代表当地没有房源。', 'This does not mean there are no rental posts.',
    '站内有没有房源？', '如果没有房源，可以发布求助。', 'If there are no rental posts, consider broadening the city.',
  ]) assert.deepEqual(guardCommunityAbsence({ answer, searches: { posts: { status: 'completed', matchingCount: 2 } } }), { answer, changed: false, warning: undefined, suggestedActions: [] }, answer);
});

test('repair removes only the unsupported community clause, retaining independent sourced guidance', () => {
  const result = guardCommunityAbsence({ answer: '请先核对租约和押金条件。[[tenant-guide]]\n站内没有 Sunnyvale 房源。', locale: 'zh-Hans' });
  assert.ok(result.changed); assert.match(result.answer, /核对租约和押金条件。\s*\[\[tenant-guide\]\]/); assert.match(result.answer, /本轮尚未检索/);
});

test('the reported mixed Chinese claim retains the unrelated bare URL and decimal exactly', () => {
  const retained = '参考 https://www.baylink.us/guides/rental-lease-checklist-before-signing ，金额例子 1.5 不是费用承诺。';
  const result = guardCommunityAbsence({ answer: `站内没有 Sunnyvale 房源。${retained}`, locale: 'zh-Hans' });
  assert.equal(result.changed, true); assert.match(result.answer, /本轮尚未检索/);
  assert.ok(result.answer.endsWith(retained));
  assert.doesNotMatch(result.answer, /www\. baylink|1\. 5/);
});

test('repair preserves unrelated Markdown, URL query punctuation, citations and paragraph whitespace verbatim', () => {
  const before = '\tRead [A. sentence, example](https://www.baylink.us/guides/rental-lease-checklist-before-signing?amount=1.5&tags=a,b#intro) [[source.1]].\n\nAmount 1.5 is an illustration, not a promised fee.\n';
  const after = 'Source: https://www.baylink.us/guides/tenant-source?q=1.5&tags=a,b#section; reference [[source.2]].\r\nFinal paragraph stays unchanged.  ';
  const result = guardCommunityAbsence({ answer: `${before}There are no rental posts in Sunnyvale.  ${after}`, locale: 'en' });
  assert.equal(result.changed, true); assert.match(result.answer, /have not queried/);
  assert.ok(result.answer.startsWith(before)); assert.ok(result.answer.endsWith(`  ${after}`));
  assert.doesNotMatch(result.answer, /https:\/\/www\. baylink|1\. 5|source\. 1/);
});

test('adjacent Chinese sentence boundaries repair each claim while retaining independent text and citations', () => {
  const first = '请核对租约。[[tenant-source]]';
  const middle = '金额例子 1.5，参考 https://www.baylink.us/guides/tenant-source?amount=1.5&tags=a,b。';
  const last = '原有结尾[[official-source]]。';
  const result = guardCommunityAbsence({ answer: `${first}站内没有 Sunnyvale 房源。${middle}本站暂无清洁服务帖子。${last}` });
  assert.equal(result.changed, true); assert.ok(result.answer.startsWith(first)); assert.ok(result.answer.includes(middle)); assert.ok(result.answer.endsWith(last));
  assert.match(result.answer, /公开房源帖子/); assert.match(result.answer, /公开服务帖子/);
});

test('reference-token text is not a standalone assertion and no-repair output remains byte-for-byte unchanged', () => {
  const answers = [
    '参考 [站内没有房源。示例标题](https://www.baylink.us/guides/tenant-source?q=1.5&tags=a,b) [[source.1]]。',
    'Reference https://www.baylink.us/guides/tenant-source?query=站内没有房源&q=1.5&tags=a,b .\n\nAmount 1.5 is illustrative.  ',
    '\tFound 2 rental posts.\r\nCheck [Guide. A, B](https://www.baylink.us/guides/tenant-source?amount=1.5&tags=a,b) [[source.2]].  ',
  ];
  for (const answer of answers) {
    const result = guardCommunityAbsence({ answer, locale: 'en' });
    assert.equal(result.changed, false); assert.equal(result.answer, answer);
  }
});

test('an actual positive query repairs a contradictory empty-collection assertion without losing its result cards', () => {
  const result = guardCommunityAbsence({ answer: 'There are no rental posts in Sunnyvale.', locale: 'en', searches: { posts: { status: 'completed', matchingCount: 2 } } });
  assert.match(result.answer, /query returned 2 matching records/); assert.doesNotMatch(result.answer, /returned no matches|have not queried/);
});

test('actual v2 synthesis retains its sourced article and source IDs while repairing a separate unqueried post claim', async () => {
  const guide = { slug: 'tenant-cautions', url: '/guides/tenant-cautions', title: 'Sunnyvale 租房：租约与押金', summary: '核对租约和押金。', content: '租房前核对租约、押金和书面条件。没有书面租约时，不要假定可以扣除押金。', keywords: ['租房', '租约', '押金', 'Sunnyvale'], categories: ['rent'] };
  for (const appendAbsence of [false, true]) {
    const assistant = createBayBayAssistant({ config, catalog, guideCatalog: [guide], isTest: true, now: () => NOW, ai: async payload => {
      const source = JSON.parse(payload.input[0].content).evidence.find(row => row.kind === 'guide');
      assert.ok(source, 'a real retrieved guide is supplied to the fixture provider');
      return final(`没有书面租约时，请先核对押金和书面条件。[[${source.id}]]${appendAbsence ? '\n站内没有 Sunnyvale 房源。' : ''}`);
    } });
    const result = await assistant.run({ message: 'Sunnyvale 租房押金注意事项', searchMode: 'site' });
    assert.match(result.answer, /没有书面租约时/); assert.match(result.answer, /\[1\]/);
    assert.equal(result.sources[0].url, guide.url);
    assert.equal(result.research.warnings.includes('community_absence_unverified'), appendAbsence);
    if (appendAbsence) assert.match(result.answer, /本轮尚未检索/);
    else assert.equal(result.degraded, false);
  }
});

async function routeFixture(t, answer, seed = {}, guideCatalog = []) {
  const models = createMemoryModels(seed), find = models.Post.find;
  let postQueries = 0, guideCalls = 0, agentCalls = 0;
  models.Post.find = function (...args) { postQueries++; return find.apply(this, args); };
  const app = createApplication({ config, models, guideCatalog, guideCatalogEn: [], plannerCatalog: catalog, plannerNow: () => NOW,
    ai: { guideChat: async () => { guideCalls++; return { answer }; }, baybay: async () => { agentCalls++; return final(answer); } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  return { ask: async body => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ searchMode: 'site', ...body }) });
    return { status: response.status, body: await response.json() };
  }, calls: () => ({ postQueries, guideCalls, agentCalls }) };
}

test('actual legacy HTTP absence repair preserves the validated checklist and its article references', async t => {
  const guide = { slug: 'tenant-checklist', url: '/guides/tenant-checklist', title: 'Sunnyvale 租房押金与租约核对', summary: '租房前核对租约和押金。', content: 'Sunnyvale 租房前核对租约、押金和书面条件。', keywords: ['Sunnyvale', '租房', '押金', '租约'], categories: ['rent'] };
  const answer = '先核对租约和押金条件，确认费用后再与发布者联系。';
  const unchanged = await routeFixture(t, answer, {}, [guide]);
  const repaired = await routeFixture(t, `${answer}站内没有 Sunnyvale 房源。`, {}, [guide]);
  const request = { message: 'Sunnyvale 签租约前应注意什么？', locale: 'zh-Hans', searchMode: 'site' };
  const before = await unchanged.ask(request), after = await repaired.ask(request);
  assert.equal(before.status, 200); assert.equal(after.status, 200);
  assert.equal(before.body.interactiveCards[0].id, 'rent-checklist-v1');
  assert.ok(before.body.interactiveCards[0].items.length > 0);
  assert.ok(before.body.interactiveCards[0].actions.some(action => action.type === 'postAssist'));
  assert.deepEqual(after.body.interactiveCards, before.body.interactiveCards);
  assert.deepEqual(after.body.suggestedGuides, before.body.suggestedGuides);
  assert.ok(after.body.suggestedGuides.some(row => row.slug === guide.slug && row.url === guide.url));
  assert.match(after.body.answer, /先核对租约和押金条件/); assert.match(after.body.answer, /本轮尚未检索/);
  assert.equal(after.body.research.warnings.includes('community_absence_unverified'), true);
});

test('actual v2 HTTP absence repair preserves an independent retrieved article citation and public source', async t => {
  const guide = { slug: 'tenant-source', url: '/guides/tenant-source', title: 'Sunnyvale 租房押金与租约', summary: '核对押金和租约。', content: '租房前核对押金和书面租约条件。', keywords: ['Sunnyvale', '租房', '押金', '租约'], categories: ['rent'] };
  const app = createApplication({ config, models: createMemoryModels(), guideCatalog: [guide], guideCatalogEn: [], plannerCatalog: catalog, plannerNow: () => NOW,
    ai: { baybay: async payload => {
      const source = JSON.parse(payload.input[0].content).evidence.find(row => row.kind === 'guide');
      assert.ok(source);
      return final(`请先核对租约和押金条件。[[${source.id}]]\n站内没有 Sunnyvale 房源。`);
    } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: '请介绍 Sunnyvale 租房注意事项', locale: 'zh-Hans', searchMode: 'site', assistantVersion: 2 }) });
  const body = await response.json();
  assert.equal(response.status, 200); assert.equal(body.responseMode, 'assistant');
  assert.match(body.answer, /核对租约和押金条件。\s*\[1\]/); assert.match(body.answer, /本轮尚未检索/);
  assert.deepEqual(body.sources, [{ title: guide.title, url: guide.url }]);
  assert.ok(body.evidence.some(row => row.kind === 'guide' && row.url === guide.url));
  assert.ok(body.suggestedGuides.some(row => row.url === guide.url));
});
for (const row of cases) for (const assistantVersion of [undefined, 2]) {
  test(`${row.locale}: actual ${assistantVersion === 2 ? 'v2' : 'legacy'} API assembly rejects a provider's unqueried negative claim`, async t => {
    const f = await routeFixture(t, row.rental);
    // General advice deliberately takes the synthesis path, not the dedicated
    // deterministic public-post search being tested in ai-search.test.js.
    const result = await f.ask({ message: '请介绍 Sunnyvale 租房注意事项', locale: row.locale, assistantVersion });
    assert.equal(result.status, 200); assert.match(result.body.answer, row.pending);
    assert.equal(result.body.degraded, true); assert.ok(result.body.research.warnings.includes('community_absence_unverified'));
    assert.equal(f.calls().postQueries, 0);
    assert.equal(f.calls()[assistantVersion === 2 ? 'agentCalls' : 'guideCalls'], 1);
    assert.equal(result.body.suggestedActions[0].url, '/category/rent');
  });
}

test('actual public-post searches retain positive cards and honest filtered zero results', async t => {
  const f = await routeFixture(t, 'A model must not generate this deterministic response.', { Post: [{ id: 'public-rental', title: 'Sunnyvale Studio 出租', city: 'Sunnyvale', category: '租屋', type: 'provider', status: 'active', isDeleted: false, createdAt: NOW, description: 'Studio 出租', budget: '$1800/月' }] });
  const positive = await f.ask({ message: 'Sunnyvale 有 Studio 吗？', locale: 'en', assistantVersion: 2 });
  assert.equal(positive.status, 200); assert.equal(positive.body.responseMode, 'search'); assert.equal(positive.body.matchingPosts[0].id, 'public-rental');
  assert.equal(positive.body.research?.warnings?.includes('community_absence_unverified') || false, false);
  const zero = await f.ask({ message: 'Fremont 有 Studio 吗？', locale: 'en', assistantVersion: 2 });
  assert.equal(zero.status, 200); assert.equal(zero.body.responseMode, 'search'); assert.equal(zero.body.matchingPosts.length, 0);
  assert.match(zero.body.answer, /(?:search found no public posts|search did not find|No public posts matched|No matches|did not find)/i);
  assert.doesNotMatch(zero.body.answer, /There are no rental posts|have not queried/);
  assert.equal(f.calls().postQueries, 2); assert.equal(f.calls().agentCalls + f.calls().guideCalls, 0);
});
