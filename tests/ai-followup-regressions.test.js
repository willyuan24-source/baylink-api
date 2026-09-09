const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { createMemoryModels } = require('./support/memory-models');

dotenv.config = () => { throw new Error('Follow-up tests must not load .env'); };
mongoose.connect = async () => { throw new Error('Follow-up tests must not connect to Mongo'); };
const { createApplication } = require('../server');

// Undated fixtures keep conversation tests independent of the month they run in.
const catalog = [
  { slug: 'family-handcraft', url: '/guides/family-handcraft', title: '亲子免费手工与领取福利', summary: '亲子儿童免费手工的参与条件。', keywords: ['免费', '亲子', '手工', '儿童', '福利'], categories: ['other'], content: '亲子免费手工按活动条件安排，儿童需由监护人陪同。', sources: [], updatedAt: '2026-09-09' },
  { slug: 'library', url: '/guides/library', title: '图书馆办卡与资源', summary: '图书馆的办卡与借阅。', keywords: ['图书馆', '办卡', '借书'], categories: ['other'], content: '图书馆资源应按所属系统的资格要求使用。', sources: [], updatedAt: '2026-09-09' },
  { slug: 'cleaning', url: '/guides/cleaning', title: '清洁服务如何写清楚', summary: '列明清洁服务范围与报价方式。', keywords: ['清洁', '服务', '客户'], categories: ['cleaning'], content: '清洁服务供方发布时写清服务区域与报价方式。', sources: [], updatedAt: '2026-09-09' },
  { slug: 'rent', url: '/guides/rent', title: '租房准备', summary: '租房前核对区域和预算。', keywords: ['租房', 'Hayward', 'Fremont'], categories: ['rent'], content: '租房前确认地区、预算和供需方向。', sources: [], updatedAt: '2026-09-09' },
];
const rental = (id, city) => ({ id, title: `${city} 独立 Studio 出租`, description: '月租 $1900，房源详情请联系发布者确认。', category: '租屋', city, budget: '$1900/月', type: 'provider', authorId: 'owner', status: 'active', isDeleted: false, adminHidden: false, createdAt: 100, confirmedAt: 99, likes: [], comments: [], reports: [] });

async function fixture(t, { ai, posts = [], guideCatalog = catalog } = {}) {
  const models = createMemoryModels({ Post: posts, User: [] });
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-followup-regression-secret-long-enough' }, models, ai, guideCatalog });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  return async body => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
}

test('a short explicit library topic outranks past family freebies, even while an unrelated article remains open', async t => {
  const received = [];
  const request = await fixture(t, { ai: { guideChat: async payload => { received.push(payload); return { answer: '图书馆的办卡和数字资源取决于所属系统，请先查看图书馆指南。' }; } } });
  const history = [{ role: 'user', content: '免费亲子手工有哪些' }, { role: 'assistant', content: '可以查看亲子免费手工及儿童福利。' }];
  for (const currentPath of ['/', '/guides/family-handcraft']) {
    const response = await request({ message: '图书馆', history, context: { currentPath } });
    assert.equal(response.status, 200);
    assert.equal(response.data.responseMode, 'ai');
    assert.equal(response.data.suggestedGuides[0]?.slug, 'library', `Current explicit subject should lead the links on ${currentPath}`);
    assert.equal(received.at(-1).guideSources[0]?.url, '/guides/library', 'The model should receive the requested subject as its leading source');
  }
});

test('an explicitly requested current article still resolves after unrelated earlier conversation', async t => {
  let received;
  const request = await fixture(t, { ai: { guideChat: async payload => { received = payload; return { answer: '这篇亲子手工指南说明了参与条件和监护人陪同要求，请按项目原文确认。' }; } } });
  const response = await request({ message: '帮我总结这篇', context: { currentPath: '/guides/family-handcraft' }, history: [{ role: 'user', content: '图书馆怎么借书' }, { role: 'assistant', content: '先按图书馆系统办理借书卡。' }] });
  assert.equal(response.status, 200);
  assert.equal(received.currentGuideTitle, catalog[0].title);
  assert.equal(received.guideSources[0]?.url, catalog[0].url);
  assert.equal(response.data.suggestedGuides[0]?.slug, catalog[0].slug);
});

test('a cleaning supplier asking how to write the post retains supplier and cleaning actions', async t => {
  const request = await fixture(t);
  const response = await request({ message: '那怎么写帖子？', context: { currentPath: '/' }, history: [{ role: 'user', content: '我提供清洁服务，想找客户' }, { role: 'assistant', content: '写清服务范围和报价方式，发布服务介绍。' }] });
  assert.equal(response.status, 200);
  const composerActions = response.data.suggestedActions.filter(action => action.type === 'post' || action.type === 'postAssist');
  assert.ok(composerActions.length > 0, 'The follow-up must still offer a supplier composer, not only reading links');
  for (const action of composerActions) {
    assert.equal(action.postType, 'provider');
    assert.equal(action.category, 'cleaning');
    assert.doesNotMatch(action.label, /求助|需求|求职/);
  }
  assert.deepEqual(response.data.interactiveCards, [], 'Consumer hiring checklists do not apply to a supplier');
});

test('a rental-search follow-up replaces Hayward with Fremont and performs a real filtered search', async t => {
  let aiCalls = 0;
  const request = await fixture(t, { posts: [rental('hayward-home', 'Hayward'), rental('fremont-home', 'Fremont')], ai: { guideChat: async () => { aiCalls++; return { answer: '这是不应该替代实际帖子检索的模拟回答。' }; } } });
  const firstQuestion = '找 Hayward 的租房';
  const first = await request({ message: firstQuestion, context: { currentPath: '/' } });
  assert.equal(first.data.responseMode, 'search');
  assert.deepEqual(first.data.matchingPosts.map(post => post.id), ['hayward-home']);
  for (const message of ['那Fremont呢', 'Fremont呢', 'Fremont 呢？']) {
    const followup = await request({ message, context: { currentPath: '/' }, history: [{ role: 'user', content: firstQuestion }, { role: 'assistant', content: first.data.answer }] });
    assert.equal(followup.status, 200);
    assert.equal(followup.data.responseMode, 'search');
    assert.deepEqual(followup.data.matchingPosts.map(post => post.id), ['fremont-home']);
    assert.match(followup.data.answer, /Fremont/);
  }
  assert.equal(aiCalls, 0, 'Public post searches must continue through the read-only search path');
});

test('search and ambiguous-location responses both exclude archived guide references', async t => {
  const archive = { slug: 'ride-deals-2000-01', url: '/guides/ride-deals-2000-01', title: '2000 年 1 月接送优惠', summary: '已结束的接送优惠月刊。', keywords: ['接送', '优惠'], categories: ['ride'], content: '2000 年 1 月已结束的接送优惠。', sources: [], updatedAt: '2000-01-01' };
  const evergreen = { slug: 'ride-basics', url: '/guides/ride-basics', title: '接送准备指南', summary: '接送前确认时间地点。', keywords: ['接送'], categories: ['ride'], content: '接送需确认日期、人数和行李。', sources: [], updatedAt: '2026-09-09' };
  const request = await fixture(t, { guideCatalog: [archive, evergreen] });
  for (const message of ['找 Hayward 接送', '我在 San Francisco 上班，想在 Fremont 找接送']) {
    const response = await request({ message, context: { currentPath: '/' } });
    assert.equal(response.status, 200);
    assert.equal(response.data.responseMode, 'search');
    assert.ok(response.data.suggestedGuides.some(guide => guide.slug === evergreen.slug));
    assert.ok(!response.data.suggestedGuides.some(guide => guide.slug === archive.slug), `${message}: old edition should not escape through an early search return`);
    if (message.includes('San Francisco')) assert.match(response.data.matchNote, /尚未检索/);
  }
});
