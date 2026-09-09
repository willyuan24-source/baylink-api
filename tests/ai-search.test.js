const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { createMemoryModels } = require('./support/memory-models');
const { monthlyRent, monthlyCeiling, summarizeMatches, planPostSearch } = require('../lib/baybaySearch');
const { detectLocation } = require('../lib/postSearch');
const { sanitizeAiDescription } = require('../lib/postDraft');
const { fetchAiJson } = require('../lib/aiRequest');
dotenv.config = () => { throw new Error('AI tests must not load .env'); };
mongoose.connect = async () => { throw new Error('AI tests must not connect to Mongo'); };
const { createApplication } = require('../server');
const SECRET = 'isolated-ai-search-test-secret-with-32-characters';
const post = (id, overrides = {}) => ({
  id, title: 'Hayward 独立 Studio 出租，$1900/月', description: '月租$1900。电话 415-555-0123，邮件 private@example.test',
  category: '租屋', city: 'Hayward', budget: '$1900', type: 'provider', authorId: 'owner', createdAt: 100,
  confirmedAt: 99, status: 'active', isDeleted: false, adminHidden: false, likes: [], comments: [], reports: [],
  contactPreference: { mode: 'manual_approve', methods: [{ type: 'phone', value: 'private-contact-value', enabled: true }] },
  ...overrides,
});
async function fixture(t, { posts, ai, guideCatalog } = {}) {
  const models = createMemoryModels({
    Post: posts || [post('studio')],
    User: [{ id: 'admin', role: 'admin', accountStatus: 'active' }, { id: 'owner', role: 'user', nickname: 'Neighbor' }],
    UserBlock: [{ blockerId: 'admin', blockedUserId: 'blocked' }],
  });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, ai, guideCatalog });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const base = `http://127.0.0.1:${application.server.address().port}`;
  const token = jwt.sign({ id: 'admin', role: 'admin' }, SECRET, { expiresIn: '1h' });
  const request = async (path, body, authenticated = false) => {
    const res = await fetch(`${base}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(authenticated ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, data: await res.json() };
  };
  return { request, models };
}

test('synonym and compound searches filter before pagination, keep visibility, and treat punctuation literally', async t => {
  const { request } = await fixture(t, { posts: [
    post('new-rent', { createdAt: 104 }), post('older-rent', { category: '出租', createdAt: 101 }),
    post('outside', { city: 'San Jose', title: 'San Jose 独立 Studio 月租$1900' }),
    post('hidden', { adminHidden: true, createdAt: 106 }), post('closed', { status: 'closed', createdAt: 107 }),
    post('used', { category: '闲置', title: 'Hayward 二手书桌', description: '闲置物品', createdAt: 108 }),
  ] });
  for (const word of ['租房', '租屋', '出租']) {
    const response = await request(`/api/posts?keyword=${encodeURIComponent(`Hayward ${word} Studio`)}&limit=1`);
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.posts.map(item => item.id), ['new-rent']);
    assert.equal(response.data.hasMore, true);
    const second = await request(`/api/posts?keyword=${encodeURIComponent(`Hayward ${word} Studio`)}&limit=1&page=2`);
    assert.deepEqual(second.data.posts.map(item => item.id), ['older-rent']);
    assert.equal(second.data.hasMore, false);
  }
  assert.deepEqual((await request(`/api/posts?keyword=${encodeURIComponent('南湾租房')}`)).data.posts.map(item => item.id), ['outside']);
  assert.deepEqual((await request(`/api/posts?keyword=${encodeURIComponent('二手')}`)).data.posts.map(item => item.id), ['used']);
  assert.deepEqual((await request(`/api/posts?category=${encodeURIComponent('租房')}`)).data.posts.map(item => item.id).sort(), ['new-rent', 'older-rent', 'outside']);
  assert.equal((await request('/api/posts?keyword=%5B')).data.posts.length, 0);
  assert.equal((await request('/api/posts?keyword[$ne]=x')).status, 400);
});

test('BayBay returns only real public active matching cards without AI, private fields or writes', async t => {
  const { request, models } = await fixture(t, { posts: [
    post('studio'), post('hidden', { adminHidden: true, createdAt: 200 }),
    post('closed', { status: 'closed' }), post('deleted', { isDeleted: true }),
    post('request', { type: 'client' }), post('over-budget', { budget: '$2100/月' }),
    post('nightly', { budget: '$100/晚' }), post('unclear', { budget: '$1500', title: 'Hayward Studio', description: '费用待沟通' }),
    post('wrong-region', { city: '南湾', title: 'San Jose Studio', description: '月租$1900' }),
    post('wrong-room', { title: 'Hayward 单间出租', description: '月租$1900' }),
  ], ai: { guideChat: () => { throw new Error('A clear listing search must not call AI'); } } });
  const before = JSON.stringify(models.Post.rows);
  const response = await request('/api/ai/guide-chat', { message: '我想在东湾找月租2000美元以内的Studio，现在站内有哪些？' });
  assert.equal(response.status, 200);
  assert.equal(response.data.responseMode, 'search');
  assert.equal(response.data.degraded, false);
  assert.deepEqual(response.data.matchingPosts.map(item => item.id), ['studio']);
  assert.deepEqual(Object.keys(response.data.matchingPosts[0]).sort(), ['id', 'title', 'city', 'budget', 'confirmedAt', 'createdAt', 'status', 'category'].sort());
  assert.match(response.data.matchNote, /单位不明确/);
  assert.match(response.data.matchNote, /是否仍可用/);
  assert.ok(!JSON.stringify(response.data).includes('private'));
  assert.ok(!JSON.stringify(response.data).includes('415-555'));
  assert.equal(JSON.stringify(models.Post.rows), before);
});

test('BayBay public visibility stays strict for admins and respects their author blocks', async t => {
  const { request } = await fixture(t, { posts: [post('public'), post('hidden', { adminHidden: true }), post('blocked', { authorId: 'blocked' })] });
  const response = await request('/api/ai/guide-chat', { message: '东湾有哪些 Studio 出租？' }, true);
  assert.deepEqual(response.data.matchingPosts.map(item => item.id), ['public']);
});

test('unknown budget units remain visible as uncertainty, never silently treated as monthly filters', async t => {
  const { request } = await fixture(t);
  const response = await request('/api/ai/guide-chat', { message: '东湾找 Studio，预算2000以内' });
  assert.match(response.data.matchNote, /没有按价格筛选/);
  assert.ok(!response.data.answer.includes('月租不超过'));
  const none = await request('/api/ai/guide-chat', { message: '北湾找月租1000美元以内的Studio' });
  assert.deepEqual(none.data.matchingPosts, []);
  assert.match(none.data.answer, /本次检索没有找到/);
});

test('specific services match their provider category and roommate searches do not return unrelated whole studios', async t => {
  const { request } = await fixture(t, { posts: [
    post('moving', { category: '搬家', title: 'Hayward 搬家和家具搬运' }),
    post('furniture', { category: '闲置', title: 'Hayward 出售家具' }),
    post('translation', { category: '翻译', title: 'Hayward 中英翻译' }), post('studio'),
  ] });
  const moving = await request('/api/ai/guide-chat', { message: '东湾找搬家师傅搬家具' });
  assert.deepEqual(moving.data.matchingPosts.map(item => item.id), ['moving']);
  const translation = await request('/api/ai/guide-chat', { message: '东湾找翻译，有哪些？' });
  assert.deepEqual(translation.data.matchingPosts.map(item => item.id), ['translation']);
  const roommate = await request('/api/ai/guide-chat', { message: '东湾找室友' });
  assert.deepEqual(roommate.data.matchingPosts, []);
});

test('monthly rent parsing requires a single clear amount and does not equate daily, ranges, or deposits with rent', () => {
  for (const budget of ['$1900/月', '$1,900/month', '每月1900美元']) assert.equal(monthlyRent(post('p', { budget })), 1900);
  assert.equal(monthlyRent(post('p')), 1900);
  for (const budget of ['$100/天', '$800/周', '$1900起/月', '$1500-1900/月', '$1900/月 + 押金1900', '押金1900/月', 'CNY1900/月', 'HKD1900/月', '$1900/月/人']) assert.equal(monthlyRent(post('p', { budget })), null, budget);
  assert.equal(monthlyRent(post('p', { budget: '$1900', title: 'Studio', description: '' })), null);
  assert.equal(monthlyCeiling('月租 $2,000 以内', 'rent'), 2000);
  assert.equal(monthlyCeiling('日租200美元以内', 'rent'), null);
  assert.equal(monthlyCeiling('预算2000以内', 'rent'), null);
  assert.equal(monthlyCeiling('找月租1900的Studio，押金1000以内', 'rent'), null);
  const result = summarizeMatches(Array.from({ length: 205 }, (_, i) => post(`p${i}`)), planPostSearch('东湾找Studio', 'rent'));
  assert.equal(result.matchingPosts.length, 3);
  assert.match(result.matchNote, /最新 200 条/);
});

test('bare budget confirmation excludes deposit clauses, partial decimals and conflicting monthly amounts', () => {
  for (const description of ['押金$1900/月，月租$2500', '月租$1900.99', '月租$11900', '月租约1900', '月租1900起']) {
    assert.equal(monthlyRent({ budget: '$1900', description }), null, description);
  }
  assert.equal(monthlyRent({ budget: '$1900', title: 'Studio $1900/月', description: '月租$2500' }), null);
  assert.equal(monthlyRent({ budget: '$1900', description: '押金$2000，月租$1,900' }), 1900);
  assert.equal(monthlyRent({ budget: '$1900.99', description: '月租$1900.99' }), 1900.99);
  const result = summarizeMatches([
    post('deposit-price', { title: 'Hayward Studio', description: '押金$1900/月，月租$2500' }),
    post('decimal-price', { title: 'Hayward Studio', description: '月租$1900.99' }),
  ], planPostSearch('东湾找月租1900美元以内的Studio', 'rent'));
  assert.deepEqual(result.matchingPosts, []);
});

test('supplier and recruiter requests do not incorrectly search for competing providers', () => {
  assert.equal(planPostSearch('我提供清洁，找客户', 'cleaning'), null);
  assert.equal(planPostSearch('招聘兼职，有没有求职的人', 'part-time'), null);
  assert.equal(planPostSearch('我在东湾找清洁服务', 'cleaning').query.type, 'provider');
});

test('supplier and recruiter responses use provider actions and remove consumer checklists end to end', async t => {
  const { request } = await fixture(t);
  for (const [message, category, label] of [
    ['我提供清洁，找客户', 'cleaning', '服务介绍'],
    ['招聘兼职，有没有求职的人', 'part-time', '招聘信息'],
  ]) {
    const response = await request('/api/ai/guide-chat', { message });
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.matchingPosts, []);
    assert.deepEqual(response.data.interactiveCards, []);
    assert.match(response.data.answer, new RegExp(label));
    assert.ok(response.data.suggestedActions.length > 0);
    for (const action of response.data.suggestedActions) {
      assert.equal(action.postType, 'provider');
      assert.equal(action.category, category);
      assert.match(action.label, new RegExp(label));
      assert.ok(!/清洁需求|求职信息/.test(action.label));
    }
  }
  let modelContext;
  const ai = await fixture(t, { ai: { guideChat: async payload => {
    modelContext = payload;
    return { answer: '你可以介绍清洁范围、服务地区和报价方式，再发布清洁服务介绍。', safetyNote: '' };
  } } });
  const generated = await ai.request('/api/ai/guide-chat', { message: '我提供清洁，找客户' });
  assert.equal(generated.data.responseMode, 'ai');
  assert.equal(modelContext.inferredPostType, 'provider');
  assert.ok(generated.data.suggestedActions.every(action => action.postType === 'provider'));
  assert.deepEqual(generated.data.interactiveCards, []);
});

test('Peninsula shorthand is enforced and multiple possible destinations ask for clarification', async t => {
  assert.equal(detectLocation('半岛找Studio').label, '中半岛');
  assert.equal(detectLocation('South San Francisco 找房').label, 'South San Francisco');
  const { request } = await fixture(t, { posts: [post('peninsula', { city: 'Millbrae', title: 'Millbrae Studio' }), post('east-bay')] });
  const peninsula = await request('/api/ai/guide-chat', { message: '半岛找Studio' });
  assert.deepEqual(peninsula.data.matchingPosts.map(item => item.id), ['peninsula']);
  const multiple = await request('/api/ai/guide-chat', { message: '我在 San Francisco 上班，想在 Fremont 找 Studio' });
  assert.deepEqual(multiple.data.matchingPosts, []);
  assert.match(multiple.data.answer, /希望在哪一个地点/);
  assert.match(multiple.data.matchNote, /尚未检索/);
});

test('matching cards redact contact handles embedded in titles', async t => {
  const { request } = await fixture(t, { posts: [
    post('contact', { title: 'Hayward Studio 微信号：baylink_test_123 wx:private_handle' }),
    post('english-contact', { title: 'Hayward Studio WeChat ID: english_private_handle' }),
  ] });
  const response = await request('/api/ai/guide-chat', { message: '东湾找Studio' });
  assert.equal(response.data.matchingPosts.length, 2);
  assert.ok(!JSON.stringify(response.data.matchingPosts).includes('baylink_test_123'));
  assert.ok(!JSON.stringify(response.data.matchingPosts).includes('private_handle'));
  assert.ok(!JSON.stringify(response.data.matchingPosts).includes('english_private_handle'));
});

test('guide answers preserve the model answer and receive actual guide text/sources, not fake listing data', async t => {
  let context;
  const answer = '签租约前请核对费用条款、租赁期限以及押金退还条件，逐项记录不明确的地方并向房东确认。';
  const catalog = [{ title: '测试租约指南', slug: 'lease-test', url: '/guides/lease-test', keywords: ['租约'], categories: ['rent'], summary: '费用核对', content: '正文：逐项核对费用。', sources: [{ title: '官方示例', url: 'https://example.test/source' }], updatedAt: '2026-09-08' }];
  const { request } = await fixture(t, { guideCatalog: catalog, ai: { guideChat: async payload => { context = payload; return { answer, safetyNote: '' }; } } });
  const response = await request('/api/ai/guide-chat', { message: '签租约前应注意什么？' });
  assert.equal(response.data.answer, answer);
  assert.ok(response.data.interactiveCards.length > 0);
  assert.equal(response.data.degraded, false);
  assert.equal(context.guideSources[0].content, catalog[0].content);
  assert.deepEqual(context.guideSources[0].sources, catalog[0].sources);
  assert.deepEqual(context.matchingPosts, []);
  assert.equal(context.searchPerformed, false);
});

test('a completed multistep guide answer is returned intact beyond the former 180-character cutoff', async t => {
  const answer = [
    '1. 先确认交接日期和租约中的费用分工，列出需要自己办理的服务，以及已经由房东或物业统一提供的项目。',
    '2. 再确认水电燃气的服务范围、账户办理方式和开始日期，把需要衔接的时间写在同一张清单上，避免遗漏交接。',
    '3. 查询新地址能安装哪些宽带服务，确认设备、安装时间和收费内容，再安排安装并保留预约记录。',
    '4. 核对邮寄地址和邮件转寄安排，按实际情况更新重要账户，同时保留各项提交或确认记录。',
    '5. 入住当天记录交接情况，测试已经开通的服务；如果预约尚未完成，及时向对应服务方确认下一步。',
    '6. 最后按清单逐项复核，完成的项目做标记，尚未确认的费用和日期继续向相关服务方核实。',
  ].join('\n\n');
  assert.ok(answer.length > 180 && answer.length <= 1200);
  const { request } = await fixture(t, { ai: { guideChat: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ answer, safetyNote: '' }) } }] }) } });
  const response = await request('/api/ai/guide-chat', { message: '搬到湾区新住处后，水电网和地址变更应该按什么顺序办理？请根据站内指南说明。' });
  assert.equal(response.data.responseMode, 'ai');
  assert.equal(response.data.degraded, false);
  assert.equal(response.data.answer, answer);
  assert.ok(response.data.answer.endsWith('核实。'));
});

test('length-limited or otherwise unfinished completions degrade even when their partial JSON is valid', async t => {
  for (const finishReason of ['length', 'content_filter', null]) {
    const partial = '1. 确认水电服务。\n2. 安排宽带安装。\n3. 邮';
    const { request } = await fixture(t, { ai: { guideChat: async () => ({ choices: [{ finish_reason: finishReason, message: { content: JSON.stringify({ answer: partial, safetyNote: '' }) } }] }) } });
    const response = await request('/api/ai/guide-chat', { message: '搬家后水电网和地址变更应该按什么顺序办理？' });
    assert.equal(response.data.responseMode, 'fallback');
    assert.equal(response.data.degraded, true);
    assert.notEqual(response.data.answer, partial);
  }
});

test('an oversized completed answer falls back instead of slicing a sentence', async t => {
  const answer = `1. ${'完整的说明。'.repeat(220)}最后一句必须完整。`;
  const { request } = await fixture(t, { ai: { guideChat: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ answer, safetyNote: '' }) } }] }) } });
  const response = await request('/api/ai/guide-chat', { message: '搬家后水电网应该按什么顺序办理？' });
  assert.equal(response.data.degraded, true);
  assert.equal(response.data.responseMode, 'fallback');
  assert.ok(!response.data.answer.startsWith('1. 完整的说明。'));
});

test('missing AI configuration and provider failures are labeled degraded, and malformed input is rejected', async t => {
  const { request } = await fixture(t);
  const response = await request('/api/ai/guide-chat', { message: '怎样避免二手交易骗局？' });
  assert.equal(response.data.degraded, true);
  assert.equal(response.data.responseMode, 'fallback');
  assert.match(response.data.matchNote, /AI 暂时不可用/);
  assert.equal((await request('/api/ai/guide-chat', { message: { $ne: '' } })).status, 400);
  assert.equal((await request('/api/ai/guide-chat', { message: '长'.repeat(501) })).status, 400);
  const failing = await fixture(t, { ai: { guideChat: async () => { throw new Error('Simulated provider outage'); } } });
  assert.equal((await failing.request('/api/ai/guide-chat', { message: '租约如何核对？' })).data.degraded, true);
  const malformed = await fixture(t, { ai: { guideChat: async () => ({ safetyNote: 'missing answer' }) } });
  assert.equal((await malformed.request('/api/ai/guide-chat', { message: '租约如何核对？' })).data.degraded, true);
});

test('post draft preserves user facts and resolves North Bay without changing old posts', async t => {
  const intent = '我想在 Sausalito 求租，月租预算1800美元，10月1日入住。';
  const { request } = await fixture(t, { ai: { postAssist: async () => ({ title: 'Sausalito 求租', description: intent, area: '旧金山', category: 'rent', type: 'client' }) } });
  const response = await request('/api/ai/post-assist', { intent, type: 'client', tone: 'clear' }, true);
  assert.equal(response.status, 200);
  assert.equal(response.data.draft.area, '北湾');
  assert.equal(response.data.draft.description, intent);
  assert.equal(sanitizeAiDescription(`标题\n${intent}`, '标题', intent), intent);
});

test('AI timeout aborts a stalled transport and response-body timeout is also bounded', async () => {
  let signal;
  await assert.rejects(fetchAiJson('https://example.test', {}, { timeoutMs: 10, fetchImpl: async (_url, options) => { signal = options.signal; return new Promise(() => {}); } }), /timed out/);
  assert.equal(signal.aborted, true);
  await assert.rejects(fetchAiJson('https://example.test', {}, { timeoutMs: 10, fetchImpl: async () => ({ ok: true, json: () => new Promise(() => {}) }) }), /timed out/);
});
