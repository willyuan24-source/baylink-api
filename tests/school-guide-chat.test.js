const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { createMemoryModels } = require('./support/memory-models');
const { selectConversationGuides, resolveConversationRequest, groundedGuideFallback, isSchoolRequest } = require('../lib/guideConversation');

dotenv.config = () => { throw new Error('School tests must not load .env'); };
mongoose.connect = async () => { throw new Error('School tests must not connect to Mongo'); };
const { createApplication } = require('../server');

const schoolGuide = (region, city) => ({
  slug: `${region}-school-district-enrollment-guide`,
  url: `/guides/${region}-school-district-enrollment-guide`,
  title: `${city}学校与学区：地址核验与入学`,
  summary: '按年级和学年核对官方学区入口，申请不保证指定学校。',
  keywords: ['学校与学区', '学区', '入学', city],
  categories: ['other'],
  content: `${city}学校与学区：请自行在官方 School Locator 核对地址。城市不等于学区。入学年级、申请学年和分配结果请向官方确认。`,
  sources: [{ title: '官方学区招生', url: 'https://example.test/official-enrollment' }],
  updatedAt: '2026-09-27',
});
const sf = schoolGuide('sf', '旧金山');
const east = { ...schoolGuide('east-bay', '东湾'), content: 'Fremont Berkeley Oakland：学校与学区入学入口。新生应按年级和学年向官方确认。' };
const family = {
  slug: 'family-freebies', url: '/guides/family-freebies',
  title: '孩子儿童亲子免费手工：周末入场优惠',
  summary: '儿童孩子亲子免费手工，去哪里玩一天的路线与半天福利。',
  keywords: ['孩子', '儿童', '亲子', '免费', '手工', '优惠', '周末', '福利'],
  content: '儿童学校主题手工与免费周末活动。', categories: ['other'], updatedAt: '2026-09-27',
};
const rent = { slug: 'rent', url: '/guides/rent', title: '租房押金与租约', summary: '租房前核对合同。', keywords: ['租房'], content: '租房预算与押金', categories: ['rent'] };
const catalog = [family, rent, sf, east];
const history = question => [{ role: 'user', content: question }, { role: 'assistant', content: '请核对官方入口。' }];

test('school enrollment excludes family freebies even when the request includes children and free education', () => {
  for (const message of ['孩子免费公立学校怎么入学', '刚搬到 Fremont，孩子上学怎么办', '東灣孩子入學要哪些材料', 'How do I enroll my child in a public school?']) {
    const selected = selectConversationGuides(catalog, message, 'other');
    assert.ok(selected.length > 0, message);
    assert.ok(selected.every(guide => guide.slug.endsWith('school-district-enrollment-guide')), message);
  }
  assert.equal(selectConversationGuides(catalog, 'Fremont 孩子入学', 'other')[0].slug, east.slug);
  assert.equal(selectConversationGuides(catalog, '旧金山学校入学', 'other')[0].slug, sf.slug);
});

test('school lookup does not substitute unrelated guides when school content is unavailable', () => {
  assert.deepEqual(selectConversationGuides([family, rent], '孩子学校入学', 'other'), []);
  assert.equal(selectConversationGuides(catalog, '孩子周末免费手工', 'other')[0].slug, family.slug);
});

test('switching from leisure to school clears old topic and current article bias', () => {
  const previous = history('东湾周末亲子免费手工');
  const message = '旧金山孩子入学需要哪些材料';
  assert.equal(resolveConversationRequest(message, previous), message);
  const selected = selectConversationGuides(catalog, message, 'other', family.url, previous);
  assert.equal(selected[0].slug, sf.slug);
  assert.ok(selected.every(guide => guide.slug !== family.slug));
});

test('school follow-ups preserve enrollment context while replacing only the requested location', () => {
  const previous = history('旧金山孩子入学怎么申请');
  const request = resolveConversationRequest('Fremont 呢？', previous);
  assert.match(request, /Fremont/);
  assert.match(request, /入学/);
  assert.doesNotMatch(request, /旧金山/);
  assert.equal(selectConversationGuides(catalog, 'Fremont 呢？', 'other', '/', previous)[0].slug, east.slug);
  assert.match(resolveConversationRequest('孩子读三年级，需要哪些材料', previous), /旧金山/);
  assert.match(resolveConversationRequest('孩子六岁', previous), /入学/);
});

test('an explicit leisure or housing question can leave the school topic', () => {
  const previous = history('旧金山学校入学');
  for (const message of ['那周末免费手工呢', '那我想租房呢']) {
    assert.equal(resolveConversationRequest(message, previous), message);
  }
  assert.equal(selectConversationGuides(catalog, '那周末免费手工呢', 'other', sf.url, previous)[0].slug, family.slug);
});

test('school fallback gives district verification guidance without presenting leisure conditions', () => {
  const answer = groundedGuideFallback([sf]);
  assert.match(answer, /城市不等于学区/);
  assert.match(answer, /自行在官方地址查询工具/);
  assert.match(answer, /不要在对话中提交/);
  assert.match(answer, /不代表实时查询结果/);
  assert.doesNotMatch(answer, /免费领取门槛/);
});

async function fixture(t, ai, guideCatalog = catalog, guideCatalogEn = []) {
  const models = createMemoryModels({ Post: [], User: [] });
  const application = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-school-chat-secret-more-than-32-characters' },
    models, ai, guideCatalog, guideCatalogEn,
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return async body => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() };
  };
}

test('API keeps moving-related enrollment questions on school sources instead of marketplace search', async t => {
  let received;
  const request = await fixture(t, { guideChat: async payload => {
    received = payload;
    return { answer: '请先按目标年级和学年查看官方入学入口，再自行在学区工具核对住址。' };
  } });
  const response = await request({
    message: '刚搬家到 Fremont，孩子入学怎么申请？',
    context: { currentPath: family.url, categoryHint: 'moving' },
    history: history('东湾孩子周末免费手工'),
  });
  assert.equal(response.status, 200);
  assert.equal(response.data.responseMode, 'ai');
  assert.equal(received.inferredIntent, 'school');
  assert.equal(received.inferredCategory, 'other');
  assert.equal(received.searchPerformed, false);
  assert.deepEqual(received.matchingPosts, []);
  assert.equal(received.guideSources[0].url, east.url);
  assert.ok(received.guideSources.every(guide => guide.url !== family.url));
  assert.deepEqual(received.guideSources[0].sources, east.sources);
  assert.ok(response.data.suggestedActions.every(action => !action.postType));
  assert.deepEqual(response.data.interactiveCards, []);
});

test('API school fallback remains useful without a provider or a school catalog', async t => {
  const request = await fixture(t, undefined, [family, rent]);
  const response = await request({ message: '孩子入学需要什么', context: { categoryHint: 'rent' } });
  assert.equal(response.data.responseMode, 'fallback');
  assert.deepEqual(response.data.suggestedGuides, []);
  assert.match(response.data.answer, /城市不等于学区/);
  assert.match(response.data.answer, /不要在对话中提交孩子姓名/);
  assert.ok(response.data.suggestedActions.every(action => !action.postType));
  assert.deepEqual(response.data.interactiveCards, []);
});

test('published guides rank the requested region first across all five areas', () => {
  const published = require('../data/guide-catalog.json');
  for (const [message, region] of [
    ['旧金山孩子入学', 'sf'], ['东湾学校学区', 'east-bay'],
    ['San Mateo school enrollment', 'peninsula'], ['南湾孩子入学', 'south-bay'],
    ['北湾学区入学', 'north-bay'], ['Fremont school enrollment', 'east-bay'],
  ]) {
    const selected = selectConversationGuides(published, message, 'other');
    assert.equal(selected[0]?.slug, `${region}-school-district-enrollment-guide`, message);
  }
});

test('English school fallback stays on enrollment with or without translated published guides', async t => {
  const withoutCatalog = await fixture(t, undefined, [family, rent]);
  const noSources = await withoutCatalog({ message: 'How do I enroll my child in school?', locale: 'en' });
  assert.match(noSources.data.answer, /A city is not a school district/);
  assert.match(noSources.data.answer, /Do not share a child's name/);
  assert.doesNotMatch(noSources.data.answer, /weekend ideas|\p{Script=Han}/u);
  const withCatalog = await fixture(t, undefined, require('../data/guide-catalog.json'), require('../data/guide-catalog.en.json'));
  const published = await withCatalog({ message: 'San Mateo school enrollment', locale: 'en' });
  assert.equal(published.data.suggestedGuides[0]?.slug, 'peninsula-school-district-enrollment-guide');
  assert.match(published.data.answer, /A city is not a school district/);
  assert.match(published.data.answer, /This is not a live check/);
  assert.doesNotMatch(published.data.answer, /\p{Script=Han}/u);
});

test('campus sightseeing retains the real Stanford art walk in Chinese and English after school context', async t => {
  const request = await fixture(t, undefined, require('../data/guide-catalog.json'), require('../data/guide-catalog.en.json'));
  for (const [message, locale] of [
    ['周末去斯坦福大学散步看展', 'zh-Hans'],
    ['A weekend Stanford University campus art walk', 'en'],
  ]) {
    assert.equal(isSchoolRequest(message), false);
    const response = await request({ message, locale, history: history('孩子学校入学怎么办'), context: { currentPath: sf.url } });
    assert.ok(response.data.suggestedGuides.some(guide => guide.slug === 'stanford-cantor-campus-art-walk'), message);
  }
  const berkeleyVisit = '那 UC Berkeley campus tour 呢？';
  assert.equal(isSchoolRequest(berkeleyVisit), false);
  assert.equal(resolveConversationRequest(berkeleyVisit, history('孩子学校入学怎么办')), berkeleyVisit);
  for (const message of ['周末参观学校前想了解孩子入学申请', 'School admissions and a campus tour', '周末想了解大学申请材料', 'A campus visit and college applications', '三年级转学需要哪些材料']) {
    assert.equal(isSchoolRequest(message), true, message);
  }
});

test('school hiring and repairs retain their marketplace intent', async t => {
  for (const message of ['学校招聘老师', '大学需要维修水管', 'University hiring teachers', 'School building repair service']) {
    assert.equal(isSchoolRequest(message), false, message);
  }
  const requests = [];
  const request = await fixture(t, { guideChat: async payload => {
    requests.push(payload);
    return { answer: '请先说明职位职责、工作地点、报酬和申请方式，并发布招聘信息。' };
  } });
  await request({ message: '我们学校招聘老师，怎么发布招聘？' });
  assert.equal(requests[0].inferredIntent, 'part-time');
  const repair = await request({ message: '帮学校找维修水管服务' });
  assert.equal(repair.data.responseMode, 'search');
  assert.ok(repair.data.suggestedActions.every(action => !action.category || action.category === 'repair'));
});
