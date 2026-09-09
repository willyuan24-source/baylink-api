const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { createMemoryModels } = require('./support/memory-models');

dotenv.config = () => { throw new Error('Locale direction tests must not read .env'); };
mongoose.connect = async () => { throw new Error('Locale direction tests must not connect to Mongo'); };
const { createApplication } = require('../server');

const cleaningPost = {
  id: 'cleaning-offer', title: 'Fremont 清洁服务', description: '提供预约清洁服务。',
  category: '清洁', city: 'Fremont', budget: '按范围报价', type: 'provider', authorId: 'owner',
  status: 'active', isDeleted: false, adminHidden: false, createdAt: 100,
  likes: [], comments: [], reports: [],
};

async function fixture(t) {
  const models = createMemoryModels({ Post: [cleaningPost], User: [] });
  let searches = 0;
  const originalFind = models.Post.find;
  models.Post.find = function (...args) { searches += 1; return originalFind.apply(this, args); };
  const aiRequests = [];
  const application = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-locale-provider-regression-secret-long-enough' },
    models, guideCatalog: [], guideCatalogEn: [],
    ai: { guideChat: async payload => {
      aiRequests.push(payload);
      return { answer: 'Describe your offering, location, availability and pricing before publishing.' };
    } },
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async message => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, locale: 'en' }),
    });
    return { status: response.status, data: await response.json() };
  };
  return { request, aiRequests, searchCount: () => searches };
}

const providerCases = [
  ['I am looking for cleaning clients in Fremont', 'cleaning'],
  ['I am looking for customers for my cleaning service', 'cleaning'],
  ['I am selling a sofa in Fremont', 'used'],
  ['I am hiring part-time staff in Fremont', 'part-time'],
];

for (const [message, category] of providerCases) {
  test(`English supplier direction is preserved: ${message}`, async t => {
    const { request, aiRequests, searchCount } = await fixture(t);
    const { status, data } = await request(message);
    assert.equal(status, 200);
    assert.equal(data.responseMode, 'ai');
    assert.equal(searchCount(), 0, 'An offering must not search for competing providers');
    assert.deepEqual(data.matchingPosts, []);
    assert.equal(aiRequests.length, 1);
    assert.equal(aiRequests[0].message, message, 'The model still receives the original English request');
    assert.equal(aiRequests[0].inferredPostType, 'provider');
    assert.equal(aiRequests[0].inferredCategory, category);
    assert.deepEqual(data.interactiveCards, [], 'Consumer checklists must not accompany a supplier request');
    assert.deepEqual(data.suggestedActions.map(action => action.type).sort(), ['post', 'postAssist']);
    assert.ok(data.suggestedActions.every(action => action.postType === 'provider' && action.category === category));
  });
}

test('looking for a cleaning service remains a consumer search with a real matching post', async t => {
  const { request, aiRequests, searchCount } = await fixture(t);
  const { status, data } = await request('I am looking for a cleaning service in Fremont');
  assert.equal(status, 200);
  assert.equal(data.responseMode, 'search');
  assert.equal(searchCount(), 1);
  assert.equal(aiRequests.length, 0, 'A concrete post search must use the database, not an AI completion');
  assert.deepEqual(data.matchingPosts.map(post => post.id), ['cleaning-offer']);
  assert.equal(data.matchingPosts[0].title, cleaningPost.title, 'Community post text remains unchanged');
  const composerActions = data.suggestedActions.filter(action => ['post', 'postAssist'].includes(action.type));
  assert.deepEqual(composerActions.map(action => action.type).sort(), ['post', 'postAssist']);
  assert.ok(composerActions.every(action => action.postType === 'client' && action.category === 'cleaning'));
});
