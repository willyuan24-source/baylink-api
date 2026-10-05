const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides } = require('../lib/guideConversation');
const catalog = require('../data/guide-catalog.json');

test('a Sunnyvale plumbing request only promotes repair guidance, never local schools or freebies', () => {
  const question = '请找 Sunnyvale 今天能上门修漏水水管的师傅，预算150美元。只列站内真实可联系的信息；如果没有，请直接说明，不要编造师傅、电话、执照或保证报价。';
  const guides = selectConversationGuides(catalog, question, 'repair', '/', [], '2026-10-04');
  assert.ok(guides.length > 0);
  assert.ok(guides.every(guide => guide.categories.includes('repair')));
  assert.ok(guides.some(guide => /repair-request|service-safety/.test(guide.slug)));
});

test('English cleaning searches remain about the service and explicitly opened articles are still readable', () => {
  const guides = selectConversationGuides(require('../data/guide-catalog.en.json'), 'Find a cleaning service in Sunnyvale with a clear price quote', 'cleaning', '/', [], '2026-10-04');
  assert.ok(guides.length > 0);
  assert.ok(guides.every(guide => guide.categories.includes('cleaning')));
  const article = catalog.find(guide => guide.slug === 'bay-area-freebies-deals-2026-10');
  assert.ok(selectConversationGuides(catalog, '总结这篇与维修有关的内容', 'repair', article.url, [], '2026-10-04').some(guide => guide.slug === article.slug));
});
