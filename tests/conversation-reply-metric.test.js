const test = require('node:test');
const assert = require('node:assert/strict');
const { createConversationReplyMetric } = require('../lib/conversationReplyMetric');
const { memory } = require('./support/notification-memory');
const at = Date.parse('2026-10-06T12:00:00Z');
function fixture() {
  let time = at;
  const Metric = memory(), ProductMetric = memory(), Post = memory([{ id: 'post_1', authorId: 'owner', isDeleted: false }]);
  const metric = createConversationReplyMetric({ Metric, ProductMetric, Post, now: () => time });
  const conversation = { id: 'dm_pair', userIds: ['requester', 'owner'] };
  const message = (id, senderId, createdAt = time) => ({ id, senderId, createdAt, conversationId: conversation.id, type: 'text', messageType: 'text' });
  return { Metric, ProductMetric, Post, metric, conversation, message, clock: value => { time = value; } };
}
test('opening a verified post context does not count; actual request and first owner answer count once', async () => {
  const f = fixture(); await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1', locale: 'en' });
  assert.equal(f.ProductMetric.rows.size, 0);
  await Promise.all([f.metric.recordMessage(f.message('request_1', 'requester')), f.metric.recordMessage(f.message('request_1', 'requester'))]);
  f.clock(at + 1000); await Promise.all([f.metric.recordMessage(f.message('reply_1', 'owner')), f.metric.recordMessage(f.message('reply_2', 'owner'))]);
  const events = [...f.ProductMetric.rows.values()]; assert.equal(events.find(row => row.event === 'message_request_started').count, 1); assert.equal(events.find(row => row.event === 'owner_reply_24h').count, 1);
  assert.ok(events.every(row => row.locale === 'en')); assert.doesNotMatch(JSON.stringify(events), /requester|owner|dm_pair|post_1/);
});
test('legacy unknown context, wrong owner, system/contact-card and late replies never count', async () => {
  const f = fixture(); await f.metric.recordMessage(f.message('legacy', 'owner')); assert.equal(f.ProductMetric.rows.size, 0);
  assert.equal(await f.metric.bindPostContext({ conversation: { id: 'dm_other', userIds: ['requester', 'other'] }, requesterId: 'requester', postId: 'post_1' }), false);
  await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1' });
  await f.metric.recordMessage({ ...f.message('system', 'requester'), messageType: 'system' });
  await f.metric.recordMessage({ ...f.message('contact', 'requester'), type: 'contact_card' }); assert.equal(f.ProductMetric.rows.size, 0);
  await f.metric.recordMessage(f.message('request', 'requester')); f.clock(at + 86400001); await f.metric.recordMessage(f.message('late', 'owner'));
  assert.equal([...f.ProductMetric.rows.values()].some(row => row.event === 'owner_reply_24h'), false);
});
test('reply exactly within 24 hours counts; deletion cleanup removes private associations', async () => {
  const f = fixture(); await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1' }); await f.metric.recordMessage(f.message('request', 'requester'));
  f.clock(at + 86400000); await f.metric.recordMessage(f.message('boundary', 'owner')); assert.equal([...f.ProductMetric.rows.values()].find(row => row.event === 'owner_reply_24h').count, 1);
  await f.metric.eraseUser('requester'); assert.equal(f.Metric.rows.size, 0);
});
