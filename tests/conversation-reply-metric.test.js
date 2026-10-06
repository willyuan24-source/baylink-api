const test = require('node:test');
const assert = require('node:assert/strict');
const { createConversationReplyMetric } = require('../lib/conversationReplyMetric');
const { memory } = require('./support/notification-memory');
const at = Date.parse('2026-10-06T12:00:00Z');
function fixture() {
  let time = at;
  const Metric = memory(), ProductMetric = memory(), Message = memory(), Post = memory([{ id: 'post_1', authorId: 'owner', isDeleted: false }]);
  const metric = createConversationReplyMetric({ Metric, ProductMetric, Post, Message, now: () => time });
  const conversation = { id: 'dm_pair', userIds: ['requester', 'owner'] };
  const message = (id, senderId, createdAt = time) => { const row = { _id: id, id, senderId, createdAt, conversationId: conversation.id, type: 'text', messageType: 'text' }; Message.rows.set(id, row); return row; };
  return { Metric, ProductMetric, Post, Message, metric, conversation, message, clock: value => { time = value; } };
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
  const legacy = fixture(); await legacy.metric.recordMessage(legacy.message('legacy', 'owner')); assert.equal(legacy.ProductMetric.rows.size, 0);
  assert.equal(await legacy.metric.bindPostContext({ conversation: { id: 'dm_other', userIds: ['requester', 'other'] }, requesterId: 'requester', postId: 'post_1' }), false);
  const f = fixture();
  await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1' });
  const system = { ...f.message('system', 'requester'), messageType: 'system' }; f.Message.rows.set(system.id, system); await f.metric.recordMessage(system);
  const card = { ...f.message('contact', 'requester'), type: 'contact_card' }; f.Message.rows.set(card.id, card); await f.metric.recordMessage(card); assert.equal(f.ProductMetric.rows.size, 0);
  await f.metric.recordMessage(f.message('request', 'requester')); f.clock(at + 86400001); await f.metric.recordMessage(f.message('late', 'owner'));
  assert.equal([...f.ProductMetric.rows.values()].find(row => row.event === 'message_request_started').count, 1);
  assert.equal([...f.ProductMetric.rows.values()].some(row => row.event === 'owner_reply_24h'), false);
});
test('reply exactly within 24 hours counts; deletion cleanup removes private associations', async () => {
  const f = fixture(); await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1' }); await f.metric.recordMessage(f.message('request', 'requester'));
  f.clock(at + 86400000); await f.metric.recordMessage(f.message('boundary', 'owner')); assert.equal([...f.ProductMetric.rows.values()].find(row => row.event === 'owner_reply_24h').count, 1);
  await f.metric.eraseUser('requester'); assert.equal(f.Metric.rows.size, 0);
});

test('cross-day responses belong to the first request cohort and legacy history stays unknown', async () => {
  const f = fixture(), firstAt = Date.parse('2026-10-31T23:59:00-07:00'); f.clock(firstAt);
  await f.metric.bindPostContext({ conversation: f.conversation, requesterId: 'requester', postId: 'post_1' }); await f.metric.recordMessage(f.message('request', 'requester'));
  f.clock(firstAt + 2 * 60000); await f.metric.recordMessage(f.message('reply', 'owner'));
  assert.deepEqual([...f.ProductMetric.rows.values()].map(row => row.day), ['2026-10-31', '2026-10-31']);
  const legacy = fixture(); legacy.message('old_request', 'requester');
  assert.equal(await legacy.metric.bindPostContext({ conversation: legacy.conversation, requesterId: 'requester', postId: 'post_1' }), false);
  legacy.clock(at + 1000); await legacy.metric.recordMessage(legacy.message('new_request', 'requester')); assert.equal(legacy.ProductMetric.rows.size, 0);
});
