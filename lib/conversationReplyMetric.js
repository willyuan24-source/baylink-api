const crypto = require('node:crypto');
const { bayAreaDate } = require('./eventEngagement');
const DAY = 86400000;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(value);
const plain = row => row?.toObject ? row.toObject() : row;

function createConversationResponseMetricModel(mongoose, injected = {}) {
  if (injected.ConversationResponseMetric) return injected.ConversationResponseMetric;
  const schema = new mongoose.Schema({
    _id: String, conversationId: String, postId: String, requesterId: String, ownerId: String,
    firstRequestMessageAt: Number, firstRequestMessageId: String, requestCountedAt: Number,
    firstOwnerReplyAt: Number, firstOwnerReplyMessageId: String, replyCountedAt: Number, locale: String,
    expiresAt: Date,
  }, { strict: 'throw', versionKey: false });
  schema.index({ conversationId: 1, requesterId: 1, ownerId: 1 }, { unique: true });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  schema.index({ ownerId: 1 });
  schema.index({ requesterId: 1 });
  return mongoose.models.ConversationResponseMetric || mongoose.model('ConversationResponseMetric', schema);
}

function createConversationReplyMetric({ Metric, ProductMetric, Post, now = Date.now, enabled = true }) {
  const increment = async (event, at, locale) => {
    if (!ProductMetric) return;
    const day = bayAreaDate(at), key = { day, event, locale };
    const expiresAt = new Date(Date.parse(`${day}T00:00:00Z`) + 180 * DAY);
    try {
      await ProductMetric.updateOne(key, { $inc: { count: 1 }, $setOnInsert: { _id: `${day}:${event}:${locale}`, ...key, expiresAt } }, { upsert: true, runValidators: true });
    } catch (error) {
      if (error.code !== 11000) throw error;
      await ProductMetric.updateOne(key, { $inc: { count: 1 } });
    }
  };
  const bindPostContext = async ({ conversation, requesterId, postId, locale }) => {
    if (!enabled || !id(postId) || !id(requesterId) || !id(conversation?.id) || !Array.isArray(conversation.userIds) || conversation.userIds.length !== 2 || !conversation.userIds.includes(requesterId)) return false;
    const post = plain(await Post.findOne({ id: postId, isDeleted: false, adminHidden: { $ne: true }, status: { $ne: 'closed' } }).select('id authorId'));
    if (!post || post.authorId === requesterId || !conversation.userIds.includes(post.authorId)) return false;
    const _id = hash(`reply:${conversation.id}:${requesterId}:${post.authorId}`);
    try {
      await Metric.updateOne({ _id }, { $setOnInsert: { conversationId: conversation.id, postId, requesterId, ownerId: post.authorId,
        locale: ['en', 'zh-Hant'].includes(locale) ? locale : 'zh-Hans', expiresAt: new Date(now() + 180 * DAY) } }, { upsert: true, runValidators: true });
    } catch (error) { if (error.code !== 11000) throw error; }
    return true;
  };
  const recordMessage = async message => {
    if (!enabled || !id(message?.id) || !id(message.conversationId) || !id(message.senderId)
      || !Number.isFinite(message.createdAt) || message.createdAt < now() - 5 * 60 * 1000 || message.createdAt > now() + 60000
      || (message.messageType && message.messageType !== 'text') || !['text', 'image'].includes(message.type)) return;
    const rows = await Metric.find({ conversationId: message.conversationId, $or: [{ requesterId: message.senderId }, { ownerId: message.senderId }] }).limit(2).lean();
    for (const row of rows) {
      const post = plain(await Post.findOne({ id: row.postId, authorId: row.ownerId, isDeleted: false, adminHidden: { $ne: true } }).select('id'));
      if (!post) continue;
      if (message.senderId === row.requesterId) {
        const marked = await Metric.findOneAndUpdate({ _id: row._id, firstRequestMessageAt: { $exists: false } }, { $set: {
          firstRequestMessageAt: message.createdAt, firstRequestMessageId: message.id, requestCountedAt: now(),
        } }, { new: true });
        // Mark before the optional aggregate: a transient failure may undercount;
        // it cannot count the same private request twice or fail message delivery.
        if (marked) await increment('message_request_started', message.createdAt, row.locale);
      } else if (Number.isFinite(row.firstRequestMessageAt) && message.createdAt >= row.firstRequestMessageAt && message.createdAt - row.firstRequestMessageAt <= DAY) {
        const marked = await Metric.findOneAndUpdate({ _id: row._id, firstRequestMessageAt: row.firstRequestMessageAt, firstOwnerReplyAt: { $exists: false } }, { $set: {
          firstOwnerReplyAt: message.createdAt, firstOwnerReplyMessageId: message.id, replyCountedAt: now(),
        } }, { new: true });
        if (marked) await increment('owner_reply_24h', message.createdAt, row.locale);
      }
    }
  };
  const eraseUser = (userId, { session } = {}) => Metric.deleteMany({ $or: [{ requesterId: userId }, { ownerId: userId }] }, session ? { session } : {});
  return { bindPostContext, recordMessage, eraseUser };
}

module.exports = { createConversationResponseMetricModel, createConversationReplyMetric };
