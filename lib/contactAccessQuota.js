const crypto = require('node:crypto');
const { bayAreaDate } = require('./eventEngagement');

const DAILY_LIMIT = 10;
const failure = (status, code, message) => Object.assign(new Error(message), { status, code, publicSafe: true });

// A verified number is a shared abuse-control key, not a unique person. Keep
// existing shared/legacy accounts; never install a unique index on User.phone.
function verifiedContactPhone(user) {
  if (user?.isPhoneVerified !== true) return null;
  const raw = user.phoneNormalized || user.phone;
  if (typeof raw !== 'string' || !/^[+\d\s().-]+$/.test(raw)) return null;
  const digits = raw.replace(/\D/g, '');
  return /^1\d{10}$/.test(digits) ? `+${digits}` : /^\d{10}$/.test(digits) ? `+1${digits}` : null;
}

function createContactAccessQuotaModel(mongoose, injected = {}) {
  if (injected.ContactAccessQuota) return injected.ContactAccessQuota;
  const schema = new mongoose.Schema({
    _id: { type: String, required: true }, count: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true },
  }, { versionKey: false });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.ContactAccessQuota || mongoose.model('ContactAccessQuota', schema);
}

function createContactAccessQuota({ Model, secret, now = Date.now }) {
  if (typeof secret !== 'string' || !secret) throw new Error('Contact quota signing secret is required');
  async function reserve(kind, value, day, timestamp) {
    const digest = crypto.createHmac('sha256', secret).update(`contact-access:v1:${day}:${kind}:${value}`).digest('hex');
    const _id = `${day}:${digest}`;
    try {
      await Model.updateOne({ _id }, { $setOnInsert: { count: 0, expiresAt: new Date(timestamp + 3 * 86400000) } }, { upsert: true });
    } catch (error) { if (error.code !== 11000) throw error; }
    // _id is unique even before a background secondary index is ready. One
    // conditional Mongo update enforces this identity's limit across instances.
    return !!await Model.findOneAndUpdate({ _id, count: { $lt: DAILY_LIMIT } }, { $inc: { count: 1 } }, { new: true });
  }
  return {
    async claim(user, { requirePhone = false } = {}) {
      const phone = verifiedContactPhone(user);
      if (requirePhone && !phone) throw failure(403, 'VERIFIED_CONTACT_REQUIRED', '请先验证手机号，再请求自动公开的联系方式。');
      if (typeof user?.id !== 'string' || !user.id) throw failure(503, 'CONTACT_QUOTA_UNAVAILABLE', '暂时无法确认联系请求额度，请稍后重试。');
      const timestamp = now(), day = bayAreaDate(timestamp);
      try {
        // Reserve account first so one account cannot drain many phone buckets.
        // These are bounded attempts, not billable successes: a subsequent
        // denial/write failure deliberately does not refund the earlier claim.
        if (!await reserve('account', user.id, day, timestamp)
          || phone && !await reserve('phone', phone, day, timestamp)) {
          throw failure(429, 'CONTACT_DAILY_LIMIT', '该账号或已验证手机号今日联系请求已达上限，请明天再试。');
        }
      } catch (error) {
        if (error.code === 'CONTACT_DAILY_LIMIT') throw error;
        throw failure(503, 'CONTACT_QUOTA_UNAVAILABLE', '暂时无法确认联系请求额度，请稍后重试。');
      }
    },
  };
}

module.exports = { DAILY_LIMIT, verifiedContactPhone, createContactAccessQuotaModel, createContactAccessQuota };
