const crypto = require('node:crypto');
const { bayAreaDate } = require('./eventEngagement');

// Durable daily ceilings for phone-verification SMS (SEC-09). The in-memory
// limiter in server.js resets on every deploy or restart; these counters live in
// Mongo, so a restart cannot reopen a number's or the site's daily budget.
const NUMBER_DAILY_LIMIT = 5;
const USER_DAILY_LIMIT = 5;
const GLOBAL_DAILY_LIMIT = 100;
// A verified number is shared by families, so it is not unique per account, but a
// number already verified on this many OTHER accounts cannot verify another one.
const MAX_OTHER_VERIFIED_ACCOUNTS = 2;

const failure = (status, code, error) => ({ ok: false, status, code, error });

function createSmsQuotaModel(mongoose, injected = {}) {
  if (injected.SmsQuota) return injected.SmsQuota;
  const schema = new mongoose.Schema({
    _id: { type: String, required: true }, count: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true },
  }, { versionKey: false });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.SmsQuota || mongoose.model('SmsQuota', schema);
}

const configuredLimit = (value, fallback) => /^\d+$/.test(String(value ?? '').trim()) ? Math.min(100000, Number(String(value).trim())) : fallback;

function createSmsQuota({ Model, secret, config = {}, now = Date.now }) {
  if (typeof secret !== 'string' || !secret) throw new Error('SMS quota signing secret is required');
  const globalLimit = configuredLimit(config.SMS_VERIFY_DAILY_LIMIT, GLOBAL_DAILY_LIMIT);
  // Keys are day-scoped HMAC digests: the collection never stores a phone number or user id.
  const keyFor = (day, kind, value) => `${day}:${crypto.createHmac('sha256', secret).update(`sms-verify:v1:${day}:${kind}:${value}`).digest('hex')}`;
  async function reserve(_id, limit, timestamp) {
    if (limit <= 0) return false;
    try {
      await Model.updateOne({ _id }, { $setOnInsert: { count: 0, expiresAt: new Date(timestamp + 3 * 86400000) } }, { upsert: true });
    } catch (error) { if (error.code !== 11000) throw error; }
    // One conditional update on the unique _id enforces the limit across instances.
    return !!await Model.findOneAndUpdate({ _id, count: { $lt: limit } }, { $inc: { count: 1 } }, { new: true });
  }
  // Nothing has been sent yet when a later ceiling refuses, so earlier holds are returned.
  const refund = async _id => { try { await Model.updateOne({ _id, count: { $gt: 0 } }, { $inc: { count: -1 } }); } catch { /* Bounded: at worst one unused hold. */ } };
  return {
    globalLimit,
    /**
     * Reserve one verification SMS for this account and number before the provider call.
     * A provider failure after a successful claim is not refunded (the SMS may have gone out).
     */
    async claim({ userId, phone }) {
      if (typeof userId !== 'string' || !userId || typeof phone !== 'string' || !/^\+[1-9]\d{7,14}$/.test(phone)) return failure(400, 'SMS_QUOTA_INPUT', '请输入有效的美国手机号。');
      const timestamp = now(), day = bayAreaDate(timestamp);
      const holds = [];
      try {
        const steps = [
          [keyFor(day, 'number', phone), NUMBER_DAILY_LIMIT, failure(429, 'SMS_NUMBER_DAILY_LIMIT', '今日验证码发送次数已达上限。')],
          [keyFor(day, 'user', userId), USER_DAILY_LIMIT, failure(429, 'SMS_USER_DAILY_LIMIT', '今日验证码发送次数已达上限。')],
          [keyFor(day, 'global', 'all'), globalLimit, failure(503, 'SMS_DAILY_CAPACITY', '短信验证今天的发送量已满，请明天再试。')],
        ];
        for (const [_id, limit, refusal] of steps) {
          if (!await reserve(_id, limit, timestamp)) {
            await Promise.all(holds.map(refund));
            return refusal;
          }
          holds.push(_id);
        }
        return { ok: true };
      } catch {
        await Promise.all(holds.map(refund));
        return failure(503, 'SMS_QUOTA_UNAVAILABLE', '短信服务暂时不可用，请稍后再试。');
      }
    },
  };
}

module.exports = { NUMBER_DAILY_LIMIT, USER_DAILY_LIMIT, GLOBAL_DAILY_LIMIT, MAX_OTHER_VERIFIED_ACCOUNTS, createSmsQuotaModel, createSmsQuota };
