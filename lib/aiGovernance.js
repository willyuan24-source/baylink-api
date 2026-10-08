const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { bayAreaDate } = require('./eventEngagement');
const { metricFeature } = require('./aiRuntimeMetrics');
const execution = new AsyncLocalStorage();
const positive = (value, fallback, ceiling) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Math.min(Number(value), ceiling) : fallback;
const limitValue = (value, fallback, ceiling) => value !== undefined && value !== '' && Number.isSafeInteger(Number(value)) && Number(value) >= 0 ? Math.min(Number(value), ceiling) : fallback;
const cancelled = () => Object.assign(new Error('Request cancelled'), { code: 'REQUEST_CANCELLED', status: 499 });
function assertActive(signal = execution.getStore()?.signal) { if (signal?.aborted) throw cancelled(); }

function createAiGovernanceModel(mongoose, injected = {}) {
  if (injected.AiGovernance) return injected.AiGovernance;
  const schema = new mongoose.Schema({
    id: { type: String, unique: true, required: true }, count: { type: Number, default: 0 },
    identities: { type: mongoose.Schema.Types.Mixed, default: {} },
    calls: { type: Number, default: 0 }, inputTokens: { type: Number, default: 0 }, outputTokens: { type: Number, default: 0 },
    failures: { type: Number, default: 0 }, cancellations: { type: Number, default: 0 },
    latencyMs: { type: Number, default: 0 }, expiresAt: { type: Date, required: true },
    // Spend ledger documents (ai-usd:YYYY-MM-DD, ai-usd:YYYY-MM) only. No defaults:
    // they are created by an atomic $inc upsert, never by the quota documents.
    microUsd: { type: Number, min: 0 }, pricedCalls: { type: Number, min: 0 }, unpricedCalls: { type: Number, min: 0 },
  }, { versionKey: false });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.AiGovernance || mongoose.model('AiGovernance', schema);
}

// Spend ledger: integer micro-USD per Pacific day and month, aggregated over
// every governed provider call. Day rows are kept 62 days, month rows 400 days.
const LEDGER_DAY_TTL_DAYS = 62, LEDGER_MONTH_TTL_DAYS = 400;
const ledgerDayId = day => `ai-usd:${day}`;
const ledgerMonthId = day => `ai-usd:${day.slice(0, 7)}`;
const usdLimit = (value, fallback) => value !== undefined && value !== '' && Number.isFinite(Number(value)) && Number(value) >= 0 ? Math.min(Number(value), 100000) : fallback;

function createAiGovernance({ Model, config = {}, now = Date.now, isTest = false, metrics }) {
  const globalLimit = limitValue(config.AI_DAILY_REQUEST_LIMIT, 1000, 100000);
  const guestLimit = limitValue(config.AI_GUEST_DAILY_LIMIT, 15, 1000);
  const memberLimit = limitValue(config.AI_USER_DAILY_LIMIT, 40, 5000);
  const concurrency = positive(config.AI_CONCURRENCY_LIMIT, 6, 100);
  let active = 0;
  const idFor = () => `ai:${bayAreaDate(now())}`;
  const identityFor = ({ userId, ip }, id) => crypto.createHmac('sha256', config.JWT_SECRET).update(`${userId ? 'user:' + userId : 'ip:' + ip}:${id}`).digest('hex');
  async function claim({ userId, ip }) {
    const id = idFor();
    const hash = identityFor({ userId, ip }, id);
    const identity = `identities.${hash}`;
    try { await Model.updateOne({ id }, { $setOnInsert: { id, count: 0, identities: {}, expiresAt: new Date(now() + 3 * 86400000) } }, { upsert: true }); }
    catch (error) { if (error.code !== 11000) throw error; }
    // Global and identity reservations change ONE document atomically. No
    // partial reservation, cross-document race or raw account/IP persistence.
    const result = await Model.findOneAndUpdate({ id, count: { $lt: globalLimit }, $or: [{ [identity]: { $exists: false } }, { [identity]: { $lt: userId ? memberLimit : guestLimit } }] }, { $inc: { count: 1, [identity]: 1 } }, { new: true });
    return !!result;
  }
  async function usage(identity) {
    const id = idFor(), row = await Model.findOne({ id }).lean();
    const limit = identity.userId ? memberLimit : guestLimit;
    const count = row?.identities?.[identityFor(identity, id)] || 0;
    const tomorrow = new Date(Date.parse(`${id.slice(3)}T12:00:00Z`) + 86400000).toISOString().slice(0, 10);
    // Pacific midnight is UTC 07:00 in DST and UTC 08:00 otherwise.
    const seven = Date.parse(`${tomorrow}T07:00:00Z`);
    const resetAt = new Date(bayAreaDate(seven) === tomorrow ? seven : seven + 3600000).toISOString();
    return { remaining: Math.max(0, Math.min(limit - count, globalLimit - (row?.count || 0))), limit, resetAt, degraded: false };
  }
  async function record(values) {
    const increment = {};
    for (const [key, value] of Object.entries(values)) if (['calls', 'inputTokens', 'outputTokens', 'failures', 'cancellations', 'latencyMs'].includes(key) && Number.isSafeInteger(value) && value >= 0) increment[key] = value;
    if (Object.keys(increment).length) await Model.updateOne({ id: idFor() }, { $inc: increment }).catch(() => {});
  }
  // One atomic $inc per ledger document. A concurrent first insert can lose the
  // unique-id race (E11000); only that definite rejection is retried, as a plain
  // $inc, so no increment is applied twice or dropped.
  async function incrementLedger(id, increment, expiresAt) {
    try {
      await Model.updateOne({ id }, { $inc: increment, $setOnInsert: { expiresAt } }, { upsert: true, setDefaultsOnInsert: false });
    } catch (error) {
      if (error.code !== 11000) throw error;
      await Model.updateOne({ id }, { $inc: increment });
    }
  }
  /** Add one provider call's cost to today's and this month's ledger. Caps are not enforced here. */
  async function recordSpend(billing = {}) {
    const priced = billing.priced === true && Number.isSafeInteger(billing.microUsd) && billing.microUsd >= 0;
    if (!priced && billing.priced !== false) return;
    const timestamp = now(), day = bayAreaDate(timestamp);
    const increment = priced ? { microUsd: billing.microUsd, pricedCalls: 1 } : { unpricedCalls: 1 };
    await Promise.all([
      incrementLedger(ledgerDayId(day), increment, new Date(timestamp + LEDGER_DAY_TTL_DAYS * 86400000)),
      incrementLedger(ledgerMonthId(day), increment, new Date(timestamp + LEDGER_MONTH_TTL_DAYS * 86400000)),
    ]).catch(() => {});
  }
  const softDailyUsd = usdLimit(config.AI_SPEND_SOFT_DAILY_USD, 6), hardDailyUsd = usdLimit(config.AI_SPEND_HARD_DAILY_USD, 10);
  /** Today's and this month's recorded spend. Caps are reported, NOT enforced yet. */
  async function getSpendState() {
    const day = bayAreaDate(now());
    const [today, month] = await Promise.all([Model.findOne({ id: ledgerDayId(day) }).lean(), Model.findOne({ id: ledgerMonthId(day) }).lean()]);
    const amount = row => Number.isSafeInteger(row?.microUsd) && row.microUsd >= 0 ? row.microUsd : 0;
    const calls = (row, key) => Number.isSafeInteger(row?.[key]) && row[key] >= 0 ? row[key] : 0;
    const dayMicroUsd = amount(today), monthMicroUsd = amount(month);
    const level = dayMicroUsd >= Math.round(hardDailyUsd * 1e6) ? 'hard' : dayMicroUsd >= Math.round(softDailyUsd * 1e6) ? 'soft' : 'ok';
    return {
      day, month: day.slice(0, 7), dayMicroUsd, monthMicroUsd, dayUsd: dayMicroUsd / 1e6, monthUsd: monthMicroUsd / 1e6,
      dayPricedCalls: calls(today, 'pricedCalls'), dayUnpricedCalls: calls(today, 'unpricedCalls'),
      caps: { softDailyUsd, hardDailyUsd, enforced: false }, level,
    };
  }
  function middleware(identityFor) {
    return async (req, res, next) => {
      const runtime = metrics?.startRequest(metricFeature(req.path));
      req.aiRuntime = runtime;
      if (runtime) {
        const sendJson = res.json;
        res.json = function(body) {
          runtime.response({ ok: body?.ok, degraded: body?.degraded }, res.statusCode);
          return sendJson.call(this, body);
        };
        res.once('finish', () => runtime.end({ status: res.statusCode }));
        res.once('close', () => runtime.end({ cancelled: !res.writableEnded, status: res.statusCode }));
      }
      if (active >= concurrency) return res.status(429).json({ ok: false, error: 'AI is busy. Please try again shortly.', code: 'AI_CONCURRENCY_LIMIT' });
      const controller = new AbortController();
      let released = false;
      active++;
      const release = () => { if (!released) { released = true; active--; } };
      req.once('aborted', () => controller.abort());
      res.once('close', () => { if (!res.writableEnded) { controller.abort(); void record({ cancellations: 1 }); } release(); });
      res.once('finish', release);
      req.aiSignal = controller.signal;
      // Count attempted requests even after cancellation; already submitted
      // provider work can be billable. Never refund consumed quota blindly.
      let reservation;
      const reserve = () => reservation ||= (async () => {
        assertActive(controller.signal);
        try {
          const userId = await identityFor(req);
          if (!await claim({ userId, ip: req.ip || req.socket?.remoteAddress || 'unknown' })) throw Object.assign(new Error('今日 AI 额度已用完，请明天再试；仍可浏览站内资料。'), { status: 429, code: 'AI_DAILY_LIMIT' });
        } catch (error) {
          if (error.code === 'AI_DAILY_LIMIT') throw error;
          throw Object.assign(new Error('AI quota is temporarily unavailable.'), { status: 503, code: 'AI_QUOTA_UNAVAILABLE' });
        }
      })();
      execution.run({ signal: controller.signal, reserve, record, recordSpend, runtime, feature: metricFeature(req.path), providerCalls: 0, maxProviderCalls: 8 }, next);
    };
  }
  return { claim, usage, record, recordSpend, getSpendState, middleware, model: Model };
}

function aiExecution() { return execution.getStore(); }
async function reserveAiCall() {
  const context = aiExecution();
  assertActive();
  if (!context) return;
  await context.reserve();
  if (++context.providerCalls > context.maxProviderCalls) throw Object.assign(new Error('AI provider call limit reached'), { code: 'AI_CALL_LIMIT', status: 429 });
}
function governProviders(ai = {}) {
  return Object.fromEntries(Object.entries(ai).map(([key, value]) => [key, typeof value === 'function' ? async (...args) => { await reserveAiCall(); const result = await value(...args); assertActive(); return result; } : value]));
}
module.exports = { createAiGovernanceModel, createAiGovernance, aiExecution, assertActive, cancelled, reserveAiCall, governProviders };
