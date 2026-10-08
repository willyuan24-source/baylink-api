const crypto = require('node:crypto');
const { bayAreaDate } = require('./eventEngagement');
const { createRateLimiter } = require('./rateLimit');
const { ROUTE_TEMPLATES, routeTemplate } = require('./routeTemplates');
const { releaseLabel } = require('./clientErrors');

// Reader feedback (gate G9): the footer sheet, "这条信息有误？" on content pages and
// BayBay 👎 reasons. Unauthenticated. Kept 90 days. The route template, entity and
// reason are allowlisted; free text and contact are what the reader typed.
const FEEDBACK_KINDS = Object.freeze(['page', 'content', 'baybay']);
const FEEDBACK_REASONS = Object.freeze({
  // 我在做什么: 找活动 / 办事 / 问 BayBay / 计划 / 其他
  page: Object.freeze(['find-events', 'get-help', 'ask-baybay', 'plan', 'other']),
  // 这条信息有误: 已过期 / 时间不对 / 地点不对 / 价格不对 / 链接打不开 / 已取消或关门 / 其他
  content: Object.freeze(['outdated', 'wrong-time', 'wrong-place', 'wrong-price', 'broken-link', 'closed', 'other']),
  // BayBay 👎: 答错了 / 太慢 / 没答到 / 其他
  baybay: Object.freeze(['wrong-answer', 'too-slow', 'not-answered', 'other']),
});
const ENTITY_KINDS = Object.freeze(['event', 'place', 'guide', 'offer', 'opening', 'post']);
const ENTITY_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,159}$/;
const LOCALES = Object.freeze(['zh-Hans', 'zh-Hant', 'en']);
const READING_SIZES = Object.freeze(['standard', 'large', 'extra-large']);
const FIELDS = Object.freeze(['kind', 'routeTemplate', 'reason', 'text', 'contact', 'entity', 'locale', 'readingSize', 'release', 'website']);
const MAX_TEXT = 500;
const MAX_CONTACT = 80;
const RETENTION_DAYS = 90;
const VISITOR_DAILY_LIMIT = 10;
const GLOBAL_DAILY_LIMIT = 500;
const DAY_MS = 86400000;
const ADMIN_PAGE = 100;
const ADMIN_PAGE_MAX = 200;
// Control characters except tab and newline, and the bidirectional marks, embeddings, overrides and
// isolates that can disguise or reorder text in admin. Written as escapes so this file has no hidden text.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARACTERS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const failure = (status, code, error) => Object.assign(new Error(error), { status, code });
const plainObject = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const length = value => [...value].length;

/** Trimmed reader text with unsafe characters removed, '' when absent, or null when invalid. */
function readerText(value, maximum) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') return null;
  const clean = value.replace(/\r\n?/g, '\n').replace(UNSAFE_CHARACTERS, '').trim();
  return length(clean) <= maximum ? clean : null;
}

/** The stored record for a valid body, or null. Never copies an unknown key. */
function normalizeFeedback(body) {
  if (!plainObject(body) || Object.keys(body).some(key => !FIELDS.includes(key))) return null;
  const { kind, reason } = body;
  if (!FEEDBACK_KINDS.includes(kind) || !FEEDBACK_REASONS[kind].includes(reason)) return null;
  const route = body.routeTemplate === undefined ? 'other' : routeTemplate(body.routeTemplate);
  const text = readerText(body.text, MAX_TEXT);
  const contact = readerText(body.contact, MAX_CONTACT);
  const release = releaseLabel(body.release);
  if (route === null || text === null || contact === null || release === null) return null;
  if (body.locale !== undefined && !LOCALES.includes(body.locale)) return null;
  if (body.readingSize !== undefined && !READING_SIZES.includes(body.readingSize)) return null;
  let entity;
  if (body.entity !== undefined) {
    const value = body.entity;
    if (!plainObject(value) || Object.keys(value).some(key => !['kind', 'id'].includes(key))
      || !ENTITY_KINDS.includes(value.kind) || typeof value.id !== 'string' || !ENTITY_ID.test(value.id)) return null;
    entity = { kind: value.kind, id: value.id };
  }
  return { kind, reason, route, text, ...(contact ? { contact } : {}), ...(entity ? { entity } : {}),
    locale: body.locale || 'zh-Hans', readingSize: body.readingSize || 'standard', release };
}

function createFeedbackModels(mongoose, injected = {}) {
  const Feedback = injected.Feedback || mongoose.models.Feedback || mongoose.model('Feedback', (() => {
    const schema = new mongoose.Schema({
      _id: { type: String, required: true },
      kind: { type: String, required: true, enum: FEEDBACK_KINDS },
      reason: { type: String, required: true, enum: [...new Set(Object.values(FEEDBACK_REASONS).flat())] },
      route: { type: String, required: true, enum: ROUTE_TEMPLATES },
      text: { type: String, default: '', maxlength: MAX_TEXT * 2 },
      contact: { type: String, maxlength: MAX_CONTACT * 2 },
      entity: { type: new mongoose.Schema({
        kind: { type: String, required: true, enum: ENTITY_KINDS },
        id: { type: String, required: true, match: ENTITY_ID },
      }, { _id: false, strict: 'throw' }), default: undefined },
      locale: { type: String, required: true, enum: LOCALES },
      readingSize: { type: String, required: true, enum: READING_SIZES },
      release: { type: String, required: true, maxlength: 32 },
      createdAt: { type: Date, required: true },
      expiresAt: { type: Date, required: true },
    }, { strict: 'throw', versionKey: false });
    schema.index({ createdAt: -1 });
    schema.index({ kind: 1, createdAt: -1 });
    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    return schema;
  })());
  // Daily counters. A visitor's row is keyed by an HMAC of the day and the visitor
  // key, so the stored id can neither be reversed nor linked across days.
  const FeedbackQuota = injected.FeedbackQuota || mongoose.models.FeedbackQuota || mongoose.model('FeedbackQuota', (() => {
    const schema = new mongoose.Schema({
      _id: { type: String, required: true },
      count: { type: Number, default: 0, min: 0 },
      expiresAt: { type: Date, required: true },
    }, { strict: 'throw', versionKey: false });
    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    return schema;
  })());
  return { Feedback, FeedbackQuota };
}

function registerFeedback(app, { mongoose, models = {}, secret, authenticateToken, requireAdmin, getClientIp, now = Date.now, limiter = createRateLimiter({ capacity: 20000 }) }) {
  if (typeof secret !== 'string' || !secret) throw new Error('Feedback quota signing secret is required');
  const { Feedback, FeedbackQuota } = createFeedbackModels(mongoose, models);
  const visitorDigest = (day, key) => crypto.createHmac('sha256', secret).update(`feedback:v1:${day}:${key}`).digest('hex');
  const limited = (req, kind, maxRequests) => !limiter.check(`feedback-${kind}:${getClientIp(req)}`, { windowMs: 60000, maxRequests });
  const admin = (req, res, next) => req.user?.role === 'admin' ? requireAdmin(req, res, next) : res.status(403).json({ error: '仅管理员可查看反馈。' });

  /** One conditional increment; false once the counter has reached its limit. */
  async function reserve(_id, limit, timestamp) {
    try {
      await FeedbackQuota.updateOne({ _id }, { $setOnInsert: { count: 0, expiresAt: new Date(timestamp + 2 * DAY_MS) } }, { upsert: true });
    } catch (error) { if (error.code !== 11000) throw error; }
    return !!await FeedbackQuota.findOneAndUpdate({ _id, count: { $lt: limit } }, { $inc: { count: 1 } }, { new: true });
  }
  /** Best effort: gives back a slot reserved for a submission that was not stored. */
  async function refund(_id) {
    try { await FeedbackQuota.updateOne({ _id, count: { $gt: 0 } }, { $inc: { count: -1 } }); } catch { /* the slot stays used */ }
  }

  app.post('/api/feedback', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (limited(req, 'minute', 5)) return res.status(429).json({ ok: false, code: 'FEEDBACK_RATE_LIMIT', error: '提交太频繁，请稍后再试。' });
    const record = normalizeFeedback(req.body);
    if (!record || (req.body.website !== undefined && typeof req.body.website !== 'string')) {
      return res.status(400).json({ ok: false, code: 'FEEDBACK_INVALID', error: '反馈格式无效。' });
    }
    // Honeypot: a filled hidden field looks accepted but writes nothing.
    if (req.body.website?.trim()) return res.status(202).json({ ok: true });
    const timestamp = now(), day = bayAreaDate(timestamp);
    const visitorQuota = `${day}:visitor:${visitorDigest(day, getClientIp(req))}`, globalQuota = `${day}:global`;
    // The visitor's own counter goes first, so a visitor past their limit cannot use up the
    // site-wide one. A slot is given back when a later step refuses or fails.
    const reserved = [];
    try {
      if (!await reserve(visitorQuota, VISITOR_DAILY_LIMIT, timestamp)) {
        throw failure(429, 'FEEDBACK_DAILY_LIMIT', '今天的反馈次数已用完，请明天再试。');
      }
      reserved.push(visitorQuota);
      if (!await reserve(globalQuota, GLOBAL_DAILY_LIMIT, timestamp)) {
        throw failure(429, 'FEEDBACK_GLOBAL_LIMIT', '今天收到的反馈已达上限，请明天再试。');
      }
      reserved.push(globalQuota);
      await Feedback.create({ _id: crypto.randomUUID(), ...record, createdAt: new Date(timestamp), expiresAt: new Date(timestamp + RETENTION_DAYS * DAY_MS) });
      res.status(202).json({ ok: true });
    } catch (error) {
      await Promise.all(reserved.map(refund));
      if (error.status === 429) return res.status(429).json({ ok: false, code: error.code, error: error.message });
      res.status(503).json({ ok: false, code: 'FEEDBACK_UNAVAILABLE', error: '暂时无法提交反馈，请稍后重试。' });
    }
  });

  const PUBLIC_FIELDS = 'kind reason route text contact entity locale readingSize release createdAt';
  const publicRow = row => ({ id: row._id, kind: row.kind, reason: row.reason, route: row.route, text: row.text || '',
    ...(row.contact ? { contact: row.contact } : {}), ...(row.entity ? { entity: { kind: row.entity.kind, id: row.entity.id } } : {}),
    locale: row.locale, readingSize: row.readingSize, release: row.release, createdAt: new Date(row.createdAt).toISOString() });

  // Newest first. ?kind=page|content|baybay, ?before=<createdAt of the last row seen>, ?limit=1..200.
  app.get('/api/admin/feedback', authenticateToken, admin, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (limited(req, 'admin', 60)) return res.status(429).json({ error: '操作太频繁，请稍后再试。' });
    const query = req.query, filter = {};
    const before = typeof query.before === 'string' ? Date.parse(query.before) : NaN;
    const limit = query.limit === undefined ? ADMIN_PAGE : Number(query.limit);
    if (Object.keys(query).some(key => !['kind', 'before', 'limit'].includes(key))
      || (query.kind !== undefined && !FEEDBACK_KINDS.includes(query.kind))
      || (query.before !== undefined && !Number.isFinite(before))
      || !Number.isInteger(limit) || limit < 1 || limit > ADMIN_PAGE_MAX) return res.status(400).json({ error: '筛选条件无效。' });
    if (query.kind) filter.kind = query.kind;
    if (query.before !== undefined) filter.createdAt = { $lt: new Date(before) };
    try {
      const rows = await Feedback.find(filter).select(PUBLIC_FIELDS).sort({ createdAt: -1 }).limit(limit + 1).lean();
      const items = rows.slice(0, limit).map(publicRow);
      res.json({ items, ...(rows.length > limit ? { nextBefore: items.at(-1).createdAt } : {}), retentionDays: RETENTION_DAYS });
    } catch { res.status(503).json({ error: '反馈暂不可用，请稍后重试。' }); }
  });

  // Removes one entry, e.g. spam, or a reader asking to delete what they sent.
  app.delete('/api/admin/feedback/:id', authenticateToken, admin, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (limited(req, 'admin', 60)) return res.status(429).json({ error: '操作太频繁，请稍后再试。' });
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: '反馈编号无效。' });
    try {
      const result = await Feedback.deleteOne({ _id: req.params.id });
      if (!result.deletedCount) return res.status(404).json({ error: '反馈不存在或已过期。' });
      res.json({ ok: true });
    } catch { res.status(503).json({ error: '暂时无法删除，请稍后重试。' }); }
  });

  return { models: { Feedback, FeedbackQuota } };
}

module.exports = { FEEDBACK_KINDS, FEEDBACK_REASONS, ENTITY_KINDS, READING_SIZES, RETENTION_DAYS, VISITOR_DAILY_LIMIT, GLOBAL_DAILY_LIMIT, MAX_TEXT, MAX_CONTACT, normalizeFeedback, createFeedbackModels, registerFeedback };
