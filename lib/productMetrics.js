const { bayAreaDate } = require('./eventEngagement');

const PRODUCT_EVENTS = Object.freeze([
  'planner_recommendation', 'plan_saved', 'plan_shared',
  'official_source_click', 'favorite_saved', 'planner_map_opened',
]);
const PRODUCT_LOCALES = Object.freeze(['zh-Hans', 'zh-Hant', 'en']);
const RETENTION_DAYS = 180;
const DAY_MS = 86400000;
const calendarDay = (day, offset) => new Date(Date.parse(`${day}T12:00:00Z`) + offset * DAY_MS).toISOString().slice(0, 10);
const emptyCounts = () => Object.fromEntries(PRODUCT_EVENTS.map(event => [event, 0]));

function createProductMetricModel(mongoose, injected = {}) {
  if (injected.ProductMetric) return injected.ProductMetric;
  const schema = new mongoose.Schema({
    // A deterministic aggregate key also avoids the first-action timestamp
    // that a default Mongo ObjectId would encode.
    _id: { type: String, required: true },
    day: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    event: { type: String, required: true, enum: PRODUCT_EVENTS },
    locale: { type: String, required: true, enum: PRODUCT_LOCALES },
    count: { type: Number, required: true, min: 0 },
    // One expiration timestamp per day bucket, never an individual action time.
    expiresAt: { type: Date, required: true },
  }, { strict: 'throw', versionKey: false });
  schema.index({ day: 1, event: 1, locale: 1 }, { unique: true });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.ProductMetric || mongoose.model('ProductMetric', schema);
}

function registerProductMetrics(app, { ProductMetric, authenticateToken, requireAdmin, checkRateLimit, getClientIp, now = Date.now }) {
  const unavailable = res => res.status(503).json({ ok: false, error: '统计暂不可用，请稍后重试。' });
  const limit = (kind, maxRequests) => (req, res, next) => {
    // IP is used solely in the existing short-lived in-memory abuse limiter.
    // It is never passed into the model, response or application logs here.
    if (!checkRateLimit(`product-metrics-${kind}:${getClientIp(req)}`, { windowMs: 60000, maxRequests })) return res.status(429).json({ ok: false, error: '操作太频繁，请稍后再试。' });
    next();
  };
  const admin = (req, res, next) => req.user?.role === 'admin' ? requireAdmin(req, res, next) : res.status(403).json({ error: '仅管理员可访问产品统计。' });

  app.post('/api/product-events', limit('write', 60), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['event', 'locale'].includes(key))
      || !PRODUCT_EVENTS.includes(body.event)
      || (body.locale !== undefined && !PRODUCT_LOCALES.includes(body.locale))) return res.status(400).json({ ok: false, error: '统计事件格式无效。' });
    const key = { day: bayAreaDate(now()), event: body.event, locale: body.locale || 'zh-Hans' };
    const expiresAt = new Date(`${calendarDay(key.day, RETENTION_DAYS)}T00:00:00Z`);
    try {
      try {
        await ProductMetric.updateOne(key, { $inc: { count: 1 }, $setOnInsert: { _id: `${key.day}:${key.event}:${key.locale}`, ...key, expiresAt } }, { upsert: true, setDefaultsOnInsert: false, runValidators: true });
      } catch (error) {
        if (error.code !== 11000) throw error;
        // Only retry a unique-key insertion race. An uncertain/network write
        // is not retried, because it might already have incremented the bucket.
        const recovered = await ProductMetric.updateOne(key, { $inc: { count: 1 } }, { runValidators: true });
        if (recovered.matchedCount === 0) throw new Error('Metric bucket is unavailable');
      }
      res.json({ ok: true });
    } catch { unavailable(res); }
  });

  app.get('/api/admin/product-metrics', authenticateToken, admin, limit('read', 60), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query).length) return res.status(400).json({ error: '统计固定显示最近 30 天。' });
    const through = bayAreaDate(now());
    const from = calendarDay(through, -29);
    try {
      const rows = await ProductMetric.find({ day: { $gte: from, $lte: through } }).select('day event locale count -_id').sort({ day: 1, event: 1, locale: 1 }).limit(30 * PRODUCT_EVENTS.length * PRODUCT_LOCALES.length).lean();
      const daily = rows.filter(row => PRODUCT_EVENTS.includes(row.event) && PRODUCT_LOCALES.includes(row.locale) && Number.isSafeInteger(row.count) && row.count >= 0)
        .map(row => ({ day: row.day, event: row.event, locale: row.locale, count: row.count }));
      const counts = emptyCounts();
      for (const row of daily) counts[row.event] += row.count;
      res.json({ days: 30, from, through, counts, daily });
    } catch { unavailable(res); }
  });
}

module.exports = { PRODUCT_EVENTS, PRODUCT_LOCALES, RETENTION_DAYS, createProductMetricModel, registerProductMetrics };
