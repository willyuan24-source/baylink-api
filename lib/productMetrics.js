const { bayAreaDate } = require('./eventEngagement');

const PRODUCT_EVENTS = Object.freeze([
  'planner_recommendation', 'plan_saved', 'plan_shared',
  'planner_outing_adopted', 'planner_edit_applied', 'planner_web_search',
  'official_source_click', 'favorite_saved', 'planner_map_opened',
  'nav_click', 'home_module_click', 'search_submitted', 'search_zero_result',
  'event_detail_open', 'ics_download', 'share_card_download', 'baybay_ask',
  'baybay_degraded', 'baybay_fast', 'baybay_slow', 'baybay_helpful', 'baybay_unhelpful',
  'signup_gate', 'contact_click', 'message_first_sent', 'site_arrival_from_card',
  'site_arrival_from_opus', 'client_error', 'newsletter_signup',
  'page_view', 'site_source_direct', 'site_source_search', 'site_source_wechat',
  'site_source_social', 'site_source_card', 'site_source_opus', 'site_source_other',
  'message_request_started', 'owner_reply_24h', 'signup_completed',
  'opus_title', 'opus_first_card', 'opus_visit_new',
  ...['home', 'nav', 'play', 'photo', 'family', 'share', 'guide', 'promo', 'direct'].map(value => `opus_start_${value}`),
  ...['lt10', '10to30', 'gt30'].map(value => `opus_cold_start_${value}`),
  ...['tour', 'week', 'free', 'local', 'resume'].map(value => `opus_mode_${value}`),
  ...['plan', 'official', 'maps', 'guide', 'offer', 'ics', 'event', 'wish'].map(value => `opus_real_action_${value}`),
  ...['photo', 'card'].map(value => `opus_share_${value}`),
  ...['1d', '7d', '30d'].map(value => `opus_returning_${value}`),
  ...['ch1', 'ch2', 'ch3', 'ch4', 'ch5', 'done'].map(value => `opus_tour_${value}`),
]);
const PRODUCT_LOCALES = Object.freeze(['zh-Hans', 'zh-Hant', 'en']);
const SERVER_EVENTS = Object.freeze(['message_request_started', 'owner_reply_24h', 'signup_completed']);
const RETENTION_DAYS = 180;
const DAY_MS = 86400000;
const calendarDay = (day, offset) => new Date(Date.parse(`${day}T12:00:00Z`) + offset * DAY_MS).toISOString().slice(0, 10);
const emptyCounts = () => Object.fromEntries(PRODUCT_EVENTS.map(event => [event, 0]));

/** Internal aggregate counters accept no user identifiers, URLs or message content. */
async function recordServerProductEvent(ProductMetric, event, locale = 'zh-Hans', timestamp = Date.now()) {
  if (!SERVER_EVENTS.includes(event)) throw new Error('Unsupported internal metric');
  const key = { day: bayAreaDate(timestamp), event, locale: PRODUCT_LOCALES.includes(locale) ? locale : 'zh-Hans' };
  const expiresAt = new Date(`${calendarDay(key.day, RETENTION_DAYS)}T00:00:00Z`);
  try {
    await ProductMetric.updateOne(key, { $inc: { count: 1 }, $setOnInsert: { _id: `${key.day}:${key.event}:${key.locale}`, ...key, expiresAt } }, { upsert: true, setDefaultsOnInsert: false, runValidators: true });
  } catch (error) {
    if (error.code !== 11000) throw error;
    const recovered = await ProductMetric.updateOne(key, { $inc: { count: 1 } }, { runValidators: true });
    if (!recovered.matchedCount) throw new Error('Metric bucket is unavailable');
  }
}

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
    if (req.headers.dnt === '1' || req.headers['sec-gpc'] === '1') return res.json({ ok: true, skipped: true });
    if (!checkRateLimit(`product-metrics-day:${getClientIp(req)}`, { windowMs: 86400000, maxRequests: 300 })) return res.status(429).json({ ok: false, error: '统计已达今日上限。' });
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['event', 'locale'].includes(key))
      || !PRODUCT_EVENTS.includes(body.event)
      || SERVER_EVENTS.includes(body.event)
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

module.exports = { PRODUCT_EVENTS, PRODUCT_LOCALES, SERVER_EVENTS, RETENTION_DAYS, createProductMetricModel, registerProductMetrics, recordServerProductEvent };
