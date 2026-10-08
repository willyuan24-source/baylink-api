const { bayAreaDate } = require('./eventEngagement');
const { createRateLimiter } = require('./rateLimit');
const { ROUTE_TEMPLATES, routeTemplate } = require('./routeTemplates');

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
  // BayBay answer latency buckets (<3 s, 3-8 s, 8-15 s, >15 s) and the feedback sheet funnel.
  ...['lt3', '3to8', '8to15', 'gt15'].map(value => `baybay_latency_${value}`),
  'feedback_open', 'feedback_sent',
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
// Ingestion keeps its own in-memory limiter. Its day-long per-visitor keys used to
// share the 20,000-key auth limiter, where a full table rejects new login keys.
const INGEST_LIMITER_CAPACITY = 50000;
// Cap on per-day route rows (day x event x route) in the admin report; 30-day route totals are never capped.
const REPORT_ROUTE_DAILY = 20000;
const calendarDay = (day, offset) => new Date(Date.parse(`${day}T12:00:00Z`) + offset * DAY_MS).toISOString().slice(0, 10);
const emptyCounts = () => Object.fromEntries(PRODUCT_EVENTS.map(event => [event, 0]));
const expiryFor = day => new Date(`${calendarDay(day, RETENTION_DAYS)}T00:00:00Z`);

/** One atomic increment of a deterministic aggregate bucket; retries only a unique-key insertion race. */
async function bump(Model, key, _id) {
  try {
    await Model.updateOne(key, { $inc: { count: 1 }, $setOnInsert: { _id, ...key, expiresAt: expiryFor(key.day) } }, { upsert: true, setDefaultsOnInsert: false, runValidators: true });
  } catch (error) {
    if (error.code !== 11000) throw error;
    // An uncertain/network write is not retried, because it might already have incremented the bucket.
    const recovered = await Model.updateOne(key, { $inc: { count: 1 } }, { runValidators: true });
    if (!recovered.matchedCount) throw new Error('Metric bucket is unavailable');
  }
}

/** Internal aggregate counters accept no user identifiers, URLs or message content. */
async function recordServerProductEvent(ProductMetric, event, locale = 'zh-Hans', timestamp = Date.now()) {
  if (!SERVER_EVENTS.includes(event)) throw new Error('Unsupported internal metric');
  const key = { day: bayAreaDate(timestamp), event, locale: PRODUCT_LOCALES.includes(locale) ? locale : 'zh-Hans' };
  await bump(ProductMetric, key, `${key.day}:${key.event}:${key.locale}`);
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

/**
 * Route-template breakdown of the same counts, in its own collection so the
 * existing unique {day, event, locale} index needs no production migration.
 * Payloads without a route are counted only in ProductMetric.
 */
function createProductRouteMetricModel(mongoose, injected = {}) {
  if (injected.ProductRouteMetric) return injected.ProductRouteMetric;
  const schema = new mongoose.Schema({
    _id: { type: String, required: true },
    day: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    event: { type: String, required: true, enum: PRODUCT_EVENTS },
    locale: { type: String, required: true, enum: PRODUCT_LOCALES },
    route: { type: String, required: true, enum: ROUTE_TEMPLATES },
    count: { type: Number, required: true, min: 0 },
    expiresAt: { type: Date, required: true },
  }, { strict: 'throw', versionKey: false });
  schema.index({ day: 1, event: 1, locale: 1, route: 1 }, { unique: true });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.ProductRouteMetric || mongoose.model('ProductRouteMetric', schema);
}

function registerProductMetrics(app, { ProductMetric, ProductRouteMetric, authenticateToken, requireAdmin, checkRateLimit, getClientIp, now = Date.now, limiter = createRateLimiter({ capacity: INGEST_LIMITER_CAPACITY }) }) {
  const unavailable = res => res.status(503).json({ ok: false, error: '统计暂不可用，请稍后重试。' });
  const limit = (kind, maxRequests, check = checkRateLimit) => (req, res, next) => {
    // The visitor key is used solely in short-lived in-memory abuse limiters.
    // It is never passed into the model, response or application logs here.
    if (!check(`product-metrics-${kind}:${getClientIp(req)}`, { windowMs: 60000, maxRequests })) return res.status(429).json({ ok: false, error: '操作太频繁，请稍后再试。' });
    next();
  };
  const admin = (req, res, next) => req.user?.role === 'admin' ? requireAdmin(req, res, next) : res.status(403).json({ error: '仅管理员可访问产品统计。' });

  const ingest = limiter.check;

  app.post('/api/product-events', limit('write', 60, ingest), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (req.headers.dnt === '1' || req.headers['sec-gpc'] === '1') return res.json({ ok: true, skipped: true });
    if (!ingest(`product-metrics-day:${getClientIp(req)}`, { windowMs: 86400000, maxRequests: 300 })) return res.status(429).json({ ok: false, error: '统计已达今日上限。' });
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['event', 'locale', 'route'].includes(key))
      || !PRODUCT_EVENTS.includes(body.event)
      || SERVER_EVENTS.includes(body.event)
      || (body.locale !== undefined && !PRODUCT_LOCALES.includes(body.locale))
      // route is optional; a string outside the allowlist is counted as 'other', never stored raw.
      || (body.route !== undefined && routeTemplate(body.route) === null)) return res.status(400).json({ ok: false, error: '统计事件格式无效。' });
    const key = { day: bayAreaDate(now()), event: body.event, locale: body.locale || 'zh-Hans' };
    try {
      await bump(ProductMetric, key, `${key.day}:${key.event}:${key.locale}`);
      if (body.route !== undefined) {
        const routeKey = { ...key, route: routeTemplate(body.route) };
        await bump(ProductRouteMetric, routeKey, `${key.day}:${key.event}:${key.locale}:${routeKey.route}`);
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
      res.json({ days: 30, from, through, counts, daily, ...await routeReport(from, through) });
    } catch { unavailable(res); }
  });

  // The route breakdown is secondary: if it cannot be read, totals still answer.
  // Both parts are grouped in Mongo (locales combined), so every stored row of the window counts.
  async function routeReport(from, through) {
    const window = { $match: { day: { $gte: from, $lte: through }, event: { $in: PRODUCT_EVENTS }, route: { $in: ROUTE_TEMPLATES }, count: { $gte: 0 } } };
    try {
      const [totals, daily] = await Promise.all([
        // At most one row per allowlisted event and route template, so it needs no cap.
        ProductRouteMetric.aggregate([window, { $group: { _id: { event: '$event', route: '$route' }, count: { $sum: '$count' } } }]),
        // Newest days first, so when the cap is reached it is the oldest days that are left out.
        ProductRouteMetric.aggregate([window, { $group: { _id: { day: '$day', event: '$event', route: '$route' }, count: { $sum: '$count' } } },
          { $sort: { '_id.day': -1, '_id.event': 1, '_id.route': 1 } }, { $limit: REPORT_ROUTE_DAILY + 1 }]),
      ]);
      const routes = totals.map(({ _id, count }) => ({ event: _id.event, route: _id.route, count }))
        .sort((a, b) => a.event.localeCompare(b.event) || b.count - a.count || a.route.localeCompare(b.route));
      const routeDaily = daily.slice(0, REPORT_ROUTE_DAILY).map(({ _id, count }) => ({ day: _id.day, event: _id.event, route: _id.route, count }))
        .sort((a, b) => a.day.localeCompare(b.day) || a.event.localeCompare(b.event) || a.route.localeCompare(b.route));
      return { routes, routeDaily, routesTruncated: daily.length > REPORT_ROUTE_DAILY };
    } catch { return { routes: null, routeDaily: null, routesTruncated: false }; }
  }
}

module.exports = { PRODUCT_EVENTS, PRODUCT_LOCALES, SERVER_EVENTS, RETENTION_DAYS, REPORT_ROUTE_DAILY, createProductMetricModel, createProductRouteMetricModel, registerProductMetrics, recordServerProductEvent };
