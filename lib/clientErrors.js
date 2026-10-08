const { bayAreaDate } = require('./eventEngagement');
const { createRateLimiter } = require('./rateLimit');
const { ROUTE_TEMPLATES, routeTemplate } = require('./routeTemplates');

// Browser error beacons as daily aggregates. A row is one Pacific day + kind +
// route template + release + fingerprint, with a count. The client sends a short
// hash of the error name and the first 60 characters of the message (digits and
// URLs stripped), never the message, stack, URL or anything typed by the reader.
const ERROR_KINDS = Object.freeze(['render', 'error', 'rejection', 'chunk']);
const RETENTION_DAYS = 30;
const DAY_MS = 86400000;
const FINGERPRINT = /^[a-z0-9]{6,16}$/;
const COMMIT = /^[0-9a-f]{7,40}$/i;
const RELEASE_LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/i;
// Bounded cardinality: after this many distinct buckets in one process and day,
// new combinations share one overflow bucket per kind and route.
const MAX_BUCKETS_PER_DAY = 2000;
const OVERFLOW = 'overflow';
const REPORT_ROWS = 20000;
const REPORT_GROUPS = 200;
const calendarDay = (day, offset) => new Date(Date.parse(`${day}T12:00:00Z`) + offset * DAY_MS).toISOString().slice(0, 10);

/** A commit becomes its first 12 hex digits; a short label stays; anything else is 'unknown'. */
function releaseLabel(value) {
  if (value === undefined) return 'unknown';
  if (typeof value !== 'string') return null;
  if (COMMIT.test(value)) return value.slice(0, 12).toLowerCase();
  return RELEASE_LABEL.test(value) ? value.toLowerCase() : 'unknown';
}

function createClientErrorMetricModel(mongoose, injected = {}) {
  if (injected.ClientErrorMetric) return injected.ClientErrorMetric;
  const schema = new mongoose.Schema({
    _id: { type: String, required: true },
    day: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    kind: { type: String, required: true, enum: ERROR_KINDS },
    route: { type: String, required: true, enum: ROUTE_TEMPLATES },
    release: { type: String, required: true, maxlength: 32 },
    fp: { type: String, required: true, match: /^(?:[a-z0-9]{6,16}|overflow)$/ },
    count: { type: Number, required: true, min: 0 },
    expiresAt: { type: Date, required: true },
  }, { strict: 'throw', versionKey: false });
  schema.index({ day: 1, kind: 1, route: 1, release: 1, fp: 1 }, { unique: true });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.ClientErrorMetric || mongoose.model('ClientErrorMetric', schema);
}

function registerClientErrors(app, { mongoose, models = {}, authenticateToken, requireAdmin, getClientIp, now = Date.now, limiter = createRateLimiter({ capacity: 20000 }) }) {
  const ClientErrorMetric = createClientErrorMetricModel(mongoose, models);
  const seen = { day: null, ids: new Set() };
  const unavailable = res => res.status(503).json({ ok: false, error: '统计暂不可用，请稍后重试。' });
  const limited = (req, kind, windowMs, maxRequests) => !limiter.check(`client-errors-${kind}:${getClientIp(req)}`, { windowMs, maxRequests });
  const admin = (req, res, next) => req.user?.role === 'admin' ? requireAdmin(req, res, next) : res.status(403).json({ error: '仅管理员可访问错误统计。' });

  /** The bucket to increment, folding new combinations into overflow once the day's cap is reached. */
  function bucket(key) {
    if (seen.day !== key.day) Object.assign(seen, { day: key.day, ids: new Set() });
    const id = `${key.day}:${key.kind}:${key.route}:${key.release}:${key.fp}`;
    if (seen.ids.has(id) || seen.ids.size < MAX_BUCKETS_PER_DAY) { seen.ids.add(id); return { _id: id, key }; }
    const overflow = { ...key, release: OVERFLOW, fp: OVERFLOW };
    return { _id: `${key.day}:${key.kind}:${key.route}:${OVERFLOW}:${OVERFLOW}`, key: overflow };
  }

  app.post('/api/client-errors', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (limited(req, 'minute', 60000, 30)) return res.status(429).json({ ok: false, error: '操作太频繁，请稍后再试。' });
    if (req.headers.dnt === '1' || req.headers['sec-gpc'] === '1') return res.json({ ok: true, skipped: true });
    if (limited(req, 'day', DAY_MS, 200)) return res.status(429).json({ ok: false, error: '统计已达今日上限。' });
    const body = req.body;
    const release = releaseLabel(body?.release);
    const route = body?.route === undefined ? 'other' : routeTemplate(body.route);
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['kind', 'route', 'release', 'fp'].includes(key))
      || !ERROR_KINDS.includes(body.kind) || typeof body.fp !== 'string' || !FINGERPRINT.test(body.fp)
      || route === null || release === null) return res.status(400).json({ ok: false, error: '错误统计格式无效。' });
    const day = bayAreaDate(now());
    const { _id, key } = bucket({ day, kind: body.kind, route, release, fp: body.fp });
    const expiresAt = new Date(`${calendarDay(day, RETENTION_DAYS)}T00:00:00Z`);
    try {
      try {
        await ClientErrorMetric.updateOne(key, { $inc: { count: 1 }, $setOnInsert: { _id, ...key, expiresAt } }, { upsert: true, setDefaultsOnInsert: false, runValidators: true });
      } catch (error) {
        if (error.code !== 11000) throw error;
        // Only a unique-key insertion race is retried; an uncertain write might already have counted.
        const recovered = await ClientErrorMetric.updateOne(key, { $inc: { count: 1 } }, { runValidators: true });
        if (!recovered.matchedCount) throw new Error('Error bucket is unavailable');
      }
      res.json({ ok: true });
    } catch { unavailable(res); }
  });

  app.get('/api/admin/client-errors', authenticateToken, admin, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (limited(req, 'admin', 60000, 60)) return res.status(429).json({ error: '操作太频繁，请稍后再试。' });
    if (Object.keys(req.query).length) return res.status(400).json({ error: '错误统计固定显示最近 30 天。' });
    const through = bayAreaDate(now());
    const from = calendarDay(through, -(RETENTION_DAYS - 1));
    try {
      const rows = await ClientErrorMetric.find({ day: { $gte: from, $lte: through } }).select('day kind route release fp count -_id').sort({ day: 1 }).limit(REPORT_ROWS).lean();
      const groups = new Map(), daily = new Map();
      for (const row of rows) {
        if (!ERROR_KINDS.includes(row.kind) || !ROUTE_TEMPLATES.includes(row.route) || !Number.isSafeInteger(row.count) || row.count < 0) continue;
        const id = [row.kind, row.route, row.release, row.fp].join('|');
        const group = groups.get(id) || { kind: row.kind, route: row.route, release: row.release, fp: row.fp, count: 0, firstDay: row.day, lastDay: row.day };
        group.count += row.count;
        if (row.day < group.firstDay) group.firstDay = row.day;
        if (row.day > group.lastDay) group.lastDay = row.day;
        groups.set(id, group);
        const dayKey = `${row.day}|${row.kind}`;
        daily.set(dayKey, (daily.get(dayKey) || 0) + row.count);
      }
      const ranked = [...groups.values()].sort((a, b) => b.count - a.count || b.lastDay.localeCompare(a.lastDay));
      res.json({ days: RETENTION_DAYS, from, through,
        total: ranked.reduce((sum, group) => sum + group.count, 0),
        groups: ranked.slice(0, REPORT_GROUPS), groupsTruncated: ranked.length > REPORT_GROUPS || rows.length >= REPORT_ROWS,
        daily: [...daily].map(([key, count]) => { const [day, kind] = key.split('|'); return { day, kind, count }; }).sort((a, b) => a.day.localeCompare(b.day) || a.kind.localeCompare(b.kind)) });
    } catch { res.status(503).json({ error: '错误统计暂不可用，请稍后重试。' }); }
  });

  return { models: { ClientErrorMetric } };
}

module.exports = { ERROR_KINDS, RETENTION_DAYS, MAX_BUCKETS_PER_DAY, releaseLabel, createClientErrorMetricModel, registerClientErrors };
