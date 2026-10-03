const { plain, fail, loadPlannerCatalog, active } = require('./planner');
const { localInstant } = require('./serviceBookings');
const { canonicalEventId } = require('./eventId');

const MODES = { drive: 'DRIVE', walk: 'WALK', transit: 'TRANSIT' };
const ENDPOINT = 'https://routes.googleapis.com/directions/v2:computeRoutes';
function travelInput(body, catalog, now = Date.now()) {
  if (!plain(body) || Object.keys(body).some(key => !['from', 'to', 'date', 'time', 'travelMode', 'locale'].includes(key)) || !Object.hasOwn(MODES, body.travelMode)) throw fail('请选择两个已收录地点和出行方式。');
  if (body.locale !== undefined && !['zh-Hans', 'zh-Hant', 'en'].includes(body.locale)) throw fail('语言无效。');
  if (!catalog) throw fail('地点资料暂不可用。', 503);
  const resolve = stop => {
    if (!plain(stop) || Object.keys(stop).some(key => !['kind', 'id'].includes(key)) || !['event', 'place'].includes(stop.kind) || typeof stop.id !== 'string') throw fail('地点格式无效。');
    const row = catalog[stop.kind === 'event' ? 'events' : 'places'].find(row => row.id === (stop.kind === 'event' ? canonicalEventId(stop.id) : stop.id));
    const p = row?.location;
    if (!row || !active(row) || !p || p.precision !== 'venue' || !Number.isFinite(p.lat) || !Number.isFinite(p.lng) || p.lat < 36 || p.lat > 40 || p.lng < -124 || p.lng > -120) throw fail('此站尚无准确地点，请在地图中核对入口。', 422);
    return { kind: stop.kind, id: row.id, title: row.title, location: { lat: p.lat, lng: p.lng } };
  };
  const from = resolve(body.from), to = resolve(body.to);
  if (from.kind === to.kind && from.id === to.id) throw fail('请选择不同的出发地和目的地。');
  const at = localInstant(body.date, body.time);
  if (at < now || at > now + 100 * 86400000) throw fail('路线查询支持未来 100 天内的出发时间；过去的时间请重新选择。');
  return { from, to, departureAt: new Date(at).toISOString(), travelMode: body.travelMode, locale: body.locale || 'zh-Hans' };
}

async function computeTravel(input, { apiKey, fetchImpl = fetch, signal }) {
  const waypoint = stop => ({ location: { latLng: { latitude: stop.location.lat, longitude: stop.location.lng } } });
  const response = await fetchImpl(ENDPOINT, { method: 'POST', signal,
    headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'routes.duration,routes.distanceMeters,routes.warnings' },
    body: JSON.stringify({ origin: waypoint(input.from), destination: waypoint(input.to), travelMode: MODES[input.travelMode],
      departureTime: input.departureAt, ...(input.travelMode === 'drive' ? { routingPreference: 'TRAFFIC_AWARE' } : {}),
      languageCode: input.locale === 'en' ? 'en-US' : input.locale === 'zh-Hant' ? 'zh-TW' : 'zh-CN', units: 'IMPERIAL', computeAlternativeRoutes: false }) });
  if (!response.ok) throw fail('路程查询暂不可用，请打开地图核对。', 503);
  return response.json();
}

// The deadline covers both response headers and JSON consumption. Some injected
// transports or stalled body streams can ignore abort, so abort alone is not enough.
async function travelWithDeadline(execute, timeoutMs = 10000) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => execute(controller.signal)),
      new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(fail('路线查询超时，请打开地图核对。', 503)); }, timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}

function travelResult(raw, input, now) {
  const route = raw?.routes?.[0], match = /^(\d+(?:\.\d+)?)s$/.exec(route?.duration || '');
  const seconds = match ? Number(match[1]) : NaN;
  if (!Number.isFinite(seconds) || seconds < 1 || seconds > 86400 || !Number.isFinite(route.distanceMeters) || route.distanceMeters < 0 || route.distanceMeters > 1000000) throw fail('没有取得可用路线，请在地图中核对。', 503);
  return { ok: true, provider: 'google-maps', from: { kind: input.from.kind, id: input.from.id }, to: { kind: input.to.kind, id: input.to.id },
    travelMode: input.travelMode, departureAt: input.departureAt, checkedAt: new Date(now).toISOString(), durationMinutes: Math.ceil(seconds / 60), distanceMeters: route.distanceMeters,
    warnings: Array.isArray(route.warnings) ? route.warnings.filter(x => typeof x === 'string').slice(0, 5).map(x => x.slice(0, 1500)) : [] };
}

/** On-demand text estimates only: no polylines, caching, itinerary writes or billing without explicit enablement. */
function registerPlannerTravel(app, { config = {}, Quota, checkRateLimit, catalog: supplied, now = Date.now, fetchImpl, compute, isTest = false }) {
  const catalog = loadPlannerCatalog(supplied);
  const enabled = (isTest && typeof compute === 'function') || (!isTest && config.PLANNER_TRAVEL_ENABLED === 'true' && !!config.GOOGLE_ROUTES_API_KEY);
  const dailyLimit = /^\d+$/.test(String(config.PLANNER_TRAVEL_DAILY_LIMIT)) ? Math.min(10000, Number(config.PLANNER_TRAVEL_DAILY_LIMIT)) : 100;
  const available = !!(enabled && Quota && dailyLimit > 0);
  app.get('/api/planner/travel-capabilities', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ available });
  });
  app.post('/api/planner/travel-estimate', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const input = travelInput(req.body, catalog, now());
      if (!available) throw fail('站内路程查询尚未启用，请通过地图核对交通时间。', 503);
      const ip = req.ip || req.socket?.remoteAddress || 'unknown';
      if (!checkRateLimit(`planner-travel-minute:${ip}`, { windowMs: 60000, maxRequests: 5 }) || !checkRateLimit(`planner-travel-day:${ip}`, { windowMs: 86400000, maxRequests: 20 })) throw fail('查询太频繁，请稍后再试。', 429);
      const id = `planner-travel:${new Date(now()).toISOString().slice(0, 10)}`;
      try { await Quota.updateOne({ id }, { $setOnInsert: { id, count: 0, expiresAt: new Date(now() + 3 * 86400000) } }, { upsert: true }); }
      catch (error) { if (error.code !== 11000) throw error; }
      if (!await Quota.findOneAndUpdate({ id, count: { $lt: dailyLimit } }, { $inc: { count: 1 } }, { new: true })) throw fail('今天的路线查询额度已用完，请打开地图核对。', 429);
      const raw = await travelWithDeadline(signal => isTest && compute ? compute(input) : computeTravel(input, { apiKey: config.GOOGLE_ROUTES_API_KEY, fetchImpl, signal }));
      res.json(travelResult(raw, input, now()));
    } catch (error) { res.status(error.status || 503).json({ ok: false, error: error.status ? error.message : '路程查询暂不可用，请打开地图核对。' }); }
  });
}
module.exports = { travelInput, travelResult, computeTravel, travelWithDeadline, registerPlannerTravel };
