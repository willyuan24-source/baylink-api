const crypto = require('node:crypto');
const { ID, REGIONS, TRAVEL, plain, validDate, text, fail, active, loadPlannerCatalog, recommend } = require('./planner');
const { bayAreaDate } = require('./eventEngagement');

const defaults = () => ({ regions: [], interests: [], travelMode: 'any' });
const emptyAccount = () => ({ preferences: defaults(), favorites: [], plans: [], revision: 0 });
const publicAccount = row => ({ preferences: row?.preferences || defaults(), favorites: row?.favorites || [], plans: row?.plans || [] });
const version = value => Number.isSafeInteger(value) && value >= 1 && value <= Number.MAX_SAFE_INTEGER - 1;
const favoriteKinds = ['event', 'place', 'guide'];

function createPlannerModel(mongoose, injected = {}) {
  if (injected.PlannerAccount) return injected.PlannerAccount;
  const schema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    preferences: { type: mongoose.Schema.Types.Mixed, default: defaults },
    favorites: { type: [mongoose.Schema.Types.Mixed], default: [] },
    plans: { type: [mongoose.Schema.Types.Mixed], default: [] },
    revision: { type: Number, required: true, default: 0 },
  });
  return mongoose.models.PlannerAccount || mongoose.model('PlannerAccount', schema);
}

function registerPlanner(app, { PlannerAccount, authenticateToken, checkRateLimit, getClientIp, catalog: suppliedCatalog, now = Date.now, config = {}, ai, isTest = false }) {
  const catalog = loadPlannerCatalog(suppliedCatalog);
  const rows = { event: new Map(catalog?.events.map(row => [row.id, row]) || []), place: new Map(catalog?.places.map(row => [row.id, row]) || []), guide: new Map(catalog?.guides.map(row => [row.slug, row]) || []) };
  const limit = (kind, maximum) => (req, res, next) => {
    if (!checkRateLimit(`planner-${kind}-ip:${getClientIp(req)}`, { windowMs: 60000, maxRequests: maximum })
      || (req.user && !checkRateLimit(`planner-${kind}-user:${req.user.id}`, { windowMs: 60000, maxRequests: maximum }))) return res.status(429).json({ error: '操作太频繁，请稍后再试。' });
    next();
  };
  const requireCatalog = () => { if (!catalog) throw fail('行程资料暂不可用，请稍后重试。', 503); };
  const handler = fn => async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try { await fn(req, res); }
    catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : '暂时无法保存或读取计划，请稍后重试。' }); }
  };
  // Updates replace one bounded private document under a compare-and-swap revision.
  // Retrying always rereads the winner: separate devices cannot overwrite one another's favorites or plans.
  const mutate = async (userId, transform) => {
    try { await PlannerAccount.updateOne({ userId }, { $setOnInsert: { userId, ...emptyAccount() } }, { upsert: true, runValidators: true }); }
    catch (error) { if (error.code !== 11000) throw error; }
    for (let attempt = 0; attempt < 5; attempt++) {
      const current = await PlannerAccount.findOne({ userId }).lean();
      if (!current) throw fail('暂时无法读取账号计划。', 503);
      const account = { ...emptyAccount(), ...current, preferences: { ...defaults(), ...current.preferences } };
      const result = transform(account);
      const saved = await PlannerAccount.findOneAndUpdate({ userId, revision: account.revision }, {
        $set: { preferences: account.preferences, favorites: account.favorites, plans: account.plans }, $inc: { revision: 1 },
      }, { new: true, runValidators: true });
      if (saved) return result;
    }
    throw fail('另一台设备刚刚修改了资料，请刷新后重试。', 409);
  };
  const lookup = (kind, id) => {
    requireCatalog();
    if (!favoriteKinds.includes(kind) || typeof id !== 'string' || !ID.test(id)) throw fail('收藏项目格式无效。');
    const row = rows[kind].get(id);
    if (!row) throw fail('这个项目尚未发布或已下架。', 404);
    return row;
  };
  const planBody = (body, updating = false) => {
    requireCatalog();
    const allowed = ['title', 'date', 'stops', ...(updating ? ['version'] : [])];
    if (!plain(body) || Object.keys(body).some(key => !allowed.includes(key)) || !text(body.title, 80) || body.title.trim().length < 1
      || !validDate(body.date) || !Array.isArray(body.stops) || !body.stops.length || body.stops.length > 6 || (updating && !version(body.version))) throw fail('计划需要名称、有效日期及 1–6 个地点。');
    if (body.date < bayAreaDate(now())) throw fail('请选择今天或未来日期。');
    const seen = new Set();
    for (const stop of body.stops) {
      if (!plain(stop) || Object.keys(stop).some(key => !['kind', 'id'].includes(key)) || !['event', 'place'].includes(stop.kind)) throw fail('计划地点格式无效。');
      const row = lookup(stop.kind, stop.id);
      const key = `${stop.kind}:${stop.id}`;
      if (seen.has(key)) throw fail('计划中不能重复添加同一地点。');
      seen.add(key);
      if (!active(row)) throw fail('这个活动或地点已暂停。', 410);
      if (stop.kind === 'event' && (row.startDate > body.date || row.endDate < body.date)) throw fail('活动日期与计划日期不一致。');
    }
    return { title: body.title.trim(), date: body.date, stops: body.stops.map(({ kind, id }) => ({ kind, id })) };
  };

  app.post('/api/planner/recommend', limit('recommend', 15), handler(async (req, res) => {
    requireCatalog();
    res.json(await recommend({ body: req.body, catalog, now, config, ai, isTest }));
  }));
  app.get('/api/planner/me', authenticateToken, limit('read', 120), handler(async (req, res) => {
    res.json(publicAccount(await PlannerAccount.findOne({ userId: req.user.id }).lean()));
  }));
  app.patch('/api/planner/preferences', authenticateToken, limit('write', 60), handler(async (req, res) => {
    const body = req.body;
    if (!plain(body) || Object.keys(body).some(key => !['regions', 'interests', 'travelMode'].includes(key)) || !Object.keys(body).length) throw fail('偏好格式无效。');
    if (body.regions !== undefined && (!Array.isArray(body.regions) || body.regions.length > 5 || body.regions.some(value => !REGIONS.includes(value)))) throw fail('地区偏好无效。');
    if (body.interests !== undefined && (!Array.isArray(body.interests) || body.interests.length > 12 || body.interests.some(value => !text(value, 40) || !value.trim()))) throw fail('兴趣最多 12 项，每项最多 40 字。');
    if (body.travelMode !== undefined && !TRAVEL.includes(body.travelMode)) throw fail('出行方式无效。');
    const patch = { ...body, ...(body.regions ? { regions: [...new Set(body.regions)] } : {}), ...(body.interests ? { interests: [...new Set(body.interests.map(value => value.trim()))] } : {}) };
    const preferences = await mutate(req.user.id, account => account.preferences = { ...account.preferences, ...patch });
    res.json({ preferences });
  }));
  app.put('/api/planner/favorites/:kind/:id', authenticateToken, limit('write', 60), handler(async (req, res) => {
    if (req.body && (!plain(req.body) || Object.keys(req.body).length)) throw fail('收藏请求格式无效。');
    const { kind, id } = req.params;
    lookup(kind, id);
    const favorites = await mutate(req.user.id, account => {
      if (!account.favorites.some(row => row.kind === kind && row.id === id)) {
        if (account.favorites.length >= 150) throw fail('收藏最多 150 项，请先移除一些。');
        account.favorites.push({ kind, id });
      }
      return account.favorites;
    });
    res.json({ favorites });
  }));
  app.delete('/api/planner/favorites/:kind/:id', authenticateToken, limit('write', 60), handler(async (req, res) => {
    if (req.body && (!plain(req.body) || Object.keys(req.body).length)) throw fail('收藏请求格式无效。');
    const { kind, id } = req.params;
    // Removing retired content remains possible after a catalog refresh.
    if (!favoriteKinds.includes(kind) || !ID.test(id)) throw fail('收藏项目格式无效。');
    const favorites = await mutate(req.user.id, account => account.favorites = account.favorites.filter(row => row.kind !== kind || row.id !== id));
    res.json({ favorites });
  }));
  app.post('/api/planner/plans', authenticateToken, limit('write', 60), handler(async (req, res) => {
    const value = planBody(req.body);
    const timestamp = new Date(now()).toISOString();
    const plan = { id: crypto.randomUUID(), ...value, version: 1, createdAt: timestamp, updatedAt: timestamp };
    await mutate(req.user.id, account => {
      if (account.plans.length >= 30) throw fail('最多保存 30 个计划，请先移除一些。');
      account.plans.push(plan);
    });
    res.status(201).json({ plan });
  }));
  app.put('/api/planner/plans/:id', authenticateToken, limit('write', 60), handler(async (req, res) => {
    if (!ID.test(req.params.id)) throw fail('计划编号无效。');
    const value = planBody(req.body, true);
    const plan = await mutate(req.user.id, account => {
      const index = account.plans.findIndex(row => row.id === req.params.id);
      if (index < 0) throw fail('计划不存在。', 404);
      const previous = account.plans[index];
      if (previous.version !== req.body.version) throw fail('另一台设备已修改此计划，请刷新后重试。', 409);
      const next = { ...previous, ...value, version: previous.version + 1, updatedAt: new Date(now()).toISOString() };
      account.plans[index] = next;
      return next;
    });
    res.json({ plan });
  }));
  app.delete('/api/planner/plans/:id', authenticateToken, limit('write', 60), handler(async (req, res) => {
    if (!ID.test(req.params.id) || !plain(req.body) || Object.keys(req.body).some(key => key !== 'version') || !version(req.body.version)) throw fail('请提供计划的当前版本。');
    await mutate(req.user.id, account => {
      const previous = account.plans.find(row => row.id === req.params.id);
      if (!previous) throw fail('计划不存在。', 404);
      if (previous.version !== req.body.version) throw fail('另一台设备已修改此计划，请刷新后重试。', 409);
      account.plans = account.plans.filter(row => row.id !== req.params.id);
    });
    res.json({ ok: true });
  }));
  return { catalog };
}

module.exports = { createPlannerModel, registerPlanner };
