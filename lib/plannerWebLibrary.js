const { safeUrl } = require('./plannerWebSearch');
const { plain, validDate, fail } = require('./planner');
const LIMITS = { id: 100, name: 160, city: 100, summary: 700, timeSummary: 500, priceSummary: 500 };
const FIELDS = [...Object.keys(LIMITS), 'sourceUrls', 'checkedAt', 'requestedDate'];
const timestamp = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value) && validDate(value.slice(0, 10)) && Number.isFinite(Date.parse(value));

function validateWebCandidates(values) {
  if (!Array.isArray(values) || values.length > 20) throw fail('最多保存 20 个站外候选。');
  const seen = new Set();
  return values.map(value => {
    if (!plain(value) || Object.keys(value).some(key => !FIELDS.includes(key))) throw fail('站外候选格式无效。');
    const result = {};
    for (const [key, limit] of Object.entries(LIMITS)) {
      if (value[key] === null && !['id', 'name'].includes(key)) { result[key] = null; continue; }
      if (typeof value[key] !== 'string' || !value[key].trim() || value[key].length > limit || /[\u0000-\u001f\u007f]/.test(value[key])) throw fail('站外候选文字无效。');
      result[key] = value[key].trim();
    }
    if (!/^[A-Za-z0-9_-]+$/.test(result.id) || seen.has(result.id)) throw fail('站外候选编号重复或无效。');
    seen.add(result.id);
    if (!Array.isArray(value.sourceUrls) || !value.sourceUrls.length || value.sourceUrls.length > 5 || value.sourceUrls.some(url => !safeUrl(url))) throw fail('站外候选需要有效的公开网页来源。');
    result.sourceUrls = [...new Set(value.sourceUrls.map(safeUrl))];
    if (value.checkedAt !== null && !timestamp(value.checkedAt)) throw fail('资料查询时间无效。');
    if (value.requestedDate !== null && !validDate(value.requestedDate)) throw fail('候选日期无效。');
    // These are private user-kept references, never published catalog facts.
    return { ...result, checkedAt: value.checkedAt, requestedDate: value.requestedDate };
  });
}

function registerPlannerWebLibrary(app, { PlannerAccount, authenticateToken, limit, handler, emptyAccount }) {
  app.get('/api/planner/web-candidates', authenticateToken, limit('read', 120), handler(async (req, res) => {
    const row = await PlannerAccount.findOne({ userId: req.user.id }).lean();
    res.json({ candidates: row?.webCandidates || [], revision: row?.webCandidatesRevision || 0 });
  }));
  app.put('/api/planner/web-candidates', authenticateToken, limit('write', 60), handler(async (req, res) => {
    const body = req.body;
    if (!plain(body) || Object.keys(body).some(key => !['candidates', 'revision'].includes(key)) || !Number.isSafeInteger(body.revision) || body.revision < 0 || body.revision >= Number.MAX_SAFE_INTEGER) throw fail('候选版本无效，请重新读取。');
    const candidates = validateWebCandidates(body.candidates);
    try { await PlannerAccount.updateOne({ userId: req.user.id }, { $setOnInsert: { userId: req.user.id, ...emptyAccount() } }, { upsert: true, runValidators: true }); }
    catch (error) { if (error.code !== 11000) throw error; }
    const query = { userId: req.user.id, ...(body.revision === 0 ? { $or: [{ webCandidatesRevision: 0 }, { webCandidatesRevision: { $exists: false } }] } : { webCandidatesRevision: body.revision }) };
    const saved = await PlannerAccount.findOneAndUpdate(query, { $set: { webCandidates: candidates }, $inc: { webCandidatesRevision: 1 } }, { new: true, runValidators: true });
    if (!saved) throw fail('另一台设备已修改候选，请重新读取后再保存。', 409);
    res.json({ candidates: saved.webCandidates, revision: saved.webCandidatesRevision });
  }));
}
module.exports = { validateWebCandidates, registerPlannerWebLibrary };
