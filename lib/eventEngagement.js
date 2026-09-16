const fs = require('node:fs');
const path = require('node:path');

const EVENT_ID = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,119}$/;
const pacificDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit' });
const bayAreaDate = now => {
  const parts = pacificDate.formatToParts(new Date(now));
  return ['year', 'month', 'day'].map(type => parts.find(part => part.type === type).value).join('-');
};
const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)
  && Number.isFinite(Date.parse(`${value}T12:00:00Z`)) && new Date(`${value}T12:00:00Z`).toISOString().startsWith(value);

function loadEventCatalog(supplied) {
  try {
    const rows = supplied === undefined ? JSON.parse(fs.readFileSync(path.join(__dirname, '../data/event-catalog.json'), 'utf8')) : supplied;
    if (!Array.isArray(rows) || !rows.length || rows.length > 10000) return null;
    const catalog = new Map();
    for (const row of rows) {
      if (!row || typeof row.id !== 'string' || !EVENT_ID.test(row.id) || catalog.has(row.id)
        || typeof row.title !== 'string' || !row.title.trim() || !validDate(row.startDate) || !validDate(row.endDate) || row.startDate > row.endDate) return null;
      catalog.set(row.id, { id: row.id, startDate: row.startDate, endDate: row.endDate });
    }
    return catalog;
  } catch { return null; }
}

function registerEventEngagement(app, { EventInterest, User, UserBlock, authenticateToken, checkRateLimit, getClientIp, assertAccountCanPost, catalog: suppliedCatalog, now = Date.now }) {
  const catalog = loadEventCatalog(suppliedCatalog);
  const optionalAuth = (req, res, next) => req.headers.authorization === undefined ? next() : authenticateToken(req, res, next);
  const rateLimit = (mutation = false) => (req, res, next) => {
    const kind = mutation ? 'write' : 'read';
    const ipAllowed = checkRateLimit(`event-${kind}-ip:${getClientIp(req)}`, { windowMs: 60000, maxRequests: mutation ? 120 : 180 });
    const userAllowed = !req.user || checkRateLimit(`event-${kind}-user:${req.user.id}`, { windowMs: 60000, maxRequests: mutation ? 40 : 120 });
    if (!ipAllowed || !userAllowed) return res.status(429).json({ error: '操作太频繁，请稍后再试。' });
    next();
  };
  const requireEvent = (id, res) => {
    if (!catalog) { res.status(503).json({ error: '活动资料暂不可用，请稍后重试。' }); return null; }
    const event = typeof id === 'string' && EVENT_ID.test(id) && catalog.get(id);
    if (!event) { res.status(404).json({ error: '活动不存在。' }); return null; }
    return event;
  };
  const eligibleMembers = [
    { $lookup: { from: User.collection.name, localField: 'userId', foreignField: 'id', as: 'member' } },
    { $unwind: '$member' },
    { $match: { 'member.isBanned': { $ne: true }, 'member.accountStatus': { $nin: ['limited', 'suspended'] } } },
  ];
  const engagements = async (ids, userId) => {
    const [counts, own] = await Promise.all([
      EventInterest.aggregate([
        { $match: { eventId: { $in: ids }, interested: true } },
        ...eligibleMembers,
        // The unique index prevents new duplicates. Group by member as well so
        // legacy/imported rows can never inflate the public count.
        { $group: { _id: { eventId: '$eventId', userId: '$userId' }, buddy: { $max: { $cond: [{ $eq: ['$lookingForBuddy', true] }, 1, 0] } } } },
        { $group: { _id: '$_id.eventId', interestedCount: { $sum: 1 }, buddyCount: { $sum: '$buddy' } } },
      ]),
      userId ? EventInterest.find({ eventId: { $in: ids }, userId }).select('eventId interested lookingForBuddy').lean() : [],
    ]);
    const byEvent = new Map(counts.map(row => [row._id, row]));
    const mine = new Map(own.map(row => [row.eventId, row]));
    return ids.map(eventId => ({
      eventId, interestedCount: byEvent.get(eventId)?.interestedCount || 0, buddyCount: byEvent.get(eventId)?.buddyCount || 0,
      me: userId ? { interested: mine.get(eventId)?.interested === true, lookingForBuddy: mine.get(eventId)?.interested === true && mine.get(eventId)?.lookingForBuddy === true } : null,
    }));
  };
  const unavailable = res => res.status(503).json({ error: '活动报名暂不可用，请稍后重试。' });

  app.get('/api/events/engagement', optionalAuth, rateLimit(), async (req, res) => {
    const raw = req.query.ids;
    if (typeof raw !== 'string' || !raw.length || raw.length > 12099) return res.status(400).json({ error: '请提供 1–100 个活动编号。' });
    const ids = raw.split(',');
    if (ids.length > 100 || ids.some(id => !EVENT_ID.test(id))) return res.status(400).json({ error: '请提供 1–100 个有效活动编号。' });
    if (!catalog) return unavailable(res);
    if (ids.some(id => !catalog.has(id))) return res.status(404).json({ error: '活动不存在。' });
    try { res.json({ events: await engagements([...new Set(ids)], req.user?.id) }); }
    catch { unavailable(res); }
  });

  app.get('/api/events/:eventId/buddies', optionalAuth, rateLimit(), async (req, res) => {
    const event = requireEvent(req.params.eventId, res);
    if (!event) return;
    const rawLimit = req.query.limit;
    if (rawLimit !== undefined && (typeof rawLimit !== 'string' || !/^(?:[1-9]|1\d|20)$/.test(rawLimit))) return res.status(400).json({ error: '每页人数须为 1–20。' });
    const limit = rawLimit === undefined ? 20 : Number(rawLimit);
    const rawCursor = req.query.cursor;
    let cursor = '';
    if (rawCursor !== undefined) {
      if (typeof rawCursor !== 'string' || !/^[A-Za-z0-9_-]{1,800}$/.test(rawCursor)) return res.status(400).json({ error: '分页位置无效。' });
      cursor = Buffer.from(rawCursor, 'base64url').toString('utf8');
      if (!cursor || cursor.length > 200 || /[\u0000-\u001f\u007f\ufffd]/.test(cursor) || Buffer.from(cursor).toString('base64url') !== rawCursor) return res.status(400).json({ error: '分页位置无效。' });
    }
    try {
      const blocks = req.user ? await UserBlock.find({ $or: [{ blockerId: req.user.id }, { blockedUserId: req.user.id }] }).select('blockerId blockedUserId').lean() : [];
      const excluded = [...new Set(blocks.map(block => block.blockerId === req.user.id ? block.blockedUserId : block.blockerId))];
      const rows = await EventInterest.aggregate([
        { $match: { eventId: event.id, interested: true, lookingForBuddy: true, userId: { $nin: excluded, ...(cursor ? { $gt: cursor } : {}) } } },
        ...eligibleMembers,
        { $group: { _id: '$userId', member: { $first: '$member' } } },
        { $sort: { _id: 1 } }, { $limit: limit + 1 },
        { $project: { _id: 1, 'member.id': 1, 'member.nickname': 1, 'member.avatar': 1, 'member.city': 1 } },
      ]);
      const page = rows.slice(0, limit);
      res.json({ eventId: event.id, buddies: page.map(({ member }) => ({ id: member.id, nickname: member.nickname || '湾区邻居', avatar: member.avatar || '', city: member.city || '' })), nextCursor: rows.length > limit ? Buffer.from(page.at(-1)._id).toString('base64url') : null });
    } catch { unavailable(res); }
  });

  app.put('/api/events/:eventId/interest', authenticateToken, rateLimit(true), async (req, res) => {
    const event = requireEvent(req.params.eventId, res);
    if (!event) return;
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['interested', 'lookingForBuddy'].includes(key))
      || typeof body.interested !== 'boolean' || typeof body.lookingForBuddy !== 'boolean' || (body.lookingForBuddy && !body.interested)) return res.status(400).json({ error: '请明确选择是否想去、是否寻找搭子；找搭子需要同时选择想去。' });
    const joining = body.interested || body.lookingForBuddy;
    const ended = joining && event.endDate < bayAreaDate(now());
    const accountError = joining && assertAccountCanPost(req.user);
    try {
      const timestamp = now();
      const query = { eventId: event.id, userId: req.user.id };
      if (ended || accountError) {
        if (body.interested && !body.lookingForBuddy) {
          // Removing public visibility is allowed while keeping existing private interest.
          // Match atomically without upsert or setting interested, so a concurrent full
          // cancellation cannot be turned back into a join by this withdrawal.
          const existing = await EventInterest.findOneAndUpdate(
            { ...query, interested: true },
            { $set: { lookingForBuddy: false, updatedAt: timestamp } },
            { new: true, upsert: false, runValidators: true },
          );
          if (existing) return res.json((await engagements([event.id], req.user.id))[0]);
        }
        return ended ? res.status(410).json({ error: '活动已结束，不能再报名；仍可取消已有意向。' })
          : res.status(403).json({ error: accountError });
      }
      const update = { $set: { interested: body.interested, lookingForBuddy: body.lookingForBuddy, updatedAt: timestamp }, $setOnInsert: { ...query, createdAt: timestamp } };
      try { await EventInterest.updateOne(query, update, { upsert: joining, runValidators: true }); }
      catch (error) {
        if (error.code !== 11000) throw error;
        // Concurrent first writes may race to insert. Apply this explicit set
        // to the winning row; never create a second member/event entry.
        await EventInterest.updateOne(query, { $set: update.$set }, { runValidators: true });
      }
      res.json((await engagements([event.id], req.user.id))[0]);
    } catch { unavailable(res); }
  });
}

module.exports = { registerEventEngagement, loadEventCatalog, bayAreaDate };
