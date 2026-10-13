const fs = require('node:fs');
const path = require('node:path');
const { publicProfileCity } = require('./memberSocial');
const { canonicalEventId } = require('./eventId');
const eventIdAliases = require('../data/event-id-aliases.json');
const { eventStatus } = require('./eventStatus');

const EVENT_ID = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,119}$/;
const MAX_EVENT_IDS_PER_REQUEST = 200;
const MAX_EVENT_IDS_QUERY_LENGTH = MAX_EVENT_IDS_PER_REQUEST * 121 - 1;
const pacificDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit' });
const bayAreaDate = now => {
  const parts = pacificDate.formatToParts(new Date(now));
  return ['year', 'month', 'day'].map(type => parts.find(part => part.type === type).value).join('-');
};
const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)
  && Number.isFinite(Date.parse(`${value}T12:00:00Z`)) && new Date(`${value}T12:00:00Z`).toISOString().startsWith(value);

/** Editorial statuses by event ID. The web's event export carries no status; the overlay's `status` reaches the API
 * in the planner catalog (API-STATUS). An unreadable planner file leaves sign-ups as before, never a 503. */
function plannerStatuses(plannerEvents) {
  let rows = plannerEvents;
  if (rows === undefined) {
    try { rows = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/planner-catalog.json'), 'utf8')).events; } catch { rows = []; }
  }
  return new Map((Array.isArray(rows) ? rows : []).filter(row => row && typeof row.id === 'string' && eventStatus(row)).map(row => [row.id, eventStatus(row)]));
}

/** `supplied` replaces data/event-catalog.json (tests); its rows may carry `status` themselves. Without it, statuses
 * come from data/planner-catalog.json, or from `plannerEvents` when given. */
function loadEventCatalog(supplied, plannerEvents) {
  try {
    const rows = supplied === undefined ? JSON.parse(fs.readFileSync(path.join(__dirname, '../data/event-catalog.json'), 'utf8')) : supplied;
    if (!Array.isArray(rows) || !rows.length || rows.length > 10000) return null;
    const statuses = plannerStatuses(plannerEvents === undefined && supplied !== undefined ? [] : plannerEvents);
    const catalog = new Map();
    for (const row of rows) {
      if (!row || typeof row.id !== 'string' || !EVENT_ID.test(row.id) || catalog.has(row.id)
        || typeof row.title !== 'string' || !row.title.trim() || !validDate(row.startDate) || !validDate(row.endDate) || row.startDate > row.endDate) return null;
      // Explicit confirmed days ([] = none confirmed), as in the planner loader.
      if (row.occurrenceDates !== undefined && (!Array.isArray(row.occurrenceDates) || row.occurrenceDates.length > 10000
        || row.occurrenceDates.some(date => !validDate(date) || date < row.startDate || date > row.endDate))) return null;
      const status = eventStatus(row) || statuses.get(row.id);
      catalog.set(row.id, { id: row.id, startDate: row.startDate, endDate: row.endDate,
        ...(row.occurrenceDates !== undefined ? { occurrenceDates: [...row.occurrenceDates] } : {}), ...(status ? { status } : {}) });
    }
    return catalog;
  } catch { return null; }
}

const SIGN_UP_CLOSED = {
  EVENT_ENDED: { status: 410, text: ['活动已结束，不能再报名；仍可取消已有意向。', '活動已結束，不能再報名；仍可取消已有意向。', 'This event has ended, so new sign-ups are closed. You can still withdraw your interest.'] },
  EVENT_CANCELLED: { status: 410, text: ['活动已取消，不能再登记想去或找搭子；仍可取消已有意向。', '活動已取消，不能再登記想去或找搭子；仍可取消已有意向。', 'This event has been cancelled, so new sign-ups are closed. You can still withdraw your interest.'] },
  EVENT_POSTPONED: { status: 409, text: ['活动已延期，新日期公布前暂不能登记想去或找搭子；仍可取消已有意向。', '活動已延期，新日期公佈前暫不能登記想去或找搭子；仍可取消已有意向。', 'This event has been postponed. Sign-ups reopen once a new date is announced; you can still withdraw your interest.'] },
  EVENT_NO_CONFIRMED_DATE: { status: 409, text: ['这个活动还没有确认的举办日期，暂不能登记想去或找搭子；仍可取消已有意向。', '這個活動還沒有確認的舉辦日期，暫不能登記想去或找搭子；仍可取消已有意向。', 'This event has no confirmed date yet, so sign-ups are closed for now. You can still withdraw your interest.'] },
};
/** Why a new interest or buddy opt-in is refused today, or null. Withdrawing is always allowed. */
function signUpClosed(event, today) {
  const status = eventStatus(event);
  if (status === 'cancelled') return 'EVENT_CANCELLED';
  if (status === 'postponed') return 'EVENT_POSTPONED';
  if (event.endDate < today) return 'EVENT_ENDED';
  // occurrenceDates: [] means no day is confirmed (San Mateo 11/5); all confirmed days past means it is over.
  if (Array.isArray(event.occurrenceDates) && !event.occurrenceDates.some(date => date >= today)) return event.occurrenceDates.length ? 'EVENT_ENDED' : 'EVENT_NO_CONFIRMED_DATE';
  return null;
}
/** ?locale=en|zh-Hant|zh-Hans, else Accept-Language; Simplified Chinese by default (the body takes no extra keys). */
function requestLocale(req) {
  const query = typeof req.query?.locale === 'string' ? req.query.locale : '';
  const tag = /^(?:en|zh)\b/i.test(query) ? query : String(req.headers?.['accept-language'] || '').split(',')[0].trim();
  return /^en\b/i.test(tag) ? 'en' : /^zh-(?:Hant|TW|HK|MO)\b/i.test(tag) ? 'zh-Hant' : 'zh-Hans';
}

function registerEventEngagement(app, { EventInterest, User, UserBlock, authenticateToken, checkRateLimit, getClientIp, assertAccountCanPost, catalog: suppliedCatalog, now = Date.now }) {
  const catalog = loadEventCatalog(suppliedCatalog);
  const aliases = Object.entries(eventIdAliases).filter(([, id]) => catalog?.has(id));
  const equivalentIds = id => {
    const canonical = canonicalEventId(id);
    return [canonical, ...aliases.filter(([, target]) => target === canonical).map(([alias]) => alias)];
  };
  // Collapse historical IDs before grouping by member, rather than summing
  // per-ID counts (which would count the same person twice).
  const canonicalExpression = aliases.reduce((expression, [alias, id]) => ({ $cond: [{ $eq: ['$eventId', alias] }, id, expression] }), '$eventId');
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
    const event = typeof id === 'string' && EVENT_ID.test(id) && catalog.get(canonicalEventId(id));
    if (!event) { res.status(404).json({ error: '活动不存在。' }); return null; }
    return event;
  };
  const eligibleMembers = [
    { $lookup: { from: User.collection.name, localField: 'userId', foreignField: 'id', as: 'member' } },
    { $unwind: '$member' },
    { $match: { 'member.isBanned': { $ne: true }, 'member.accountStatus': { $nin: ['limited', 'suspended'] } } },
  ];
  const engagements = async (ids, userId) => {
    const storedIds = [...new Set(ids.flatMap(equivalentIds))];
    const [counts, own] = await Promise.all([
      EventInterest.aggregate([
        { $match: { eventId: { $in: storedIds }, interested: true } },
        ...eligibleMembers,
        // The unique index prevents new duplicates. Group by member as well so
        // legacy/imported rows can never inflate the public count.
        { $group: { _id: { eventId: canonicalExpression, userId: '$userId' }, buddy: { $max: { $cond: [{ $eq: ['$lookingForBuddy', true] }, 1, 0] } } } },
        { $group: { _id: '$_id.eventId', interestedCount: { $sum: 1 }, buddyCount: { $sum: '$buddy' } } },
      ]),
      userId ? EventInterest.find({ eventId: { $in: storedIds }, userId }).select('eventId interested lookingForBuddy').lean() : [],
    ]);
    const byEvent = new Map(counts.map(row => [row._id, row]));
    const mine = new Map();
    for (const row of own) {
      const id = canonicalEventId(row.eventId);
      const state = mine.get(id) || { interested: false, lookingForBuddy: false };
      if (row.interested === true) {
        state.interested = true;
        state.lookingForBuddy ||= row.lookingForBuddy === true;
      }
      mine.set(id, state);
    }
    return ids.map(eventId => {
      const id = canonicalEventId(eventId);
      return {
        eventId, interestedCount: byEvent.get(id)?.interestedCount || 0, buddyCount: byEvent.get(id)?.buddyCount || 0,
        me: userId ? mine.get(id) || { interested: false, lookingForBuddy: false } : null,
      };
    });
  };
  const unavailable = res => res.status(503).json({ error: '活动报名暂不可用，请稍后重试。' });

  app.get('/api/events/engagement', optionalAuth, rateLimit(), async (req, res) => {
    const raw = req.query.ids;
    if (typeof raw !== 'string' || !raw.length || raw.length > MAX_EVENT_IDS_QUERY_LENGTH) return res.status(400).json({ error: `请提供 1–${MAX_EVENT_IDS_PER_REQUEST} 个活动编号。` });
    const ids = raw.split(',');
    if (ids.length > MAX_EVENT_IDS_PER_REQUEST || ids.some(id => !EVENT_ID.test(id))) return res.status(400).json({ error: `请提供 1–${MAX_EVENT_IDS_PER_REQUEST} 个有效活动编号。` });
    if (!catalog) return unavailable(res);
    if (ids.some(id => !catalog.has(canonicalEventId(id)))) return res.status(404).json({ error: '活动不存在。' });
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
        { $match: { eventId: { $in: equivalentIds(event.id) }, interested: true, lookingForBuddy: true, userId: { $nin: excluded, ...(cursor ? { $gt: cursor } : {}) } } },
        ...eligibleMembers,
        { $group: { _id: '$userId', member: { $first: '$member' } } },
        { $sort: { _id: 1 } }, { $limit: limit + 1 },
        { $project: { _id: 1, 'member.id': 1, 'member.nickname': 1, 'member.avatar': 1, 'member.city': 1, 'member.profileVisibility': 1 } },
      ]);
      const page = rows.slice(0, limit);
      res.json({ eventId: req.params.eventId, buddies: page.map(({ member }) => ({ id: member.id, nickname: member.nickname || '湾区邻居', avatar: member.avatar || '', city: publicProfileCity(member) })), nextCursor: rows.length > limit ? Buffer.from(page.at(-1)._id).toString('base64url') : null });
    } catch { unavailable(res); }
  });

  app.put('/api/events/:eventId/interest', authenticateToken, rateLimit(true), async (req, res) => {
    const event = requireEvent(req.params.eventId, res);
    if (!event) return;
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['interested', 'lookingForBuddy'].includes(key))
      || typeof body.interested !== 'boolean' || typeof body.lookingForBuddy !== 'boolean' || (body.lookingForBuddy && !body.interested)) return res.status(400).json({ error: '请明确选择是否想去、是否寻找搭子；找搭子需要同时选择想去。' });
    const joining = body.interested || body.lookingForBuddy;
    // Ended, cancelled, postponed or without a confirmed day: no new interest or buddy opt-in (API-STATUS).
    const closed = joining && signUpClosed(event, bayAreaDate(now()));
    const accountError = joining && assertAccountCanPost(req.user);
    try {
      const timestamp = now();
      const query = { eventId: event.id, userId: req.user.id };
      const ids = equivalentIds(event.id);
      const groupQuery = ids.length > 1 ? { ...query, eventId: { $in: ids } } : query;
      if (closed || accountError) {
        if (body.interested && !body.lookingForBuddy) {
          // Removing public visibility is allowed while keeping existing private interest.
          // Match atomically without upsert or setting interested, so a concurrent full
          // cancellation cannot be turned back into a join by this withdrawal.
          const existing = await EventInterest.findOneAndUpdate(
            { ...groupQuery, interested: true },
            { $set: { lookingForBuddy: false, updatedAt: timestamp } },
            { new: true, upsert: false, runValidators: true },
          );
          if (existing) {
            // A member may have opted in under both IDs before the merge.
            // Never restore interest while withdrawing public visibility.
            if (ids.length > 1) await EventInterest.updateMany(groupQuery, { $set: { lookingForBuddy: false, updatedAt: timestamp } }, { runValidators: true });
            return res.json((await engagements([req.params.eventId], req.user.id))[0]);
          }
        }
        if (!closed) return res.status(403).json({ error: accountError });
        const locale = requestLocale(req);
        return res.status(SIGN_UP_CLOSED[closed].status).json({ code: closed, error: SIGN_UP_CLOSED[closed].text[locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0] });
      }
      const update = { $set: { interested: body.interested, lookingForBuddy: body.lookingForBuddy, updatedAt: timestamp }, $setOnInsert: { ...query, createdAt: timestamp } };
      if (!joining && ids.length > 1) {
        // Clear every historical row; a cancellation through either URL must
        // not leave the member publicly visible through the other one.
        await EventInterest.updateMany(groupQuery, { $set: update.$set }, { runValidators: true });
        return res.json((await engagements([req.params.eventId], req.user.id))[0]);
      }
      try { await EventInterest.updateOne(query, update, { upsert: joining, runValidators: true }); }
      catch (error) {
        if (error.code !== 11000) throw error;
        // Concurrent first writes may race to insert. Apply this explicit set
        // to the winning row; never create a second member/event entry.
        await EventInterest.updateOne(query, { $set: update.$set }, { runValidators: true });
      }
      // New writes always target the canonical row. Retire this member's old
      // aliases only on an explicit write, never during reads or deployment.
      if (ids.length > 1) await EventInterest.updateMany({ userId: req.user.id, eventId: { $in: ids.slice(1) } }, { $set: { interested: false, lookingForBuddy: false, updatedAt: timestamp } }, { runValidators: true });
      res.json((await engagements([req.params.eventId], req.user.id))[0]);
    } catch { unavailable(res); }
  });
}

module.exports = { registerEventEngagement, loadEventCatalog, signUpClosed, bayAreaDate, MAX_EVENT_IDS_PER_REQUEST };
