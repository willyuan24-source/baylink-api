const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { localInstant, TIMEZONE } = require('./serviceBookings');
const { outingSearch } = require('./outingSearch');

const DAY = 86400000;
const CONSENT = 'outings-adult-public-v1';
const MAX_MEMBERS = 100, MAX_MESSAGES = 500, MAX_RECEIPTS = 1000;
const EDITABLE = ['title', 'description', 'eventId', 'date', 'startTime', 'endTime', 'city', 'venue', 'capacity', 'costNote', 'transport', 'language', 'cover'];
const CRITICAL = ['eventId', 'date', 'startTime', 'endTime', 'city', 'venue', 'costNote', 'transport', 'language'];
const REASONS = new Set(['spam', 'scam', 'harassment', 'illegal', 'misleading', 'duplicate', 'other']);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const validId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,140}$/.test(value);
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const keys = (value, allowed) => { if (!plain(value) || Object.keys(value).some(key => !allowed.includes(key))) throw fail('小队请求格式无效。'); };
const text = (value, max, min = 0) => {
  if (typeof value !== 'string' || value.trim().length < min || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) throw fail('请检查文字长度和格式。');
  return value.trim();
};
const safeUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : undefined; } catch { return undefined; } };
const active = user => !!user && !user.isBanned && !['limited', 'suspended'].includes(user.accountStatus);
const phoneCurrent = user => user?.isPhoneVerified === true && !user.phoneVerificationCodeHash
  && (!user.phoneVerificationLastSentAt || (Number.isFinite(user.phoneVerifiedAt) && user.phoneVerifiedAt >= user.phoneVerificationLastSentAt));
const validDate = value => typeof value === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(`${value}T12:00:00Z`)) && new Date(`${value}T12:00:00Z`).toISOString().slice(0, 10) === value;

// Store only a display preference or a bounded content reference. The frontend
// resolves known editorial sources; no user-provided URL is fetched or rendered.
function validateOutingCover(value) {
  if (value === undefined) return undefined;
  if (!plain(value) || !Object.hasOwn(value, 'kind')) throw fail('小队配图格式无效。');
  if (['auto', 'card'].includes(value.kind)) {
    if (Object.keys(value).some(key => key !== 'kind')) throw fail('小队配图格式无效。');
    return { kind: value.kind };
  }
  if (!['guide', 'event', 'offer', 'opening'].includes(value.kind)
    || Object.keys(value).some(key => !['kind', 'id'].includes(key))
    || !Object.hasOwn(value, 'id') || typeof value.id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,139}$/.test(value.id)) throw fail('请选择有效的站内配图来源。');
  return { kind: value.kind, id: value.id };
}

function loadOutingCatalog(supplied) {
  try {
    const rows = supplied === undefined ? JSON.parse(fs.readFileSync(path.join(__dirname, '../data/event-catalog.json'), 'utf8')) : supplied;
    const planner = supplied === undefined ? JSON.parse(fs.readFileSync(path.join(__dirname, '../data/planner-catalog.json'), 'utf8')).events : [];
    if (!Array.isArray(rows) || rows.length > 10000) return null;
    const catalog = new Map();
    for (const row of rows) {
      if (!validId(row.id) || catalog.has(row.id) || !validDate(row.startDate) || !validDate(row.endDate) || row.startDate > row.endDate
        || typeof row.title !== 'string' || ('occurrenceDates' in row && (!Array.isArray(row.occurrenceDates) || row.occurrenceDates.some(day => !validDate(day) || day < row.startDate || day > row.endDate)))) return null;
      const officialUrl = safeUrl(row.officialUrl || planner.find(event => event.id === row.id)?.officialUrl);
      const { officialUrl: _ignoredUrl, ...event } = row;
      catalog.set(row.id, { ...event, ...(officialUrl ? { officialUrl } : {}) });
    }
    return catalog;
  } catch { return null; }
}

function validateOutingInput(input, catalog, now) {
  const result = { title: text(input.title, 100, 2), description: text(input.description, 1200), city: text(input.city, 80, 1), venue: text(input.venue, 200, 2), costNote: text(input.costNote, 300),
    eventId: input.eventId, date: input.date, startTime: input.startTime, endTime: input.endTime, capacity: input.capacity, transport: input.transport, language: input.language };
  if (result.eventId !== null && !validId(result.eventId)) throw fail('活动编号无效。');
  const cover = validateOutingCover(input.cover);
  if (cover !== undefined) result.cover = cover;
  if (!Number.isInteger(result.capacity) || result.capacity < 2 || result.capacity > 8) throw fail('小队须为2–8人，包含队长。');
  if (!['own', 'transit', 'walk'].includes(result.transport) || !['any', 'zh', 'en'].includes(result.language)) throw fail('请选择有效的交通和交流语言。');
  result.startAt = localInstant(result.date, result.startTime); result.endAt = localInstant(result.date, result.endTime);
  if (result.startAt <= now || result.startAt > now + 180 * DAY || result.endAt <= result.startAt) throw fail('请选择未来180天内、同一天开始和结束的时间。');
  if (result.eventId) {
    if (!catalog) throw fail('活动目录暂不可用，请稍后重试。', 503);
    const event = catalog.get(result.eventId);
    if (!event) throw fail('关联活动不存在。', 404);
    if (result.date < event.startDate || result.date > event.endDate || (Array.isArray(event.occurrenceDates) && !event.occurrenceDates.includes(result.date))) throw fail('这一天不是已确认的活动场次。');
    result.eventTitle = event.title;
    if (event.officialUrl) result.officialUrl = event.officialUrl;
  }
  return { ...result, timezone: TIMEZONE };
}

function createOutingModel(mongoose, injected = {}) {
  if (injected.Outing) return injected.Outing;
  const schema = new mongoose.Schema({
    id: { type: String, unique: true, required: true }, hostId: { type: String, required: true, index: true },
    title: String, description: String, eventId: { type: String, default: null }, eventTitle: String, officialUrl: String,
    cover: { type: mongoose.Schema.Types.Mixed, default: undefined, validate: { validator(value) { try { validateOutingCover(value); return true; } catch { return false; } }, message: 'Invalid outing cover' } },
    date: String, startTime: String, endTime: String, startAt: Number, endAt: Number, timezone: String,
    city: String, venue: String, capacity: Number, costNote: String, transport: String, language: String,
    status: { type: String, enum: ['open', 'cancelled', 'completed'], default: 'open' },
    revision: { type: Number, default: 1 }, planVersion: { type: Number, default: 1 }, notificationRevision: { type: Number, default: 0 },
    members: { type: [mongoose.Schema.Types.Mixed], default: [] }, messages: { type: [mongoose.Schema.Types.Mixed], default: [] },
    receipts: { type: [mongoose.Schema.Types.Mixed], default: [] }, notices: { type: [mongoose.Schema.Types.Mixed], default: [] },
    timePoll: { type: mongoose.Schema.Types.Mixed, default: undefined },
    createFingerprint: String, createdAt: Number, updatedAt: Number, adultConsentAt: Number, publicPlaceConsentAt: Number, consentVersion: String,
  });
  schema.index({ status: 1, startAt: 1, id: 1 });
  schema.index({ 'members.userId': 1, updatedAt: -1 });
  return mongoose.models.Outing || mongoose.model('Outing', schema);
}

function registerOutings(app, deps) {
  const { Outing, User, UserBlock, Message, Conversation, Report, authenticateToken, requireAdmin, checkRateLimit, getClientIp, officialStatus, openConversation, emitMessage, createModerationLog, now = Date.now } = deps;
  const catalog = loadOutingCatalog(deps.catalog);
  const verified = user => phoneCurrent(user) || officialStatus(user) === 'approved' || (officialStatus(user) === 'none' && user?.isOfficialVerified === true);
  const user = id => User.findOne({ id }).lean();
  const blocked = async (a, b) => a !== b && !!await UserBlock.findOne({ $or: [{ blockerId: a, blockedUserId: b }, { blockerId: b, blockedUserId: a }] }).lean();
  const member = (row, userId) => row.members.find(item => item.userId === userId);
  const confirmed = row => row.members.filter(item => item.status === 'confirmed');
  const waitlisted = item => item.status === 'requested' && item.waitlisted === true;
  const status = row => row.status === 'open' && row.endAt <= now() ? 'completed' : row.status;
  const get = async id => { if (!validId(id)) throw fail('小队编号无效。'); const row = await Outing.findOne({ id }).lean(); if (!row) throw fail('小队不存在。', 404); return row; };
  const requireActive = async id => { const value = await user(id); if (!active(value)) throw fail('账号当前不能参与小队。', 403); return value; };
  const requireVerified = async id => { const value = await requireActive(id); if (!verified(value)) throw fail('请先完成当前手机号验证或平台资料审核，再参与小队。', 403); return value; };
  const compatible = async (row, id) => { for (const other of confirmed(row)) if (await blocked(id, other.userId)) throw fail('当前无法与这支小队互动。', 403); };
  const requireHost = (row, id) => { if (row.hostId !== id) throw fail('只有队长可以执行此操作。', 403); };
  const upcoming = row => { if (status(row) !== 'open' || row.startAt <= now()) throw fail('小队已开始、结束或取消。', 409); };
  const requireDiscussion = async (row, id, writing = false) => {
    await requireActive(id); await requireActive(row.hostId);
    const own = member(row, id);
    if (own?.status !== 'confirmed') throw fail('讨论仅向已确认成员开放。', 403);
    await compatible(row, id);
    if (writing && (status(row) !== 'open' || own.confirmedVersion !== row.planVersion)) throw fail('请先确认最新安排；已结束或取消的小队不能继续发言。', 409);
  };
  const dto = async (row, viewerId, includeMembers = true) => {
    const own = member(row, viewerId), host = await user(row.hostId), isHost = viewerId === row.hostId;
    const output = Object.fromEntries([...EDITABLE, 'id', 'eventTitle', 'officialUrl', 'startAt', 'endAt', 'timezone', 'revision', 'planVersion', 'createdAt', 'updatedAt'].filter(key => row[key] !== undefined).map(key => [key, row[key]]));
    Object.assign(output, { status: status(row), host: { id: row.hostId, nickname: host?.nickname || '湾区邻居', verified: active(host) && verified(host) }, confirmedCount: confirmed(row).length,
      me: own ? { userId: own.userId, role: own.role, status: own.status, confirmedVersion: own.confirmedVersion, waitlisted: waitlisted(own) } : null });
    if (isHost) {
      output.requestCount = row.members.filter(item => item.status === 'requested').length;
      output.waitlistCount = row.members.filter(waitlisted).length;
      output.waitlistReviewNeeded = status(row) === 'open' && row.startAt > now() && active(host) && verified(host) && output.confirmedCount < row.capacity && output.waitlistCount > 0;
    }
    if (includeMembers && (isHost || own?.status === 'confirmed') && active(await user(viewerId)) && !await blocked(viewerId, row.hostId)) {
      output.members = [];
      for (const item of row.members) {
        if (!isHost && (item.status !== 'confirmed' || await blocked(viewerId, item.userId))) continue;
        const profile = await user(item.userId);
        const requestedAt = Number.isFinite(item.requestedAt) ? item.requestedAt : item.updatedAt;
        output.members.push({ userId: item.userId, nickname: profile?.nickname || '湾区邻居', role: item.role, status: item.status, confirmedVersion: item.confirmedVersion, waitlisted: waitlisted(item),
          ...(isHost && Number.isFinite(requestedAt) && item.role !== 'host' ? { requestedAt } : {}), ...(isHost && item.note ? { note: item.note } : {}) });
      }
    }
    // Availability is private to the current team. Public cards, applicants and
    // former members never receive a poll or another person's availability.
    if (includeMembers && row.timePoll && own?.status === 'confirmed') {
      try {
        await requireDiscussion(row, viewerId);
        const eligible = [];
        for (const item of confirmed(row)) if (active(await user(item.userId))) eligible.push(item.userId);
        const votes = row.timePoll.votes.filter(vote => eligible.includes(vote.userId));
        const poll = row.timePoll;
        output.timePoll = { id: poll.id, status: poll.status, planVersion: poll.planVersion, createdAt: poll.createdAt,
          ...(poll.closedAt ? { closedAt: poll.closedAt } : {}), ...(poll.selectedOptionId ? { selectedOptionId: poll.selectedOptionId } : {}), ...(poll.closeReason ? { closeReason: poll.closeReason } : {}),
          eligibleCount: eligible.length, repliedCount: votes.length,
          options: poll.options.map(option => ({ ...option, counts: Object.fromEntries(['yes', 'maybe', 'no'].map(answer => [answer, votes.filter(vote => vote.answers[option.id] === answer).length])) })),
          myAnswers: votes.find(vote => vote.userId === viewerId)?.answers || null };
      } catch (error) { if (![403, 409].includes(error.status)) throw error; }
    }
    return output;
  };
  const requestIdentity = (actorId, scope, body) => {
    if (!validId(body.idempotencyKey) || body.idempotencyKey.length < 8) throw fail('请使用8至140位唯一请求编号。');
    const { idempotencyKey, revision, ...payload } = body;
    if (scope === 'action:request' && payload.waitlist === false) delete payload.waitlist;
    return { key: hash(`${actorId}:${scope}:${idempotencyKey}`), fingerprint: hash(JSON.stringify(payload)) };
  };
  const addNotice = (row, actorId, targetId, label) => {
    if (actorId === targetId) return;
    const id = `outing_${hash(`${row.id}:${row.revision + 1}:${actorId}:${targetId}:${label}`).slice(0, 40)}`;
    row.notices.push({ id, actorId, targetId, label, at: now(), state: 'pending', text: `BAYLINK 小队 · ${label}\n${row.title}\n${row.date} ${row.startTime}–${row.endTime}（洛杉矶时间）\nhttps://www.baylink.us/together?outing=${row.id}\n组队不等于活动购票或主办方报名。` });
  };
  const mutate = async (id, actorId, scope, body, transform) => {
    const identity = requestIdentity(actorId, scope, body);
    if (!Number.isSafeInteger(body.revision) || body.revision < 1) throw fail('请提供当前小队版本。');
    for (let attempt = 0; attempt < 12; attempt++) {
      const row = await get(id);
      if (deps.holdAccount) {
        // Wait for every acquisition to settle, including a rejected sibling;
        // no late acquisition may escape the request ledger after it releases.
        const ids = [...new Set([actorId, row.hostId, ...row.members.map(item => item.userId)])].sort();
        const holds = await Promise.allSettled(ids.map(id => deps.holdAccount(id)));
        const rejected = holds.find(result => result.status === 'rejected');
        if (rejected) throw rejected.reason;
      }
      const previous = row.receipts.find(receipt => receipt.key === identity.key);
      if (previous) { if (previous.fingerprint !== identity.fingerprint) throw fail('同一请求编号不能用于不同内容。', 409); return { row, result: previous.result, replayed: true }; }
      if (row.revision !== body.revision) throw fail('小队已更新，请刷新后重试。', 409);
      const result = await transform(row);
      // Async account/block checks may cross the actual start/end deadline.
      if (['edit', 'action:request', 'action:accept', 'action:reconfirm'].includes(scope) || scope.startsWith('poll:')) upcoming(row);
      if (scope === 'poll:adopt' && row.startAt <= now()) throw fail('候选时间已经开始，请重新协商。', 409);
      if (scope === 'message' && status(row) !== 'open') throw fail('小队已经结束或取消，不能继续发言。', 409);
      row.receipts.push({ ...identity, result }); row.receipts = row.receipts.slice(-MAX_RECEIPTS);
      row.notices = row.notices.filter(notice => notice.state !== 'sent' && notice.state !== 'skipped').concat(row.notices.filter(notice => ['sent', 'skipped'].includes(notice.state)).slice(-30));
      if (row.notices.length > 1500 && !scope.startsWith('action:') && scope !== 'admin-cancel') throw fail('小队通知待处理，请稍后重试。', 503);
      if (row.notices.length > 1500 && scope === 'action:request') throw fail('小队通知待处理，请稍后再申请。', 503);
      const { _id, __v, revision, notificationRevision, ...values } = row;
      values.updatedAt = now();
      const saved = await Outing.findOneAndUpdate({ id, revision, notificationRevision }, { $set: values, $inc: { revision: 1 } }, { new: true, runValidators: true });
      if (saved) return { row: typeof saved.toObject === 'function' ? saved.toObject() : saved, result };
    }
    throw fail('小队正在更新，请使用同一请求重试。', 409);
  };
  // Notification delivery uses a separate CAS clock so it cannot invalidate a user's form revision.
  const noticeChange = async (id, change) => {
    for (let attempt = 0; attempt < 12; attempt++) {
      const row = await get(id), result = change(row.notices);
      if (result === false) return false;
      const saved = await Outing.findOneAndUpdate({ id, revision: row.revision, notificationRevision: row.notificationRevision }, { $set: { notices: row.notices }, $inc: { notificationRevision: 1 } }, { new: true, runValidators: true });
      if (saved) return result;
    }
    return false;
  };
  const drain = async (id, maximum = 8) => {
    const initial = await get(id);
    for (const pending of initial.notices.filter(notice => ['pending', 'failed'].includes(notice.state) || (notice.state === 'processing' && notice.claimedAt <= now() - 120000)).slice(0, maximum)) {
      const claim = crypto.randomUUID();
      const notice = await noticeChange(id, notices => {
        const item = notices.find(value => value.id === pending.id);
        if (!item || ['sent', 'skipped'].includes(item.state) || (item.state === 'processing' && item.claimedAt > now() - 120000)) return false;
        item.state = 'processing'; item.claim = claim; item.claimedAt = now(); return clone(item);
      });
      if (!notice) continue;
      let state = 'failed';
      try {
        const row = await get(id), peer = notice.targetId === row.hostId ? notice.actorId : notice.targetId;
        if (!active(await user(row.hostId)) || !active(await user(peer)) || await blocked(row.hostId, peer)) state = 'skipped';
        else {
          const conversation = await openConversation(row.hostId, peer), _id = hash(notice.id).slice(0, 24);
          let message;
          try { message = await Message.findOneAndUpdate({ _id }, { $setOnInsert: { id: notice.id, conversationId: conversation.id, senderId: notice.actorId === peer ? peer : row.hostId,
            type: 'text', messageType: 'system', content: notice.text, createdAt: notice.at, readBy: [] } }, { new: true, upsert: true, runValidators: true }); }
          catch (error) { if (error.code !== 11000) throw error; message = await Message.findOne({ _id }); if (!message) throw error; }
          await Conversation.findOneAndUpdate({ id: conversation.id }, { $max: { updatedAt: notice.at } });
          if (deps.enqueueNotification && notice.targetId === row.hostId && /加入申请|候补申请/.test(notice.label)) {
            await deps.enqueueNotification({ topic: 'outing_request', recipientId: row.hostId, actorId: notice.actorId,
              sourceId: row.id, eventId: notice.id, createdAt: notice.at });
          }
          state = 'sent';
          try { await emitMessage(row.hostId, message); await emitMessage(peer, message); } catch { /* Persisted history recovers offline delivery. */ }
        }
      } catch { /* Keep failed work available for bounded recovery on the next read. */ }
      await noticeChange(id, notices => { const item = notices.find(value => value.id === notice.id); if (!item || item.claim !== claim) return false; item.state = state; return true; });
    }
  };
  const response = async (row, viewerId) => {
    try { await drain(row.id); } catch { /* The membership mutation already committed. */ }
    row = await get(row.id);
    return { outing: await dto(row, viewerId), ...(row.notices.some(notice => !['sent', 'skipped'].includes(notice.state)) ? { notificationWarning: '安排已保存，部分站内通知尚未送达；请在小队页面确认。' } : {}) };
  };
  const handler = fn => async (req, res) => { res.set('Cache-Control', 'no-store'); try { await fn(req, res); } catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : '小队暂不可用。刚提交的操作请先刷新核对，再使用相同请求重试。' }); } };
  const optionalAuth = (req, res, next) => req.headers.authorization === undefined ? next() : authenticateToken(req, res, next);
  const limit = (maximum = 40) => (req, res, next) => {
    const scope = maximum === 40 ? 'write' : 'read';
    const allowed = checkRateLimit(`outings:${scope}:ip:${getClientIp(req)}`, { windowMs: 60000, maxRequests: maximum * 3 })
      && (!req.user || checkRateLimit(`outings:${scope}:user:${req.user.id}`, { windowMs: 60000, maxRequests: maximum }));
    return allowed ? next() : res.status(429).json({ error: '操作过于频繁，请稍后重试。' });
  };
  const base = '/api/outings';
  app.get(base, optionalAuth, limit(120), handler(async (req, res) => {
    const search = outingSearch(req.query, now(), deps.config?.JWT_SECRET);
    // At most 81 documents are read. A page may be empty with a next cursor when
    // privacy/availability filters exclude its scan window; the caller can continue.
    const rows = await Outing.find(search.filter).sort(search.sort).limit(81).lean(), visible = [];
    let scanned = 0, last;
    for (const row of rows.slice(0, 80)) {
      scanned++; last = row;
      if (search.openSeats && confirmed(row).length >= row.capacity) continue;
      if (!active(await user(row.hostId)) || (req.user && await blocked(req.user.id, row.hostId))) continue;
      visible.push(await dto(row, req.user?.id, false));
      if (visible.length === 20) break;
    }
    res.json({ outings: visible, nextCursor: last && rows.length > scanned ? search.cursor(last) : null });
  }));
  app.get(`${base}/me`, authenticateToken, limit(120), handler(async (req, res) => {
    const rows = await Outing.find({ 'members.userId': req.user.id }).sort({ updatedAt: -1 }).limit(100).lean();
    for (const row of rows.filter(row => row.notices.some(notice => ['pending', 'failed'].includes(notice.state) || (notice.state === 'processing' && notice.claimedAt <= now() - 120000))).slice(0, 5)) {
      try { await drain(row.id, 2); } catch { /* A later read retries pending notices. */ }
    }
    res.json({ outings: await Promise.all(rows.map(row => dto(row, req.user.id))) });
  }));
  app.post(base, authenticateToken, limit(), handler(async (req, res) => {
    keys(req.body, [...EDITABLE, 'adultConsent', 'publicPlaceConsent', 'idempotencyKey']);
    const owner = await requireVerified(req.user.id);
    if (req.body.adultConsent !== true || req.body.publicPlaceConsent !== true) throw fail('请本人声明年满18岁，并确认在公共场地集合。');
    const identity = requestIdentity(owner.id, 'create', req.body), id = `outing_${hash(identity.key).slice(0, 40)}`;
    const previous = await Outing.findOne({ id }).lean();
    if (previous) { if (previous.createFingerprint !== identity.fingerprint) throw fail('同一请求编号不能用于不同内容。', 409); return res.json({ outing: await dto(previous, owner.id) }); }
    const details = validateOutingInput(req.body, catalog, now());
    if (await Outing.countDocuments({ hostId: owner.id, status: 'open', endAt: { $gt: now() } }) >= 10) throw fail('最多同时组织10支未结束小队。', 429);
    const timestamp = now();
    const row = { _id: hash(id).slice(0, 24), id, ...details, hostId: owner.id, status: 'open', revision: 1, planVersion: 1, notificationRevision: 0,
      members: [{ userId: owner.id, role: 'host', status: 'confirmed', confirmedVersion: 1, everConfirmed: true, adultConsentAt: timestamp, consentVersion: CONSENT }], messages: [], notices: [], receipts: [],
      createFingerprint: identity.fingerprint, createdAt: timestamp, updatedAt: timestamp, adultConsentAt: timestamp, publicPlaceConsentAt: timestamp, consentVersion: CONSENT };
    try { await Outing.updateOne({ _id: row._id }, { $setOnInsert: row }, { upsert: true, runValidators: true }); } catch (error) { if (error.code !== 11000) throw error; }
    const saved = await get(id);
    if (saved.createFingerprint !== identity.fingerprint) throw fail('请求编号冲突。', 409);
    res.json({ outing: await dto(saved, owner.id) });
  }));
  app.get(`${base}/:id`, optionalAuth, limit(120), handler(async (req, res) => {
    const row = await get(req.params.id);
    if (!member(row, req.user?.id) && (!active(await user(row.hostId)) || (req.user && await blocked(req.user.id, row.hostId)))) throw fail('小队当前不可用。', 404);
    res.json({ outing: await dto(row, req.user?.id) });
  }));
  app.patch(`${base}/:id`, authenticateToken, limit(), handler(async (req, res) => {
    keys(req.body, [...EDITABLE, 'revision', 'idempotencyKey', 'publicPlaceConsent']);
    requireHost(await get(req.params.id), req.user.id); await requireVerified(req.user.id);
    const { row } = await mutate(req.params.id, req.user.id, 'edit', req.body, async row => {
      requireHost(row, req.user.id); await requireVerified(req.user.id); upcoming(row);
      if (!EDITABLE.some(key => key in req.body)) throw fail('请提供要修改的安排。');
      if ('venue' in req.body && req.body.venue !== row.venue && req.body.publicPlaceConsent !== true) throw fail('更改地点时请确认仍在公共场地集合。');
      const next = validateOutingInput({ ...row, ...req.body }, catalog, now());
      if (next.capacity < confirmed(row).length) throw fail('人数上限不能小于已确认人数。', 409);
      const changed = CRITICAL.some(key => next[key] !== row[key]);
      delete row.eventTitle; delete row.officialUrl; Object.assign(row, next);
      if (changed) {
        if (row.timePoll?.status === 'open') Object.assign(row.timePoll, { status: 'closed', closedAt: now(), closeReason: 'arrangement-changed' });
        row.planVersion++; member(row, row.hostId).confirmedVersion = row.planVersion;
        for (const item of row.members.filter(item => ['requested', 'confirmed'].includes(item.status))) addNotice(row, row.hostId, item.userId, '安排已变更，请查看并重新确认');
      }
      if (req.body.publicPlaceConsent === true) row.publicPlaceConsentAt = now();
      return null;
    });
    res.json(await response(row, req.user.id));
  }));
  app.post(`${base}/:id/actions`, authenticateToken, limit(), handler(async (req, res) => {
    keys(req.body, ['action', 'userId', 'revision', 'idempotencyKey', 'adultConsent', 'note', 'waitlist']);
    const action = req.body.action;
    if (!['request', 'withdraw', 'accept', 'decline', 'remove', 'cancel', 'reconfirm'].includes(action)) throw fail('小队操作无效。');
    if ('waitlist' in req.body && (action !== 'request' || typeof req.body.waitlist !== 'boolean')) throw fail('候补选项只适用于加入申请，且须明确选择。');
    if (['accept', 'decline', 'remove'].includes(action) ? !validId(req.body.userId) : req.body.userId !== undefined) throw fail('成员编号无效。');
    if (req.body.note !== undefined) text(req.body.note, 500);
    const before = await get(req.params.id);
    if (!['withdraw', 'cancel'].includes(action)) {
      await requireVerified(req.user.id); await requireVerified(before.hostId);
      if (['request', 'reconfirm'].includes(action)) await compatible(before, req.user.id);
      else {
        requireHost(before, req.user.id);
        if (action === 'accept') { await requireVerified(req.body.userId); await compatible(before, req.body.userId); }
      }
    }
    const { row } = await mutate(req.params.id, req.user.id, `action:${action}`, req.body, async row => {
      const own = member(row, req.user.id), target = member(row, req.body.userId);
      if (action === 'withdraw') {
        if (!own || own.role === 'host' || !['requested', 'confirmed'].includes(own.status)) throw fail('当前不能退出；队长请取消小队。', 409);
        const wasConfirmed = own.status === 'confirmed';
        if (wasConfirmed) own.messageAccessThrough = row.messages.length;
        own.status = 'left'; own.waitlisted = false; own.updatedAt = now();
        if (row.timePoll) row.timePoll.votes = row.timePoll.votes.filter(vote => vote.userId !== own.userId);
        const reviewNeeded = wasConfirmed && status(row) === 'open' && row.startAt > now() && confirmed(row).length < row.capacity && row.members.some(waitlisted);
        addNotice(row, req.user.id, row.hostId, reviewNeeded ? '一位成员已退出，有空位请审核候补申请' : '一位成员已退出'); return null;
      }
      if (action === 'cancel') {
        requireHost(row, req.user.id);
        if (status(row) !== 'open') throw fail('小队已经结束或取消。', 409);
        row.status = 'cancelled'; for (const item of row.members.filter(item => ['requested', 'confirmed'].includes(item.status))) addNotice(row, row.hostId, item.userId, '小队已取消'); return null;
      }
      await requireVerified(req.user.id); upcoming(row); await requireActive(row.hostId);
      if (action === 'request') {
        if (req.body.adultConsent !== true) throw fail('请本人声明年满18岁。');
        if (own?.role === 'host' || (own && !['left'].includes(own.status))) throw fail('你已申请，或这次申请已被队长处理。', 409);
        await compatible(row, req.user.id);
        const full = confirmed(row).length >= row.capacity;
        if (full && req.body.waitlist !== true) throw fail('小队已满员，可明确选择申请候补。', 409);
        if (!own && row.members.length >= MAX_MEMBERS) throw fail('这支小队的申请已达上限。', 409);
        const value = { userId: req.user.id, role: 'member', status: 'requested', waitlisted: full && req.body.waitlist === true, requestedAt: now(), confirmedVersion: row.planVersion, note: text(req.body.note || '', 500), adultConsentAt: now(), consentVersion: CONSENT, updatedAt: now() };
        if (own) Object.assign(own, value); else row.members.push(value);
        addNotice(row, req.user.id, row.hostId, value.waitlisted ? '收到新的候补申请' : '收到新的加入申请');
      } else if (action === 'reconfirm') {
        if (own?.status !== 'confirmed' || req.body.adultConsent !== true) throw fail('只有已确认成员可以确认新安排，并须声明年满18岁。', 403);
        await compatible(row, req.user.id); own.confirmedVersion = row.planVersion; own.adultConsentAt = now();
      } else {
        requireHost(row, req.user.id);
        if (!target || target.role === 'host' || (action === 'remove' ? target.status !== 'confirmed' : target.status !== 'requested')) throw fail('成员状态已变化，请刷新。', 409);
        if (action === 'accept') {
          await requireVerified(target.userId); await compatible(row, target.userId);
          if (confirmed(row).length >= row.capacity) throw fail('最后一个名额已被使用。', 409);
          target.status = 'confirmed'; target.everConfirmed = true; // Preserve the version the applicant actually agreed to.
        } else { if (target.status === 'confirmed') target.messageAccessThrough = row.messages.length; target.status = action === 'decline' ? 'declined' : 'removed'; if (row.timePoll) row.timePoll.votes = row.timePoll.votes.filter(vote => vote.userId !== target.userId); }
        target.waitlisted = false;
        target.updatedAt = now(); addNotice(row, row.hostId, target.userId, { accept: '加入申请已通过', decline: '加入申请未通过', remove: '你已被移出小队' }[action]);
      }
      return null;
    });
    res.json(await response(row, req.user.id));
  }));
  app.post(`${base}/:id/time-poll`, authenticateToken, limit(), handler(async (req, res) => {
    const action = req.body?.action;
    const actionKeys = { create: ['options'], vote: ['pollId', 'answers'], close: ['pollId'], adopt: ['pollId', 'optionId'] };
    if (!Object.hasOwn(actionKeys, action)) throw fail('时间投票操作无效。');
    keys(req.body, ['action', 'revision', 'idempotencyKey', ...actionKeys[action]]);
    const access = async row => {
      await requireVerified(req.user.id); await requireVerified(row.hostId);
      await requireDiscussion(row, req.user.id, true); upcoming(row);
      if (action !== 'vote') requireHost(row, req.user.id);
    };
    // An exact retry cannot restore access after departure, blocking or cancel.
    await access(await get(req.params.id));
    const { row } = await mutate(req.params.id, req.user.id, `poll:${action}`, req.body, async row => {
      await access(row);
      if (action === 'create') {
        if (row.timePoll?.status === 'open') throw fail('请先结束当前投票，再提出新时间。', 409);
        if (!Array.isArray(req.body.options) || req.body.options.length < 2 || req.body.options.length > 3) throw fail('请提供2至3个候选时间。');
        const options = req.body.options.map((option, index) => {
          keys(option, ['date', 'startTime', 'endTime']);
          if (Object.keys(option).length !== 3) throw fail('每个候选时间都需要日期、开始和结束时间。');
          const value = validateOutingInput({ ...row, ...option }, catalog, now());
          return { id: `option-${index + 1}`, date: value.date, startTime: value.startTime, endTime: value.endTime, startAt: value.startAt, endAt: value.endAt };
        });
        if (new Set(options.map(option => `${option.date}:${option.startTime}:${option.endTime}`)).size !== options.length) throw fail('候选时间不能重复。');
        row.timePoll = { id: `poll_${hash(`${row.id}:${req.body.idempotencyKey}`).slice(0, 40)}`, status: 'open', planVersion: row.planVersion, createdAt: now(), options, votes: [] };
        for (const item of confirmed(row)) addNotice(row, row.hostId, item.userId, '队长发起了时间投票，当前安排暂不变');
      } else {
        const poll = row.timePoll;
        if (!validId(req.body.pollId) || !poll || poll.id !== req.body.pollId || poll.status !== 'open' || poll.planVersion !== row.planVersion) throw fail('投票已结束或安排已变化，请刷新。', 409);
        if (action === 'vote') {
          keys(req.body.answers, poll.options.map(option => option.id));
          if (Object.keys(req.body.answers).length !== poll.options.length || Object.values(req.body.answers).some(answer => !['yes', 'maybe', 'no'].includes(answer))) throw fail('请为每个候选时间选择可以、待定或不行。');
          if (poll.options.every(option => option.startAt <= now())) throw fail('候选时间都已过去，请队长结束投票。', 409);
          const vote = { userId: req.user.id, answers: clone(req.body.answers), updatedAt: now() };
          poll.votes = poll.votes.filter(item => item.userId !== req.user.id).concat(vote);
        } else if (action === 'close') Object.assign(poll, { status: 'closed', closedAt: now(), closeReason: 'host-closed' });
        else {
          const selected = poll.options.find(option => option.id === req.body.optionId);
          if (!selected || selected.startAt <= now()) throw fail('这个候选时间无效或已开始，请选择其他时间。', 409);
          const next = validateOutingInput({ ...row, date: selected.date, startTime: selected.startTime, endTime: selected.endTime }, catalog, now());
          const changed = ['date', 'startTime', 'endTime'].some(key => next[key] !== row[key]);
          Object.assign(row, next);
          Object.assign(poll, { status: 'adopted', closedAt: now(), selectedOptionId: selected.id });
          if (changed) { row.planVersion++; member(row, row.hostId).confirmedVersion = row.planVersion; }
          for (const item of row.members.filter(item => ['requested', 'confirmed'].includes(item.status))) addNotice(row, row.hostId, item.userId, changed ? '投票时间已采用，请查看并重新确认安排' : '时间投票已结束，保留当前安排');
        }
      }
      return null;
    });
    res.json(await response(row, req.user.id));
  }));
  app.get(`${base}/:id/messages`, authenticateToken, limit(120), handler(async (req, res) => {
    const row = await get(req.params.id); await requireDiscussion(row, req.user.id);
    res.json({ messages: row.messages.slice(-100) });
  }));
  app.post(`${base}/:id/messages`, authenticateToken, limit(), handler(async (req, res) => {
    keys(req.body, ['text', 'revision', 'idempotencyKey']); const content = text(req.body.text, 2000, 1);
    // Even exact retries must not restore access after a member leaves or is removed.
    await requireDiscussion(await get(req.params.id), req.user.id, true);
    const { row, result } = await mutate(req.params.id, req.user.id, 'message', req.body, async row => {
      await requireDiscussion(row, req.user.id, true);
      if (row.messages.length >= MAX_MESSAGES) throw fail('本次讨论已达500条上限；仍可查看、退出或取消小队。', 409);
      const sender = await user(req.user.id), id = `outmsg_${hash(`${row.id}:${req.user.id}:${req.body.idempotencyKey}`).slice(0, 40)}`;
      row.messages.push({ id, outingId: row.id, senderId: req.user.id, senderName: sender.nickname || '湾区邻居', text: content, createdAt: now() }); return id;
    });
    res.json({ message: row.messages.find(message => message.id === result) });
  }));
  app.post(`${base}/:id/reports`, authenticateToken, limit(), handler(async (req, res) => {
    keys(req.body, ['reason', 'details', 'messageId']);
    if (!REASONS.has(req.body.reason)) throw fail('举报原因无效。');
    const detail = text(req.body.details || '', 1500), row = await get(req.params.id);
    let message;
    if (req.body.messageId !== undefined) {
      if (!validId(req.body.messageId)) throw fail('消息编号无效。');
      // Former confirmed members may report messages they could see, without reopening discussion access.
      const own = member(row, req.user.id);
      const visibleMessages = own?.status === 'confirmed' ? row.messages : own?.everConfirmed ? row.messages.slice(0, own.messageAccessThrough || 0) : [];
      message = visibleMessages.find(item => item.id === req.body.messageId);
      if (!own?.everConfirmed || !message) throw fail('无权举报这条讨论消息。', 403);
      if (!message) throw fail('讨论消息不存在。', 404);
    }
    const targetUserId = message?.senderId || row.hostId;
    if (targetUserId === req.user.id) throw fail('不能举报自己的内容。');
    const targetType = message ? 'outing_message' : 'outing', targetId = message?.id || row.id;
    if (deps.holdAccount) await deps.holdAccount(targetUserId);
    const reportId = `outreport_${hash(`${req.user.id}:${targetType}:${targetId}:${Math.floor(now() / DAY)}`).slice(0, 40)}`;
    const evidence = { title: row.title, date: row.date, startTime: row.startTime, endTime: row.endTime, city: row.city, venue: row.venue, description: row.description, ...(message ? { message: clone(message) } : {}) };
    await Report.updateOne({ id: reportId }, { $setOnInsert: { id: reportId, reporterId: req.user.id, reporterNickname: req.user.nickname || '', targetType, targetId, targetUserId, targetOutingId: row.id,
      evidence, reason: req.body.reason, detail, status: 'open', createdAt: now(), updatedAt: now() } }, { upsert: true, runValidators: true });
    res.json({ reportId });
  }));
  app.get('/api/admin/outings/:id', authenticateToken, requireAdmin, limit(120), handler(async (req, res) => {
    res.json({ outing: await dto(await get(req.params.id), null, false) });
  }));
  app.post('/api/admin/outings/:id/cancel', authenticateToken, requireAdmin, limit(), handler(async (req, res) => {
    keys(req.body, ['revision', 'idempotencyKey', 'reason']); const reason = text(req.body.reason, 500, 2);
    const { row, replayed } = await mutate(req.params.id, req.user.id, 'admin-cancel', req.body, async row => {
      if (row.status === 'cancelled') throw fail('小队已取消。', 409);
      row.status = 'cancelled'; for (const item of row.members.filter(item => ['requested', 'confirmed'].includes(item.status))) addNotice(row, req.user.id, item.userId, '管理员已取消小队'); return null;
    });
    if (!replayed) await createModerationLog({ admin: req.user, action: 'outing_cancelled', targetType: 'outing', targetId: row.id, targetUserId: row.hostId, reason });
    res.json(await response(row, req.user.id));
  }));
  return { catalog };
}

module.exports = { createOutingModel, registerOutings, loadOutingCatalog, validateOutingInput, validateOutingCover, MAX_MESSAGES, CONSENT };
