const crypto = require('node:crypto');

const TIMEZONE = 'America/Los_Angeles';
const CONSENT_VERSION = 'service-booking-sms-v1';
const CATEGORIES = new Set(['维修', '清洁', '接送', '搬家', '翻译', '其他', 'repair', 'cleaning', 'ride', 'moving', 'translation', 'other']);
const LIVE = new Set(['pending', 'confirmed']);
const DAY = 86400000;
const copy = value => JSON.parse(JSON.stringify(value));
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const id = value => typeof value === 'string' && /^[\w-]{1,140}$/.test(value);
const bodyKeys = (value, keys) => { if (!plain(value) || Object.keys(value).some(key => !keys.includes(key))) throw fail('预约请求格式无效。'); };
const defaults = () => ({ enabled: false, mode: 'request', minNoticeMinutes: 120, bufferMinutes: 30 });
const empty = providerId => ({ _id: hash(`service-provider:${providerId}`).slice(0, 24), providerId, revision: 0, settings: [], slots: [], bookings: [], operations: [], sms: { enabled: false } });
const accountActive = user => !!user && !user.isBanned && !['limited', 'suspended'].includes(user.accountStatus);
// The legacy OTP start updates the phone before verification and retains its old
// boolean badge. A newer unfinished challenge must not verify the replacement.
const phoneCurrent = user => user?.isPhoneVerified === true && !user.phoneVerificationCodeHash
  && (!user.phoneVerificationLastSentAt || (Number.isFinite(user.phoneVerifiedAt) && user.phoneVerifiedAt >= user.phoneVerificationLastSentAt));
const servicePost = post => !!post && post.type === 'provider' && CATEGORIES.has(post.category);
const publicPost = post => !!post && !post.isDeleted && !post.adminHidden && (!post.status || post.status === 'active');
const settingsFor = (agenda, postId) => ({ ...defaults(), ...agenda?.settings.find(item => item.postId === postId) });
const overlap = (a, b, buffers = false) => {
  const padding = buffers ? Math.max(a.bufferMinutes || 0, b.bufferMinutes || 0) * 60000 : 0;
  return a.startAt < b.endAt + padding && b.startAt < a.endAt + padding;
};

/** Resolve wall-clock time explicitly in LA, rejecting nonexistent and ambiguous DST minutes. */
function localInstant(date, time) {
  if (!/^20\d{2}-\d{2}-\d{2}$/.test(date || '') || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time || '')) throw fail('请填写有效的日期和24小时制时间。');
  const utc = Date.parse(`${date}T${time}:00Z`);
  if (!Number.isFinite(utc) || new Date(utc).toISOString().slice(0, 10) !== date) throw fail('日期无效。');
  const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const candidates = [7, 8].map(offset => utc + offset * 3600000).filter(instant => {
    const parts = Object.fromEntries(formatter.formatToParts(instant).map(part => [part.type, part.value]));
    return `${parts.year}-${parts.month}-${parts.day}` === date && `${parts.hour}:${parts.minute}` === time;
  });
  if (candidates.length !== 1) throw fail('这个洛杉矶时间位于夏令时切换的重复或缺失时段，请选择其他时间。');
  return candidates[0];
}
function parseSlot(value, now) {
  bodyKeys(value, ['date', 'startTime', 'endTime']);
  const startAt = localInstant(value.date, value.startTime), endAt = localInstant(value.date, value.endTime);
  if (endAt - startAt < 15 * 60000 || endAt - startAt > 12 * 3600000) throw fail('时段须为同一天的15分钟至12小时。');
  if (startAt <= now || startAt > now + 180 * DAY) throw fail('请选择未来180天内尚未开始的时段。');
  return { ...value, startAt, endAt, timezone: TIMEZONE };
}

function createServiceBookingModel(mongoose, injected = {}) {
  if (injected.ServiceBookingAgenda) return injected.ServiceBookingAgenda;
  const schema = new mongoose.Schema({
    providerId: { type: String, required: true, index: true }, revision: { type: Number, default: 0 },
    settings: { type: [mongoose.Schema.Types.Mixed], default: [] }, slots: { type: [mongoose.Schema.Types.Mixed], default: [] },
    bookings: { type: [mongoose.Schema.Types.Mixed], default: [] }, operations: { type: [mongoose.Schema.Types.Mixed], default: [] },
    sms: { type: mongoose.Schema.Types.Mixed, default: () => ({ enabled: false }) },
  });
  schema.index({ 'bookings.customerId': 1 });
  // Deterministic _id uses MongoDB's existing unique primary index, including first-write races.
  return mongoose.models.ServiceBookingAgenda || mongoose.model('ServiceBookingAgenda', schema);
}

function registerServiceBookings(app, deps) {
  const { Agenda, Post, User, UserBlock, Message, Conversation, authenticateToken, checkRateLimit, getClientIp, openConversation, emitMessage, officialStatus, config = {}, now = Date.now, sendSms, testSms } = deps;
  const verified = user => {
    const status = officialStatus(user);
    return phoneCurrent(user) || status === 'approved' || (status === 'none' && user?.isOfficialVerified === true);
  };
  const read = providerId => Agenda.findOne({ _id: empty(providerId)._id }).lean();
  const eventFor = (booking, actorId, change = '') => ({ id: `notice_${hash(`${booking.id}:${change || booking.status}`).slice(0, 32)}`, actorId, status: booking.status, at: now(), inApp: 'pending', sms: 'pending',
    // An outbox retry must describe the arrangement at the time of this event,
    // even if a later reschedule changed the booking before delivery recovered.
    snapshot: { postTitle: booking.postTitle, date: booking.date, startTime: booking.startTime, endTime: booking.endTime, ...(change ? { change: change.split(':')[0], reschedule: copy(booking.reschedule) } : {}) } });
  const expire = agenda => {
    for (const booking of agenda.bookings) if (booking.status === 'pending' && booking.expiresAt <= now()) {
      booking.status = 'expired'; booking.updatedAt = now(); booking.updates.push(eventFor(booking, booking.providerId));
    }
    for (const booking of agenda.bookings) if (booking.reschedule?.status === 'pending' && booking.reschedule.expiresAt <= now()) {
      booking.reschedule.status = 'expired'; booking.reschedule.resolvedAt = now(); booking.updatedAt = now();
      booking.updates.push(eventFor(booking, booking.reschedule.proposedBy, `reschedule_expired:${booking.reschedule.id}`));
    }
  };
  const mutate = async (providerId, transform) => {
    const seed = empty(providerId);
    try { await Agenda.updateOne({ _id: seed._id }, { $setOnInsert: seed }, { upsert: true, runValidators: true }); }
    catch (error) { if (error.code !== 11000) throw error; }
    for (let attempt = 0; attempt < 12; attempt++) {
      const current = await read(providerId);
      if (!current) throw fail('预约资料暂不可用，请稍后重试。', 503);
      const agenda = copy(current); expire(agenda);
      const result = await transform(agenda);
      const { _id, revision, __v, ...values } = agenda;
      const saved = await Agenda.findOneAndUpdate({ _id, revision }, { $set: values, $inc: { revision: 1 } }, { new: true, runValidators: true });
      if (saved) return { agenda: typeof saved.toObject === 'function' ? saved.toObject() : saved, result };
    }
    throw fail('时段刚被其他操作更新，请使用同一请求重试。', 409);
  };
  const load = async providerId => {
    const current = await read(providerId);
    if (!current) return empty(providerId);
    if (current.bookings.some(row => (row.status === 'pending' && row.expiresAt <= now()) || (row.reschedule?.status === 'pending' && row.reschedule.expiresAt <= now()))) return (await mutate(providerId, () => null)).agenda;
    return current;
  };
  const usersFor = async (a, b) => Promise.all([User.findOne({ id: a }).lean(), User.findOne({ id: b }).lean()]);
  const blocked = async (a, b) => !!await UserBlock.findOne({ $or: [{ blockerId: a, blockedUserId: b }, { blockerId: b, blockedUserId: a }] }).lean();
  const getPost = async postId => {
    if (!id(postId)) throw fail('服务编号无效。');
    const post = await Post.findOne({ id: postId }).lean();
    if (!post) throw fail('服务不存在。', 404);
    const owner = await User.findOne({ id: post.authorId }).lean();
    return { post, owner };
  };
  const requireProvider = ({ post, owner }, userId) => {
    if (post.authorId !== userId) throw fail('只有这条服务的发布者可以管理时段。', 403);
    if (!servicePost(post) || !publicPost(post)) throw fail('仅正常展示中的本地服务提供帖子可以开放预约。', 409);
    if (!accountActive(owner) || !verified(owner)) throw fail('服务者须先完成手机验证或通过官方认证，且账号状态正常。', 403);
  };
  const requireBookable = async ({ post, owner }, customerId) => {
    if (post.authorId === customerId) throw fail('不能预约自己的服务。');
    if (!servicePost(post) || !publicPost(post) || !accountActive(owner) || !verified(owner)) throw fail('这项服务当前不开放预约。', 409);
    const customer = await User.findOne({ id: customerId }).lean();
    if (!accountActive(customer) || await blocked(post.authorId, customerId)) throw fail('当前无法向这位服务者预约。', 403);
    return customer;
  };
  const unavailable = (slot, agenda, settings, exceptBookingId) => {
    if (!settings.enabled) return '服务者尚未开放预约。';
    if (slot.startAt <= now()) return '这个时段已开始或已过期。';
    if (slot.startAt < now() + settings.minNoticeMinutes * 60000) return '未满足服务者的最短提前预约时间。';
    if (agenda.bookings.some(row => row.id !== exceptBookingId && (LIVE.has(row.status) || row.status === 'completed') && overlap({ ...slot, bufferMinutes: settings.bufferMinutes }, row, true))) return '这个时段或相邻缓冲时间已有预约。';
    return '';
  };
  const availability = async postId => {
    const { post, owner } = await getPost(postId), agenda = await load(post.authorId), settings = settingsFor(agenda, post.id);
    const eligible = servicePost(post) && publicPost(post) && accountActive(owner) && verified(owner);
    return { eligible, providerVerified: verified(owner), ...settings, enabled: eligible && settings.enabled, timezone: TIMEZONE,
      ...(!eligible ? { reason: '本地服务提供者须通过手机验证或官方认证，且帖子与账号正常。' } : {}),
      slots: eligible ? agenda.slots.filter(slot => slot.postId === post.id).map(slot => { const reason = unavailable(slot, agenda, settings); return { ...slot, available: !reason, ...(reason ? { reason } : {}) }; }) : [],
    };
  };
  const operation = (agenda, actorId, scope, key, payload, run, booking) => {
    if (!id(key) || key.length < 8) throw fail('请使用8至140位的唯一请求编号。');
    const identity = hash(`${actorId}:${scope}:${key}`), fingerprint = hash(JSON.stringify(payload));
    // A booking can transition at most twice (confirm, then cancel/complete).
    // Keep those bounded receipts with the booking so a full creation journal
    // cannot trap existing reservations. Read old global receipts for compatibility.
    const records = booking ? (booking.actionOperations ||= []) : agenda.operations;
    const previous = records.find(row => row.id === identity) || (booking && agenda.operations.find(row => row.id === identity));
    if (previous) { if (previous.fingerprint !== fingerprint) throw fail('同一个请求编号不能用于不同内容。', 409); return previous.result; }
    if (records.length >= (booking ? 2 : 4000)) throw fail(booking ? '预约状态已变化，请刷新后再操作。' : '新增预约历史已达到当前容量；已有预约仍可处理，请联系平台。', 409);
    const result = run(); records.push({ id: identity, fingerprint, result }); return result;
  };
  const smsConfigured = () => config.SERVICE_BOOKING_SMS_ENABLED === 'true' && config.SERVICE_BOOKING_SMS_OPT_OUT_CONFIGURED === 'true'
    && !!config.TWILIO_MESSAGING_SERVICE_SID && (config.NODE_ENV === 'test' ? typeof testSms === 'function' : typeof sendSms === 'function');
  const smsEligible = user => accountActive(user) && phoneCurrent(user) && /^\+[1-9]\d{7,14}$/.test(user.phoneNormalized || '');
  const publicSms = (agenda, user) => ({ enabled: !!agenda.sms.enabled, eligible: smsEligible(user), configured: smsConfigured(), consentVersion: agenda.sms.consentVersion, consentedAt: agenda.sms.consentedAt });
  const publicBooking = booking => { const { updates, actionOperations, rescheduleOperations, rescheduleCount, ...value } = booking; return value; };
  const notifications = update => ({ inApp: update?.inApp === 'processing' ? 'pending' : update?.inApp || 'pending', sms: update?.sms === 'processing' ? 'pending' : update?.sms || 'pending' });
  const noticeText = booking => {
    const changes = { reschedule_proposed: '收到改期提议，待对方同意', reschedule_accepted: '双方已同意改期', reschedule_declined: '改期被婉拒，原预约保留', reschedule_withdrawn: '改期提议已撤回，原预约保留', reschedule_expired: '改期提议已过期，原预约保留' };
    const proposal = booking.change === 'reschedule_proposed' && booking.reschedule;
    return `BAYLINK 服务预约 · ${changes[booking.change] || { pending: '待服务者确认', confirmed: '已确认', declined: '已拒绝', cancelled: '已取消', expired: '申请已过期', completed: '已标记完成' }[booking.status]}\n${booking.postTitle}\n${booking.date} ${booking.startTime}–${booking.endTime}（洛杉矶时间）${proposal ? `\n提议时间：${proposal.date} ${proposal.startTime}–${proposal.endTime}\n对方同意且新时段仍可约后才会改期，原预约在此之前保留。` : ''}\n预约编号：${booking.id}\nhttps://www.baylink.us/me/bookings\n这是时间安排记录，不含支付；价格、地点和服务范围请双方另行确认。`;
  };

  // Durable, idempotent in-app outbox. SMS is at-most-once after claiming: an
  // ambiguous provider timeout/crash is shown as unknown and never auto-retried.
  const deliver = async (providerId, bookingId, eventId) => {
    const token = crypto.randomUUID();
    const claimed = await mutate(providerId, agenda => {
      const booking = agenda.bookings.find(row => row.id === bookingId), event = booking?.updates.find(row => row.id === eventId);
      if (!event) return false;
      if (event.inApp === 'processing' && now() - event.claimedAt < 120000) return false;
      if (!['pending', 'failed', 'processing'].includes(event.inApp) && event.sms !== 'pending') return false;
      event.claim = token; event.claimedAt = now();
      if (['pending', 'failed', 'processing'].includes(event.inApp)) event.inApp = 'processing';
      if (event.sms === 'processing') event.sms = 'unknown';
      return true;
    });
    if (!claimed.result) return;
    let booking = claimed.agenda.bookings.find(row => row.id === bookingId), event = booking.updates.find(row => row.id === eventId);
    const [owner, customer] = await usersFor(providerId, booking.customerId);
    const allowed = accountActive(owner) && accountActive(customer) && !await blocked(providerId, booking.customerId);
    let inApp = event.inApp, conversationId = booking.conversationId;
    if (inApp === 'processing') {
      if (!allowed) inApp = 'skipped';
      else try {
        const conversation = await openConversation(providerId, booking.customerId); conversationId = conversation.id;
        const digest = hash(`service-booking-notice:${eventId}`), _id = digest.slice(0, 24);
        let message;
        try { message = await Message.findOneAndUpdate({ _id }, { $setOnInsert: { id: `booking_${digest}`, conversationId, senderId: event.actorId,
          type: 'text', messageType: 'system', content: noticeText({ ...booking, ...event.snapshot, status: event.status }), createdAt: event.at, readBy: [] } }, { new: true, upsert: true, runValidators: true }); }
        catch (error) { if (error.code !== 11000) throw error; message = await Message.findOne({ _id }); if (!message) throw error; }
        await Conversation.findOneAndUpdate({ id: conversationId }, { $max: { updatedAt: event.at } });
        inApp = 'sent';
        // The durable message is authoritative even if a recipient is offline.
        try { await emitMessage(providerId, message); await emitMessage(booking.customerId, message); } catch { /* History reload recovers the persisted notice. */ }
      } catch { inApp = 'failed'; }
    }
    let sms = event.sms;
    if (sms === 'pending') {
      const consent = claimed.agenda.sms;
      if (event.actorId === providerId || !consent.enabled) sms = 'disabled';
      else if (!allowed || !smsEligible(owner) || consent.verifiedPhone !== owner.phoneNormalized) sms = 'not_eligible';
      else if (!smsConfigured()) sms = 'unconfigured';
      else {
        const smsClaim = await mutate(providerId, async agenda => { const update = agenda.bookings.find(row => row.id === bookingId).updates.find(row => row.id === eventId);
          const currentOwner = await User.findOne({ id: providerId }).lean();
          if (update.claim !== token || update.sms !== 'pending' || !agenda.sms.enabled || !smsEligible(currentOwner)
            || agenda.sms.verifiedPhone !== currentOwner.phoneNormalized || await blocked(providerId, booking.customerId)) return false;
          update.sms = 'processing'; return { to: currentOwner.phoneNormalized }; });
        if (smsClaim.result) {
          try {
            let timeout;
            const sent = await Promise.race([
              (config.NODE_ENV === 'test' ? testSms : sendSms)({ to: smsClaim.result.to, body: `${noticeText({ ...booking, ...event.snapshot, status: event.status })}\n回复 STOP 停止预约短信。`, eventId }),
              new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('SMS outcome unknown')), 5000); }),
            ]).finally(() => clearTimeout(timeout));
            sms = sent?.sid ? 'sent' : 'unknown';
          } catch (error) {
            sms = error?.code === 21610 ? 'failed' : 'unknown';
            if (error?.code === 21610) await mutate(providerId, agenda => { agenda.sms.enabled = false; agenda.sms.optedOutAt = now(); });
          }
        } else sms = 'disabled';
      }
    }
    await mutate(providerId, agenda => { const row = agenda.bookings.find(item => item.id === bookingId), update = row.updates.find(item => item.id === eventId);
      if (update.claim !== token) return;
      update.inApp = inApp; update.sms = sms; if (conversationId) row.conversationId = conversationId;
    });
  };
  const bookingResponse = async (providerId, bookingId, eventId) => {
    // Notification failures never roll back an already committed reservation.
    try { await deliver(providerId, bookingId, eventId); } catch { /* Stored pending/processing state remains truthful and retryable. */ }
    const agenda = await load(providerId), booking = agenda.bookings.find(row => row.id === bookingId);
    return { booking: publicBooking(booking), notifications: notifications(booking.updates.find(row => row.id === eventId)) };
  };
  const handler = fn => async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try { await fn(req, res); } catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : '预约暂不可用。若刚提交，请先查看我的预约，再使用相同请求重试。' }); }
  };
  const limit = (max = 40) => (req, res, next) => checkRateLimit(`service-bookings:${req.user?.id || getClientIp(req)}`, { windowMs: 60000, maxRequests: max }) ? next() : res.status(429).json({ error: '预约操作过于频繁，请稍后重试。' });
  const base = '/api/service-bookings';
  app.get(`${base}/posts/:postId`, limit(120), handler(async (req, res) => res.json(await availability(req.params.postId))));
  app.patch(`${base}/posts/:postId/settings`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['enabled', 'mode', 'minNoticeMinutes', 'bufferMinutes']);
    if (!Object.keys(req.body).length || ('enabled' in req.body && typeof req.body.enabled !== 'boolean') || ('mode' in req.body && !['request', 'instant'].includes(req.body.mode))
      || ('minNoticeMinutes' in req.body && ![0, 60, 120, 1440].includes(req.body.minNoticeMinutes)) || ('bufferMinutes' in req.body && ![0, 15, 30, 60].includes(req.body.bufferMinutes))) throw fail('预约设置无效。');
    const info = await getPost(req.params.postId); requireProvider(info, req.user.id);
    await mutate(req.user.id, async agenda => { requireProvider(await getPost(info.post.id), req.user.id); const next = { ...settingsFor(agenda, info.post.id), ...req.body, postId: info.post.id };
      agenda.settings = [...agenda.settings.filter(row => row.postId !== info.post.id), next];
      if (agenda.settings.length > 100) throw fail('最多管理100条服务的预约。');
    });
    res.json(await availability(info.post.id));
  }));
  app.post(`${base}/posts/:postId/slots`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['slots', 'idempotencyKey']);
    if (!Array.isArray(req.body.slots) || !req.body.slots.length || req.body.slots.length > 30) throw fail('一次可添加1至30个时段。');
    const info = await getPost(req.params.postId); requireProvider(info, req.user.id);
    const result = await mutate(req.user.id, async agenda => {
      requireProvider(await getPost(info.post.id), req.user.id);
      return operation(agenda, req.user.id, `slots:${info.post.id}`, req.body.idempotencyKey, req.body.slots, () => {
        const slots = req.body.slots.map(value => ({ ...parseSlot(value, now()), id: crypto.randomUUID(), postId: info.post.id }));
        for (let index = 0; index < slots.length; index++) if ([...agenda.slots.filter(row => row.endAt > now()), ...slots.slice(0, index)].some(row => overlap(row, slots[index]))) throw fail('同一服务者的可用时段不能重叠，包括其他服务帖子。', 409);
        agenda.slots = [...agenda.slots.filter(row => row.endAt > now()), ...slots];
        if (agenda.slots.length > 300) throw fail('最多保留300个未来时段。');
        return { slotIds: slots.map(row => row.id) };
      });
    });
    res.json({ ...await availability(info.post.id), ...result.result });
  }));
  app.delete(`${base}/posts/:postId/slots/:slotId`, authenticateToken, limit(), handler(async (req, res) => {
    const info = await getPost(req.params.postId);
    if (info.post.authorId !== req.user.id) throw fail('只有服务者可移除时段。', 403);
    await mutate(req.user.id, agenda => {
      if (agenda.bookings.some(row => row.slotId === req.params.slotId && LIVE.has(row.status))) throw fail('请先处理或取消这个时段的预约。', 409);
      agenda.slots = agenda.slots.filter(row => !(row.id === req.params.slotId && row.postId === info.post.id));
    });
    res.json(await availability(info.post.id));
  }));
  app.post(`${base}/posts/:postId/book`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['slotId', 'note', 'idempotencyKey']);
    if (!id(req.body.slotId) || (req.body.note !== undefined && (typeof req.body.note !== 'string' || req.body.note.length > 500 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(req.body.note)))) throw fail('请选择时段，备注最多500字。');
    const info = await getPost(req.params.postId); await requireBookable(info, req.user.id);
    const result = await mutate(info.post.authorId, async agenda => {
      const current = await getPost(info.post.id), customer = await requireBookable(current, req.user.id);
      return operation(agenda, req.user.id, `book:${info.post.id}`, req.body.idempotencyKey, { slotId: req.body.slotId, note: req.body.note || '' }, () => {
        const settings = settingsFor(agenda, info.post.id), slot = agenda.slots.find(row => row.id === req.body.slotId && row.postId === info.post.id);
        if (!slot) throw fail('这个时段已移除，请重新选择。', 409);
        const reason = unavailable(slot, agenda, settings); if (reason) throw fail(reason, 409);
        if (agenda.bookings.filter(row => row.customerId === req.user.id && LIVE.has(row.status) && row.endAt > now()).length >= 5) throw fail('你向这位服务者已有5个有效预约，请先处理后再添加。', 429);
        if (agenda.bookings.length >= 2000) throw fail('服务者的预约历史已达到当前容量，请联系平台。', 409);
        const booking = { ...slot, id: crypto.randomUUID(), slotId: slot.id, providerId: info.post.authorId, customerId: req.user.id,
          providerName: current.owner.nickname || '服务者', customerName: customer.nickname || '客户', postTitle: current.post.title,
          status: settings.mode === 'instant' ? 'confirmed' : 'pending', note: req.body.note?.trim() || '', bufferMinutes: settings.bufferMinutes,
          createdAt: now(), updatedAt: now(), ...(settings.mode === 'request' ? { expiresAt: Math.min(now() + DAY, slot.startAt) } : {}), updates: [] };
        const event = eventFor(booking, req.user.id); booking.updates.push(event); agenda.bookings.push(booking);
        return { bookingId: booking.id, eventId: event.id };
      });
    });
    res.json(await bookingResponse(info.post.authorId, result.result.bookingId, result.result.eventId));
  }));
  app.post(`${base}/:providerId/:bookingId/actions`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['action', 'idempotencyKey']);
    if (!id(req.params.providerId) || !id(req.params.bookingId) || !['confirm', 'decline', 'cancel', 'complete'].includes(req.body.action)) throw fail('预约操作无效。');
    const existing = await read(req.params.providerId), ownBooking = existing?.bookings.find(row => row.id === req.params.bookingId);
    if (!ownBooking || ![ownBooking.providerId, ownBooking.customerId].includes(req.user.id)) throw fail('没有这份预约的访问权限。', 404);
    const result = await mutate(req.params.providerId, async agenda => {
      const booking = agenda.bookings.find(row => row.id === req.params.bookingId);
      if (!booking || ![booking.providerId, booking.customerId].includes(req.user.id)) throw fail('没有这份预约的访问权限。', 404);
      if (req.body.action !== 'cancel' && req.user.id !== booking.providerId) throw fail('只有服务者可以执行这个操作。', 403);
      if (req.body.action === 'confirm') await requireBookable(await getPost(booking.postId), booking.customerId);
      return operation(agenda, req.user.id, `action:${booking.id}`, req.body.idempotencyKey, { action: req.body.action }, () => {
        const next = { confirm: 'confirmed', decline: 'declined', cancel: 'cancelled', complete: 'completed' }[req.body.action];
        if (booking.status === 'pending' && booking.expiresAt <= now()) throw fail('预约申请已过期，请刷新后重新选择时段。', 409);
        const permitted = req.body.action === 'confirm' || req.body.action === 'decline' ? booking.status === 'pending'
          : req.body.action === 'cancel' ? LIVE.has(booking.status) : booking.status === 'confirmed' && now() >= booking.endAt;
        if (!permitted) throw fail('预约状态已变化，或尚未结束，请刷新后再操作。', 409);
        if (req.body.action === 'confirm' && booking.startAt <= now()) throw fail('预约已开始，不能补确认。', 409);
        booking.status = next; booking.updatedAt = now();
        if (!LIVE.has(next) && booking.reschedule?.status === 'pending') { booking.reschedule.status = 'cancelled'; booking.reschedule.resolvedAt = now(); }
        const event = eventFor(booking, req.user.id); booking.updates.push(event);
        return { bookingId: booking.id, eventId: event.id };
      }, booking);
    });
    res.json(await bookingResponse(req.params.providerId, result.result.bookingId, result.result.eventId));
  }));
  const participantBooking = async req => {
    if (!id(req.params.providerId) || !id(req.params.bookingId)) throw fail('预约编号无效。');
    const agenda = await read(req.params.providerId), booking = agenda?.bookings.find(row => row.id === req.params.bookingId);
    if (!booking || ![booking.providerId, booking.customerId].includes(req.user.id)) throw fail('没有这份预约的访问权限。', 404);
    return booking;
  };
  app.get(`${base}/:providerId/:bookingId/reschedule-options`, authenticateToken, limit(120), handler(async (req, res) => {
    const own = await participantBooking(req), agenda = await load(own.providerId), booking = agenda.bookings.find(row => row.id === own.id);
    await requireBookable(await getPost(booking.postId), booking.customerId);
    if (booking.status !== 'confirmed' || booking.startAt <= now()) throw fail('只有尚未开始的已确认预约可以改期。', 409);
    const settings = settingsFor(agenda, booking.postId);
    res.json({ bookingId: booking.id, slots: agenda.slots.filter(slot => slot.postId === booking.postId && slot.id !== booking.slotId).map(slot => {
      const reason = unavailable(slot, agenda, settings, booking.id); return { ...slot, available: !reason, ...(reason ? { reason } : {}) };
    }) });
  }));
  app.post(`${base}/:providerId/:bookingId/reschedule`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['action', 'slotId', 'proposalId', 'idempotencyKey']);
    const { action, slotId, proposalId, idempotencyKey } = req.body;
    if (!['propose', 'accept', 'decline', 'withdraw'].includes(action) || !id(idempotencyKey) || idempotencyKey.length < 8
      || (action === 'propose' ? !id(slotId) || proposalId !== undefined : !id(proposalId) || slotId !== undefined)) throw fail('改期请求格式无效。');
    await participantBooking(req);
    const result = await mutate(req.params.providerId, async agenda => {
      const booking = agenda.bookings.find(row => row.id === req.params.bookingId);
      if (!booking || ![booking.providerId, booking.customerId].includes(req.user.id)) throw fail('没有这份预约的访问权限。', 404);
      const identity = hash(`${req.user.id}:reschedule:${booking.id}:${idempotencyKey}`), fingerprint = hash(JSON.stringify({ action, slotId, proposalId }));
      const receipts = booking.rescheduleOperations ||= [], previous = receipts.find(row => row.id === identity);
      if (previous) { if (previous.fingerprint !== fingerprint) throw fail('同一个请求编号不能用于不同内容。', 409); return previous.result; }
      if (booking.status !== 'confirmed' || booking.startAt <= now()) throw fail('只有尚未开始的已确认预约可以改期。', 409);
      // Declining/withdrawing remains possible after a listing closes or a block.
      // Only new proposals and acceptance need current booking eligibility.
      if (action === 'propose' || action === 'accept') await requireBookable(await getPost(booking.postId), booking.customerId);
      if (booking.startAt <= now()) throw fail('预约已开始，不能改期。', 409);
      const settings = settingsFor(agenda, booking.postId);
      let change;
      if (action === 'propose') {
        if (booking.reschedule?.status === 'pending') throw fail('已有待回应的改期提议，请先处理或撤回。', 409);
        if ((booking.rescheduleCount || 0) >= 30) throw fail('这份预约的改期次数已达上限；仍可处理现有提议或取消预约。', 409);
        const slot = agenda.slots.find(row => row.id === slotId && row.postId === booking.postId);
        if (!slot || slot.id === booking.slotId) throw fail('请选择另一个已发布的时段。', 409);
        const reason = unavailable(slot, agenda, settings, booking.id); if (reason) throw fail(reason, 409);
        booking.reschedule = { id: crypto.randomUUID(), slotId: slot.id, proposedBy: req.user.id, status: 'pending', createdAt: now(),
          expiresAt: Math.min(now() + DAY, booking.startAt, slot.startAt), date: slot.date, startTime: slot.startTime, endTime: slot.endTime, startAt: slot.startAt, endAt: slot.endAt };
        booking.rescheduleCount = (booking.rescheduleCount || 0) + 1; change = 'reschedule_proposed';
      } else {
        const proposal = booking.reschedule;
        if (!proposal || proposal.id !== proposalId || proposal.status !== 'pending' || proposal.expiresAt <= now()) throw fail('改期提议已变化或过期，请刷新预约。', 409);
        if (action === 'withdraw' ? proposal.proposedBy !== req.user.id : proposal.proposedBy === req.user.id) throw fail(action === 'withdraw' ? '只有提议者可以撤回。' : '只有对方可以同意或婉拒改期。', 403);
        if (action === 'accept') {
          const slot = agenda.slots.find(row => row.id === proposal.slotId && row.postId === booking.postId);
          if (!slot || slot.startAt !== proposal.startAt || slot.endAt !== proposal.endAt) throw fail('提议的时段已移除或改变，原预约仍保留。', 409);
          const reason = unavailable(slot, agenda, settings, booking.id); if (reason) throw fail(`${reason}原预约仍保留。`, 409);
          // One agenda CAS moves the existing booking; no cancel/rebook gap.
          Object.assign(booking, { slotId: slot.id, date: slot.date, startTime: slot.startTime, endTime: slot.endTime, startAt: slot.startAt, endAt: slot.endAt, bufferMinutes: settings.bufferMinutes });
        }
        proposal.status = { accept: 'accepted', decline: 'declined', withdraw: 'withdrawn' }[action]; proposal.resolvedAt = now();
        change = `reschedule_${proposal.status}`;
      }
      booking.updatedAt = now(); const event = eventFor(booking, req.user.id, `${change}:${booking.reschedule.id}`); booking.updates.push(event);
      const result = { bookingId: booking.id, eventId: event.id }; receipts.push({ id: identity, fingerprint, result }); return result;
    });
    res.json(await bookingResponse(req.params.providerId, result.result.bookingId, result.result.eventId));
  }));
  app.get(`${base}/me`, authenticateToken, limit(120), handler(async (req, res) => {
    const docs = await Agenda.find({ $or: [{ providerId: req.user.id }, { 'bookings.customerId': req.user.id }] }).lean();
    const asProvider = [], asCustomer = []; let drained = 0;
    for (const doc of docs) {
      let agenda = await load(doc.providerId);
      for (const booking of agenda.bookings) {
        if (booking.providerId !== req.user.id && booking.customerId !== req.user.id) continue;
        for (const update of booking.updates) if (drained < 5 && (['pending', 'failed'].includes(update.inApp) || (update.inApp === 'processing' && now() - update.claimedAt >= 120000))) {
          drained++;
          try { await deliver(doc.providerId, booking.id, update.id); } catch { /* Reading reservations must remain available when notifications fail. */ }
        }
      }
      if (drained) agenda = await load(doc.providerId);
      for (const booking of agenda.bookings) {
        if (booking.providerId !== req.user.id && booking.customerId !== req.user.id) continue;
        const row = { ...publicBooking(booking), notifications: notifications(booking.updates.at(-1)) };
        (booking.providerId === req.user.id ? asProvider : asCustomer).push(row);
      }
    }
    const sort = (a, b) => b.createdAt - a.createdAt;
    const user = await User.findOne({ id: req.user.id }).lean();
    res.json({ asCustomer: asCustomer.sort(sort), asProvider: asProvider.sort(sort), sms: publicSms(await load(req.user.id), user) });
  }));
  app.patch(`${base}/sms-settings`, authenticateToken, limit(), handler(async (req, res) => {
    bodyKeys(req.body, ['enabled']); if (typeof req.body.enabled !== 'boolean') throw fail('短信设置无效。');
    const user = await User.findOne({ id: req.user.id }).lean();
    if (req.body.enabled && !smsEligible(user)) throw fail('先验证可接收短信的手机号，才能单独开启预约通知。', 403);
    if (req.body.enabled && !smsConfigured()) throw fail('预约短信尚未配置完成；站内预约和私信通知仍可使用。', 409);
    const result = await mutate(req.user.id, agenda => { agenda.sms = req.body.enabled
      ? { enabled: true, consentVersion: CONSENT_VERSION, consentedAt: now(), verifiedPhone: user.phoneNormalized }
      : { ...agenda.sms, enabled: false, optedOutAt: now() }; });
    res.json({ sms: publicSms(result.agenda, user) });
  }));
  return { load, mutate };
}

module.exports = { TIMEZONE, CONSENT_VERSION, localInstant, parseSlot, overlap, createServiceBookingModel, registerServiceBookings };
