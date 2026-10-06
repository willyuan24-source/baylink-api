const crypto = require('node:crypto');

const HALF_HOUR = 30 * 60 * 1000;
const DAY = 86400000;
const TOPICS = Object.freeze(['message', 'contact_request', 'outing_request']);
const CHANNELS = Object.freeze(['email', 'sms']);
const ACTIVE = user => !!user && !user.isBanned && !user.accountDeletionPending && !['suspended', 'deleted'].includes(user.accountStatus);
const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const emailOf = user => String(user?.email || '').trim().toLowerCase();
const emailHash = user => hash(`email:${emailOf(user)}`);
const phoneOf = user => String(user?.phoneNormalized || '').trim();
const emptyPreferences = () => Object.fromEntries(CHANNELS.map(channel => [channel, Object.fromEntries(TOPICS.map(topic => [topic, false]))]));
const fail = (message, status = 400, code) => Object.assign(new Error(message), { status, code });
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(value);
const safeLocale = value => ['en', 'zh-Hant'].includes(value) ? value : 'zh-Hans';
const utcDay = at => new Date(at).toISOString().slice(0, 10);
const plain = row => row && typeof row.toObject === 'function' ? row.toObject() : row;
const lean = query => typeof query?.lean === 'function' ? query.lean() : query;

function createNotificationModels(mongoose, injected = {}) {
  const create = (name, fields, indexes = []) => {
    if (injected[name]) return injected[name];
    const schema = new mongoose.Schema(fields, { strict: 'throw', versionKey: false });
    for (const [keys, options] of indexes) schema.index(keys, options);
    return mongoose.models[name] || mongoose.model(name, schema);
  };
  return {
    NotificationAccount: create('NotificationAccount', {
      _id: String, userId: { type: String, required: true }, revision: Number, consentRevision: Number,
      preferences: { type: mongoose.Schema.Types.Mixed, required: true }, locale: String,
      verifiedEmailHash: String, emailVerifiedAt: Number, requestDay: String, requests: Number, lastRequestedAt: Number,
    }, [[{ userId: 1 }, { unique: true }]]),
    NotificationToken: create('NotificationToken', {
      _id: String, recipientId: String, purpose: { type: String, enum: ['verify', 'unsubscribe'] }, channel: String,
      emailHash: String, sealed: { type: String, select: false }, usedAt: Number, expiresAt: Date,
    }, [[{ expiresAt: 1 }, { expireAfterSeconds: 0 }], [{ recipientId: 1 }, {}]]),
    NotificationJob: create('NotificationJob', {
      _id: String, recipientId: String, actorId: String, topic: String, channel: String, scope: String,
      consentRevision: Number, targetHash: String, locale: String, linkPath: String, tokenId: String,
      status: { type: String, enum: ['queued', 'sending', 'sent', 'cancelled', 'failed', 'unknown'] },
      availableAt: Number, createdAt: Number, expiresAt: Date, attempts: Number, claim: String, leaseUntil: Number, providerId: String, budgetReserved: Boolean,
    }, [[{ status: 1, availableAt: 1 }, {}], [{ recipientId: 1 }, {}], [{ expiresAt: 1 }, { expireAfterSeconds: 0 }]]),
    NotificationWindow: create('NotificationWindow', {
      _id: String, recipientId: String, lastSentAt: Number, claim: String, leaseUntil: Number, expiresAt: Date,
    }, [[{ expiresAt: 1 }, { expireAfterSeconds: 0 }], [{ recipientId: 1 }, {}]]),
    NotificationBudget: create('NotificationBudget', {
      _id: String, count: Number, users: { type: mongoose.Schema.Types.Mixed, required: true }, expiresAt: Date,
    }, [[{ expiresAt: 1 }, { expireAfterSeconds: 0 }]]),
  };
}

function trustedOrigin(config = {}) {
  const raw = config.NOTIFICATION_FRONTEND_URL || 'https://www.baylink.us';
  const url = new URL(raw);
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || (url.protocol !== 'https:' && !(config.NODE_ENV !== 'production' && url.hostname === 'localhost' && url.protocol === 'http:'))
    || (config.NODE_ENV === 'production' && !['www.baylink.us', 'baylink.us'].includes(url.hostname))) throw new Error('Invalid notification frontend origin');
  return url.origin;
}

function createNotificationService(deps) {
  const { User, UserBlock, NotificationAccount: Account, NotificationToken: Token, NotificationJob: Job, NotificationWindow: Window, NotificationBudget: Budget } = deps;
  const config = deps.config || {}, now = deps.now || Date.now, origin = trustedOrigin(config);
  const enabled = config.NOTIFICATION_DELIVERY_ENABLED === 'true';
  const configuredLimit = (value, fallback) => /^\d+$/.test(String(value ?? '')) ? Math.min(100000, Number(value)) : fallback;
  // Tests must supply isolated queue models. Existing tests never fall through to Mongo or providers.
  const ready = !deps.isTest || deps.isolated === true;
  const secret = config.NOTIFICATION_TOKEN_KEY || config.JWT_SECRET;
  const key = secret ? crypto.createHash('sha256').update(`baylink:notification-tokens:${secret}`).digest() : null;
  const seal = value => {
    if (!key) throw fail('邮箱验证暂不可用。', 503);
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const bytes = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), bytes]).toString('base64url');
  };
  const unseal = value => {
    const bytes = Buffer.from(value, 'base64url'), decipher = crypto.createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
  };
  const getUser = async id => plain(await lean(User.findOne({ id })));
  const getAccount = async id => {
    try {
      return plain(await Account.findOneAndUpdate({ _id: hash(`account:${id}`) }, { $setOnInsert: {
        userId: id, revision: 0, consentRevision: 0, preferences: emptyPreferences(), locale: 'zh-Hans', requests: 0, lastRequestedAt: 0,
      } }, { upsert: true, new: true, runValidators: true }));
    } catch (error) {
      if (error.code !== 11000) throw error;
      return plain(await lean(Account.findOne({ userId: id })));
    }
  };
  const blocked = async (actorId, recipientId) => actorId && UserBlock && await UserBlock.exists({ $or: [
    { blockerId: actorId, blockedUserId: recipientId }, { blockerId: recipientId, blockedUserId: actorId },
  ] });
  const verifiedEmail = (user, account) => ACTIVE(user) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailOf(user)) && account?.verifiedEmailHash === emailHash(user);
  const verifiedPhone = user => ACTIVE(user) && user.isPhoneVerified === true && /^\+[1-9]\d{7,14}$/.test(phoneOf(user));
  const dto = (user, account) => ({
    preferences: emptyPreferencesWith(account?.preferences), locale: safeLocale(account?.locale),
    emailVerified: !!verifiedEmail(user, account), phoneVerified: !!verifiedPhone(user),
    deliveryEnabled: enabled, emailDeliveryAvailable: enabled && typeof deps.sendEmail === 'function', smsDeliveryAvailable: enabled && typeof deps.sendSms === 'function',
  });
  const ensureReady = () => { if (!ready) throw fail('通知设置暂不可用。', 503); };
  const preferences = async id => { ensureReady(); const user = await getUser(id); if (!ACTIVE(user)) throw fail('账号当前不可用。', 403); return dto(user, await getAccount(id)); };
  const updatePreferences = async (id, payload) => {
    ensureReady();
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).some(key => !['preferences', 'locale'].includes(key))) throw fail('通知设置格式无效。');
    const patch = payload.preferences;
    if (patch !== undefined && (!patch || typeof patch !== 'object' || Array.isArray(patch) || Object.keys(patch).some(key => !CHANNELS.includes(key)))) throw fail('通知渠道无效。');
    if (payload.locale !== undefined && !['zh-Hans', 'zh-Hant', 'en'].includes(payload.locale)) throw fail('通知语言无效。');
    const user = await getUser(id); if (!ACTIVE(user)) throw fail('账号当前不可用。', 403);
    for (let attempt = 0; attempt < 8; attempt++) {
      const account = await getAccount(id), next = emptyPreferencesWith(account.preferences);
      for (const [channel, values] of Object.entries(patch || {})) {
        if (!values || typeof values !== 'object' || Array.isArray(values) || Object.entries(values).some(([topic, value]) => !TOPICS.includes(topic) || typeof value !== 'boolean')) throw fail('请选择明确的通知选项。');
        if (Object.values(values).includes(true) && !(channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user))) throw fail(channel === 'email' ? '请先验证当前邮箱。' : '请先验证当前手机号。', 409, 'NOTIFICATION_VERIFICATION_REQUIRED');
        Object.assign(next[channel], values);
      }
      const saved = await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, {
        $set: { preferences: next, locale: payload.locale || account.locale }, $inc: { revision: 1, consentRevision: 1 },
      }, { new: true, runValidators: true });
      if (saved) {
        // A new consent epoch prevents a later opt-in from reviving old queued work.
        await Job.updateMany({ recipientId: id, topic: { $ne: 'verify' }, status: 'queued', consentRevision: { $ne: saved.consentRevision } }, { $set: { status: 'cancelled' } });
        return dto(user, plain(saved));
      }
    }
    throw fail('通知设置正在更新，请重试。', 409);
  };
  const token = async (recipientId, purpose, channel, targetHash, lifetime) => {
    const raw = crypto.randomBytes(32).toString('base64url'), id = hash(raw);
    await Token.create({ _id: id, recipientId, purpose, channel, emailHash: targetHash, sealed: seal(raw), usedAt: 0, expiresAt: new Date(now() + lifetime) });
    return id;
  };
  const startEmailVerification = async id => {
    ensureReady(); const user = await getUser(id);
    if (!ACTIVE(user) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailOf(user))) throw fail('当前账号邮箱不可用。', 403);
    const at = now(), day = utcDay(at);
    for (let attempt = 0; attempt < 8; attempt++) {
      const account = await getAccount(id);
      if (verifiedEmail(user, account)) return { ...dto(user, account), alreadyVerified: true };
      if (account.lastRequestedAt > at - 60000 || (account.requestDay === day && account.requests >= 5)) throw fail('验证邮件请求过于频繁，请稍后再试。', 429);
      const reserved = await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, { $set: { requestDay: day, requests: account.requestDay === day ? account.requests + 1 : 1, lastRequestedAt: at }, $inc: { revision: 1 } }, { new: true });
      if (!reserved) continue;
      const tokenId = await token(id, 'verify', 'email', emailHash(user), HALF_HOUR);
      await Job.create({ _id: hash(`verify:${tokenId}`), recipientId: id, topic: 'verify', channel: 'email', targetHash: emailHash(user), locale: safeLocale(account.locale), tokenId,
        status: 'queued', createdAt: at, availableAt: at, attempts: 0, expiresAt: new Date(at + HALF_HOUR) });
      return { ...dto(user, plain(reserved)), queued: true, expiresInSeconds: 1800 };
    }
    throw fail('验证邮件正在准备，请稍后重试。', 409);
  };
  const consumeToken = async (raw, purpose) => {
    ensureReady();
    if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(raw)) throw fail('链接无效或已过期。');
    const row = plain(await lean(Token.findOne({ _id: hash(raw), purpose, usedAt: 0, expiresAt: { $gt: new Date(now()) } })));
    if (!row) throw fail('链接无效、已使用或已过期。');
    const user = await getUser(row.recipientId);
    if (!ACTIVE(user) || (purpose === 'verify' && row.emailHash !== emailHash(user))) throw fail('链接无效或邮箱已更改。');
    const used = await Token.findOneAndUpdate({ _id: row._id, usedAt: 0, expiresAt: { $gt: new Date(now()) } }, { $set: { usedAt: now() || 1 }, $unset: { sealed: '' } }, { new: true });
    if (!used) throw fail('链接已经使用。');
    return { row, user };
  };
  const verifyEmail = async raw => {
    const { row, user } = await consumeToken(raw, 'verify');
    await getAccount(row.recipientId);
    await Account.updateOne({ userId: row.recipientId }, { $set: { verifiedEmailHash: row.emailHash, emailVerifiedAt: now() }, $inc: { revision: 1 } });
    await Job.updateMany({ recipientId: row.recipientId, topic: 'verify', status: 'queued' }, { $set: { status: 'cancelled' } });
    return { ok: true, emailVerified: true };
  };
  const unsubscribe = async raw => {
    const { row } = await consumeToken(raw, 'unsubscribe');
    if (!CHANNELS.includes(row.channel)) throw fail('链接无效。');
    await Account.updateOne({ userId: row.recipientId }, { $set: { [`preferences.${row.channel}`]: Object.fromEntries(TOPICS.map(topic => [topic, false])) }, $inc: { revision: 1, consentRevision: 1 } });
    await Job.updateMany({ recipientId: row.recipientId, channel: row.channel, topic: { $ne: 'verify' }, status: 'queued' }, { $set: { status: 'cancelled' } });
    return { ok: true };
  };
  const enqueueEvent = async event => {
    if (!ready) return { skipped: true };
    if (!event || !TOPICS.includes(event.topic) || !validId(event.recipientId) || !validId(event.actorId) || !validId(event.sourceId) || !validId(event.eventId) || event.recipientId === event.actorId) return { skipped: true };
    const at = Number.isSafeInteger(event.createdAt) ? event.createdAt : now();
    // No backfill: both old and future events are refused, including recovered legacy system messages.
    if (at < now() - 5 * 60 * 1000 || at > now() + 60000) return { skipped: true };
    const user = await getUser(event.recipientId), actor = await getUser(event.actorId);
    if (!ACTIVE(user) || !ACTIVE(actor) || await blocked(event.actorId, event.recipientId)) return { skipped: true };
    const account = await getAccount(event.recipientId), prefs = emptyPreferencesWith(account.preferences);
    const scope = `${event.topic}:${event.sourceId}`;
    const linkPath = event.topic === 'message' ? `/messages/${encodeURIComponent(event.sourceId)}` : event.topic === 'contact_request' ? '/me' : `/together?outing=${encodeURIComponent(event.sourceId)}`;
    let queued = 0;
    for (const channel of CHANNELS) {
      if (!prefs[channel][event.topic] || !(channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user))) continue;
      const id = hash(`${event.recipientId}:${channel}:${scope}:${Math.floor(at / HALF_HOUR)}`);
      const targetHash = channel === 'email' ? emailHash(user) : hash(`phone:${phoneOf(user)}`);
      // One immutable generic notice covers every event in this conversation/window.
      // The payload remains stable for provider idempotency even if more messages arrive.
      const existing = await lean(Job.findOne({ _id: id })); if (existing) continue;
      const tokenId = await token(event.recipientId, 'unsubscribe', channel, targetHash, 30 * DAY);
      try {
        await Job.updateOne({ _id: id }, { $setOnInsert: { recipientId: event.recipientId, actorId: event.actorId, topic: event.topic, channel, scope,
          consentRevision: account.consentRevision, targetHash, locale: safeLocale(account.locale), linkPath, tokenId, status: 'queued', createdAt: at,
          availableAt: at + HALF_HOUR, attempts: 0, expiresAt: new Date(at + DAY) } }, { upsert: true, runValidators: true });
        queued++;
      } catch (error) { if (error.code !== 11000) throw error; }
    }
    return { queued };
  };
  const link = (path, locale) => `${origin}${locale === 'en' ? '/en' : locale === 'zh-Hant' ? '/zh-Hant' : ''}${path}`;
  const content = async job => {
    const item = plain(await Token.findOne({ _id: job.tokenId, usedAt: 0, expiresAt: { $gt: new Date(now()) } }).select('+sealed'));
    if (!item?.sealed) return null;
    const raw = unseal(item.sealed);
    const hant = job.locale === 'zh-Hant';
    if (job.topic === 'verify') {
      const href = link(`/verify-email#token=${raw}`, job.locale);
      return { subject: job.locale === 'en' ? 'Verify your BAYLINK email' : hant ? '驗證你的 BAYLINK 信箱' : '验证你的 BAYLINK 邮箱', text: job.locale === 'en' ? `Verify your email within 30 minutes: ${href}\nIf you did not request this, ignore this email.` : hant ? `請在30分鐘內驗證信箱：${href}\n如果不是你本人請求，請忽略這封郵件。` : `请在30分钟内验证邮箱：${href}\n如果不是你本人请求，请忽略这封邮件。` };
    }
    const labels = job.locale === 'en' ? { message: 'new messages', contact_request: 'a new contact request', outing_request: 'a new team application' } : hant ? { message: '新的站內訊息', contact_request: '新的聯絡請求', outing_request: '新的小隊申請' } : { message: '新的站内消息', contact_request: '新的联系请求', outing_request: '新的小队申请' };
    const href = link(job.linkPath, job.locale), optout = link(`/notifications/unsubscribe#token=${raw}`, job.locale);
    return { subject: job.locale === 'en' ? 'BAYLINK account notification' : hant ? 'BAYLINK 站內通知' : 'BAYLINK 站内通知', text: job.locale === 'en'
      ? `You have ${labels[job.topic]} on BAYLINK. Sign in to view: ${href}\nTurn off these notifications: ${optout}`
      : hant ? `你在 BAYLINK 收到${labels[job.topic]}，請登入查看：${href}\n關閉此渠道通知：${optout}` : `你在 BAYLINK 收到${labels[job.topic]}，请登录查看：${href}\n关闭此渠道通知：${optout}` };
  };
  const runOnce = async (maximum = 10) => {
    if (!ready || !enabled) return { processed: 0, disabled: true };
    const at = now();
    // A process that died during SMS submission may have reached Twilio. Never blindly resend.
    await Job.updateMany({ status: 'sending', channel: 'sms', leaseUntil: { $lte: at } }, { $set: { status: 'unknown' } });
    await Job.updateMany({ status: 'sending', channel: 'email', leaseUntil: { $lte: at }, createdAt: { $lte: at - 23 * 60 * 60 * 1000 } }, { $set: { status: 'unknown' } });
    await Job.updateMany({ status: 'sending', channel: 'email', leaseUntil: { $lte: at }, createdAt: { $gt: at - 23 * 60 * 60 * 1000 } }, { $set: { status: 'queued', availableAt: at } });
    const rows = await lean(Job.find({ status: 'queued', availableAt: { $lte: at } }).sort({ availableAt: 1 }).limit(Math.min(20, Math.max(1, maximum))));
    let processed = 0;
    for (const value of rows) {
      const claim = crypto.randomUUID(), job = plain(await Job.findOneAndUpdate({ _id: value._id, status: 'queued' }, { $set: { status: 'sending', claim, leaseUntil: now() + 120000 }, $inc: { attempts: 1 } }, { new: true }));
      if (!job) continue;
      const finish = (status, extra = {}) => Job.updateOne({ _id: job._id, status: 'sending', claim }, { $set: { status, ...extra }, $unset: { claim: '', leaseUntil: '' } });
      const user = await getUser(job.recipientId), actor = job.actorId ? await getUser(job.actorId) : null, account = plain(await lean(Account.findOne({ userId: job.recipientId })));
      const valid = ACTIVE(user) && new Date(job.expiresAt).getTime() > now() && (job.channel === 'email' ? emailHash(user) === job.targetHash : hash(`phone:${phoneOf(user)}`) === job.targetHash)
        && (job.topic === 'verify' || (ACTIVE(actor) && !await blocked(job.actorId, job.recipientId) && account?.consentRevision === job.consentRevision
          && account.preferences?.[job.channel]?.[job.topic] === true && (job.channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user))));
      if (!valid) { await finish('cancelled'); continue; }
      const sender = job.channel === 'email' ? deps.sendEmail : deps.sendSms;
      if (typeof sender !== 'function') { await finish('queued', { availableAt: now() + 5 * 60 * 1000 }); continue; }
      let windowId;
      if (job.topic !== 'verify') {
        windowId = hash(`${job.recipientId}:${job.channel}:${job.scope}`);
        try { await Window.updateOne({ _id: windowId }, { $setOnInsert: { recipientId: job.recipientId, lastSentAt: 0, leaseUntil: 0, expiresAt: new Date(now() + 7 * DAY) } }, { upsert: true }); } catch (error) { if (error.code !== 11000) throw error; }
        const window = await Window.findOneAndUpdate({ _id: windowId, leaseUntil: { $lte: now() }, lastSentAt: { $lte: now() - HALF_HOUR } }, { $set: { claim, leaseUntil: now() + 120000 } }, { new: true });
        if (!window) { await finish('queued', { availableAt: now() + HALF_HOUR }); continue; }
      }
      try {
        const message = await content(job);
        if (!message) { await finish('cancelled'); continue; }
        // Persisted claim, fresh account checks, provider idempotency key, immutable body.
        const freshUser = await getUser(job.recipientId), freshAccount = plain(await lean(Account.findOne({ userId: job.recipientId })));
        const stillClaimed = await Job.exists({ _id: job._id, status: 'sending', claim });
        if (!stillClaimed || !ACTIVE(freshUser) || (job.channel === 'email' ? emailHash(freshUser) !== job.targetHash : hash(`phone:${phoneOf(freshUser)}`) !== job.targetHash)
          || (job.topic !== 'verify' && (freshAccount?.consentRevision !== job.consentRevision || freshAccount.preferences?.[job.channel]?.[job.topic] !== true))) { await finish('cancelled'); continue; }
        if (!job.budgetReserved) {
          const limit = configuredLimit(config[`NOTIFICATION_${job.channel.toUpperCase()}_DAILY_LIMIT`], job.channel === 'email' ? 1000 : 100);
          const userLimit = configuredLimit(config[`NOTIFICATION_${job.channel.toUpperCase()}_USER_DAILY_LIMIT`], job.channel === 'email' ? 20 : 5);
          const day = utcDay(now()), budgetId = `notifications:${day}:${job.channel}`;
          const userKey = `users.${crypto.createHmac('sha256', key).update(`${day}:${job.recipientId}`).digest('hex')}`;
          try { await Budget.updateOne({ _id: budgetId }, { $setOnInsert: { count: 0, users: {}, expiresAt: new Date(now() + 3 * DAY) } }, { upsert: true }); } catch (error) { if (error.code !== 11000) throw error; }
          const reserved = limit > 0 && userLimit > 0 && await Budget.findOneAndUpdate({ _id: budgetId, count: { $lt: limit }, $or: [{ [userKey]: { $exists: false } }, { [userKey]: { $lt: userLimit } }] }, { $inc: { count: 1, [userKey]: 1 } }, { new: true });
          if (!reserved) { await finish('failed'); continue; }
          await Job.updateOne({ _id: job._id, claim, status: 'sending' }, { $set: { budgetReserved: true } });
          // Reservations are never refunded after ambiguous provider failures.
        }
        let deadline;
        const result = await Promise.race([
          Promise.resolve().then(() => sender({ to: job.channel === 'email' ? emailOf(freshUser) : phoneOf(freshUser), ...message, body: message.text, idempotencyKey: `baylink-notification/${job._id}` })),
          new Promise((resolve, reject) => { deadline = setTimeout(() => reject(new Error('Notification provider deadline')), 20000); deadline.unref?.(); }),
        ]).finally(() => clearTimeout(deadline));
        if (windowId) await Window.updateOne({ _id: windowId, claim }, { $set: { lastSentAt: now(), leaseUntil: 0 }, $unset: { claim: '' } });
        await finish('sent', { providerId: String(result?.id || result?.sid || '').slice(0, 200) });
        processed++;
      } catch (error) {
        const definite429 = Number(error.status || error.statusCode) === 429;
        const status = Number(error.status || error.statusCode);
        const retry = job.attempts < 5 && ((job.channel === 'email' && (!status || status === 429 || status >= 500)) || definite429) && now() - job.createdAt < 23 * 60 * 60 * 1000;
        await finish(retry ? 'queued' : job.channel === 'sms' && (!status || status >= 500) ? 'unknown' : 'failed', retry ? { availableAt: now() + Math.min(HALF_HOUR, 60000 * 2 ** job.attempts) } : {});
      } finally {
        if (windowId) await Window.updateOne({ _id: windowId, claim }, { $unset: { claim: '' }, $set: { leaseUntil: 0 } });
      }
    }
    return { processed };
  };
  const eraseUser = async (id, { session } = {}) => {
    const options = session ? { session } : {};
    await Job.deleteMany({ $or: [{ recipientId: id }, { actorId: id }] }, options);
    await Token.deleteMany({ recipientId: id }, options);
    await Window.deleteMany({ recipientId: id }, options);
    await Account.deleteMany({ userId: id }, options);
  };
  let timer, running = false;
  const tick = async () => { if (running) return; running = true; try { await runOnce(); } catch { /* Durable queue survives DB/provider failure; no PII logging. */ } finally { running = false; } };
  const start = () => { if (enabled && ready && !deps.isTest && !timer) { timer = setInterval(tick, 30000); timer.unref?.(); } };
  const stop = () => { if (timer) clearInterval(timer); timer = null; };
  return { preferences, updatePreferences, startEmailVerification, verifyEmail, unsubscribe, enqueueEvent, runOnce, eraseUser, start, stop, enabled };
}

function emptyPreferencesWith(values) {
  const result = emptyPreferences();
  for (const channel of CHANNELS) for (const topic of TOPICS) result[channel][topic] = values?.[channel]?.[topic] === true;
  return result;
}

function registerNotifications(app, deps) {
  const models = createNotificationModels(deps.mongoose, deps.models), service = createNotificationService({ ...deps, ...models, isolated: !!deps.models?.NotificationAccount });
  const limit = (name, maximum, authenticated = true) => (req, res, next) => {
    const allowed = deps.checkRateLimit(`notification:${name}:ip:${deps.getClientIp(req)}`, { windowMs: 60000, maxRequests: maximum * 3 })
      && (!authenticated || deps.checkRateLimit(`notification:${name}:user:${req.user.id}`, { windowMs: 60000, maxRequests: maximum }));
    return allowed ? next() : res.status(429).json({ error: '操作过于频繁，请稍后再试。' });
  };
  const handler = fn => async (req, res) => { res.set('Cache-Control', 'no-store'); try { res.json(await fn(req)); } catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : '通知服务暂不可用。', ...(error.code ? { code: error.code } : {}) }); } };
  app.get('/api/notifications/preferences', deps.authenticateToken, limit('read', 60), handler(req => service.preferences(req.user.id)));
  app.patch('/api/notifications/preferences', deps.authenticateToken, limit('prefs', 10), handler(req => service.updatePreferences(req.user.id, req.body)));
  app.post('/api/notifications/email/start', deps.authenticateToken, limit('verify-start', 3), handler(req => service.startEmailVerification(req.user.id)));
  app.post('/api/notifications/email/verify', limit('verify-token', 10, false), handler(req => service.verifyEmail(req.body?.token)));
  app.post('/api/notifications/unsubscribe', limit('unsubscribe', 10, false), handler(req => service.unsubscribe(req.body?.token)));
  return { ...service, models };
}

module.exports = { TOPICS, CHANNELS, HALF_HOUR, createNotificationModels, createNotificationService, registerNotifications, trustedOrigin };
