const crypto = require('node:crypto');
const { acquireAccountOperation } = require('./accountPrivacy');

const HALF_HOUR = 30 * 60 * 1000;
// The first notice for a thread waits five minutes so a reply read in-app never
// also arrives by email/SMS; later events in that thread coalesce into one notice
// at most every HALF_HOUR (rolling, per recipient/channel/thread).
const FIRST_NOTICE_DELAY = 5 * 60 * 1000;
const DAY = 86400000;
const TOPICS = Object.freeze(['message', 'contact_request', 'outing_request', 'comment']);
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
// Optional page language sent with verification calls; anything else is ignored (never an error).
const pageLocale = value => ['zh-Hans', 'zh-Hant', 'en'].includes(value) ? value : undefined;
const utcDay = at => new Date(at).toISOString().slice(0, 10);
const plain = row => row && typeof row.toObject === 'function' ? row.toObject() : row;
const lean = query => typeof query?.lean === 'function' ? query.lean() : query;
// Durable rolling-throttle record for one recipient/channel/thread.
const windowKey = (recipientId, channel, scope) => hash(`${recipientId}:${channel}:${scope}`);
// Fixed, whitelisted site paths only; ids were validated by enqueueEvent.
const linkPathFor = (topic, sourceId) => topic === 'message' ? `/messages/${encodeURIComponent(sourceId)}`
  : topic === 'contact_request' ? '/messages'
    : topic === 'comment' ? `/posts/${encodeURIComponent(sourceId)}`
      : `/together?outing=${encodeURIComponent(sourceId)}`;
// Jobs queued before `sourceId` was stored carry it in `scope` ("topic:sourceId"; ids have no colon).
const sourceOf = job => job.sourceId || String(job.scope || '').slice(String(job.scope || '').indexOf(':') + 1);

// H14 (API-NOTIFY-2): a verified email gets these two kinds by default, once, unless the member
// has already made a choice (saved settings or used an unsubscribe link). SMS stays opt-in.
const EMAIL_DEFAULT_TOPICS = Object.freeze(['message', 'contact_request']);
const DEFAULTS_VERSION = 1;
const defaultPreferences = () => {
  const result = emptyPreferences();
  for (const topic of EMAIL_DEFAULT_TOPICS) result.email[topic] = true;
  return result;
};
// Activation is a code default, not a Render step: it stays false until the web copy is truthful
// (WEB-COMMUNITY-2 and the privacy policy still say verification never turns reminders on), then the
// captain flips this one constant. NOTIFICATION_EMAIL_DEFAULTS overrides it: "on"/"true" turns the
// preset on early; any other non-empty value ("off") is the kill switch (docs/g5-production-checklist.md §5).
const EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT = false;
const emailDefaultsActive = (config = {}, byDefault = EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT) => {
  const value = String(config.NOTIFICATION_EMAIL_DEFAULTS ?? '').trim().toLowerCase();
  return value === '' ? byDefault === true : ['on', 'true'].includes(value);
};
const anyPreferenceOn = preferences => CHANNELS.some(channel => TOPICS.some(topic => preferences?.[channel]?.[topic] === true));
// The member's own choice: a saved setting or an unsubscribe link (both start a new consent epoch).
const customizedAccount = account => Number(account?.consentRevision) > 0;
// The setting names exactly as the web settings card shows them (NotificationPreferencesCard).
const SETTING_LABELS = Object.freeze({
  'zh-Hans': { message: '新的私信', contact_request: '新的联系请求', outing_request: '新的小队申请', comment: '我的帖子有新评论' },
  'zh-Hant': { message: '新的私訊', contact_request: '新的聯絡請求', outing_request: '新的小隊申請', comment: '我的帖子有新留言' },
  en: { message: 'New private messages', contact_request: 'New contact requests', outing_request: 'New team applications', comment: 'New comments on my posts' },
});
// The first line of a reminder names the kind with the same words as the setting (subject and reason line).
const LEADS = Object.freeze({
  'zh-Hans': { message: '你在 BAYLINK 收到新的私信', contact_request: '你在 BAYLINK 收到新的联系请求', outing_request: '你在 BAYLINK 收到新的小队申请', comment: '你在 BAYLINK 的帖子有新评论' },
  'zh-Hant': { message: '你在 BAYLINK 收到新的私訊', contact_request: '你在 BAYLINK 收到新的聯絡請求', outing_request: '你在 BAYLINK 收到新的小隊申請', comment: '你在 BAYLINK 的帖子有新留言' },
  en: { message: 'You have new private messages on BAYLINK', contact_request: 'You have a new contact request on BAYLINK', outing_request: 'You have a new team application on BAYLINK', comment: 'Your post on BAYLINK has new comments' },
});

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
      // H14: which defaults version this account has been settled against, and when defaults were turned on (absent = never).
      defaultsVersion: Number, defaultsAppliedAt: Number,
    }, [[{ userId: 1 }, { unique: true }]]),
    NotificationToken: create('NotificationToken', {
      _id: String, recipientId: String, purpose: { type: String, enum: ['verify', 'unsubscribe'] }, channel: String,
      // Unsubscribe tokens carry the kind they turn off; tokens issued before H14 have none and turn off the whole channel.
      topic: String,
      emailHash: String, sealed: { type: String, select: false }, usedAt: Number, expiresAt: Date,
    }, [[{ expiresAt: 1 }, { expireAfterSeconds: 0 }], [{ recipientId: 1 }, {}]]),
    NotificationJob: create('NotificationJob', {
      _id: String, recipientId: String, actorId: String, topic: String, channel: String, scope: String, sourceId: String,
      consentRevision: Number, targetHash: String, locale: String, linkPath: String, tokenId: String,
      status: { type: String, enum: ['queued', 'sending', 'sent', 'cancelled', 'failed', 'unknown'] },
      availableAt: Number, createdAt: Number, expiresAt: Date, attempts: Number, claim: String, leaseUntil: Number, providerId: String, budgetReserved: Boolean,
      // Coalescing ledger: how many events this one notice covers and the latest one; `reason` explains a cancellation (e.g. read in-app).
      events: Number, lastEventAt: Number, reason: String,
    }, [[{ status: 1, availableAt: 1 }, {}], [{ recipientId: 1 }, {}], [{ recipientId: 1, scope: 1, status: 1 }, {}], [{ expiresAt: 1 }, { expireAfterSeconds: 0 }]]),
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

const DEFAULT_ORIGIN = 'https://www.baylink.us';
// A bad NOTIFICATION_FRONTEND_URL must not stop the whole API from booting: links
// fall back to the canonical site and one structured warning is logged. The value
// itself is not logged (a URL can carry credentials).
function notificationOrigin(config = {}, log = line => console.error(JSON.stringify(line))) {
  try { return trustedOrigin(config); }
  catch {
    try { log({ level: 'warn', event: 'notification_origin_invalid', setting: 'NOTIFICATION_FRONTEND_URL', fallback: DEFAULT_ORIGIN }); } catch { /* ignore */ }
    return DEFAULT_ORIGIN;
  }
}

// RFC 8058 one-click unsubscribe: mail clients POST straight to the API, so the List-Unsubscribe
// header names the API's own public origin (the web app calls the same host, src/lib/api.ts).
const DEFAULT_API_ORIGIN = 'https://baylink-api.onrender.com';
function notificationApiOrigin(config = {}, log = line => console.error(JSON.stringify(line))) {
  const raw = config.NOTIFICATION_API_URL;
  if (raw === undefined || raw === '') return DEFAULT_API_ORIGIN;
  try {
    const url = new URL(raw);
    const local = config.NODE_ENV !== 'production' && ['localhost', '127.0.0.1'].includes(url.hostname) && url.protocol === 'http:';
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash || (url.protocol !== 'https:' && !local)
      || (config.NODE_ENV === 'production' && !['baylink-api.onrender.com', 'api.baylink.us'].includes(url.hostname))) throw new Error('invalid');
    return url.origin;
  } catch {
    try { log({ level: 'warn', event: 'notification_origin_invalid', setting: 'NOTIFICATION_API_URL', fallback: DEFAULT_API_ORIGIN }); } catch { /* ignore */ }
    return DEFAULT_API_ORIGIN;
  }
}

function createNotificationService(deps) {
  const { User, UserBlock, NotificationAccount: Account, NotificationToken: Token, NotificationJob: Job, NotificationWindow: Window, NotificationBudget: Budget } = deps;
  const config = deps.config || {}, now = deps.now || Date.now, origin = notificationOrigin(config, deps.log), apiOrigin = notificationApiOrigin(config, deps.log);
  const info = deps.log || (line => console.log(JSON.stringify(line)));
  const enabled = config.NOTIFICATION_DELIVERY_ENABLED === 'true';
  const defaultsActive = emailDefaultsActive(config);
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
  // H14 migration on read, once per account: an account that never made a choice gets the email
  // defaults as soon as its current email is verified; an account that did choose keeps its choice
  // (only the version mark is written). Logged without ids; `defaultsAppliedAt` stays on the account.
  const settleDefaults = async (user, account, reason) => {
    for (let attempt = 0; attempt < 4; attempt++) {
      if (!defaultsActive || !account?._id || Number(account.defaultsVersion) >= DEFAULTS_VERSION) return account;
      // A legacy row with a reminder on but no consent epoch was also a choice.
      const untouched = !customizedAccount(account) && !anyPreferenceOn(account.preferences);
      if (untouched && !verifiedEmail(user, account)) return account;
      const $set = { defaultsVersion: DEFAULTS_VERSION };
      if (untouched) {
        for (const topic of EMAIL_DEFAULT_TOPICS) $set[`preferences.email.${topic}`] = true;
        $set.defaultsAppliedAt = now() || 1;
      }
      const saved = plain(await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, { $set, $inc: { revision: 1 } }, { new: true, runValidators: true }));
      if (saved) {
        try { info({ level: 'info', event: untouched ? 'notification_defaults_applied' : 'notification_defaults_kept', version: DEFAULTS_VERSION, reason }); } catch { /* logging never blocks */ }
        return saved;
      }
      account = plain(await lean(Account.findOne({ _id: account._id })));
    }
    return account;
  };
  const accountFor = async (user, id, reason) => settleDefaults(user, await getAccount(id), reason);
  const dto = (user, account) => {
    const preferences = emptyPreferencesWith(account?.preferences);
    return {
      preferences, locale: safeLocale(account?.locale),
      emailVerified: !!verifiedEmail(user, account), phoneVerified: !!verifiedPhone(user),
      deliveryEnabled: enabled, emailDeliveryAvailable: enabled && typeof deps.sendEmail === 'function', smsDeliveryAvailable: enabled && typeof deps.sendSms === 'function',
      // Additive fields: clients that know only the original three topics keep working.
      topics: [...TOPICS], allEnabled: Object.fromEntries(CHANNELS.map(channel => [channel, TOPICS.every(topic => preferences[channel][topic])])),
      // H14 (additive): what a verified email gets when the member has never chosen, whether that
      // preset is switched on, whether it was applied to this account, and whether the member chose.
      defaults: defaultPreferences(), defaultsActive, defaultsApplied: !!account?.defaultsAppliedAt, customized: customizedAccount(account),
    };
  };
  const ensureReady = () => { if (!ready) throw fail('通知设置暂不可用。', 503); };
  const preferences = async id => { ensureReady(); const user = await getUser(id); if (!ACTIVE(user)) throw fail('账号当前不可用。', 403); return dto(user, await accountFor(user, id, 'read')); };
  const updatePreferences = async (id, payload) => {
    ensureReady();
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).some(key => !['preferences', 'locale', 'enableAll'].includes(key))) throw fail('通知设置格式无效。');
    const patch = payload.preferences;
    if (patch !== undefined && (!patch || typeof patch !== 'object' || Array.isArray(patch) || Object.keys(patch).some(key => !CHANNELS.includes(key)))) throw fail('通知渠道无效。');
    if (payload.locale !== undefined && !['zh-Hans', 'zh-Hant', 'en'].includes(payload.locale)) throw fail('通知语言无效。');
    // One-tap "enable all": true = every channel whose destination is verified now; a
    // channel name = that channel only. Explicit consent covers the current topics only.
    const enableAll = payload.enableAll;
    if (enableAll !== undefined && enableAll !== true && !CHANNELS.includes(enableAll)) throw fail('通知渠道无效。');
    const user = await getUser(id); if (!ACTIVE(user)) throw fail('账号当前不可用。', 403);
    const verifiedChannel = (channel, account) => channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user);
    for (let attempt = 0; attempt < 8; attempt++) {
      // Saving is an explicit choice. An account not yet settled against the defaults is settled as
      // "kept" by this save (it chose from what it saw), never defaulted first and then changed.
      const account = await getAccount(id), next = emptyPreferencesWith(account.preferences);
      const settles = defaultsActive && !(Number(account.defaultsVersion) >= DEFAULTS_VERSION);
      for (const [channel, values] of Object.entries(patch || {})) {
        if (!values || typeof values !== 'object' || Array.isArray(values) || Object.entries(values).some(([topic, value]) => !TOPICS.includes(topic) || typeof value !== 'boolean')) throw fail('请选择明确的通知选项。');
        // Only a reminder being turned on needs the verified destination. Re-saving one that is
        // already on (say after an email change) keeps it; nothing is sent until the new address is verified.
        if (Object.entries(values).some(([topic, value]) => value && !next[channel][topic]) && !verifiedChannel(channel, account)) throw fail(channel === 'email' ? '请先验证当前邮箱。' : '请先验证当前手机号。', 409, 'NOTIFICATION_VERIFICATION_REQUIRED');
        Object.assign(next[channel], values);
      }
      if (enableAll !== undefined) {
        const channels = enableAll === true ? CHANNELS.filter(channel => verifiedChannel(channel, account)) : [enableAll];
        if (!channels.length) throw fail('请先验证邮箱或手机号。', 409, 'NOTIFICATION_VERIFICATION_REQUIRED');
        for (const channel of channels) {
          if (!verifiedChannel(channel, account)) throw fail(channel === 'email' ? '请先验证当前邮箱。' : '请先验证当前手机号。', 409, 'NOTIFICATION_VERIFICATION_REQUIRED');
          for (const topic of TOPICS) next[channel][topic] = true;
        }
      }
      const saved = await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, {
        $set: { preferences: next, locale: payload.locale || account.locale, ...(settles ? { defaultsVersion: DEFAULTS_VERSION } : {}) }, $inc: { revision: 1, consentRevision: 1 },
      }, { new: true, runValidators: true });
      if (saved) {
        if (settles) try { info({ level: 'info', event: 'notification_defaults_kept', version: DEFAULTS_VERSION, reason: 'choice' }); } catch { /* logging never blocks */ }
        // A new consent epoch prevents a later opt-in from reviving old queued work.
        await Job.updateMany({ recipientId: id, topic: { $ne: 'verify' }, status: 'queued', consentRevision: { $ne: saved.consentRevision } }, { $set: { status: 'cancelled' } });
        return dto(user, plain(saved));
      }
    }
    throw fail('通知设置正在更新，请重试。', 409);
  };
  const token = async (recipientId, purpose, channel, targetHash, lifetime, topic) => {
    const raw = crypto.randomBytes(32).toString('base64url'), id = hash(raw);
    await Token.create({ _id: id, recipientId, purpose, channel, ...(topic ? { topic } : {}), emailHash: targetHash, sealed: seal(raw), usedAt: 0, expiresAt: new Date(now() + lifetime) });
    return id;
  };
  // `locale` (optional, additive): the language of the page that asked. The verification email uses
  // it, and it becomes the reminder language unless the member already saved settings (and a language).
  const startEmailVerification = async (id, { locale: requested } = {}) => {
    const language = pageLocale(requested);
    ensureReady(); const user = await getUser(id);
    if (!ACTIVE(user) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailOf(user))) throw fail('当前账号邮箱不可用。', 403);
    const at = now(), day = utcDay(at);
    for (let attempt = 0; attempt < 8; attempt++) {
      const account = await accountFor(user, id, 'read');
      if (verifiedEmail(user, account)) return { ...dto(user, account), alreadyVerified: true };
      if (account.lastRequestedAt > at - 60000 || (account.requestDay === day && account.requests >= 5)) throw fail('验证邮件请求过于频繁，请稍后再试。', 429);
      const reserved = await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, { $set: { requestDay: day, requests: account.requestDay === day ? account.requests + 1 : 1, lastRequestedAt: at, ...(language && !customizedAccount(account) ? { locale: language } : {}) }, $inc: { revision: 1 } }, { new: true });
      if (!reserved) continue;
      const tokenId = await token(id, 'verify', 'email', emailHash(user), HALF_HOUR);
      await Job.create({ _id: hash(`verify:${tokenId}`), recipientId: id, topic: 'verify', channel: 'email', targetHash: emailHash(user), locale: safeLocale(language || account.locale), tokenId,
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
    // Public token routes hold the proven token owner's DB deletion gate through
    // the wrapped HTTP handler. Never write an account after its deletion purge.
    if (typeof deps.holdAccount === 'function') await deps.holdAccount(row.recipientId);
    else if (!deps.isTest) throw fail('账号操作暂不可用。', 503, 'ACCOUNT_GATE_UNAVAILABLE');
    const user = await getUser(row.recipientId);
    if (!ACTIVE(user) || (purpose === 'verify' && row.emailHash !== emailHash(user))) throw fail('链接无效或邮箱已更改。');
    const used = await Token.findOneAndUpdate({ _id: row._id, usedAt: 0, expiresAt: { $gt: new Date(now()) } }, { $set: { usedAt: now() || 1 }, $unset: { sealed: '' } }, { new: true });
    if (!used) throw fail('链接已经使用。');
    return { row, user };
  };
  const verifyEmail = async (raw, { locale: requested } = {}) => {
    const language = pageLocale(requested);
    const { row, user } = await consumeToken(raw, 'verify');
    const current = await getAccount(row.recipientId);
    await Account.updateOne({ userId: row.recipientId }, { $set: { verifiedEmailHash: row.emailHash, emailVerifiedAt: now(), ...(language && !customizedAccount(current) ? { locale: language } : {}) }, $inc: { revision: 1 } });
    await Job.updateMany({ recipientId: row.recipientId, topic: 'verify', status: 'queued' }, { $set: { status: 'cancelled' } });
    // H14: a member who never chose gets the email defaults now that this address is verified.
    const before = plain(await lean(Account.findOne({ userId: row.recipientId })));
    const after = await settleDefaults(user, before, 'verify');
    return { ok: true, emailVerified: true, defaultsApplied: !!after?.defaultsAppliedAt && after.defaultsAppliedAt !== before?.defaultsAppliedAt };
  };
  const unsubscribe = async raw => {
    const { row } = await consumeToken(raw, 'unsubscribe');
    const topic = row.topic ?? null;
    if (!CHANNELS.includes(row.channel) || (topic !== null && !TOPICS.includes(topic))) throw fail('链接无效。');
    // A link turns off its own kind only. Tokens issued before H14 carry no kind and turn off
    // the whole channel, as the emails that carried them said.
    const topics = topic ? [topic] : [...TOPICS];
    for (let attempt = 0; attempt < 8; attempt++) {
      const account = plain(await lean(Account.findOne({ userId: row.recipientId })));
      if (!account) return { ok: true, channel: row.channel, topic };
      // Using a link is the member's choice: the consent epoch moves, so defaults never return.
      const saved = plain(await Account.findOneAndUpdate({ _id: account._id, revision: account.revision }, {
        $set: Object.fromEntries(topics.map(name => [`preferences.${row.channel}.${name}`, false])), $inc: { revision: 1, consentRevision: 1 },
      }, { new: true }));
      if (!saved) continue;
      await Job.updateMany({ recipientId: row.recipientId, channel: row.channel, topic: { $in: topics }, status: 'queued' }, { $set: { status: 'cancelled' } });
      // Pending notices of the kinds that stay on move to the new epoch instead of being dropped.
      for (const channel of CHANNELS) {
        const kept = TOPICS.filter(name => saved.preferences?.[channel]?.[name] === true && !(channel === row.channel && topics.includes(name)));
        if (kept.length) await Job.updateMany({ recipientId: row.recipientId, channel, topic: { $in: kept }, status: 'queued', consentRevision: account.consentRevision }, { $set: { consentRevision: saved.consentRevision } });
      }
      return { ok: true, channel: row.channel, topic };
    }
    throw fail('通知设置正在更新，请重试。', 409);
  };
  const enqueueEvent = async event => {
    if (!ready) return { skipped: true };
    if (!event || !TOPICS.includes(event.topic) || !validId(event.recipientId) || !validId(event.actorId) || !validId(event.sourceId) || !validId(event.eventId) || event.recipientId === event.actorId) return { skipped: true };
    const at = Number.isSafeInteger(event.createdAt) ? event.createdAt : now();
    // No backfill: both old and future events are refused, including recovered legacy system messages.
    if (at < now() - 5 * 60 * 1000 || at > now() + 60000) return { skipped: true };
    const user = await getUser(event.recipientId), actor = await getUser(event.actorId);
    if (!ACTIVE(user) || !ACTIVE(actor) || await blocked(event.actorId, event.recipientId)) return { skipped: true };
    const account = await accountFor(user, event.recipientId, 'event'), prefs = emptyPreferencesWith(account.preferences);
    const scope = `${event.topic}:${event.sourceId}`;
    const linkPath = linkPathFor(event.topic, event.sourceId);
    let queued = 0, coalesced = 0;
    for (const channel of CHANNELS) {
      if (!prefs[channel][event.topic] || !(channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user))) continue;
      const targetHash = channel === 'email' ? emailHash(user) : hash(`phone:${phoneOf(user)}`);
      // One pending generic notice per recipient/channel/thread: a later event joins it
      // instead of queueing another. Its body and provider idempotency key stay fixed.
      // An expired job (TTL deletion lags) cannot absorb a new event: the worker would drop it.
      const pending = await Job.findOneAndUpdate({ recipientId: event.recipientId, channel, scope, status: 'queued', consentRevision: account.consentRevision, targetHash, expiresAt: { $gt: new Date(now()) } },
        { $inc: { events: 1 }, $max: { lastEventAt: at } }, { new: true });
      if (pending) { coalesced++; continue; }
      // First notice: T+5 min. After a send, the next one waits for the rolling 30-minute window.
      const window = plain(await lean(Window.findOne({ _id: windowKey(event.recipientId, channel, scope) })));
      const availableAt = Math.max(at + FIRST_NOTICE_DELAY, Number(window?.lastSentAt || 0) + HALF_HOUR);
      // Concurrent events in one 5-minute slot share an id (the upsert dedupes them). A job
      // only leaves `queued` after its slot has ended, so an id collision with a finished job
      // is a replay; fall back to a per-event id so a new event is never dropped.
      const base = `${event.recipientId}:${channel}:${scope}:${account.consentRevision}:${targetHash}`;
      let id = hash(`${base}:${Math.floor(at / FIRST_NOTICE_DELAY)}`);
      if (await Job.exists({ _id: id })) id = hash(`${base}:event:${event.eventId}`);
      if (await Job.exists({ _id: id })) continue;
      const tokenId = await token(event.recipientId, 'unsubscribe', channel, targetHash, 30 * DAY, event.topic);
      try {
        await Job.updateOne({ _id: id }, { $setOnInsert: { recipientId: event.recipientId, actorId: event.actorId, topic: event.topic, channel, scope, sourceId: event.sourceId,
          consentRevision: account.consentRevision, targetHash, locale: safeLocale(account.locale), linkPath, tokenId, status: 'queued', createdAt: at,
          availableAt, attempts: 0, events: 1, lastEventAt: at, expiresAt: new Date(at + DAY) } }, { upsert: true, runValidators: true });
        queued++;
      } catch (error) { if (error.code !== 11000) throw error; }
    }
    return coalesced ? { queued, coalesced } : { queued };
  };
  // Injected by the server (it owns Message/Post/ContactRequest). Anything but an explicit
  // `false` counts as unread, so a topic without a read state keeps its notice.
  const stillUnread = async job => typeof deps.stillUnread !== 'function' || await deps.stillUnread({
    topic: job.topic, recipientId: job.recipientId, actorId: job.actorId, sourceId: sourceOf(job), since: Number(job.createdAt) || 0,
  }) !== false;
  const link = (path, locale) => `${origin}${locale === 'en' ? '/en' : locale === 'zh-Hant' ? '/zh-Hant' : ''}${path}`;
  // RFC 2369 mail apps open the List-Unsubscribe URL in a browser (GET). A GET changes nothing and
  // never consumes the token (link scanners GET too): it only names the confirmation page, with the
  // token in the fragment, the kind and the reminder's language when they are known.
  const oneClickPage = async raw => {
    if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(raw)) return `${origin}/notifications/unsubscribe`;
    let topic = null, locale;
    try {
      if (ready) {
        const row = plain(await lean(Token.findOne({ _id: hash(raw), purpose: 'unsubscribe' })));
        if (TOPICS.includes(row?.topic)) topic = row.topic;
        if (validId(row?.recipientId)) locale = plain(await lean(Job.findOne({ recipientId: row.recipientId, tokenId: row._id })))?.locale;
      }
    } catch { /* the page works without the kind and language */ }
    return link(`/notifications/unsubscribe#token=${raw}${topic ? `&kind=${topic}` : ''}`, locale);
  };
  const content = async (job, account) => {
    const item = plain(await Token.findOne({ _id: job.tokenId, usedAt: 0, expiresAt: { $gt: new Date(now()) } }).select('+sealed'));
    if (!item?.sealed) return null;
    const raw = unseal(item.sealed);
    const hant = job.locale === 'zh-Hant';
    if (job.topic === 'verify') {
      const href = link(`/verify-email#token=${raw}`, job.locale);
      return { subject: job.locale === 'en' ? 'Verify your BAYLINK email' : hant ? '驗證你的 BAYLINK 信箱' : '验证你的 BAYLINK 邮箱', text: job.locale === 'en' ? `Verify your email within 30 minutes: ${href}\nIf you did not request this, ignore this email.` : hant ? `請在30分鐘內驗證信箱：${href}\n如果不是你本人請求，請忽略這封郵件。` : `请在30分钟内验证邮箱：${href}\n如果不是你本人请求，请忽略这封邮件。` };
    }
    const en = job.locale === 'en', locale = safeLocale(job.locale);
    // H14: the link names the kind it turns off; a token issued before H14 still turns off the whole channel.
    const kind = TOPICS.includes(item.topic) ? item.topic : null;
    const href = link(job.linkPath, job.locale), optout = link(`/notifications/unsubscribe#token=${raw}${kind ? `&kind=${kind}` : ''}`, job.locale);
    const lead = `${LEADS[locale][job.topic]}${en ? `. Sign in to view: ${href}` : hant ? `，請登入查看：${href}` : `，请登录查看：${href}`}`;
    const channelStop = en ? `Turn off these notifications: ${optout}` : hant ? `關閉此渠道通知：${optout}` : `关闭此渠道通知：${optout}`;
    if (job.channel === 'sms') return { subject: '', text: `${lead}\n${!kind ? channelStop : en ? `Stop these texts: ${optout}` : hant ? `關閉這類簡訊提醒：${optout}` : `关闭这类短信提醒：${optout}`}` };
    const setting = SETTING_LABELS[locale][job.topic], settings = link('/me?view=notifications', job.locale);
    // A member who never chose got this kind by default when the email was verified; say so.
    const byDefault = !!account?.defaultsAppliedAt && !customizedAccount(account) && EMAIL_DEFAULT_TOPICS.includes(job.topic);
    const why = byDefault
      ? (en ? `You get this email because "${setting}" email reminders were turned on by default when you verified your email.` : hant ? `你收到這封郵件，是因為驗證信箱後，你的帳號預設開啟了「${setting}」郵件提醒。` : `你收到这封邮件，是因为验证邮箱后，你的账号默认开启了「${setting}」邮件提醒。`)
      : (en ? `You get this email because "${setting}" email reminders are on for your account.` : hant ? `你收到這封郵件，是因為你的帳號開啟了「${setting}」郵件提醒。` : `你收到这封邮件，是因为你的账号开启了「${setting}」邮件提醒。`);
    // The body link opens a confirmation page (a second tap keeps link scanners from unsubscribing
    // anyone); only the List-Unsubscribe header below is a true one-click.
    const stop = !kind ? channelStop : en ? `Turn off these emails: ${optout}` : hant ? `關閉這類郵件：${optout}` : `关闭这类邮件：${optout}`;
    const manage = en ? `All notification settings: ${settings}` : hant ? `管理全部提醒：${settings}` : `管理全部提醒：${settings}`;
    return {
      subject: en ? `BAYLINK notification: ${setting}` : hant ? `BAYLINK 站內通知：${setting}` : `BAYLINK 站内通知：${setting}`,
      text: [lead, why, stop, manage].join('\n'),
      // RFC 8058: mail apps show their own unsubscribe button and POST here; one click, this kind only.
      ...(kind ? { headers: { 'List-Unsubscribe': `<${apiOrigin}/api/notifications/unsubscribe/one-click/${raw}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } } : {}),
    };
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
      let windowId;
      const releases = [];
      try {
        // Background jobs have no HTTP ledger. Acquire the same persistent gate
        // before any account-linked write and release only after our work settles.
        const acquire = deps.acquireAccount || (id => acquireAccountOperation(User, id));
        for (const id of [...new Set([job.recipientId, job.actorId].filter(Boolean))].sort()) releases.push(await acquire(id));
        const user = await getUser(job.recipientId), actor = job.actorId ? await getUser(job.actorId) : null, account = plain(await lean(Account.findOne({ userId: job.recipientId })));
        const valid = ACTIVE(user) && new Date(job.expiresAt).getTime() > now() && (job.channel === 'email' ? emailHash(user) === job.targetHash : hash(`phone:${phoneOf(user)}`) === job.targetHash)
          && (job.topic === 'verify' || (ACTIVE(actor) && !await blocked(job.actorId, job.recipientId) && account?.consentRevision === job.consentRevision
            && account.preferences?.[job.channel]?.[job.topic] === true && (job.channel === 'email' ? verifiedEmail(user, account) : verifiedPhone(user))));
        if (!valid) { await finish('cancelled'); continue; }
        const sender = job.channel === 'email' ? deps.sendEmail : deps.sendSms;
        if (typeof sender !== 'function') { await finish('queued', { availableAt: now() + 5 * 60 * 1000 }); continue; }
        if (job.topic !== 'verify') {
          windowId = windowKey(job.recipientId, job.channel, job.scope);
          try { await Window.updateOne({ _id: windowId }, { $setOnInsert: { recipientId: job.recipientId, lastSentAt: 0, leaseUntil: 0, expiresAt: new Date(now() + 7 * DAY) } }, { upsert: true }); } catch (error) { if (error.code !== 11000) throw error; }
          const window = await Window.findOneAndUpdate({ _id: windowId, leaseUntil: { $lte: now() }, lastSentAt: { $lte: now() - HALF_HOUR } }, { $set: { claim, leaseUntil: now() + 120000 } }, { new: true });
          if (!window) {
            // Throttled: wait for the rolling window to reopen (or the other sender's lease).
            const current = plain(await lean(Window.findOne({ _id: windowId })));
            const reopensAt = Number(current?.lastSentAt || 0) + HALF_HOUR;
            windowId = undefined;
            await finish('queued', { availableAt: Math.max(now() + 60000, reopensAt) }); continue;
          }
        }
        const message = await content(job, account);
        if (!message) { await finish('cancelled'); continue; }
        // Persisted claim, fresh account checks, provider idempotency key, immutable body.
        const freshUser = await getUser(job.recipientId), freshAccount = plain(await lean(Account.findOne({ userId: job.recipientId })));
        const stillClaimed = await Job.exists({ _id: job._id, status: 'sending', claim });
        if (!stillClaimed || !ACTIVE(freshUser) || (job.channel === 'email' ? emailHash(freshUser) !== job.targetHash : hash(`phone:${phoneOf(freshUser)}`) !== job.targetHash)
          || (job.topic !== 'verify' && (freshAccount?.consentRevision !== job.consentRevision || freshAccount.preferences?.[job.channel]?.[job.topic] !== true
            || !(job.channel === 'email' ? verifiedEmail(freshUser, freshAccount) : verifiedPhone(freshUser))
            || !ACTIVE(await getUser(job.actorId)) || await blocked(job.actorId, job.recipientId)))) { await finish('cancelled'); continue; }
        // "Only if still unread": a thread already read in-app, a request already handled or a
        // comment already removed needs no email/SMS. A failed check retries later, never sends.
        if (job.topic !== 'verify') {
          let unread;
          try { unread = await stillUnread(job); } catch { await finish('queued', { availableAt: now() + FIRST_NOTICE_DELAY }); continue; }
          if (!unread) { await finish('cancelled', { reason: 'read' }); continue; }
        }
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
        if (error.code === 'ACCOUNT_CHANGED') { await finish('cancelled'); continue; }
        const definite429 = Number(error.status || error.statusCode) === 429;
        const status = Number(error.status || error.statusCode);
        const retry = job.attempts < 5 && ((job.channel === 'email' && (!status || status === 429 || status >= 500)) || definite429) && now() - job.createdAt < 23 * 60 * 60 * 1000;
        await finish(retry ? 'queued' : job.channel === 'sms' && (!status || status >= 500) ? 'unknown' : 'failed', retry ? { availableAt: now() + Math.min(HALF_HOUR, 60000 * 2 ** job.attempts) } : {});
      } finally {
        try {
          if (windowId) await Window.updateOne({ _id: windowId, claim }, { $unset: { claim: '' }, $set: { leaseUntil: 0 } });
        } finally {
          await Promise.allSettled(releases.map(release => release()));
        }
      }
    }
    return { processed };
  };
  const eraseUser = async (id, { session } = {}) => {
    if (!ready) return;
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
  // API-SEC (G76): read-only checks for the phone-verification gate. No account row is created.
  const emailVerificationDeliverable = () => ready && enabled && typeof deps.sendEmail === 'function';
  const isEmailVerified = async id => {
    if (!ready || !validId(id)) return false;
    const user = await getUser(id);
    return !!verifiedEmail(user, plain(await lean(Account.findOne({ userId: id }))));
  };
  return { preferences, updatePreferences, startEmailVerification, verifyEmail, unsubscribe, oneClickPage, enqueueEvent, runOnce, eraseUser, start, stop, enabled, emailVerificationDeliverable, isEmailVerified };
}

function emptyPreferencesWith(values) {
  const result = emptyPreferences();
  for (const channel of CHANNELS) for (const topic of TOPICS) result[channel][topic] = values?.[channel]?.[topic] === true;
  return result;
}

function registerNotifications(app, deps) {
  const models = createNotificationModels(deps.mongoose, deps.models), service = createNotificationService({ ...deps, ...models,
    isolated: ['NotificationAccount', 'NotificationToken', 'NotificationJob', 'NotificationWindow', 'NotificationBudget'].every(name => !!deps.models?.[name]),
  });
  const limit = (name, maximum, authenticated = true) => (req, res, next) => {
    const allowed = deps.checkRateLimit(`notification:${name}:ip:${deps.getClientIp(req)}`, { windowMs: 60000, maxRequests: maximum * 3 })
      && (!authenticated || deps.checkRateLimit(`notification:${name}:user:${req.user.id}`, { windowMs: 60000, maxRequests: maximum }));
    return allowed ? next() : res.status(429).json({ error: '操作过于频繁，请稍后再试。' });
  };
  const handler = fn => async (req, res) => { res.set('Cache-Control', 'no-store'); try { res.json(await fn(req)); } catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : '通知服务暂不可用。', ...(error.code ? { code: error.code } : {}) }); } };
  app.get('/api/notifications/preferences', deps.authenticateToken, limit('read', 60), handler(req => service.preferences(req.user.id)));
  app.patch('/api/notifications/preferences', deps.authenticateToken, limit('prefs', 10), handler(req => service.updatePreferences(req.user.id, req.body)));
  app.post('/api/notifications/email/start', deps.authenticateToken, limit('verify-start', 3), handler(req => service.startEmailVerification(req.user.id, { locale: req.body?.locale })));
  app.post('/api/notifications/email/verify', limit('verify-token', 10, false), handler(req => service.verifyEmail(req.body?.token, { locale: req.body?.locale })));
  app.post('/api/notifications/unsubscribe', limit('unsubscribe', 10, false), handler(req => service.unsubscribe(req.body?.token)));
  // RFC 8058 one-click unsubscribe (the List-Unsubscribe header): the mail app POSTs
  // `List-Unsubscribe=One-Click` with no cookies. Only the POST unsubscribes, so link scanners that GET cannot.
  // The logged route is the pattern, never the token.
  app.post('/api/notifications/unsubscribe/one-click/:token', limit('one-click', 40, false), handler(req => service.unsubscribe(req.params.token)));
  // A mail app that only knows RFC 2369 opens the same URL in a browser: 303 to the web confirmation
  // page (token in the fragment, still unused). Nothing changes until the member confirms there.
  app.get('/api/notifications/unsubscribe/one-click/:token', limit('one-click-open', 40, false), async (req, res) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    res.redirect(303, await service.oneClickPage(req.params.token));
  });
  return { ...service, models };
}

// The production email adapter (server.js): Resend with the queue's idempotency key and the
// List-Unsubscribe headers of a notice. Kept here so tests can check what reaches the provider.
function resendEmailSender(resend, from) {
  return async ({ to, subject, text, headers, idempotencyKey }) => {
    const { data, error } = await resend.emails.send({ from, to, subject, text, ...(headers ? { headers } : {}) }, { idempotencyKey });
    if (error) throw Object.assign(new Error('Email rejected'), { status: error.statusCode || error.status });
    return data;
  };
}

module.exports = { TOPICS, CHANNELS, HALF_HOUR, FIRST_NOTICE_DELAY, EMAIL_DEFAULT_TOPICS, DEFAULTS_VERSION, EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT, emailDefaultsActive, createNotificationModels, createNotificationService, registerNotifications, resendEmailSender, trustedOrigin, notificationOrigin, notificationApiOrigin };
