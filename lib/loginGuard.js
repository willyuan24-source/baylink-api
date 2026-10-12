const crypto = require('node:crypto');
const { bayAreaDate } = require('./eventEngagement');
const { alertState } = require('./aiSpendAlerts');

// G44 / ENGSEC-03 (API-SEC): sign-in limits that survive a deploy or restart, and an owner
// e-mail when the administrator account keeps failing to sign in.
//
// The in-memory limiter in server.js resets on every deploy, so a guesser could resume at
// full speed after each restart. These counters live in Mongo (one small TTL document per
// key and 15-minute window) and count FAILED sign-ins only:
//   - one visitor (client IP)                       10 failures / 15 min
//   - one visitor against one account (login name)    8 failures / 15 min
//   - all visitors against one account              100 failures / 15 min
// The same numbers as the in-memory attempt limits, so nothing changes for a reader until a
// restart would have reopened them. A stranger still cannot lock the owner out everywhere:
// the per-visitor ceiling trips first, and the cross-visitor one is high (N6).
//
// Keys are HMAC digests of the window, kind and value: the collection never stores an IP
// address, login name or account id. If the store cannot be read the check fails open (the
// in-memory limiter still applies) and the error is logged once per minute.
//
// Owner alert: failures on an administrator account (wrong password, or a wrong authenticator
// code after a correct password) are also counted per Pacific day. At 10 / 50 / 200 / 1000
// (ADMIN_LOGIN_ALERT_STEPS) one e-mail goes to the owner, once per step per day. Delivery
// reuses the AI-alert gates: NOTIFICATION_DELIVERY_ENABLED=true and an owner address
// (SECURITY_ALERT_EMAIL, else AI_ALERT_EMAIL, else OWNER_DIGEST_EMAIL), Resend configured,
// and never under NODE_ENV=test.
const WINDOW_MS = 15 * 60 * 1000;
const LIMITS = Object.freeze({ visitor: 10, accountVisitor: 8, account: 100 });
const DEFAULT_ALERT_STEPS = Object.freeze([10, 50, 200, 1000]);
const DAY_MS = 86400000;

const validEmail = value => typeof value === 'string' && /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(value.trim());
const pacificTime = at => new Intl.DateTimeFormat('zh-CN', { timeZone: 'America/Los_Angeles', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(at));

function createAuthLimitModel(mongoose, injected = {}) {
  if (injected.AuthLimit) return injected.AuthLimit;
  const schema = new mongoose.Schema({
    _id: { type: String, required: true }, count: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true },
  }, { versionKey: false });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return mongoose.models.AuthLimit || mongoose.model('AuthLimit', schema);
}

/** ADMIN_LOGIN_ALERT_STEPS ("10,50,200,1000"): positive integers, ascending; default 10/50/200/1000. */
function alertSteps(config = {}) {
  const parts = String(config.ADMIN_LOGIN_ALERT_STEPS ?? '').split(',').map(part => part.trim()).filter(Boolean);
  const values = [...new Set(parts.filter(part => /^\d+$/.test(part)).map(Number).filter(value => value > 0 && value <= 1e6))].sort((a, b) => a - b);
  return values.length ? values : [...DEFAULT_ALERT_STEPS];
}

/** Whether a security alert can be sent, and to whom (the address comes only from the environment). */
function securityAlertState(config = {}) {
  const gate = alertState(config);
  if (!gate.enabled) return gate;
  const to = [config.SECURITY_ALERT_EMAIL, config.AI_ALERT_EMAIL, config.OWNER_DIGEST_EMAIL].find(validEmail);
  return to ? { enabled: true, reason: 'on', to: to.trim() } : { enabled: false, reason: 'no-owner-email' };
}

function adminAlert({ count, totp, step, steps, at }) {
  return {
    subject: `BAYLINK：管理员账号今天已有 ${count} 次登录失败`,
    text: [
      `${pacificTime(at)}（太平洋时间）管理员账号今天累计 ${count} 次登录失败。`,
      ...(totp ? [`其中 ${totp} 次是密码正确、验证器代码错误：密码可能已经泄露，请马上改密码。`] : []),
      '',
      '建议按这个顺序处理：',
      '1. 登录后在"隐私与安全"改一个新的长密码（只在 BAYLINK 用）。',
      '2. 还没开验证器的话：先设 ACCOUNT_SECURITY_ENCRYPTION_KEY，再绑定验证器，然后设 ADMIN_MFA_REQUIRED=true。',
      '3. 撤销所有管理员登录：POST /api/admin/sessions/revoke，或在 Render shell 运行 node scripts/revoke-admin-sessions.js --apply。',
      '4. 设 ADMIN_LOGIN_ID（一个不公开的长登录名），之后 "admin" 不能再登录。',
      '详细步骤：docs/account-privacy-and-mfa.md。',
      '',
      `登录限制（重启不会清零）：同一访客 15 分钟内失败 ${LIMITS.visitor} 次、同一访客对同一账号 ${LIMITS.accountVisitor} 次、所有访客对同一账号 ${LIMITS.account} 次后暂停 15 分钟。`,
      `提醒档位：每天 ${steps.join(' / ')} 次，每档每天只发一次（这封是第 ${step} 次那一档）。`,
      '',
      '— BAYLINK 自动提醒（API-SEC）',
    ].join('\n'),
  };
}

function createLoginGuard({ Model, secret, config = {}, now = Date.now, sendEmail, logger = console }) {
  if (typeof secret !== 'string' || !secret) throw new Error('Login guard signing secret is required');
  const steps = alertSteps(config);
  const keyFor = (bucket, kind, value) => `${bucket}:${crypto.createHmac('sha256', secret).update(`auth-limit:v1:${bucket}:${kind}:${value}`).digest('hex')}`;
  const windowOf = at => Math.floor(at / WINDOW_MS);
  const visitorKey = value => String(value || 'unknown').slice(0, 200);
  const accountName = value => typeof value === 'string' ? value.trim().toLowerCase().slice(0, 320) : '';
  const keys = ({ visitor, account }, at) => {
    const bucket = `w${windowOf(at)}`, v = visitorKey(visitor), a = accountName(account);
    return {
      visitor: keyFor(bucket, 'visitor', v),
      ...(a ? { accountVisitor: keyFor(bucket, 'account-visitor', `${a}\n${v}`), account: keyFor(bucket, 'account', a) } : {}),
    };
  };
  let lastError = 0;
  const logError = (where, error) => {
    const at = Date.now();
    if (at - lastError < 60000) return;
    lastError = at;
    logger.error?.(`[login-guard] ${where} failed (failing open):`, error?.code || error?.name || 'error');
  };
  async function increment(_id, at, keepMs) {
    const update = { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date(at + keepMs) } };
    for (let attempt = 0; attempt < 2; attempt++) {
      try { return (await Model.findOneAndUpdate({ _id }, update, { upsert: true, new: true }))?.count || 0; }
      catch (error) { if (error.code !== 11000 || attempt) throw error; }
    }
    return 0;
  }
  const sender = () => sendEmail || (sendEmail = require('./sourceTriage').resendSender(config));

  async function alertOwner({ count, totp, step, at }) {
    const state = securityAlertState(config);
    const id = `admin-login:${bayAreaDate(at)}:${step}`;
    if (!state.enabled) { logger.info?.(`[security-alerts] due, not sent (${state.reason}): ${id}`); return { sent: false, reason: state.reason }; }
    const send = sender();
    if (!send) { logger.info?.(`[security-alerts] due, not sent (no-sender): ${id}`); return { sent: false, reason: 'no-sender' }; }
    const message = adminAlert({ count, totp, step, steps, at });
    try {
      await send({ to: state.to, subject: message.subject, text: message.text, idempotencyKey: `baylink-${id}` });
      return { sent: true, id };
    } catch (error) {
      logger.error?.('[security-alerts] send failed:', error?.status || error?.code || 'send-failed');
      return { sent: false, reason: 'send-failed' };
    }
  }

  return {
    limits: LIMITS,
    steps,
    /** True when this visitor (or this visitor on this account, or this account) has too many recent failures. */
    async blocked({ visitor, account }) {
      const at = now(), ids = keys({ visitor, account }, at);
      try {
        const rows = await Model.find({ _id: { $in: Object.values(ids) } }).lean();
        const count = id => rows.find(row => row._id === id)?.count || 0;
        return Object.entries(ids).some(([kind, id]) => count(id) >= LIMITS[kind]);
      } catch (error) { logError('read', error); return false; }
    },
    /**
     * Count one failed sign-in. `adminAccountId` is set when the account is an administrator:
     * the failure also counts toward the owner alert. `factor` = 'password' | 'totp'.
     * Resolves after the counters are written; the alert e-mail is not awaited.
     */
    async recordFailure({ visitor, account, adminAccountId, factor = 'password' }) {
      const at = now(), ids = keys({ visitor, account }, at);
      try { await Promise.all(Object.values(ids).map(id => increment(id, at, WINDOW_MS + 60000))); }
      catch (error) { logError('write', error); }
      if (!adminAccountId) return { alert: null };
      try {
        const day = `d${bayAreaDate(at)}`;
        const count = await increment(keyFor(day, 'admin-failures', adminAccountId), at, 2 * DAY_MS);
        const totp = factor === 'totp' ? await increment(keyFor(day, 'admin-totp-failures', adminAccountId), at, 2 * DAY_MS)
          : (await Model.findOne({ _id: keyFor(day, 'admin-totp-failures', adminAccountId) }).lean())?.count || 0;
        // The atomic increment hands each count to exactly one request: one e-mail per step per day.
        if (!steps.includes(count)) return { alert: null, count };
        const pending = alertOwner({ count, totp, step: count, at });
        pending.catch(() => {});
        return { alert: pending, count };
      } catch (error) { logError('admin-count', error); return { alert: null }; }
    },
  };
}

module.exports = { LIMITS, WINDOW_MS, DEFAULT_ALERT_STEPS, createAuthLimitModel, createLoginGuard, alertSteps, securityAlertState, adminAlert };
