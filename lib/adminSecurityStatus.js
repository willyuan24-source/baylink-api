// API-OPS: the owner's administrator-account checklist as a status the owner can read
// (GET /api/admin/security-status, admin only: requireAdmin, so with ADMIN_MFA_REQUIRED=true
// only an authenticator session). One boolean per step of "Administrator account: the
// owner's safe order" in docs/account-privacy-and-mfa.md, plus when each account step last
// happened. No account ids, login names, addresses, secrets or environment values, and never
// part of a public endpoint.
const { encryptionKey } = require('./accountTotp');
const { securityAlertState } = require('./loginGuard');

const filled = value => typeof value === 'string' && value.trim() !== '';
const stamp = (row, key) => Number.isFinite(Number(row[key])) && Number(row[key]) > 0 ? Number(row[key]) : 0;
// The time each account step happened on one account (0: not done). Changing the password
// (step 1) and enabling the authenticator (step 3) also stamp sessionsRevokedAt at that same
// instant, so step 5 counts only a revoke strictly later than both: POST
// /api/admin/sessions/revoke, scripts/revoke-admin-sessions.js or "sign out everywhere".
const STEP_TIME = Object.freeze({
  passwordChangedAt: row => stamp(row, 'passwordChangedAt'),
  totpEnabledAt: row => stamp(row, 'totpEnabledAt'),
  sessionsRevokedAt: row => stamp(row, 'sessionsRevokedAt') > Math.max(stamp(row, 'passwordChangedAt'), stamp(row, 'totpEnabledAt')) ? stamp(row, 'sessionsRevokedAt') : 0,
});
// The legacy public login name. `email` is read only for this comparison and never returned.
const publicLoginName = row => String(row.email ?? '').trim().toLowerCase() === 'admin';

/**
 * { adminAccounts, checks: {…booleans}, done, total, times: {…ISO or null}, checkedAt }.
 * An account step counts as done only when every administrator account has it; its time is
 * the earliest among them (the account that did it longest ago).
 */
async function adminSecurityStatus({ User, config = {}, now = Date.now }) {
  const admins = await User.find({ role: 'admin' }).select('email passwordChangedAt totpEnabledAt sessionsRevokedAt -_id').lean();
  const everyAccount = key => admins.length > 0 && admins.every(row => STEP_TIME[key](row) > 0);
  const earliest = key => everyAccount(key) ? new Date(Math.min(...admins.map(STEP_TIME[key]))).toISOString() : null;
  const loginName = String(config.ADMIN_LOGIN_ID || '').trim();
  const checks = {
    passwordChanged: everyAccount('passwordChangedAt'),
    encryptionKeySet: encryptionKey(config) !== null,
    authenticatorOn: everyAccount('totpEnabledAt'),
    authenticatorRequired: String(config.ADMIN_MFA_REQUIRED || '').trim().toLowerCase() === 'true',
    sessionsRevoked: everyAccount('sessionsRevokedAt'),
    // Step 6: "admin" no longer signs in, either through ADMIN_LOGIN_ID or because no
    // administrator account uses it as its login name any more (a real e-mail address instead).
    privateLoginName: (loginName !== '' && loginName.toLowerCase() !== 'admin') || (admins.length > 0 && !admins.some(publicLoginName)),
    // The owner notices (sign-in failures, account changes) can be delivered: the same gates
    // as lib/loginGuard.js outside tests, plus a configured Resend sender.
    alertsOn: securityAlertState({ ...config, NODE_ENV: 'production' }).enabled && filled(config.RESEND_API_KEY) && filled(config.RESEND_FROM_EMAIL),
  };
  const values = Object.values(checks);
  return {
    adminAccounts: admins.length, checks, done: values.filter(Boolean).length, total: values.length,
    times: { passwordChangedAt: earliest('passwordChangedAt'), authenticatorOnSince: earliest('totpEnabledAt'), sessionsRevokedAt: earliest('sessionsRevokedAt') },
    checkedAt: new Date(now()).toISOString(),
  };
}

module.exports = { adminSecurityStatus };
