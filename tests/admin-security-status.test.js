// API-OPS: GET /api/admin/security-status, the owner's administrator-account checklist as
// booleans. Admin only (guests and members get nothing, and with ADMIN_MFA_REQUIRED=true only
// an authenticator session); never on a public endpoint; no ids, names, addresses or values.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { adminSecurityStatus } = require('../lib/adminSecurityStatus');

const SECRET = 'admin-security-status-secret-0123456789abcdef';
const NOW = Date.parse('2026-10-14T18:00:00Z');
const hash = bcrypt.hashSync('OnlyMockPassword7', 4);
const KEY = crypto.randomBytes(32).toString('base64');
const DONE_AT = Date.parse('2026-10-12T17:00:00Z');
const person = (id, extra = {}) => ({ id, email: `${id}@example.test`, password: hash, nickname: `Neighbor ${id}`, role: 'user', accountStatus: 'active', isBanned: false, createdAt: 1, ...extra });
const admin = (id, extra = {}) => person(id, { email: id === 'fixture-admin-id' ? 'admin' : `${id}@example.test`, role: 'admin', nickname: `Admin ${id}`, ...extra });
// Steps 1, 3 and 5 in order: enabling the authenticator stamps sessionsRevokedAt at that same
// instant, and the explicit revoke (step 5) comes a minute later.
const hardened = { passwordChangedAt: DONE_AT, totpEnabledAt: DONE_AT + 60000, sessionsRevokedAt: DONE_AT + 120000 };
const FULL = { ACCOUNT_SECURITY_ENCRYPTION_KEY: KEY, ADMIN_MFA_REQUIRED: 'true', ADMIN_LOGIN_ID: 'fixture-private-login-name',
  NOTIFICATION_DELIVERY_ENABLED: 'true', RESEND_API_KEY: 'fixture-resend-value', RESEND_FROM_EMAIL: 'alerts@example.test', SECURITY_ALERT_EMAIL: 'owner-fixture@example.test' };
const KEYS = ['passwordChanged', 'encryptionKeySet', 'authenticatorOn', 'authenticatorRequired', 'sessionsRevoked', 'privateLoginName', 'alertsOn'];

async function fixture(t, { config = {}, admins = [admin('fixture-admin-id')] } = {}) {
  const models = createMemoryModels({ User: [...admins, person('member')] });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config }, models, accountSecurityNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, token) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: response.status, data: await response.json().catch(() => ({})), raw: response };
  };
  const session = (id, extra = {}) => jwt.sign({ id, purpose: 'session', sessionIssuedAt: Date.now(), sessionRevision: 0, ...extra }, SECRET, { expiresIn: '1h' });
  return { request, session };
}

test('guests and members get nothing; an admin gets the checklist (no store)', async t => {
  const f = await fixture(t);
  const guest = await f.request('/api/admin/security-status');
  assert.equal(guest.status, 401);
  assert.deepEqual(Object.keys(guest.data).filter(key => KEYS.includes(key) || key === 'checks'), []);
  for (const token of [f.session('member'), f.session('member', { mfaVerified: true })]) {
    const member = await f.request('/api/admin/security-status', token);
    assert.equal(member.status, 403);
    assert.equal(member.data.checks, undefined);
    assert.ok(!KEYS.some(key => JSON.stringify(member.data).includes(key)));
  }
  const owner = await f.request('/api/admin/security-status', f.session('fixture-admin-id'));
  assert.equal(owner.status, 200);
  assert.equal(owner.raw.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(owner.data.checks), KEYS);
  assert.equal((await f.request('/api/admin/security-status?verbose=1', f.session('fixture-admin-id'))).status, 400);
});

test('the default state: every step open, no times', async t => {
  const f = await fixture(t);
  const { data } = await f.request('/api/admin/security-status', f.session('fixture-admin-id'));
  assert.equal(data.ok, true);
  assert.equal(data.adminAccounts, 1);
  assert.deepEqual(data.checks, Object.fromEntries(KEYS.map(key => [key, false])));
  assert.equal(data.done, 0); assert.equal(data.total, 7);
  assert.deepEqual(data.times, { passwordChangedAt: null, authenticatorOnSince: null, sessionsRevokedAt: null });
  assert.equal(data.checkedAt, new Date(NOW).toISOString());
});

test('every step done: all true, with the times; only an authenticator session can read it under ADMIN_MFA_REQUIRED', async t => {
  const f = await fixture(t, { config: FULL, admins: [admin('fixture-admin-id', hardened)] });
  assert.equal((await f.request('/api/admin/security-status', f.session('fixture-admin-id'))).status, 401, 'an authenticator account needs an authenticator session');
  const verified = await f.request('/api/admin/security-status', f.session('fixture-admin-id', { mfaVerified: true }));
  assert.equal(verified.status, 200);
  assert.deepEqual(verified.data.checks, Object.fromEntries(KEYS.map(key => [key, true])));
  assert.equal(verified.data.done, 7);
  assert.deepEqual(verified.data.times, { passwordChangedAt: '2026-10-12T17:00:00.000Z', authenticatorOnSince: '2026-10-12T17:01:00.000Z', sessionsRevokedAt: '2026-10-12T17:02:00.000Z' });
  // Nothing identifying or secret: no account id, login name, address, key or stored hash.
  const body = JSON.stringify(verified.data);
  for (const value of ['fixture-admin-id', 'fixture-private-login-name', 'owner-fixture@example.test', 'alerts@example.test', 'fixture-resend-value', KEY, hash, '"admin"']) assert.ok(!body.includes(value), value);
});

test('ADMIN_MFA_REQUIRED=true: a password-only admin session is refused like any non-admin', async t => {
  const f = await fixture(t, { config: { ADMIN_MFA_REQUIRED: 'true' } });
  const plain = await f.request('/api/admin/security-status', f.session('fixture-admin-id'));
  assert.equal(plain.status, 403); assert.equal(plain.data.checks, undefined);
  assert.equal((await f.request('/api/admin/security-status', f.session('fixture-admin-id', { mfaVerified: true }))).status, 200);
});

test('an account step counts only when every admin account has it; the time is the earliest', async () => {
  // The second account changed its password a day earlier (set-admin-password.js stamps
  // sessionsRevokedAt at that same instant) and was later signed out by an explicit revoke.
  const second = { passwordChangedAt: DONE_AT - 86400000, sessionsRevokedAt: DONE_AT - 86400000 + 3600000 };
  const rows = [admin('fixture-admin-id', hardened), admin('second', second)];
  const status = await adminSecurityStatus({ User: createMemoryModels({ User: rows }).User, config: {}, now: () => NOW });
  assert.equal(status.adminAccounts, 2);
  assert.equal(status.checks.passwordChanged, true); assert.equal(status.checks.sessionsRevoked, true);
  assert.equal(status.checks.authenticatorOn, false, 'the second account has no authenticator');
  assert.deepEqual(status.times, { passwordChangedAt: '2026-10-11T17:00:00.000Z', authenticatorOnSince: null, sessionsRevokedAt: '2026-10-11T18:00:00.000Z' });
  // One account without the explicit revoke: step 5 is open for the whole checklist.
  const partial = await adminSecurityStatus({ User: createMemoryModels({ User: [admin('fixture-admin-id', hardened), admin('second', { ...second, sessionsRevokedAt: second.passwordChangedAt })] }).User, config: {}, now: () => NOW });
  assert.equal(partial.checks.sessionsRevoked, false); assert.equal(partial.times.sessionsRevokedAt, null);
  // No admin account at all: no account step is done.
  const none = await adminSecurityStatus({ User: createMemoryModels({ User: [person('member')] }).User, config: {}, now: () => NOW });
  assert.equal(none.adminAccounts, 0); assert.equal(none.checks.passwordChanged, false); assert.equal(none.checks.authenticatorOn, false);
  assert.equal(none.checks.sessionsRevoked, false); assert.equal(none.checks.privateLoginName, false);
});

test('step 5 counts only an explicit revoke, not the sign-out that steps 1 and 3 already do', async () => {
  const status = async extra => adminSecurityStatus({ User: createMemoryModels({ User: [admin('fixture-admin-id', extra)] }).User, config: {}, now: () => NOW });
  // Step 1 only (the script and the in-app password change stamp both fields at one instant).
  const stepOne = await status({ passwordChangedAt: DONE_AT, sessionsRevokedAt: DONE_AT });
  assert.equal(stepOne.checks.passwordChanged, true); assert.equal(stepOne.checks.sessionsRevoked, false);
  assert.equal(stepOne.done, 1); assert.equal(stepOne.times.sessionsRevokedAt, null);
  // Steps 1 and 3 (enabling the authenticator stamps both fields at one instant).
  const stepThree = await status({ passwordChangedAt: DONE_AT, totpEnabledAt: DONE_AT + 60000, sessionsRevokedAt: DONE_AT + 60000 });
  assert.equal(stepThree.checks.authenticatorOn, true); assert.equal(stepThree.checks.sessionsRevoked, false); assert.equal(stepThree.done, 2);
  // A revoke before the authenticator was enabled is not step 5 either.
  assert.equal((await status({ passwordChangedAt: DONE_AT, sessionsRevokedAt: DONE_AT + 30000, totpEnabledAt: DONE_AT + 60000 })).checks.sessionsRevoked, false);
  // The explicit revoke after both.
  const stepFive = await status(hardened);
  assert.equal(stepFive.checks.sessionsRevoked, true); assert.equal(stepFive.times.sessionsRevokedAt, '2026-10-12T17:02:00.000Z');
  // A revoke alone (no password change, no authenticator) still counts as step 5.
  assert.equal((await status({ sessionsRevokedAt: DONE_AT })).checks.sessionsRevoked, true);
});

test('step 6 is also done when no admin account signs in as "admin" any more; the address is never returned', async () => {
  const realAddress = 'owner-admin@example.test';
  const status = async (rows, config = {}) => adminSecurityStatus({ User: createMemoryModels({ User: rows }).User, config, now: () => NOW });
  const moved = await status([admin('moved', { email: realAddress })]);
  assert.equal(moved.checks.privateLoginName, true);
  assert.ok(!JSON.stringify(moved).includes(realAddress));
  assert.equal((await status([admin('moved', { email: realAddress }), admin('fixture-admin-id')])).checks.privateLoginName, false, 'one account still signs in as admin');
  assert.equal((await status([admin('moved', { email: ' Admin ' })])).checks.privateLoginName, false, 'the public word in any case');
  assert.equal((await status([admin('fixture-admin-id')], { ADMIN_LOGIN_ID: 'fixture-private-login-name' })).checks.privateLoginName, true);
});

test('the configuration steps read the same rules the server enforces', async () => {
  const User = createMemoryModels({ User: [admin('fixture-admin-id')] }).User;
  const checks = async config => (await adminSecurityStatus({ User, config, now: () => NOW })).checks;
  assert.equal((await checks({ ADMIN_LOGIN_ID: ' Admin ' })).privateLoginName, false, 'the public word in any case is not a private name');
  assert.equal((await checks({ ADMIN_LOGIN_ID: '   ' })).privateLoginName, false);
  assert.equal((await checks({ ADMIN_LOGIN_ID: 'fixture-private-login-name' })).privateLoginName, true);
  assert.equal((await checks({ ADMIN_MFA_REQUIRED: ' TRUE ' })).authenticatorRequired, true);
  assert.equal((await checks({ ADMIN_MFA_REQUIRED: 'yes' })).authenticatorRequired, false);
  assert.equal((await checks({ ACCOUNT_SECURITY_ENCRYPTION_KEY: 'too-short' })).encryptionKeySet, false);
  assert.equal((await checks({ ACCOUNT_SECURITY_ENCRYPTION_KEY: KEY })).encryptionKeySet, true);
  // Alerts need delivery on, an owner address and a Resend sender; NODE_ENV=test does not matter here.
  assert.equal((await checks({ ...FULL, NODE_ENV: 'test' })).alertsOn, true);
  for (const missing of ['NOTIFICATION_DELIVERY_ENABLED', 'RESEND_API_KEY', 'RESEND_FROM_EMAIL', 'SECURITY_ALERT_EMAIL']) assert.equal((await checks({ ...FULL, [missing]: '' })).alertsOn, false, missing);
  assert.equal((await checks({ ...FULL, SECURITY_ALERT_EMAIL: '', AI_ALERT_EMAIL: 'owner-fixture@example.test' })).alertsOn, true, 'the same fallback addresses as the alerts');
});

test('public endpoints carry none of it', async t => {
  const f = await fixture(t, { config: FULL, admins: [admin('fixture-admin-id', hardened)] });
  for (const path of ['/api/health', '/api/ai/baybay-capabilities', '/api/ai/usage']) {
    for (const token of [undefined, f.session('member')]) {
      const body = JSON.stringify((await f.request(path, token)).data);
      for (const key of [...KEYS, 'adminAccounts', 'authenticatorOnSince', 'security-status']) assert.ok(!body.includes(key), `${path} ${key}`);
    }
  }
});
