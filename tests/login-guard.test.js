// G44 (API-SEC): failed sign-ins are counted in Mongo, so a deploy or restart does not
// reopen the limits, and repeated failures on the administrator account e-mail the owner
// (never from tests: NODE_ENV=test and the delivery gates keep the sender silent).
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');
const { encodeBase32, encryptSecret, totpAt } = require('../lib/accountTotp');
const { LIMITS, WINDOW_MS, createLoginGuard, alertSteps, securityAlertState } = require('../lib/loginGuard');

const SECRET = 'login-guard-secret-0123456789abcdefghijkl';
const PASSWORD = 'OnlyMockPassword7';
const hash = bcrypt.hashSync(PASSWORD, 4);
const person = (id, extra = {}) => ({ id, email: `${id}@example.test`, password: hash, nickname: `Neighbor ${id}`, role: 'user', accountStatus: 'active', isBanned: false, ...extra });
const LIVE_ALERTS = { NODE_ENV: 'production', NOTIFICATION_DELIVERY_ENABLED: 'true', OWNER_DIGEST_EMAIL: 'owner@example.test' };

function guardFixture({ config = {}, start = Date.parse('2026-10-12T17:00:00Z') } = {}) {
  const { AuthLimit } = createMemoryModels();
  let at = start;
  const mail = [], logs = [];
  const guard = createLoginGuard({ Model: AuthLimit, secret: SECRET, config, now: () => at,
    sendEmail: async message => { mail.push(message); return { id: `mock-${mail.length}` }; },
    logger: { info: line => logs.push(line), error: (...parts) => logs.push(parts.join(' ')) } });
  return { guard, AuthLimit, mail, logs, advance: ms => { at += ms; } };
}

test('per visitor, per visitor on one account and per account: the same ceilings as the in-memory limiter, counted from failures', async () => {
  const f = guardFixture();
  assert.deepEqual(LIMITS, { visitor: 10, accountVisitor: 8, account: 100 });
  const attempt = { visitor: '198.51.100.7', account: 'Owner@Example.test' };
  for (let index = 0; index < LIMITS.accountVisitor; index++) {
    assert.equal(await f.guard.blocked(attempt), false);
    await f.guard.recordFailure(attempt);
  }
  assert.equal(await f.guard.blocked(attempt), true, 'the guessing visitor is held on that account');
  assert.equal(await f.guard.blocked({ ...attempt, account: ' owner@example.test ' }), true, 'login names are compared trimmed and lower-cased');
  assert.equal(await f.guard.blocked({ visitor: '198.51.100.8', account: 'owner@example.test' }), false, 'the owner elsewhere is not');
  assert.equal(await f.guard.blocked({ visitor: '198.51.100.7', account: 'other@example.test' }), false);
  await f.guard.recordFailure({ visitor: '198.51.100.7', account: 'a@example.test' });
  await f.guard.recordFailure({ visitor: '198.51.100.7' });
  assert.equal(await f.guard.blocked({ visitor: '198.51.100.7', account: 'b@example.test' }), true, '10 failures from one visitor hold every account');
  // Distributed guessing against one account stops at 100 failures overall.
  const g = guardFixture();
  for (let index = 0; index < LIMITS.account; index++) await g.guard.recordFailure({ visitor: `203.0.113.${index % 50}:${index}`, account: 'target@example.test' });
  assert.equal(await g.guard.blocked({ visitor: '192.0.2.200', account: 'target@example.test' }), true);
  assert.equal(await g.guard.blocked({ visitor: '192.0.2.200', account: 'someone@example.test' }), false);
  // The window is fixed (15 minutes) and the rows expire on their own.
  g.advance(WINDOW_MS);
  assert.equal(await g.guard.blocked({ visitor: '192.0.2.200', account: 'target@example.test' }), false);
  const stored = JSON.stringify(f.AuthLimit.rows);
  assert.doesNotMatch(stored, /198\.51|example\.test|owner/i, 'keys are HMAC digests, never the address or login name');
  assert.ok(f.AuthLimit.rows.every(row => Date.parse(row.expiresAt) > Date.parse('2026-10-12T17:00:00Z')));
});

test('an unreadable store fails open and logs without the error details', async () => {
  const logs = [];
  const broken = { find: () => ({ lean: async () => { throw Object.assign(new Error('secret connection string'), { code: 'ECONNREFUSED' }); } }),
    findOneAndUpdate: async () => { throw Object.assign(new Error('secret'), { code: 'ECONNREFUSED' }); } };
  const guard = createLoginGuard({ Model: broken, secret: SECRET, logger: { error: (...parts) => logs.push(parts.join(' ')) } });
  assert.equal(await guard.blocked({ visitor: '198.51.100.9', account: 'x@example.test' }), false);
  await guard.recordFailure({ visitor: '198.51.100.9', account: 'x@example.test' });
  assert.equal(logs.length, 1, 'one line per minute');
  assert.doesNotMatch(logs.join('\n'), /secret/);
});

test('the limits survive a restart: a new server process still refuses the 9th attempt from the same visitor', async t => {
  const models = createMemoryModels({ User: [person('owner')] });
  const boot = async () => {
    const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, TRUST_PROXY_HOPS: 1 }, models });
    await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => application.io.close(resolve)));
    return (email, password, ip) => fetch(`http://127.0.0.1:${application.server.address().port}/api/auth/login`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify({ email, password }) }).then(response => response.status);
  };
  const first = await boot();
  for (let index = 0; index < 4; index++) assert.equal(await first('owner@example.test', 'WrongPassword1', '198.51.100.21'), 401);
  const second = await boot(); // a deploy: the in-memory limiter is empty again
  for (let index = 0; index < 4; index++) assert.equal(await second('owner@example.test', 'WrongPassword1', '198.51.100.21'), 401);
  const third = await boot();
  assert.equal(await third('owner@example.test', PASSWORD, '198.51.100.21'), 429, 'eight failures in this window, across three processes');
  assert.equal(await third('owner@example.test', PASSWORD, '198.51.100.22'), 200, 'the owner from another visitor key signs in');
  // Unknown login names count for the visitor too, so probing names is limited as well.
  for (let index = 0; index < 10; index++) assert.equal(await third(`nobody${index}@example.test`, 'WrongPassword1', '198.51.100.23'), 401);
  assert.equal(await (await boot())('owner@example.test', PASSWORD, '198.51.100.23'), 429);
});

test('admin failures: one owner e-mail at 10 / 50 / 200 / 1000 per Pacific day, with the authenticator count and no address or IP', async () => {
  const f = guardFixture({ config: LIVE_ALERTS });
  const fail = (index, factor) => f.guard.recordFailure({ visitor: `198.51.100.${index}`, account: 'admin', adminAccountId: 'admin-id', factor });
  for (let index = 0; index < 9; index++) assert.equal((await fail(index)).alert, null);
  const tenth = await fail(9, 'totp');
  assert.deepEqual(await tenth.alert, { sent: true, id: 'admin-login:2026-10-12:10' });
  assert.equal(f.mail.length, 1);
  const [message] = f.mail;
  assert.equal(message.to, 'owner@example.test');
  assert.equal(message.idempotencyKey, 'baylink-admin-login:2026-10-12:10');
  assert.match(message.subject, /管理员账号今天已有 10 次登录失败/);
  assert.match(message.text, /其中 1 次是密码正确、验证器代码错误/);
  assert.match(message.text, /\/api\/admin\/sessions\/revoke/);
  assert.match(message.text, /scripts\/revoke-admin-sessions\.js --apply/);
  assert.doesNotMatch(message.text, /198\.51|admin-id/);
  for (let index = 10; index < 49; index++) await fail(index);
  assert.equal(f.mail.length, 1, 'nothing between steps');
  await (await fail(49)).alert;
  assert.equal(f.mail.length, 2); assert.match(f.mail[1].subject, /50 次/);
  // A member's failures never alert.
  for (let index = 0; index < 12; index++) await f.guard.recordFailure({ visitor: '192.0.2.1', account: 'member@example.test' });
  assert.equal(f.mail.length, 2);
  // A new Pacific day starts again from zero.
  f.advance(86400000);
  for (let index = 0; index < 10; index++) await (await fail(index)).alert;
  assert.equal(f.mail.length, 3); assert.match(f.mail[2].subject, /10 次/); assert.doesNotMatch(f.mail[2].text, /验证器代码错误/);
});

test('alert gates: off under NODE_ENV=test, without delivery or an owner address; SECURITY_ALERT_EMAIL wins; steps are configurable', async () => {
  assert.equal(securityAlertState({ ...LIVE_ALERTS, NODE_ENV: 'test' }).enabled, false);
  assert.equal(securityAlertState({ ...LIVE_ALERTS, NOTIFICATION_DELIVERY_ENABLED: 'false' }).reason, 'delivery-disabled');
  assert.equal(securityAlertState({ ...LIVE_ALERTS, OWNER_DIGEST_EMAIL: 'not-an-address' }).reason, 'no-owner-email');
  assert.equal(securityAlertState({ ...LIVE_ALERTS, SECURITY_ALERT_EMAIL: 'security@example.test', AI_ALERT_EMAIL: 'ai@example.test' }).to, 'security@example.test');
  assert.equal(securityAlertState({ ...LIVE_ALERTS, AI_ALERT_EMAIL: 'ai@example.test' }).to, 'ai@example.test');
  // SECURITY_ALERT_EMAIL is enough on its own (no AI_ALERT_EMAIL / OWNER_DIGEST_EMAIL needed).
  assert.deepEqual(securityAlertState({ NODE_ENV: 'production', NOTIFICATION_DELIVERY_ENABLED: 'true', SECURITY_ALERT_EMAIL: ' sec@example.test ' }), { enabled: true, reason: 'on', to: 'sec@example.test' });
  assert.equal(securityAlertState({ NODE_ENV: 'test', NOTIFICATION_DELIVERY_ENABLED: 'true', SECURITY_ALERT_EMAIL: 'sec@example.test' }).reason, 'test');
  assert.equal(securityAlertState({ NODE_ENV: 'production', SECURITY_ALERT_EMAIL: 'sec@example.test' }).reason, 'delivery-disabled');
  assert.equal(securityAlertState({ NODE_ENV: 'production', NOTIFICATION_DELIVERY_ENABLED: 'true' }).reason, 'no-owner-email');
  assert.deepEqual(alertSteps({}), [10, 50, 200, 1000]);
  assert.deepEqual(alertSteps({ ADMIN_LOGIN_ALERT_STEPS: '5, 3, x, 3, 0' }), [3, 5]);
  const f = guardFixture({ config: { ...LIVE_ALERTS, NOTIFICATION_DELIVERY_ENABLED: 'false', ADMIN_LOGIN_ALERT_STEPS: '2' } });
  await f.guard.recordFailure({ visitor: 'v', account: 'admin', adminAccountId: 'admin-id' });
  assert.deepEqual(await (await f.guard.recordFailure({ visitor: 'v', account: 'admin', adminAccountId: 'admin-id' })).alert, { sent: false, reason: 'delivery-disabled' });
  assert.equal(f.mail.length, 0);
  assert.deepEqual(f.logs, ['[security-alerts] due, not sent (delivery-disabled): admin-login:2026-10-12:2']);
});

test('server: admin sign-in failures (password and authenticator) are counted, and no e-mail leaves a test run', async t => {
  const shared = encodeBase32(crypto.randomBytes(20)), key = Buffer.alloc(32, 7);
  const models = createMemoryModels();
  models.User = accountMemory([person('admin', { email: 'admin', role: 'admin', totpEnabledAt: Date.now(), accountSecurity: { secretCipher: encryptSecret(shared, 'admin', key), recoveryHashes: [] } })]);
  models.AccountAuthChallenge = accountMemory();
  const sent = [];
  const application = createApplication({ models, securityAlertEmail: async message => { sent.push(message); },
    config: { NODE_ENV: 'test', JWT_SECRET: SECRET, TRUST_PROXY_HOPS: 1, ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64'), ...LIVE_ALERTS, NODE_ENV: 'test', ADMIN_LOGIN_ALERT_STEPS: '3' } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const post = (path, body, ip) => fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify(body) }).then(async response => ({ status: response.status, data: await response.json() }));
  assert.equal((await post('/api/auth/login', { email: 'admin', password: 'WrongPassword1' }, '198.51.100.31')).status, 401);
  assert.equal((await post('/api/auth/login', { email: 'admin', password: 'WrongPassword1' }, '198.51.100.32')).status, 401);
  const challenge = await post('/api/auth/login', { email: 'admin', password: PASSWORD }, '198.51.100.33');
  assert.equal(challenge.data.mfaRequired, true);
  const wrong = await post('/api/auth/login/totp', { challengeToken: challenge.data.challengeToken, totpCode: totpAt(shared, Date.now()) === '000000' ? '111111' : '000000' }, '198.51.100.33');
  assert.equal(wrong.status, 403); assert.equal(wrong.data.code, 'MFA_INVALID');
  const day = models.AuthLimit.rows.filter(row => row._id.startsWith('d'));
  assert.deepEqual(day.map(row => row.count).sort(), [1, 3], 'three admin failures today, one of them the authenticator');
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(sent.length, 0, 'the third failure reached the alert step, but NODE_ENV=test never sends');
  const ok = await post('/api/auth/login/totp', { challengeToken: challenge.data.challengeToken, totpCode: totpAt(shared, Date.now()) }, '198.51.100.33');
  assert.equal(ok.status, 200); assert.ok(ok.data.token);
});

test('ADMIN_LOGIN_ID: 100 failures typed against the retired name "admin" never hold the owner at the authenticator step', async t => {
  const shared = encodeBase32(crypto.randomBytes(20)), key = Buffer.alloc(32, 3), privateName = 'owner-private-login';
  const models = createMemoryModels();
  models.User = accountMemory([person('admin', { email: 'admin', role: 'admin', totpEnabledAt: Date.now(), accountSecurity: { secretCipher: encryptSecret(shared, 'admin', key), recoveryHashes: [] } })]);
  models.AccountAuthChallenge = accountMemory();
  const application = createApplication({ models,
    config: { NODE_ENV: 'test', JWT_SECRET: SECRET, TRUST_PROXY_HOPS: 1, ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64'), ADMIN_LOGIN_ID: privateName } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const post = (path, body, ip) => fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify(body) }).then(async response => ({ status: response.status, data: await response.json() }));
  // A stranger spreads 100 wrong passwords for "admin" over 13 visitor keys (each under its own ceilings).
  for (let index = 0; index < LIMITS.account; index++) assert.equal((await post('/api/auth/login', { email: 'admin', password: 'WrongPassword1' }, `203.0.113.${index % 13}`)).status, 401);
  assert.equal((await post('/api/auth/login', { email: 'admin', password: PASSWORD }, '198.51.100.40')).status, 429, 'the retired name is held (and refused anyway)');
  const challenge = await post('/api/auth/login', { email: privateName, password: PASSWORD }, '198.51.100.41');
  assert.equal(challenge.status, 200); assert.equal(challenge.data.mfaRequired, true);
  const ok = await post('/api/auth/login/totp', { challengeToken: challenge.data.challengeToken, totpCode: totpAt(shared, Date.now()) }, '198.51.100.41');
  assert.equal(ok.status, 200, 'the authenticator step is keyed by the private name the owner typed, not by "admin"'); assert.ok(ok.data.token);
  // Wrong codes after the private name count toward the private name, as the password step does.
  const wrongCode = totpAt(shared, Date.now()) === '000000' ? '111111' : '000000';
  for (let round = 0; round < 2; round++) {
    const again = await post('/api/auth/login', { email: privateName, password: PASSWORD }, '198.51.100.42');
    assert.equal(again.status, 200);
    for (let index = 0; index < 4; index++) assert.equal((await post('/api/auth/login/totp', { challengeToken: again.data.challengeToken, totpCode: wrongCode }, '198.51.100.42')).status, 403);
  }
  assert.equal((await post('/api/auth/login', { email: privateName, password: PASSWORD }, '198.51.100.42')).status, 429, 'eight authenticator failures on the private name from one visitor');
});

test('the failed-sign-in alert sends the owner to steps that exist today (the offline script), not to a missing web form', () => {
  const { adminAlert } = require('../lib/loginGuard');
  const { text } = adminAlert({ count: 10, totp: 0, step: 10, steps: [10, 50], at: Date.parse('2026-10-12T17:00:00Z') });
  const first = text.split('\n').find(line => line.startsWith('1. '));
  assert.match(first, /node scripts\/set-admin-password\.js --apply/);
  assert.match(first, /--env=/); assert.match(first, /POST \/api\/users\/me\/password/); assert.match(first, /12 位/);
  assert.doesNotMatch(text, /隐私与安全/);
});

test('admin security events: one owner e-mail per change (authenticator, recovery codes, password, revoke); unknown kinds send nothing', async () => {
  const f = guardFixture({ config: LIVE_ALERTS });
  const sent = await f.guard.adminSecurityEvent({ kind: 'totp-enabled', accountId: 'admin-id' });
  assert.equal(sent.sent, true); assert.match(sent.id, /^admin-event:totp-enabled:\d+$/);
  assert.match(f.mail[0].subject, /管理员账号刚刚开启了验证器/);
  assert.match(f.mail[0].text, /如果不是你/); assert.match(f.mail[0].text, /set-admin-password\.js --apply/);
  assert.doesNotMatch(f.mail[0].text, /admin-id/);
  for (const kind of ['totp-disabled', 'recovery-codes-replaced', 'password-changed', 'sessions-revoked']) assert.equal((await f.guard.adminSecurityEvent({ kind, accountId: 'admin-id' })).sent, true, kind);
  assert.equal(f.mail.length, 5);
  assert.deepEqual(await f.guard.adminSecurityEvent({ kind: 'something-else', accountId: 'admin-id' }), { sent: false, reason: 'unknown-event' });
  assert.equal(f.mail.length, 5);
});

test('server: password change and session revoke on an admin account raise the owner notice (logged, never sent, in tests); members raise none', async t => {
  const lines = [];
  const models = createMemoryModels({ User: [person('admin', { email: 'admin', role: 'admin' }), person('member')] });
  models.User = accountMemory(models.User.rows.map(row => ({ ...row })));
  models.AccountAuthChallenge = accountMemory();
  const sent = [];
  const application = createApplication({ models, securityAlertEmail: async message => { sent.push(message); },
    securityAlertLog: { info: line => lines.push(line), error: (...parts) => lines.push(parts.join(' ')) },
    config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...LIVE_ALERTS, NODE_ENV: 'test' } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const post = (path, body, token) => fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) }).then(async response => ({ status: response.status, data: await response.json() }));
  const member = await post('/api/auth/login', { email: 'member@example.test', password: PASSWORD });
  assert.equal((await post('/api/users/me/password', { password: PASSWORD, newPassword: 'MemberNewMock8' }, member.data.token)).status, 200);
  assert.equal(lines.filter(line => line.includes('admin-event')).length, 0, 'a member changing a password is not an admin event');
  const admin = await post('/api/auth/login', { email: 'admin', password: PASSWORD });
  const changed = await post('/api/users/me/password', { password: PASSWORD, newPassword: 'AdminNewMock8Pass' }, admin.data.token);
  assert.equal(changed.status, 200);
  assert.equal((await post('/api/admin/sessions/revoke', {}, changed.data.user.token)).status, 200);
  await new Promise(resolve => setTimeout(resolve, 20));
  const events = lines.filter(line => line.includes('admin-event'));
  assert.equal(events.length, 2);
  assert.match(events[0], /^\[security-alerts\] due, not sent \(test\): admin-event:password-changed:\d+$/);
  assert.match(events[1], /admin-event:sessions-revoked:/);
  assert.equal(sent.length, 0);
});

test('server: enabling and disabling the authenticator on the admin account raise the owner notice', async t => {
  const key = Buffer.alloc(32, 5), lines = [];
  const models = createMemoryModels();
  models.User = accountMemory([person('admin', { email: 'admin', role: 'admin' })]);
  models.AccountAuthChallenge = accountMemory();
  const application = createApplication({ models, securityAlertLog: { info: line => lines.push(line), error: () => {} },
    config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64') } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const post = (path, body, token) => fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) }).then(async response => ({ status: response.status, data: await response.json() }));
  const login = await post('/api/auth/login', { email: 'admin', password: PASSWORD });
  const setup = await post('/api/users/me/security/totp/setup', { password: PASSWORD }, login.data.token);
  assert.equal(setup.status, 200);
  const enabled = await post('/api/users/me/security/totp/confirm', { password: PASSWORD, totpCode: totpAt(setup.data.secret, Date.now()), recoveryCodesSaved: true }, login.data.token);
  assert.equal(enabled.status, 200);
  const disabled = await post('/api/users/me/security/totp/disable', { password: PASSWORD, recoveryCode: setup.data.recoveryCodes[0] }, enabled.data.user.token);
  assert.equal(disabled.status, 200);
  await new Promise(resolve => setTimeout(resolve, 20));
  const events = lines.filter(line => line.includes('admin-event')).map(line => line.replace(/^.*admin-event:([a-z-]+):\d+$/, '$1'));
  assert.deepEqual(events, ['totp-enabled', 'totp-disabled']);
});
