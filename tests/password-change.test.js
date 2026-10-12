// G44 (API-SEC): a signed-in password change (the administrator's login name "admin" has no
// mailbox, so the e-mail reset never reaches it) and the owner's offline script.
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');
const { encodeBase32, encryptSecret, totpAt } = require('../lib/accountTotp');
const script = require('../scripts/set-admin-password');

const SECRET = 'password-change-secret-0123456789abcdefgh';
const PASSWORD = 'OnlyMockPassword7';
const key = Buffer.alloc(32, 9);

async function start(t, users) {
  const models = createMemoryModels();
  models.User = accountMemory(users); models.AccountAuthChallenge = accountMemory();
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64') } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, token } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json().catch(() => ({})), cache: response.headers.get('cache-control') };
  };
  return { models, request };
}

test('POST /api/users/me/password: current password required, strength checked, other sessions signed out, this browser keeps a new session', async t => {
  const f = await start(t, [{ id: 'member', email: 'member@example.test', nickname: 'Member', role: 'user', password: bcrypt.hashSync(PASSWORD, 4) }]);
  const login = await f.request('/api/auth/login', { method: 'POST', body: { email: 'member@example.test', password: PASSWORD } });
  const other = await f.request('/api/auth/login', { method: 'POST', body: { email: 'member@example.test', password: PASSWORD } });
  const token = login.data.token;
  const change = body => f.request('/api/users/me/password', { method: 'POST', token, body });
  assert.equal((await f.request('/api/users/me/password', { method: 'POST', body: { password: PASSWORD, newPassword: 'BrandNewMock8Pass' } })).status, 401);
  const weak = await change({ password: PASSWORD, newPassword: 'short' });
  assert.equal(weak.status, 400); assert.equal(weak.data.code, 'WEAK_PASSWORD');
  assert.equal((await change({ password: PASSWORD, newPassword: PASSWORD })).data.code, 'SAME_PASSWORD');
  const wrong = await change({ password: 'WrongMockPassword1', newPassword: 'BrandNewMock8Pass' });
  assert.equal(wrong.status, 403); assert.equal(wrong.data.code, 'CREDENTIAL_CONFIRMATION_REQUIRED');
  const done = await change({ password: PASSWORD, newPassword: 'BrandNewMock8Pass' });
  assert.equal(done.status, 200); assert.equal(done.cache, 'no-store'); assert.equal(done.data.user.password, undefined);
  assert.equal((await f.request('/api/users/me/security', { token: other.data.token })).status, 401, 'the other device is signed out');
  assert.equal((await f.request('/api/users/me/security', { token })).status, 401, 'so is the old token of this browser');
  assert.equal((await f.request('/api/users/me/security', { token: done.data.user.token })).status, 200, 'the new session works');
  assert.equal((await f.request('/api/auth/login', { method: 'POST', body: { email: 'member@example.test', password: PASSWORD } })).status, 401);
  assert.equal((await f.request('/api/auth/login', { method: 'POST', body: { email: 'member@example.test', password: 'BrandNewMock8Pass' } })).status, 200);
});

test('with the authenticator on, the change also needs a current code; the new session stays an authenticator session', async t => {
  const shared = encodeBase32(crypto.randomBytes(20));
  const f = await start(t, [{ id: 'admin', email: 'admin', nickname: 'Admin', role: 'admin', password: bcrypt.hashSync(PASSWORD, 4), totpEnabledAt: Date.now() - 1000,
    accountSecurity: { secretCipher: encryptSecret(shared, 'admin', key), recoveryHashes: [] } }]);
  const token = jwt.sign({ id: 'admin', purpose: 'session', sessionIssuedAt: Date.now(), sessionRevision: 0, mfaVerified: true }, SECRET, { expiresIn: '1h' });
  const noCode = await f.request('/api/users/me/password', { method: 'POST', token, body: { password: PASSWORD, newPassword: 'AdminNewMock8Pass' } });
  assert.equal(noCode.status, 403); assert.equal(noCode.data.code, 'MFA_INVALID');
  // An administrator password needs 12+ characters here too (same rule as the offline script),
  // refused before the authenticator code is used, so the same code still works below.
  assert.equal(script.strongAdminPassword('AdminMock8a'), false); assert.equal(script.strongAdminPassword('AdminMock8ab'), true);
  const short = await f.request('/api/users/me/password', { method: 'POST', token, body: { password: PASSWORD, newPassword: 'AdminMock8a', totpCode: totpAt(shared, Date.now()) } });
  assert.equal(short.status, 400); assert.equal(short.data.code, 'WEAK_PASSWORD'); assert.match(short.data.error, /管理员新密码至少 12 位/);
  const done = await f.request('/api/users/me/password', { method: 'POST', token, body: { password: PASSWORD, newPassword: 'AdminNewMock8Pass', totpCode: totpAt(shared, Date.now()) } });
  assert.equal(done.status, 200);
  assert.equal(jwt.decode(done.data.user.token).mfaVerified, true);
  assert.equal((await f.request('/api/admin/reports', { token: done.data.user.token })).status, 200);
});

function scriptFixture(users) {
  const models = createMemoryModels({ User: users });
  const lines = [];
  const fakeMongoose = { open: 0, async connect() { this.open++; }, async disconnect() { this.open--; }, models: { AdminPasswordUser: models.User } };
  const run = (argv, answers = []) => script.run({ argv, env: { MONGO_URI: 'mongodb://fixture.invalid/db' }, mongoose: fakeMongoose, log: line => lines.push(line),
    readPassword: async () => answers.shift(), now: () => 1234 });
  return { models, lines, fakeMongoose, run };
}

test('scripts/set-admin-password.js: dry run names the account; --apply asks twice, needs 12+ mixed characters, signs every session out, never prints the password', async () => {
  const f = scriptFixture([{ id: 'admin', email: 'admin', nickname: 'Admin', role: 'admin', password: 'old-hash' }, { id: 'member', role: 'user', password: 'member-hash' }]);
  assert.deepEqual(await f.run([]), { applied: false, id: 'admin' });
  assert.equal(f.models.User.rows[0].password, 'old-hash');
  await assert.rejects(f.run(['--apply'], ['Short1Aa', 'Short1Aa']), /12-128 characters/);
  await assert.rejects(f.run(['--apply'], ['LongEnoughMock12', 'LongEnoughMock13']), /two entries differ/);
  assert.equal(f.models.User.rows[0].password, 'old-hash', 'nothing changed by a refused run');
  const done = await f.run(['--apply'], ['LongEnoughMock12', 'LongEnoughMock12']);
  assert.deepEqual(done, { applied: true, id: 'admin', at: 1234 });
  const admin = f.models.User.rows[0];
  assert.ok(await bcrypt.compare('LongEnoughMock12', admin.password));
  assert.equal(admin.sessionRevision, 1); assert.equal(admin.passwordChangedAt, 1234); assert.equal(admin.sessionsRevokedAt, 1234);
  assert.equal(f.models.User.rows[1].password, 'member-hash');
  assert.equal(f.fakeMongoose.open, 0);
  assert.doesNotMatch(f.lines.join('\n'), /LongEnoughMock|fixture\.invalid/);
});

test('scripts/set-admin-password.js: more than one administrator needs --id; unknown arguments and a missing MONGO_URI are refused', async () => {
  const f = scriptFixture([{ id: 'a1', role: 'admin', password: 'h1' }, { id: 'a2', role: 'admin', password: 'h2' }]);
  await assert.rejects(f.run([]), /2 administrator accounts: pick one with --id=<a1 \| a2>/);
  assert.deepEqual(await f.run(['--id=a2']), { applied: false, id: 'a2' });
  await assert.rejects(f.run(['--id=nobody']), /No administrator account with id nobody/);
  await assert.rejects(f.run(['--password=x']), /Unknown argument/);
  await assert.rejects(script.run({ argv: [], env: {}, mongoose: f.fakeMongoose }), /MONGO_URI is not set/);
  assert.equal(script.strongAdminPassword('abcdefghijK1'), true);
  assert.equal(script.strongAdminPassword('abcdefghijk1'), false);
});
