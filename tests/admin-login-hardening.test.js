// ENGSEC-03: the administrator account signs in with the public word "admin" and MFA
// is optional for it. ADMIN_LOGIN_ID gives it a private login name (opt-in) and
// ADMIN_MFA_REQUIRED=true requires an authenticator session for admin actions
// (opt-in; off by default because the owner has no authenticator yet).
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'admin-login-hardening-secret-0123456789abcdef';
const PASSWORD = 'OnlyMockPassword7';
const hash = bcrypt.hashSync(PASSWORD, 4);

async function fixture(t, config = {}) {
  const models = createMemoryModels({ User: [
    { id: 'admin', email: 'admin', password: hash, nickname: 'Admin', role: 'admin', accountStatus: 'active', isBanned: false },
    { id: 'member', email: 'member@example.test', password: hash, nickname: 'Member', role: 'user', accountStatus: 'active', isBanned: false },
  ] });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config }, models });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, token } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json().catch(() => ({})) };
  };
  const login = email => request('/api/auth/login', { method: 'POST', body: { email, password: PASSWORD } });
  const session = (id, extra = {}) => jwt.sign({ id, purpose: 'session', sessionIssuedAt: Date.now() - 1000, sessionRevision: 0, ...extra }, SECRET, { expiresIn: '1h' });
  return { request, login, session };
}

test('by default the administrator still signs in as "admin" (no lockout) and admin routes need no authenticator', async t => {
  const f = await fixture(t);
  const login = await f.login('admin');
  assert.equal(login.status, 200); assert.ok(login.data.token);
  assert.equal((await f.login('ADMIN')).status, 200, 'the stored login name, any letter case, as before');
  assert.equal((await f.request('/api/admin/reports', { token: login.data.token })).status, 200);
  assert.equal((await f.login('member@example.test')).status, 200);
});

test('ADMIN_LOGIN_ID: the administrator signs in with the private name only; "admin" is refused like an unknown name', async t => {
  const f = await fixture(t, { ADMIN_LOGIN_ID: 'harbor-lantern-0427-owner' });
  for (const name of ['admin', 'ADMIN', ' admin ']) assert.deepEqual(await f.login(name), { status: 401, data: { error: 'Invalid credentials' } }, name);
  const login = await f.login('harbor-lantern-0427-owner');
  assert.equal(login.status, 200); assert.equal(login.data.isAdmin ?? (login.data.role === 'admin'), true);
  assert.equal((await f.login('member@example.test')).status, 200, 'members are unaffected');
  // The private name finds only the administrator account.
  const wrongPassword = await f.request('/api/auth/login', { method: 'POST', body: { email: 'harbor-lantern-0427-owner', password: 'wrong' } });
  assert.equal(wrongPassword.status, 401);
});

test('forgot-password has no "admin" special case', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/auth/forgot-password', { method: 'POST', body: { email: 'admin' } })).status, 400);
});

test('ADMIN_MFA_REQUIRED=true: admin routes and admin checks in member routes need an authenticator session; signing in and member features still work', async t => {
  const f = await fixture(t, { ADMIN_MFA_REQUIRED: 'true' });
  const login = await f.login('admin');
  assert.equal(login.status, 200, 'the administrator can still sign in to set up the authenticator');
  const plain = login.data.token;
  const reports = await f.request('/api/admin/reports', { token: plain });
  assert.equal(reports.status, 403); assert.equal(reports.data.code, 'ADMIN_MFA_REQUIRED');
  const content = { method: 'POST', body: { key: 'notice', value: 'fixture' } };
  assert.equal((await f.request('/api/content', { ...content, token: plain })).status, 403, 'a member route\'s admin check too');
  assert.equal((await f.request('/api/users/me/security', { token: plain })).status, 200, 'the security page stays open');
  const verified = f.session('admin', { mfaVerified: true });
  assert.equal((await f.request('/api/admin/reports', { token: verified })).status, 200);
  assert.equal((await f.request('/api/content', { ...content, token: verified })).status, 200);
  // Members are unaffected; a member is never an admin.
  assert.equal((await f.request('/api/admin/reports', { token: f.session('member', { mfaVerified: true }) })).status, 403);
});
