// G44 (API-SEC): with ADMIN_MFA_REQUIRED=true an administrator acts as admin only in an
// authenticator session: admin routes (API-HOTFIX) and now also the public post views
// (hidden posts, report counts, contact values), comment moderation and the admin
// exemptions. Plus the "sign every admin out" endpoint and script.
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { revokeAdminSessions } = require('../lib/adminSessions');
const script = require('../scripts/revoke-admin-sessions');

const SECRET = 'admin-mfa-sessions-secret-0123456789abcdef';
const PASSWORD = 'OnlyMockPassword7';
const hash = bcrypt.hashSync(PASSWORD, 4);
const person = (id, extra = {}) => ({ id, email: `${id}@example.test`, password: hash, nickname: `Neighbor ${id}`, role: 'user', accountStatus: 'active', isBanned: false, createdAt: 1, ...extra });
const post = (id, extra = {}) => ({ id, authorId: 'author', authorNickname: 'Neighbor author', type: 'provider', title: `A sample listing ${id}`,
  description: 'A fictional listing used only for isolated tests.', category: '闲置', city: 'San Francisco', budget: '10', timeInfo: '', createdAt: 100,
  confirmedAt: Date.now() - 60000, status: 'active', isDeleted: false, adminHidden: false, imageUrls: [], likes: [],
  reports: [{ reporterId: 'member', reason: 'spam', createdAt: 100 }],
  comments: [{ id: 'c1', authorId: 'member', authorName: 'Neighbor member', content: 'A member comment', parentId: null, createdAt: 100, isDeleted: false }],
  contactPreference: { mode: 'dm_first', methods: [{ type: 'wechat', value: 'fixture-wechat-id', enabled: true }] }, ...extra });

async function fixture(t, config = {}) {
  const models = createMemoryModels({
    User: [person('admin', { email: 'admin', nickname: 'Admin', role: 'admin' }), person('admin2', { role: 'admin', nickname: 'Second admin' }), person('member'), person('author')],
    Post: [post('open', { isFeatured: true, featuredAt: 100 }), post('hidden', { adminHidden: true, adminHiddenReason: 'fixture', isFeatured: true, featuredAt: 101 })],
  });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config }, models });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, token } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, { method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json().catch(() => ({})) };
  };
  const session = (id, extra = {}) => jwt.sign({ id, purpose: 'session', sessionIssuedAt: Date.now() - 1000, sessionRevision: 0, ...extra }, SECRET, { expiresIn: '1h' });
  return { models, request, session };
}

// What an administrator session sees and may do on member routes.
async function adminPowers(f, token) {
  const list = await f.request('/api/posts', { token });
  const listed = list.data.posts.map(row => row.id).sort();
  const open = (await f.request('/api/posts/open', { token })).data;
  return {
    listed,
    hiddenDetail: (await f.request('/api/posts/hidden', { token })).status,
    featured: (await f.request('/api/posts/featured', { token })).data.posts.map(row => row.id).sort(),
    reportsCount: open.reportsCount,
    contactValue: open.contactPreference?.methods?.[0]?.value,
    commentOnHidden: (await f.request('/api/posts/hidden/comments', { method: 'POST', token, body: { content: 'An admin note here' } })).status,
    editOthersComment: (await f.request('/api/posts/open/comments/c1', { method: 'PATCH', token, body: { content: 'Edited by someone else' } })).status,
  };
}

test('ADMIN_MFA_REQUIRED=true: a password-only admin session is an ordinary member on public post views and comment moderation', async t => {
  const f = await fixture(t, { ADMIN_MFA_REQUIRED: 'true' });
  const plain = await adminPowers(f, f.session('admin'));
  assert.deepEqual(plain, { listed: ['open'], hiddenDetail: 404, featured: ['open'], reportsCount: undefined, contactValue: undefined, commentOnHidden: 404, editOthersComment: 403 });
  const verified = await adminPowers(f, f.session('admin', { mfaVerified: true }));
  assert.deepEqual(verified, { listed: ['hidden', 'open'], hiddenDetail: 200, featured: ['hidden', 'open'], reportsCount: 1, contactValue: 'fixture-wechat-id', commentOnHidden: 200, editOthersComment: 200 });
  // A member never gains anything from an mfaVerified claim.
  const member = await adminPowers(f, f.session('member', { mfaVerified: true }));
  assert.deepEqual(member.listed, ['open']); assert.equal(member.hiddenDetail, 404); assert.equal(member.contactValue, undefined);
});

test('by default (flag off) the administrator keeps every admin view and power without an authenticator', async t => {
  const f = await fixture(t);
  const plain = await adminPowers(f, f.session('admin'));
  assert.deepEqual(plain, { listed: ['hidden', 'open'], hiddenDetail: 200, featured: ['hidden', 'open'], reportsCount: 1, contactValue: 'fixture-wechat-id', commentOnHidden: 200, editOthersComment: 200 });
});

test('ADMIN_MFA_REQUIRED=true: reserved nicknames, the official badge and the unlimited post count also need the authenticator session', async t => {
  const f = await fixture(t, { ADMIN_MFA_REQUIRED: 'true' });
  const plain = f.session('admin');
  const rename = await f.request('/api/users/me', { method: 'PATCH', token: plain, body: { nickname: 'BAYLINK 官方' } });
  assert.equal(rename.status, 400, 'a reserved word needs an admin session');
  await f.request('/api/users/me', { method: 'PATCH', token: plain, body: { isOfficialVerified: true } });
  assert.notEqual(f.models.User.rows.find(row => row.id === 'admin').isOfficialVerified, true);
  const body = { title: 'An admin announcement', description: 'A fictional admin announcement for tests.', category: '闲置', city: 'San Francisco', type: 'provider' };
  const statuses = [];
  for (let index = 0; index < 4; index++) statuses.push((await f.request('/api/posts', { method: 'POST', token: plain, body: { ...body, title: `${body.title} ${index}` } })).status);
  assert.deepEqual(statuses, [200, 200, 200, 429], 'an unverified-phone member gets 3 posts a day');
  const verified = f.session('admin', { mfaVerified: true });
  assert.equal((await f.request('/api/users/me', { method: 'PATCH', token: verified, body: { nickname: 'BAYLINK 官方' } })).status, 200);
  assert.equal((await f.request('/api/posts', { method: 'POST', token: verified, body: { ...body, title: `${body.title} 9` } })).status, 200);
});

test('POST /api/admin/sessions/revoke signs every administrator out everywhere; the caller gets a fresh session; members are untouched', async t => {
  const f = await fixture(t);
  const caller = f.session('admin'), otherDevice = f.session('admin'), secondAdmin = f.session('admin2'), member = f.session('member');
  assert.equal((await f.request('/api/admin/sessions/revoke', { method: 'POST', token: member })).status, 403);
  const revoked = await f.request('/api/admin/sessions/revoke', { method: 'POST', token: caller });
  assert.equal(revoked.status, 200); assert.equal(revoked.data.revokedAccounts, 2);
  for (const token of [caller, otherDevice, secondAdmin]) assert.equal((await f.request('/api/users/me/security', { token })).status, 401);
  assert.equal((await f.request('/api/users/me/security', { token: member })).status, 200, 'members keep their sessions');
  const fresh = revoked.data.user.token;
  assert.equal((await f.request('/api/admin/reports', { token: fresh })).status, 200, 'the caller continues with the new session');
  const log = f.models.ModerationLog.rows.find(row => row.action === 'admin_sessions_revoked');
  assert.equal(log.adminId, 'admin'); assert.equal(log.targetType, 'admin_sessions');
  const admin = f.models.User.rows.find(row => row.id === 'admin');
  assert.equal(admin.sessionRevision, 1); assert.ok(admin.sessionsRevokedAt > 0);
  assert.equal(f.models.User.rows.find(row => row.id === 'member').sessionRevision, undefined);
});

test('the revoke endpoint is an admin route: with ADMIN_MFA_REQUIRED=true it needs the authenticator session, and keeps it', async t => {
  const f = await fixture(t, { ADMIN_MFA_REQUIRED: 'true' });
  const refused = await f.request('/api/admin/sessions/revoke', { method: 'POST', token: f.session('admin') });
  assert.equal(refused.status, 403); assert.equal(refused.data.code, 'ADMIN_MFA_REQUIRED');
  const revoked = await f.request('/api/admin/sessions/revoke', { method: 'POST', token: f.session('admin', { mfaVerified: true }) });
  assert.equal(revoked.status, 200);
  assert.equal(jwt.decode(revoked.data.user.token).mfaVerified, true);
  assert.equal((await f.request('/api/admin/reports', { token: revoked.data.user.token })).status, 200);
});

test('scripts/revoke-admin-sessions.js: dry run by default, --apply revokes admins only, nothing secret printed', async () => {
  const models = createMemoryModels({ User: [person('admin', { role: 'admin' }), person('member')] });
  const lines = [];
  const fakeMongoose = { connected: 0, async connect(uri) { assert.equal(uri, 'mongodb://fixture.invalid/db'); this.connected++; }, async disconnect() { this.connected--; }, models: { AdminSessionUser: models.User } };
  const env = { MONGO_URI: 'mongodb://fixture.invalid/db' };
  const dry = await script.run({ argv: [], env, mongoose: fakeMongoose, log: line => lines.push(line) });
  assert.deepEqual(dry, { applied: false, accounts: 1 });
  assert.equal(models.User.rows[0].sessionRevision, undefined);
  const applied = await script.run({ argv: ['--apply'], env, mongoose: fakeMongoose, log: line => lines.push(line) });
  assert.equal(applied.applied, true); assert.equal(applied.accounts, 1);
  assert.equal(models.User.rows.find(row => row.id === 'admin').sessionRevision, 1);
  assert.equal(models.User.rows.find(row => row.id === 'member').sessionRevision, undefined);
  assert.equal(fakeMongoose.connected, 0, 'always disconnects');
  assert.doesNotMatch(lines.join('\n'), /fixture\.invalid|mongodb:/);
  await assert.rejects(script.run({ argv: ['--force'], env, mongoose: fakeMongoose }), /Unknown argument/);
  await assert.rejects(script.run({ argv: [], env: {}, mongoose: fakeMongoose }), /MONGO_URI is not set/);
});

test('revokeAdminSessions with no admin account changes nothing', async () => {
  const models = createMemoryModels({ User: [person('member')] });
  const result = await revokeAdminSessions({ User: models.User, now: () => 5 });
  assert.deepEqual(result, { at: 5, accounts: 0, ids: [] });
  assert.equal(models.User.rows[0].sessionsRevokedAt, undefined);
});
