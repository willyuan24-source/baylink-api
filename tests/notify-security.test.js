const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { createMemoryModels } = require('./support/memory-models');
const { memory } = require('./support/notification-memory');

// Isolated: no .env, no Mongo, no provider SDKs. Email/SMS are in-memory mocks.
dotenv.config = () => { throw new Error('Tests must not load .env'); };
mongoose.connect = async () => { throw new Error('Tests must not connect to MongoDB'); };
const { createApplication } = require('../server');
const { FIRST_NOTICE_DELAY, HALF_HOUR } = require('../lib/notifications');
const { NUMBER_DAILY_LIMIT } = require('../lib/smsQuota');

const SECRET = 'isolated-notify-security-secret-with-32-plus-chars';
const PASSWORD = 'TestPassword7';
const passwordHash = bcrypt.hashSync(PASSWORD, 4);
const sha = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const makeUser = (id, extra = {}) => ({ id, email: `${id}@example.test`, password: passwordHash, nickname: `Neighbor ${id}`, role: 'user',
  contactType: 'wechat', contactValue: 'fictional-contact', accountStatus: 'active', isBanned: false, ...extra });
const makePost = (id, authorId) => ({ id, authorId, authorNickname: `Neighbor ${authorId}`, type: 'provider', title: 'A sample community listing',
  description: 'A fictional listing used only for isolated tests.', category: '闲置', city: 'San Francisco', budget: '10', timeInfo: '', createdAt: 100,
  confirmedAt: 100, status: 'active', isDeleted: false, adminHidden: false, imageUrls: [], comments: [], likes: [], reports: [] });
const notificationModels = () => ({ NotificationAccount: memory(), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory() });
// A recipient who verified this email and opted into every email topic (what the web "enable all" button produces).
const optedIn = id => ({ _id: sha(`account:${id}`), userId: id, revision: 1, consentRevision: 1, locale: 'en', requests: 0, lastRequestedAt: 0,
  verifiedEmailHash: sha(`email:${id}@example.test`), emailVerifiedAt: 1,
  preferences: { email: { message: true, contact_request: true, outing_request: true, comment: true }, sms: { message: false, contact_request: false, outing_request: false, comment: false } } });

async function start(t, { models, config = {}, ...options } = {}) {
  const application = createApplication({ ...options, models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...config } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const url = `http://127.0.0.1:${application.server.address().port}/api`;
  const request = async (path, { as, body, method = body === undefined ? 'GET' : 'POST', headers = {} } = {}) => {
    const response = await fetch(`${url}${path}`, { method, headers: {
      ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers,
    }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await response.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    return { status: response.status, data };
  };
  return { application, request };
}

function notifyFixture(t, seed = {}) {
  const models = { ...createMemoryModels({
    User: [makeUser('owner'), makeUser('other'), makeUser('third')],
    Post: [makePost('other-post', 'other'), makePost('owner-post', 'owner')],
    Conversation: [{ id: 'conversation', userIds: ['owner', 'other'], updatedAt: 100 }],
    ...seed,
  }), ...notificationModels() };
  for (const id of ['owner', 'other']) models.NotificationAccount.rows.set(sha(`account:${id}`), optedIn(id));
  const mail = [];
  let offset = 0;
  const clock = { set: ms => { offset = ms; } };
  return start(t, { models, config: { NOTIFICATION_DELIVERY_ENABLED: 'true' }, notificationNow: () => Date.now() + offset,
    notificationEmail: async value => { mail.push(value); return { id: `mock-${mail.length}` }; } })
    .then(api => ({ ...api, models, mail, clock, jobs: topic => [...models.NotificationJob.rows.values()].filter(row => row.topic === topic) }));
}

test('three DMs in a row leave one coalesced NotificationJob due at T+5 min; reading the thread cancels the follow-up', async t => {
  const f = await notifyFixture(t);
  const before = Date.now(), ids = [];
  for (const content of ['hi', 'are you there?', 'one more']) {
    const sent = await f.request('/conversations/conversation/messages', { as: 'owner', body: { type: 'text', content } });
    assert.equal(sent.status, 200); ids.push(sent.data.id);
  }
  const [job] = f.jobs('message');
  assert.equal(f.jobs('message').length, 1, 'one pending notice per recipient/thread');
  assert.equal(job.recipientId, 'other'); assert.equal(job.status, 'queued'); assert.equal(job.events, 3);
  assert.ok(job.availableAt >= before + FIRST_NOTICE_DELAY && job.availableAt <= Date.now() + FIRST_NOTICE_DELAY);
  assert.equal((await f.application.notifications.runOnce()).processed, 0, 'nothing before T+5 min');
  f.clock.set(FIRST_NOTICE_DELAY + 1000);
  assert.equal((await f.application.notifications.runOnce()).processed, 1);
  assert.equal(f.mail.length, 1);
  assert.ok(f.mail[0].text.includes('https://www.baylink.us/en/messages/conversation'));
  assert.doesNotMatch(f.mail[0].text, /are you there|one more/);

  // A new message after the notice waits for the 30-minute window; the recipient reads it in-app first.
  f.clock.set(0);
  const later = await f.request('/conversations/conversation/messages', { as: 'owner', body: { type: 'text', content: 'still there?' } });
  ids.push(later.data.id);
  const followUp = f.jobs('message').find(row => row.status === 'queued');
  assert.ok(followUp.availableAt >= before + FIRST_NOTICE_DELAY + HALF_HOUR);
  const read = await f.request('/conversations/conversation/read', { as: 'other', body: { messageId: later.data.id, messageIds: ids } });
  assert.equal(read.status, 200); assert.equal(read.data.unreadCount, 0);
  f.clock.set(FIRST_NOTICE_DELAY + HALF_HOUR + 5000);
  await f.application.notifications.runOnce();
  assert.equal(f.mail.length, 1, 'a thread read in-app gets no email');
  assert.deepEqual(f.jobs('message').map(row => [row.status, row.events, row.reason]), [['sent', 3, undefined], ['cancelled', 1, 'read']]);
});

test('comments notify the post author and the replied-to commenter, never the commenter, and coalesce per post', async t => {
  const f = await notifyFixture(t);
  const first = await f.request('/posts/other-post/comments', { as: 'owner', body: { content: 'Is this still available?' } });
  assert.equal(first.status, 200);
  assert.deepEqual(f.jobs('comment').map(row => [row.recipientId, row.scope, row.linkPath, row.events]), [['other', 'comment:other-post', '/posts/other-post', 1]]);
  // The author replies to the commenter: only the commenter is notified.
  assert.equal((await f.request('/posts/other-post/comments', { as: 'other', body: { content: 'Yes it is.', parentId: first.data.comment.id } })).status, 200);
  // A third neighbour replies too: both the author and the parent commenter, each in their existing pending notice.
  assert.equal((await f.request('/posts/other-post/comments', { as: 'third', body: { content: 'Me too please.', parentId: first.data.comment.id } })).status, 200);
  assert.deepEqual(f.jobs('comment').map(row => [row.recipientId, row.events]).sort(), [['other', 2], ['owner', 2]]);
  // Commenting on your own post queues nothing for yourself.
  assert.equal((await f.request('/posts/owner-post/comments', { as: 'owner', body: { content: 'Price drop.' } })).status, 200);
  assert.equal(f.jobs('comment').length, 2);
  f.clock.set(FIRST_NOTICE_DELAY + 1000);
  await f.application.notifications.runOnce();
  assert.equal(f.mail.length, 2);
  for (const message of f.mail) {
    assert.match(message.text, /new comments/); assert.ok(message.text.includes('https://www.baylink.us/en/posts/other-post'));
    assert.doesNotMatch(message.text, /available|Yes it is|Me too|Neighbor/);
  }
});

test('a comment deleted before its notice is due cancels the notice', async t => {
  const f = await notifyFixture(t);
  const posted = await f.request('/posts/owner-post/comments', { as: 'third', body: { content: 'Wrong post, sorry.' } });
  assert.equal(f.jobs('comment').length, 1);
  assert.equal((await f.request(`/posts/owner-post/comments/${posted.data.comment.id}`, { as: 'third', method: 'DELETE' })).status, 200);
  f.clock.set(FIRST_NOTICE_DELAY + 1000);
  await f.application.notifications.runOnce();
  assert.equal(f.mail.length, 0);
  assert.deepEqual(f.jobs('comment').map(row => [row.status, row.reason]), [['cancelled', 'read']]);
});

test('forgot-password: 300 s cooldown and 5 emails per day per account survive restarts', async t => {
  const models = createMemoryModels({ User: [makeUser('owner')] });
  const owner = () => models.User.rows.find(row => row.id === 'owner');
  // Every request uses a fresh application: a deploy/restart clears all in-memory limiters.
  const ask = async email => (await start(t, { models, config: { AUTH_DEV_RETURN_TOKENS: 'true' } })).request('/auth/forgot-password', { body: { email } });
  const unknown = await ask('nobody@example.test');
  const issued = await ask('owner@example.test');
  assert.equal(issued.status, 200); assert.match(issued.data.devResetLink, /reset-password\?token=/);
  assert.equal(owner().passwordResetRequestCount, 1); assert.match(owner().passwordResetRequestDay, /^\d{4}-\d{2}-\d{2}$/);
  const firstHash = owner().passwordResetTokenHash;
  // 60 s later is no longer enough (old cooldown); a restart does not reopen it.
  owner().passwordResetRequestedAt -= 61000;
  const throttled = await ask('owner@example.test');
  assert.equal(throttled.data.devResetLink, undefined); assert.equal(owner().passwordResetTokenHash, firstHash);
  assert.deepEqual(throttled.data, unknown.data, 'a throttled account answers exactly like an unknown email');
  for (let count = 2; count <= 5; count++) {
    owner().passwordResetRequestedAt -= 300000;
    assert.match((await ask('owner@example.test')).data.devResetLink, /token=/);
    assert.equal(owner().passwordResetRequestCount, count);
  }
  owner().passwordResetRequestedAt -= 300000;
  assert.equal((await ask('owner@example.test')).data.devResetLink, undefined, 'the sixth email of the day is refused');
  assert.equal(owner().passwordResetRequestCount, 5);
  owner().passwordResetRequestDay = '2026-01-01';
  assert.match((await ask('owner@example.test')).data.devResetLink, /token=/, 'a new Bay Area day reopens the ceiling');
  assert.equal(owner().passwordResetRequestCount, 1);
  // The private counters never reach a client.
  const { request } = await start(t, { models });
  const signedIn = await request('/auth/login', { body: { email: 'owner@example.test', password: PASSWORD } });
  assert.equal(signedIn.status, 200); assert.ok(signedIn.data.token);
  assert.equal(JSON.stringify(signedIn.data).includes('passwordResetRequest'), false);
});

test('phone verification is refused when two other verified accounts already share the number', async t => {
  const number = '+14155550101';
  const models = createMemoryModels({ User: [makeUser('owner'), makeUser('a', { isPhoneVerified: true, phoneNormalized: number }),
    makeUser('b', { isPhoneVerified: true, phoneNormalized: number }), makeUser('c')] });
  const { request } = await start(t, { models, config: { AUTH_DEV_RETURN_TOKENS: 'true' } });
  const refused = await request('/users/me/phone/start', { as: 'owner', body: { phone: '(415) 555-0101' } });
  assert.equal(refused.status, 409); assert.equal(refused.data.code, 'PHONE_SHARED_LIMIT'); assert.equal(refused.data.devCode, undefined);
  assert.equal(models.SmsQuota.rows.length, 0, 'a refused request spends no SMS budget');
  // One other verified account (a family) is fine.
  models.User.rows.find(row => row.id === 'b').isPhoneVerified = false;
  const allowed = await request('/users/me/phone/start', { as: 'owner', body: { phone: '4155550101' } });
  assert.equal(allowed.status, 200); assert.match(allowed.data.devCode, /^\d{6}$/);
  // Re-checked at completion: b verified the number in the meantime.
  models.User.rows.find(row => row.id === 'b').isPhoneVerified = true;
  const late = await request('/users/me/phone/verify', { as: 'owner', body: { code: allowed.data.devCode } });
  assert.equal(late.status, 409); assert.equal(late.data.code, 'PHONE_SHARED_LIMIT');
  const owner = models.User.rows.find(row => row.id === 'owner');
  assert.notEqual(owner.isPhoneVerified, true); assert.equal(owner.phoneVerificationCodeHash, undefined);
  // The legacy endpoint enforces the same rule.
  const legacy = await request('/auth/verify-phone', { as: 'c', body: { phone: number } });
  assert.equal(legacy.status, 409); assert.equal(legacy.data.code, 'PHONE_SHARED_LIMIT');
});

test('the per-number SMS ceiling is durable: restarts and new accounts cannot reopen it', async t => {
  const number = '+14155550199';
  const users = Array.from({ length: NUMBER_DAILY_LIMIT + 1 }, (_, index) => makeUser(`u${index}`));
  const models = createMemoryModels({ User: users });
  const send = async id => (await start(t, { models, config: { AUTH_DEV_RETURN_TOKENS: 'true' } })).request('/users/me/phone/start', { as: id, body: { phone: number } });
  for (let index = 0; index < NUMBER_DAILY_LIMIT; index++) assert.equal((await send(`u${index}`)).status, 200);
  const refused = await send(`u${NUMBER_DAILY_LIMIT}`);
  assert.equal(refused.status, 429); assert.equal(refused.data.code, 'SMS_NUMBER_DAILY_LIMIT'); assert.equal(refused.data.devCode, undefined);
  const stored = JSON.stringify(models.SmsQuota.rows);
  assert.doesNotMatch(stored, /4155550199|u\d/, 'quota keys are HMAC digests, never the number or account');
});

test('the site-wide daily SMS ceiling refuses without spending the number or account budget', async t => {
  const models = createMemoryModels({ User: [makeUser('owner'), makeUser('other')] });
  const { request } = await start(t, { models, config: { AUTH_DEV_RETURN_TOKENS: 'true', SMS_VERIFY_DAILY_LIMIT: '1' } });
  assert.equal((await request('/users/me/phone/start', { as: 'owner', body: { phone: '4155550111' } })).status, 200);
  const refused = await request('/users/me/phone/start', { as: 'other', body: { phone: '4155550122' } });
  assert.equal(refused.status, 503); assert.equal(refused.data.code, 'SMS_DAILY_CAPACITY');
  assert.deepEqual(models.SmsQuota.rows.map(row => row.count).sort(), [0, 0, 1, 1, 1], 'the refused number/account holds were returned');
});

test('production without Twilio refuses before reserving any SMS budget', async t => {
  const models = createMemoryModels({ User: [makeUser('owner')] });
  const { request } = await start(t, { models, config: { NODE_ENV: 'production', AUTH_DEV_RETURN_TOKENS: 'true' } });
  assert.equal((await request('/users/me/phone/start', { as: 'owner', body: { phone: '4155550133' } })).status, 503);
  assert.equal(models.SmsQuota.rows.length, 0);
});

test('login lockout is per account and visitor; a high cross-visitor ceiling still caps distributed guessing', async t => {
  const { request } = await start(t, { models: createMemoryModels({ User: [makeUser('owner'), makeUser('target')] }), config: { TRUST_PROXY_HOPS: 1 } });
  const login = (email, password, ip) => request('/auth/login', { body: { email, password }, headers: { 'X-Forwarded-For': ip } });
  for (let attempt = 0; attempt < 8; attempt++) assert.equal((await login('owner@example.test', 'WrongPassword1', '198.51.100.21')).status, 401);
  assert.equal((await login('owner@example.test', PASSWORD, '198.51.100.21')).status, 429, 'the guessing visitor is held');
  assert.equal((await login('owner@example.test', PASSWORD, '198.51.100.22')).status, 200, 'the real owner elsewhere is not locked out');
  // Distributed: 13 visitors x 8 attempts against one account; the 101st attempt overall is refused.
  const statuses = [];
  for (let visitor = 30; visitor < 43; visitor++) {
    for (let attempt = 0; attempt < 8; attempt++) statuses.push((await login('target@example.test', 'WrongPassword1', `198.51.100.${visitor}`)).status);
  }
  assert.equal(statuses.filter(status => status === 401).length, 100);
  assert.equal(statuses.filter(status => status === 429).length, 4);
  assert.equal((await login('target@example.test', PASSWORD, '198.51.100.99')).status, 429);
});
