const test = require('node:test');
const assert = require('node:assert/strict');
const { createNotificationService, HALF_HOUR, trustedOrigin } = require('../lib/notifications');
const { memory } = require('./support/notification-memory');

function fixture({ enabled = true, mail, sms, holdAccount, acquireAccount, config = {} } = {}) {
  let at = Date.parse('2026-10-06T12:00:00Z');
  const sent = [], texts = [];
  const models = {
    User: memory([{ id: 'owner', email: 'owner@example.test', isPhoneVerified: true, phoneNormalized: '+16505550123' }, { id: 'guest', email: 'guest@example.test' }]),
    UserBlock: memory(), NotificationAccount: memory(), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory(),
  };
  const service = createNotificationService({ ...models, isTest: true, isolated: true, holdAccount, acquireAccount, config: { NODE_ENV: 'production', JWT_SECRET: 'notification-only-test-key', NOTIFICATION_DELIVERY_ENABLED: String(enabled), ...config }, now: () => at,
    sendEmail: mail || (async value => { sent.push(value); return { id: 'mock-email' }; }), sendSms: sms || (async value => { texts.push(value); return { sid: 'mock-sms' }; }) });
  const rawToken = value => value.text.match(/#token=([A-Za-z0-9_-]{43})/)[1];
  const verify = async () => { await service.startEmailVerification('owner'); await service.runOnce(); await service.verifyEmail(rawToken(sent.at(-1))); sent.length = 0; };
  const optIn = async (channel = 'email') => service.updatePreferences('owner', { preferences: { [channel]: { message: true, contact_request: true, outing_request: true } }, locale: 'en' });
  const event = (overrides = {}) => ({ topic: 'message', recipientId: 'owner', actorId: 'guest', sourceId: 'dm_pair', eventId: 'message_1', createdAt: at, ...overrides });
  return { models, service, sent, texts, verify, optIn, event, rawToken, clock: value => { at = value; }, advance: ms => { at += ms; }, now: () => at };
}

test('legacy accounts default off; channels require their current verified destination', async () => {
  const f = fixture(); const prefs = await f.service.preferences('owner');
  assert.equal(prefs.emailVerified, false);
  assert.equal(Object.values(prefs.preferences.email).some(Boolean), false);
  assert.equal(Object.values(prefs.preferences.sms).some(Boolean), false);
  await assert.rejects(f.optIn(), error => error.code === 'NOTIFICATION_VERIFICATION_REQUIRED');
  await assert.rejects(f.service.updatePreferences('guest', { preferences: { sms: { message: true } } }), error => error.code === 'NOTIFICATION_VERIFICATION_REQUIRED');
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 0 });
});

test('verification queues only; disabled worker never calls either provider or exposes tokens', async () => {
  const f = fixture({ enabled: false }); const response = await f.service.startEmailVerification('owner');
  assert.equal(response.queued, true); assert.equal(response.emailDeliveryAvailable, false);
  assert.deepEqual(await f.service.runOnce(), { processed: 0, disabled: true });
  assert.equal(f.sent.length, 0); assert.equal(f.texts.length, 0);
  const account = [...f.models.NotificationAccount.rows.values()][0], token = [...f.models.NotificationToken.rows.values()][0];
  assert.equal(token._id.length, 64); assert.ok(token.sealed); assert.equal(token.sealed.includes(token._id), false);
  assert.equal(JSON.stringify(response).includes(token.sealed), false); assert.equal(JSON.stringify(account).includes(token.sealed), false);
});

test('email verification token is expiring, single use, email-bound, and does not opt in', async () => {
  const f = fixture(); await f.service.startEmailVerification('owner'); await f.service.runOnce();
  const raw = f.rawToken(f.sent[0]); assert.equal(f.sent[0].text.includes('/verify-email#token='), true);
  assert.deepEqual(await f.service.verifyEmail(raw), { ok: true, emailVerified: true });
  await assert.rejects(f.service.verifyEmail(raw), /已使用/);
  const prefs = await f.service.preferences('owner'); assert.equal(prefs.emailVerified, true); assert.equal(prefs.preferences.email.message, false);
  const expired = fixture(); await expired.service.startEmailVerification('owner'); await expired.service.runOnce(); expired.advance(HALF_HOUR);
  await assert.rejects(expired.service.verifyEmail(expired.rawToken(expired.sent[0])), /过期/);
  const changed = fixture(); await changed.service.startEmailVerification('owner'); await changed.service.runOnce();
  await changed.models.User.updateOne({ id: 'owner' }, { $set: { email: 'other@example.test' } });
  await assert.rejects(changed.service.verifyEmail(changed.rawToken(changed.sent[0])), /邮箱已更改/);
});

test('anonymous verify and unsubscribe prove their token before holding the owner deletion gate', async () => {
  for (const purpose of ['verify', 'unsubscribe']) {
    let armed = false, f; const held = [];
    f = fixture({ holdAccount: async id => {
      held.push(id); assert.equal(id, 'owner');
      if (!armed) return;
      // Deletion won the gate after token lookup, before any user/account write.
      await f.service.eraseUser(id); await f.models.User.deleteMany({ id });
      throw Object.assign(new Error('Account deleted'), { code: 'ACCOUNT_CHANGED', status: 409 });
    } });
    let raw;
    if (purpose === 'verify') {
      await f.service.startEmailVerification('owner'); await f.service.runOnce(); raw = f.rawToken(f.sent[0]);
    } else {
      await f.verify(); await f.optIn(); await f.service.enqueueEvent(f.event()); f.advance(HALF_HOUR); await f.service.runOnce(); raw = f.rawToken(f.sent[0]);
    }
    const before = held.length;
    await assert.rejects(f.service[purpose === 'verify' ? 'verifyEmail' : 'unsubscribe']('B'.repeat(43)), /无效/);
    assert.equal(held.length, before, 'invalid tokens cannot select or hold an account');
    armed = true;
    await assert.rejects(f.service[purpose === 'verify' ? 'verifyEmail' : 'unsubscribe'](raw), error => error.code === 'ACCOUNT_CHANGED');
    assert.equal(held.length, before + 1);
    assert.equal(f.models.NotificationAccount.rows.size, 0, 'a late token cannot recreate deleted private preferences');
    assert.equal(f.models.NotificationToken.rows.size, 0); assert.equal(f.models.NotificationJob.rows.size, 0);
  }
});

test('background provider submission holds recipient and actor deletion gates until settled', async () => {
  let complete, entered;
  const pending = new Promise(resolve => { complete = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  const f = fixture({ sms: async value => { entered(value); return pending; } });
  await f.optIn('sms'); await f.service.enqueueEvent(f.event()); f.advance(HALF_HOUR);
  const delivery = f.service.runOnce(); await started;
  for (const id of ['owner', 'guest']) {
    assert.equal((await f.models.User.findOne({ id })).activeAccountOperations, 1);
    assert.equal(await f.models.User.findOneAndUpdate({ id, activeAccountOperations: 0 }, { $set: { accountDeletionPending: true } }), null);
  }
  complete({ sid: 'mock-only' }); assert.equal((await delivery).processed, 1);
  for (const id of ['owner', 'guest']) assert.equal((await f.models.User.findOne({ id })).activeAccountOperations, 0);
});

test('verification limits survive fresh service instances and reject burst and daily overflow', async () => {
  const f = fixture({ enabled: false }); await f.service.startEmailVerification('owner');
  await assert.rejects(f.service.startEmailVerification('owner'), error => error.status === 429);
  for (let count = 1; count < 5; count++) { f.advance(60001); await f.service.startEmailVerification('owner'); }
  f.advance(60001); await assert.rejects(f.service.startEmailVerification('owner'), error => error.status === 429);
  f.advance(86400000); assert.equal((await f.service.startEmailVerification('owner')).queued, true);
});

test('same conversation coalesces, never includes message contents, and waits 30 minutes', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  await f.service.enqueueEvent(f.event({ content: 'Private phone 650-555-9999', rawUrl: 'https://evil.test' }));
  await f.service.enqueueEvent(f.event({ eventId: 'message_2' }));
  assert.equal([...f.models.NotificationJob.rows.values()].filter(row => row.topic === 'message').length, 1);
  assert.equal((await f.service.runOnce()).processed, 0); f.advance(HALF_HOUR);
  await Promise.all([f.service.runOnce(), f.service.runOnce()]);
  assert.equal(f.sent.length, 1); assert.ok(f.sent[0].text.includes('https://www.baylink.us/en/messages/dm_pair'));
  assert.doesNotMatch(f.sent[0].text, /Private phone|650-555-9999|evil\.test|guest/);
  assert.equal((await f.service.runOnce()).processed, 0);
});

test('adjacent queue buckets still respect rolling 30-minute delivery throttle', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  f.advance(29 * 60000); await f.service.enqueueEvent(f.event()); f.advance(60000); await f.service.enqueueEvent(f.event({ eventId: 'message_2' }));
  f.advance(29 * 60000); await f.service.runOnce(); assert.equal(f.sent.length, 1);
  f.advance(60000); await f.service.runOnce(); assert.equal(f.sent.length, 1, 'delayed first send cannot allow another a minute later');
  f.advance(HALF_HOUR); await f.service.runOnce(); assert.equal(f.sent.length, 2);
});

test('opt-out cancels queue and a later opt-in cannot revive earlier events; unsubscribe consumes once', async () => {
  const f = fixture(); await f.verify(); await f.optIn(); await f.service.enqueueEvent(f.event());
  await f.service.updatePreferences('owner', { preferences: { email: { message: false } } }); await f.optIn(); f.advance(HALF_HOUR); await f.service.runOnce(); assert.equal(f.sent.length, 0);
  await f.service.enqueueEvent(f.event({ eventId: 'message_new' })); f.advance(HALF_HOUR); await f.service.runOnce(); assert.equal(f.sent.length, 1);
  const raw = f.sent[0].text.match(/unsubscribe#token=([A-Za-z0-9_-]{43})/)[1];
  await f.service.unsubscribe(raw); assert.equal((await f.service.preferences('owner')).preferences.email.message, false);
  await assert.rejects(f.service.unsubscribe(raw), /已使用/);
});

test('changed destinations, blocked sender and deletion pending prevent queued delivery', async () => {
  for (const reason of ['email', 'block', 'delete']) {
    const f = fixture(); await f.verify(); await f.optIn(); await f.service.enqueueEvent(f.event());
    if (reason === 'email') await f.models.User.updateOne({ id: 'owner' }, { $set: { email: 'changed@example.test' } });
    if (reason === 'block') await f.models.UserBlock.create({ _id: 'block', blockerId: 'owner', blockedUserId: 'guest' });
    if (reason === 'delete') await f.models.User.updateOne({ id: 'owner' }, { $set: { accountDeletionPending: true } });
    f.advance(HALF_HOUR); await f.service.runOnce(); assert.equal(f.sent.length, 0, reason);
  }
});

test('email retries use a stable key/body while ambiguous SMS does not retry', async () => {
  const calls = [], f = fixture({ mail: async value => { calls.push(value); if (calls.length === 1) throw new Error('Lost network response'); return { id: 'accepted' }; } });
  await f.optIn('sms'); await f.service.enqueueEvent(f.event()); f.advance(HALF_HOUR); await f.service.runOnce(); assert.equal(f.texts.length, 1);
  // Verification is a queue item too; Resend retries with the same immutable token link.
  await f.service.startEmailVerification('owner'); await f.service.runOnce(); f.advance(3 * 60000); await f.service.runOnce();
  assert.equal(calls.length, 2); assert.equal(calls[0].idempotencyKey, calls[1].idempotencyKey); assert.equal(calls[0].text, calls[1].text);
  const smsCalls = [], s = fixture({ sms: async value => { smsCalls.push(value); throw new Error('Timeout after provider acceptance'); } });
  await s.optIn('sms'); await s.service.enqueueEvent(s.event()); s.advance(HALF_HOUR); await s.service.runOnce(); s.advance(HALF_HOUR); await s.service.runOnce();
  assert.equal(smsCalls.length, 1); assert.equal([...s.models.NotificationJob.rows.values()][0].status, 'unknown');
});

test('deletion erases recipient and actor queues, tokens and preferences', async () => {
  const f = fixture(); await f.verify(); await f.optIn(); await f.service.enqueueEvent(f.event());
  await f.service.eraseUser('owner', { session: {} });
  assert.equal(f.models.NotificationAccount.rows.size, 0); assert.equal(f.models.NotificationToken.rows.size, 0); assert.equal(f.models.NotificationJob.rows.size, 0);
});

test('persistent atomic daily channel and account budgets cap provider submissions without refunds', async () => {
  const f = fixture({ config: { NOTIFICATION_SMS_DAILY_LIMIT: '2', NOTIFICATION_SMS_USER_DAILY_LIMIT: '1' } });
  await f.optIn('sms');
  await f.service.enqueueEvent(f.event({ sourceId: 'dm_one' })); await f.service.enqueueEvent(f.event({ sourceId: 'dm_two' }));
  f.advance(HALF_HOUR); await Promise.all([f.service.runOnce(), f.service.runOnce()]);
  assert.equal(f.texts.length, 1); assert.equal([...f.models.NotificationBudget.rows.values()][0].count, 1);
  const off = fixture({ config: { NOTIFICATION_SMS_DAILY_LIMIT: '0' } }); await off.optIn('sms'); await off.service.enqueueEvent(off.event()); off.advance(HALF_HOUR); await off.service.runOnce(); assert.equal(off.texts.length, 0);
});

test('only trusted frontend origins are accepted; recovered historical events never enqueue', async () => {
  assert.throws(() => trustedOrigin({ NODE_ENV: 'production', NOTIFICATION_FRONTEND_URL: 'https://evil.test' }));
  assert.throws(() => trustedOrigin({ NODE_ENV: 'production', NOTIFICATION_FRONTEND_URL: 'https://www.baylink.us/redirect?url=evil' }));
  const f = fixture(); await f.verify(); await f.optIn(); assert.deepEqual(await f.service.enqueueEvent(f.event({ createdAt: f.now() - 10 * 60000 })), { skipped: true });
});
