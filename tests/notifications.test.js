const test = require('node:test');
const assert = require('node:assert/strict');
const { createNotificationService, HALF_HOUR, FIRST_NOTICE_DELAY, TOPICS, trustedOrigin, notificationOrigin } = require('../lib/notifications');
const { memory } = require('./support/notification-memory');

function fixture({ enabled = true, mail, sms, holdAccount, acquireAccount, config = {}, log, stillUnread } = {}) {
  let at = Date.parse('2026-10-06T12:00:00Z');
  const sent = [], texts = [];
  const models = {
    User: memory([{ id: 'owner', email: 'owner@example.test', isPhoneVerified: true, phoneNormalized: '+16505550123' }, { id: 'guest', email: 'guest@example.test' }]),
    UserBlock: memory(), NotificationAccount: memory(), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory(),
  };
  // A fresh service over the same stores is what a deploy or restart looks like.
  const build = () => createNotificationService({ ...models, isTest: true, isolated: true, holdAccount, acquireAccount, log, stillUnread, config: { NODE_ENV: 'production', JWT_SECRET: 'notification-only-test-key', NOTIFICATION_DELIVERY_ENABLED: String(enabled), ...config }, now: () => at,
    sendEmail: mail || (async value => { sent.push(value); return { id: 'mock-email' }; }), sendSms: sms || (async value => { texts.push(value); return { sid: 'mock-sms' }; }) });
  const service = build();
  const rawToken = value => value.text.match(/#token=([A-Za-z0-9_-]{43})/)[1];
  const verify = async () => { await service.startEmailVerification('owner'); await service.runOnce(); await service.verifyEmail(rawToken(sent.at(-1))); sent.length = 0; };
  const optIn = async (channel = 'email') => service.updatePreferences('owner', { preferences: { [channel]: { message: true, contact_request: true, outing_request: true } }, locale: 'en' });
  const event = (overrides = {}) => ({ topic: 'message', recipientId: 'owner', actorId: 'guest', sourceId: 'dm_pair', eventId: 'message_1', createdAt: at, ...overrides });
  const jobs = topic => [...models.NotificationJob.rows.values()].filter(row => row.topic === topic);
  return { models, service, restart: build, sent, texts, verify, optIn, event, rawToken, jobs, clock: value => { at = value; }, advance: ms => { at += ms; }, now: () => at };
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

test('same conversation coalesces into one notice due five minutes after the first event, without message contents', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  const first = f.now();
  assert.deepEqual(await f.service.enqueueEvent(f.event({ content: 'Private phone 650-555-9999', rawUrl: 'https://evil.test' })), { queued: 1 });
  f.advance(2 * 60000);
  assert.deepEqual(await f.service.enqueueEvent(f.event({ eventId: 'message_2', createdAt: f.now() })), { queued: 0, coalesced: 1 });
  const [job] = f.jobs('message');
  assert.equal(f.jobs('message').length, 1);
  assert.equal(job.availableAt, first + FIRST_NOTICE_DELAY, 'the first notice is due at T+5 min, not T+30');
  assert.equal(job.events, 2); assert.equal(job.lastEventAt, first + 2 * 60000); assert.equal(job.sourceId, 'dm_pair');
  assert.equal((await f.service.runOnce()).processed, 0);
  f.clock(first + FIRST_NOTICE_DELAY - 1); assert.equal((await f.service.runOnce()).processed, 0);
  f.clock(first + FIRST_NOTICE_DELAY);
  await Promise.all([f.service.runOnce(), f.service.runOnce()]);
  assert.equal(f.sent.length, 1); assert.ok(f.sent[0].text.includes('https://www.baylink.us/en/messages/dm_pair'));
  assert.doesNotMatch(f.sent[0].text, /Private phone|650-555-9999|evil\.test|guest/);
  assert.equal((await f.service.runOnce()).processed, 0);
});

test('events after a notice coalesce into one follow-up when the rolling 30-minute window reopens', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  const start = f.now();
  await f.service.enqueueEvent(f.event());
  f.clock(start + FIRST_NOTICE_DELAY); await f.service.runOnce(); assert.equal(f.sent.length, 1);
  const sentAt = f.now();
  f.advance(60000); assert.deepEqual(await f.service.enqueueEvent(f.event({ eventId: 'message_2', createdAt: f.now() })), { queued: 1 });
  f.advance(4 * 60000); assert.deepEqual(await f.service.enqueueEvent(f.event({ eventId: 'message_3', createdAt: f.now() })), { queued: 0, coalesced: 1 });
  f.advance(10 * 60000); assert.deepEqual(await f.service.enqueueEvent(f.event({ eventId: 'message_4', createdAt: f.now() })), { queued: 0, coalesced: 1 });
  const followUp = f.jobs('message').find(row => row.status === 'queued');
  assert.equal(followUp.availableAt, sentAt + HALF_HOUR, 'the follow-up waits for the window, not 5 minutes');
  assert.equal(followUp.events, 3);
  f.clock(sentAt + HALF_HOUR - 1); await f.service.runOnce(); assert.equal(f.sent.length, 1, 'never two notices for one thread within 30 minutes');
  f.clock(sentAt + HALF_HOUR); await f.service.runOnce(); assert.equal(f.sent.length, 2);
  assert.deepEqual(f.jobs('message').map(row => [row.status, row.events]), [['sent', 1], ['sent', 3]]);
});

test('a duplicate pending notice (concurrent enqueue) is re-queued to the window reopening, never sent early', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  await f.service.enqueueEvent(f.event());
  // Simulate the rare race where two enqueues both found no pending notice for the thread.
  const [original] = f.jobs('message');
  await f.models.NotificationJob.create({ ...original, _id: 'f'.repeat(64), events: 1 });
  f.advance(FIRST_NOTICE_DELAY); const sentAt = f.now();
  await f.service.runOnce();
  assert.equal(f.sent.length, 1);
  const requeued = f.jobs('message').find(row => row.status === 'queued');
  assert.equal(requeued.availableAt, sentAt + HALF_HOUR, 'the rolling window decides, not now + 30 min');
  f.advance(HALF_HOUR - 1); await f.service.runOnce(); assert.equal(f.sent.length, 1);
});

test('a notice is cancelled when the thread was read in-app before it was due; a later message starts a new one', async () => {
  const calls = [], state = { unread: false };
  const f = fixture({ stillUnread: async value => { calls.push(value); if (state.fail) throw new Error('database unavailable'); return state.unread; } });
  await f.verify(); await f.optIn();
  const first = f.now();
  await f.service.enqueueEvent(f.event());
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 0);
  assert.deepEqual(calls[0], { topic: 'message', recipientId: 'owner', actorId: 'guest', sourceId: 'dm_pair', since: first });
  assert.deepEqual(f.jobs('message').map(row => [row.status, row.reason]), [['cancelled', 'read']]);
  // The read thread never reached the recipient, so the next message is a fresh first notice.
  f.advance(60000); state.unread = true;
  await f.service.enqueueEvent(f.event({ eventId: 'message_2', createdAt: f.now() }));
  const second = f.jobs('message').find(row => row.status === 'queued');
  assert.equal(second.availableAt, f.now() + FIRST_NOTICE_DELAY);
  // A failed unread check never sends and never cancels: the notice waits and retries.
  f.advance(FIRST_NOTICE_DELAY); state.fail = true; await f.service.runOnce();
  assert.equal(f.sent.length, 0); assert.equal(f.jobs('message').find(row => row._id === second._id).status, 'queued');
  state.fail = false; f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 1);
});

test('a failed unread check on SMS is retried, not recorded as an ambiguous provider submission', async () => {
  let fail = true;
  const f = fixture({ stillUnread: async () => { if (fail) throw new Error('database unavailable'); return true; } });
  await f.optIn('sms'); await f.service.enqueueEvent(f.event());
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.texts.length, 0); assert.equal(f.jobs('message')[0].status, 'queued');
  fail = false; f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.texts.length, 1); assert.equal(f.jobs('message')[0].status, 'sent');
});

test('coalescing, the 30-minute window and the 5-minute first notice survive a restart (persistence model)', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  await f.service.enqueueEvent(f.event()); f.advance(FIRST_NOTICE_DELAY);
  await f.service.runOnce(); assert.equal(f.sent.length, 1); const sentAt = f.now();
  const restarted = f.restart();
  f.advance(60000); await restarted.enqueueEvent(f.event({ eventId: 'message_2', createdAt: f.now() }));
  f.advance(60000); assert.deepEqual(await restarted.enqueueEvent(f.event({ eventId: 'message_3', createdAt: f.now() })), { queued: 0, coalesced: 1 });
  f.clock(sentAt + HALF_HOUR - 1); await f.restart().runOnce(); assert.equal(f.sent.length, 1, 'a new process still honours the stored window');
  f.clock(sentAt + HALF_HOUR); await f.restart().runOnce(); assert.equal(f.sent.length, 2);
  // What the E2E harness inspects: one row per notice, carrying how many events it covered.
  assert.deepEqual(f.jobs('message').map(({ status, events, availableAt }) => ({ status, events, availableAt })), [
    { status: 'sent', events: 1, availableAt: sentAt },
    { status: 'sent', events: 2, availableAt: sentAt + HALF_HOUR },
  ]);
  assert.equal(f.models.NotificationWindow.rows.size, 1);
});

test('replaying an already queued event is idempotent and threads stay independent', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  await f.service.enqueueEvent(f.event());
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 0, coalesced: 1 });
  await f.service.enqueueEvent(f.event({ sourceId: 'dm_other', eventId: 'message_9' }));
  assert.equal(f.jobs('message').length, 2);
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 2, 'two threads are two windows');
});

test('comment topic is opt-in, uses its own label and links to the post', async () => {
  const f = fixture(); await f.verify(); await f.optIn();
  assert.deepEqual(TOPICS, ['message', 'contact_request', 'outing_request', 'comment']);
  const prefs = await f.service.preferences('owner');
  assert.equal(prefs.preferences.email.comment, false); assert.equal(prefs.preferences.sms.comment, false);
  assert.deepEqual(prefs.topics, TOPICS);
  const comment = (overrides = {}) => f.event({ topic: 'comment', sourceId: 'post_1', eventId: '1760000000000_abcd1234', ...overrides });
  assert.deepEqual(await f.service.enqueueEvent(comment()), { queued: 0 }, 'opting into the original three topics does not opt into comments');
  await f.service.updatePreferences('owner', { preferences: { email: { comment: true } } });
  assert.deepEqual(await f.service.enqueueEvent(comment()), { queued: 1 });
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 1);
  assert.match(f.sent[0].text, /You have new comments on BAYLINK/);
  assert.ok(f.sent[0].text.includes('https://www.baylink.us/en/posts/post_1'));
  for (const [locale, label, prefix] of [['zh-Hans', '新的评论', ''], ['zh-Hant', '新的評論', '/zh-Hant']]) {
    const g = fixture(); await g.verify();
    await g.service.updatePreferences('owner', { preferences: { email: { comment: true } }, locale });
    await g.service.enqueueEvent(g.event({ topic: 'comment', sourceId: 'post_2', eventId: 'c_1', createdAt: g.now() }));
    g.advance(FIRST_NOTICE_DELAY); await g.service.runOnce();
    assert.ok(g.sent[0].text.includes(label)); assert.ok(g.sent[0].text.includes(`https://www.baylink.us${prefix}/posts/post_2`));
  }
});

test('enable all turns on every topic, only for channels whose destination is verified', async () => {
  const f = fixture();
  // The owner's phone is verified in this fixture, the email is not yet.
  const phoneOnly = await f.service.updatePreferences('owner', { enableAll: true });
  assert.equal(Object.values(phoneOnly.preferences.sms).every(Boolean), true);
  assert.equal(Object.values(phoneOnly.preferences.email).some(Boolean), false);
  assert.deepEqual(phoneOnly.allEnabled, { email: false, sms: true });
  await assert.rejects(f.service.updatePreferences('owner', { enableAll: 'email' }), error => error.status === 409 && error.code === 'NOTIFICATION_VERIFICATION_REQUIRED');
  await f.verify();
  const both = await f.service.updatePreferences('owner', { enableAll: 'email', preferences: { sms: { comment: false } } });
  assert.deepEqual(both.preferences.email, { message: true, contact_request: true, outing_request: true, comment: true });
  assert.equal(both.preferences.sms.comment, false);
  assert.deepEqual(both.allEnabled, { email: true, sms: false });
  await assert.rejects(f.service.updatePreferences('guest', { enableAll: true }), error => error.status === 409 && error.code === 'NOTIFICATION_VERIFICATION_REQUIRED');
  for (const value of ['push', false, 1, ['email']]) await assert.rejects(f.service.updatePreferences('owner', { enableAll: value }), error => error.status === 400);
  // Turning everything on is a consent change: work queued under the old consent is not revived.
  await f.service.enqueueEvent(f.event());
  await f.service.updatePreferences('owner', { enableAll: true });
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce(); assert.equal(f.sent.length + f.texts.length, 0);
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

test('an invalid NOTIFICATION_FRONTEND_URL falls back to the canonical site with one warning instead of stopping the API', async () => {
  const logs = [];
  for (const value of ['https://evil.test', 'https://www.baylink.us/redirect?url=evil', 'not a url', 'https://user:pass@www.baylink.us/']) {
    assert.equal(notificationOrigin({ NODE_ENV: 'production', NOTIFICATION_FRONTEND_URL: value }, line => logs.push(line)), 'https://www.baylink.us');
  }
  assert.equal(notificationOrigin({ NODE_ENV: 'production', NOTIFICATION_FRONTEND_URL: 'https://baylink.us' }, line => logs.push(line)), 'https://baylink.us');
  assert.equal(logs.length, 4);
  assert.deepEqual(logs[0], { level: 'warn', event: 'notification_origin_invalid', setting: 'NOTIFICATION_FRONTEND_URL', fallback: 'https://www.baylink.us' });
  assert.ok(!JSON.stringify(logs).includes('evil') && !JSON.stringify(logs).includes('pass'));
  // The service still starts and its links point at the canonical site, never the rejected host.
  const warnings = [];
  const f = fixture({ config: { NOTIFICATION_FRONTEND_URL: 'https://evil.test' }, log: line => warnings.push(line) });
  assert.equal(warnings.length, 1);
  await f.service.startEmailVerification('owner'); await f.service.runOnce();
  assert.match(f.sent.at(-1).text, /https:\/\/www\.baylink\.us\//); assert.ok(!f.sent.at(-1).text.includes('evil'));
});

test('createApplication boots with an unparsable NOTIFICATION_FRONTEND_URL', t => {
  const { createApplication } = require('../server');
  const { createMemoryModels } = require('./support/memory-models');
  const original = console.error, lines = [];
  console.error = line => lines.push(String(line));
  let application;
  try {
    application = createApplication({ models: createMemoryModels(), config: { NODE_ENV: 'test', JWT_SECRET: 'notification-boot-test-secret-thirty-two-chars', NOTIFICATION_FRONTEND_URL: 'not a url' } });
  } finally { console.error = original; }
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  assert.ok(application.app);
  assert.equal(lines.filter(line => line.includes('notification_origin_invalid')).length, 1);
});
