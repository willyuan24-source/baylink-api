// H14 (API-NOTIFY-2): default email reminders for verified emails, migration on read,
// per-kind one-click unsubscribe and the delivery gate. Isolated: in-memory models and
// mock providers only; nothing here can reach Resend, Twilio, Mongo or a real address.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  createNotificationService, resendEmailSender, notificationApiOrigin, emailDefaultsActive, FIRST_NOTICE_DELAY, HALF_HOUR, EMAIL_DEFAULT_TOPICS, DEFAULTS_VERSION, EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT,
} = require('../lib/notifications');
const { memory } = require('./support/notification-memory');

const sha = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const OFF = { message: false, contact_request: false, outing_request: false, comment: false };
const DEFAULTS = { email: { message: true, contact_request: true, outing_request: false, comment: false }, sms: OFF };
const API = 'https://baylink-api.onrender.com';
// An account row as an earlier release left it: no defaults mark.
const legacyAccount = (id, { verified = true, consentRevision = 0, preferences = { email: { ...OFF }, sms: { ...OFF } }, locale = 'zh-Hans' } = {}) => ({
  _id: sha(`account:${id}`), userId: id, revision: 3, consentRevision, locale, requests: 0, lastRequestedAt: 0, preferences,
  ...(verified ? { verifiedEmailHash: sha(`email:${id}@example.test`), emailVerifiedAt: 1 } : {}),
});

function fixture({ defaults, enabled = 'true', config = {}, seed = [] } = {}) {
  let at = Date.parse('2026-10-14T12:00:00Z');
  const sent = [], texts = [], logs = [];
  const models = {
    User: memory([{ id: 'owner', email: 'owner@example.test', isPhoneVerified: true, phoneNormalized: '+16505550123' }, { id: 'guest', email: 'guest@example.test' }, { id: 'third', email: 'third@example.test' }]),
    UserBlock: memory(), NotificationAccount: memory(seed), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory(),
  };
  const settings = { NODE_ENV: 'production', JWT_SECRET: 'notification-defaults-test-key', ...(enabled === null ? {} : { NOTIFICATION_DELIVERY_ENABLED: enabled }),
    ...(defaults === undefined ? {} : { NOTIFICATION_EMAIL_DEFAULTS: defaults }), ...config };
  const build = () => createNotificationService({ ...models, isTest: true, isolated: true, config: settings, now: () => at, log: line => logs.push(line),
    sendEmail: async value => { sent.push(value); return { id: 'mock-email' }; }, sendSms: async value => { texts.push(value); return { sid: 'mock-sms' }; } });
  const service = build();
  const rawToken = value => value.text.match(/#token=([A-Za-z0-9_-]{43})/)[1];
  const verify = async (id = 'owner', target = service) => {
    await target.startEmailVerification(id); await target.runOnce();
    const result = await target.verifyEmail(rawToken(sent.at(-1))); sent.length = 0; return result;
  };
  const event = (overrides = {}) => ({ topic: 'message', recipientId: 'owner', actorId: 'guest', sourceId: 'dm_pair', eventId: `e_${Math.random().toString(36).slice(2, 10)}`, createdAt: at, ...overrides });
  const account = id => models.NotificationAccount.rows.get(sha(`account:${id}`));
  const jobs = () => [...models.NotificationJob.rows.values()];
  const defaultsLogs = () => logs.filter(line => String(line.event).startsWith('notification_defaults_'));
  return { models, service, restart: build, sent, texts, logs, defaultsLogs, verify, event, account, jobs, rawToken, advance: ms => { at += ms; }, now: () => at };
}

test('activation: a code default the captain flips once the web copy is live; NOTIFICATION_EMAIL_DEFAULTS=on/off overrides it', () => {
  // Until WEB-COMMUNITY-2 ships truthful copy the preset is dormant; the later flip changes this one constant.
  assert.equal(EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT, false);
  for (const byDefault of [false, true]) {
    for (const value of [undefined, '', '  ']) assert.equal(emailDefaultsActive(value === undefined ? {} : { NOTIFICATION_EMAIL_DEFAULTS: value }, byDefault), byDefault, `unset → code default ${byDefault}`);
    for (const value of ['on', 'ON', ' true ']) assert.equal(emailDefaultsActive({ NOTIFICATION_EMAIL_DEFAULTS: value }, byDefault), true, value);
    // The kill switch: any other value, including typos, turns the preset off.
    for (const value of ['off', 'OFF', 'false', '0', '1', 'yes', 'disabled']) assert.equal(emailDefaultsActive({ NOTIFICATION_EMAIL_DEFAULTS: value }, byDefault), false, value);
  }
  assert.equal(emailDefaultsActive({}), EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT);
});

test('the preset is reported in the preferences DTO and stays dormant while switched off', async () => {
  assert.deepEqual(EMAIL_DEFAULT_TOPICS, ['message', 'contact_request']); assert.equal(DEFAULTS_VERSION, 1);
  for (const value of [...(EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT ? [] : [undefined, '']), 'off', 'false', '1', 'yes']) {
    const f = fixture({ defaults: value });
    const result = await f.verify();
    assert.equal(result.defaultsApplied, false, String(value));
    const prefs = await f.service.preferences('owner');
    assert.deepEqual(prefs.defaults, DEFAULTS); assert.equal(prefs.defaultsActive, false);
    assert.equal(prefs.defaultsApplied, false); assert.equal(prefs.customized, false);
    assert.deepEqual(prefs.preferences.email, OFF, 'a dormant preset never turns anything on');
    assert.equal(f.account('owner').defaultsVersion, undefined, 'no migration mark while dormant, so switching on later still migrates');
    assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 0 });
  }
  for (const value of ['on', 'ON', ' true ']) assert.equal((await fixture({ defaults: value }).service.preferences('owner')).defaultsActive, true, value);
});

test('verifying an email turns on new-DM and contact-request emails once; other kinds and SMS stay opt-in', async () => {
  const f = fixture({ defaults: 'on' });
  const before = await f.service.preferences('owner');
  assert.equal(before.emailVerified, false); assert.deepEqual(before.preferences.email, OFF, 'nothing on for an unverified address');
  assert.equal(before.defaultsActive, true); assert.equal(before.defaultsApplied, false);
  assert.equal(f.account('owner').defaultsVersion, undefined, 'an unverified, untouched account waits for its verification');
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 0 });

  assert.deepEqual(await f.verify(), { ok: true, emailVerified: true, defaultsApplied: true });
  const after = await f.service.preferences('owner');
  assert.deepEqual(after.preferences, DEFAULTS, 'SMS stays off although this phone is verified');
  assert.equal(after.defaultsApplied, true); assert.equal(after.customized, false); assert.deepEqual(after.allEnabled, { email: false, sms: false });
  assert.equal(f.account('owner').defaultsVersion, 1); assert.equal(f.account('owner').consentRevision, 0, 'defaults are not a member choice');
  assert.deepEqual(f.defaultsLogs(), [{ level: 'info', event: 'notification_defaults_applied', version: 1, reason: 'verify' }]);
  assert.ok(!JSON.stringify(f.logs).includes('owner'), 'logs carry no account id or address');

  // Once: later reads, restarts and a second verification after an email change do not log or re-apply.
  await f.service.preferences('owner'); await f.restart().preferences('owner');
  assert.equal(f.defaultsLogs().length, 1);
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 1 }, 'a new DM queues one email, no SMS');
  assert.deepEqual(f.jobs().filter(row => row.topic === 'message').map(row => row.channel), ['email']);
  assert.deepEqual(await f.service.enqueueEvent(f.event({ topic: 'outing_request', sourceId: 'outing_1' })), { queued: 0 });
  assert.deepEqual(await f.service.enqueueEvent(f.event({ topic: 'comment', sourceId: 'post_1' })), { queued: 0 });
});

test('existing accounts migrate on read: never-changed verified accounts get the defaults once, chosen ones keep their choice', async () => {
  const f = fixture({ defaults: 'on', seed: [
    legacyAccount('owner'),
    legacyAccount('guest', { consentRevision: 2 }),
    // A legacy row with a reminder on but no consent epoch was a choice as well.
    legacyAccount('third', { preferences: { email: { ...OFF, outing_request: true }, sms: { ...OFF } } }),
  ] });
  // The first DM is enough: no settings page visit is needed.
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 1 });
  assert.equal(f.account('owner').defaultsVersion, 1); assert.ok(f.account('owner').defaultsAppliedAt > 0);
  assert.equal(f.account('owner').preferences.email.message, true);
  assert.deepEqual(f.defaultsLogs(), [{ level: 'info', event: 'notification_defaults_applied', version: 1, reason: 'event' }]);

  const kept = await f.service.preferences('guest');
  assert.deepEqual(kept.preferences.email, OFF); assert.equal(kept.customized, true); assert.equal(kept.defaultsApplied, false);
  assert.equal(f.account('guest').defaultsVersion, 1, 'the choice is marked as settled');
  const legacy = await f.service.preferences('third');
  assert.deepEqual(legacy.preferences.email, { ...OFF, outing_request: true });
  assert.deepEqual(f.defaultsLogs().map(line => [line.event, line.reason]), [['notification_defaults_applied', 'event'], ['notification_defaults_kept', 'read'], ['notification_defaults_kept', 'read']]);
  await f.restart().preferences('guest');
  assert.equal(f.defaultsLogs().length, 3, 'kept accounts are settled once too');

  // After a member turns a default off it stays off, including after an email change and re-verification.
  await f.service.updatePreferences('owner', { preferences: { email: { message: false } } });
  await f.models.User.updateOne({ id: 'owner' }, { $set: { email: 'owner-new@example.test' } });
  await f.verify();
  const settled = await f.service.preferences('owner');
  assert.equal(settled.preferences.email.message, false); assert.equal(settled.preferences.email.contact_request, true); assert.equal(settled.customized, true);
});

test('an account that saved its settings before verifying keeps them when the email is verified', async () => {
  const f = fixture({ defaults: 'on' });
  // The verified phone allows an SMS choice before the email is verified.
  await f.service.updatePreferences('owner', { preferences: { sms: { message: true } } });
  assert.deepEqual(await f.verify(), { ok: true, emailVerified: true, defaultsApplied: false });
  const prefs = await f.service.preferences('owner');
  assert.deepEqual(prefs.preferences.email, OFF); assert.equal(prefs.preferences.sms.message, true);
  assert.deepEqual(f.defaultsLogs().map(line => line.event), ['notification_defaults_kept']);
});

test('a first save on an account not yet settled is a choice: it is settled as kept, never defaulted first', async () => {
  const f = fixture({ defaults: 'on', seed: [legacyAccount('owner')] });
  const saved = await f.service.updatePreferences('owner', { preferences: { email: { message: false } } });
  assert.deepEqual(saved.preferences.email, OFF, 'contact requests are not switched on behind the member');
  assert.equal(saved.defaultsApplied, false); assert.equal(saved.customized, true);
  assert.equal(f.account('owner').defaultsVersion, 1); assert.equal(f.account('owner').defaultsAppliedAt, undefined);
  assert.deepEqual(f.defaultsLogs(), [{ level: 'info', event: 'notification_defaults_kept', version: 1, reason: 'choice' }]);
  await f.service.preferences('owner'); await f.service.enqueueEvent(f.event());
  assert.equal(f.defaultsLogs().length, 1, 'settled once; the adoption count only counts real defaults');
  // While dormant a save writes no mark: switching on later settles the account (as kept, it chose).
  const g = fixture({ defaults: 'off', seed: [legacyAccount('owner')] });
  await g.service.updatePreferences('owner', { preferences: { email: { message: true } } });
  assert.equal(g.account('owner').defaultsVersion, undefined); assert.deepEqual(g.defaultsLogs(), []);
});

test('opening the one-click URL in a browser changes nothing; it names the confirmation page, kind and language', async () => {
  const f = fixture({ defaults: 'on' }); await f.verify();
  await f.service.updatePreferences('owner', { preferences: { email: { message: true } }, locale: 'zh-Hant' });
  await f.service.enqueueEvent(f.event()); f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  const raw = f.rawToken(f.sent[0]), page = `https://www.baylink.us/zh-Hant/notifications/unsubscribe#token=${raw}&kind=message`;
  assert.equal(await f.service.oneClickPage(raw), page);
  assert.equal((await f.service.preferences('owner')).preferences.email.message, true);
  assert.deepEqual(await f.service.unsubscribe(raw), { ok: true, channel: 'email', topic: 'message' }, 'the token was not consumed');
  // A spent or unknown token still opens the page (which reports it); a malformed one opens the page without a token.
  assert.equal(await f.service.oneClickPage(raw), page);
  assert.equal(await f.service.oneClickPage('A'.repeat(43)), `https://www.baylink.us/notifications/unsubscribe#token=${'A'.repeat(43)}`);
  for (const bad of ['short', `${'A'.repeat(42)}!`, undefined, { $ne: 1 }]) assert.equal(await f.service.oneClickPage(bad), 'https://www.baylink.us/notifications/unsubscribe');
});

test('each notice links to an unsubscribe for its own kind only, with RFC 8058 one-click headers', async () => {
  const f = fixture({ defaults: 'on' }); await f.verify();
  await f.service.enqueueEvent(f.event());
  await f.service.enqueueEvent(f.event({ topic: 'contact_request', sourceId: 'post_1' }));
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 2);
  const dm = f.sent.find(mail => mail.text.includes('收到新的私信，')), request = f.sent.find(mail => mail.text.includes('收到新的联系请求，'));
  for (const [mail, kind, setting] of [[dm, 'message', '新的私信'], [request, 'contact_request', '新的联系请求']]) {
    const raw = f.rawToken(mail);
    // Subject, first line and reason line name the kind with the same words as the settings card.
    assert.ok(mail.text.startsWith(`你在 BAYLINK 收到${setting}，请登录查看：https://www.baylink.us/messages`));
    assert.ok(mail.text.includes(`https://www.baylink.us/notifications/unsubscribe#token=${raw}&kind=${kind}`));
    assert.ok(mail.text.includes(`你收到这封邮件，是因为验证邮箱后，你的账号默认开启了「${setting}」邮件提醒。`), 'a defaulted member is told it was on by default');
    // The body link opens a confirmation page, so it does not promise one click.
    assert.ok(mail.text.includes(`关闭这类邮件：https://www.baylink.us/notifications/unsubscribe#token=`)); assert.ok(!mail.text.includes('一键'));
    assert.ok(mail.text.includes('管理全部提醒：https://www.baylink.us/me?view=notifications'));
    assert.equal(mail.subject, `BAYLINK 站内通知：${setting}`);
    assert.deepEqual(mail.headers, { 'List-Unsubscribe': `<${API}/api/notifications/unsubscribe/one-click/${raw}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' });
  }
  assert.ok(!dm.text.includes('guest'), 'no sender identity or message text');

  // Pending notices of both kinds, then the DM link is used.
  f.advance(HALF_HOUR);
  await f.service.enqueueEvent(f.event({ sourceId: 'dm_two' }));
  await f.service.enqueueEvent(f.event({ topic: 'contact_request', sourceId: 'post_2' }));
  assert.deepEqual(await f.service.unsubscribe(f.rawToken(dm)), { ok: true, channel: 'email', topic: 'message' });
  const prefs = await f.service.preferences('owner');
  assert.deepEqual(prefs.preferences.email, { ...DEFAULTS.email, message: false }); assert.equal(prefs.customized, true);
  await assert.rejects(f.service.unsubscribe(f.rawToken(dm)), /已使用/);
  // The pending DM notice is cancelled; the contact-request notice survives the new consent epoch and is sent.
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.length, 3); assert.ok(f.sent[2].text.includes('新的联系请求'));
  assert.ok(f.sent[2].text.includes('是因为你的账号开启了「新的联系请求」'), 'after a choice the reason no longer says "by default"');
  assert.equal(f.jobs().find(row => row.sourceId === 'dm_two').status, 'cancelled');
  assert.deepEqual(await f.service.enqueueEvent(f.event({ sourceId: 'dm_three' })), { queued: 0 }, 'new DMs stay off');
});

test('English and zh-Hant notices name the setting; SMS carries a short per-kind link and no headers', async () => {
  for (const [locale, prefix, subject, why, stop] of [
    ['en', '/en', 'BAYLINK notification: New private messages', 'You get this email because "New private messages" email reminders are on for your account.', 'Turn off these emails: '],
    ['zh-Hant', '/zh-Hant', 'BAYLINK 站內通知：新的私訊', '你收到這封郵件，是因為你的帳號開啟了「新的私訊」郵件提醒。', '關閉這類郵件：'],
  ]) {
    const f = fixture({ defaults: 'on' }); await f.verify();
    await f.service.updatePreferences('owner', { preferences: { sms: { message: true } }, locale });
    await f.service.enqueueEvent(f.event()); f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
    const [mail] = f.sent, [sms] = f.texts;
    assert.equal(mail.subject, subject); assert.ok(mail.text.includes(why)); assert.ok(mail.text.includes(stop));
    assert.ok(mail.text.startsWith(locale === 'en' ? 'You have new private messages on BAYLINK. Sign in to view: ' : '你在 BAYLINK 收到新的私訊，請登入查看：'));
    assert.ok(!/one click|一鍵/.test(mail.text));
    assert.ok(mail.text.includes(`https://www.baylink.us${prefix}/me?view=notifications`));
    assert.ok(sms.body.includes(`https://www.baylink.us${prefix}/notifications/unsubscribe#token=`) && sms.body.includes('&kind=message'));
    assert.equal(sms.headers, undefined); assert.equal(sms.body.split('\n').length, 2, 'SMS stays two lines');
  }
});

test('unsubscribe tokens issued before H14 carry no kind and still turn off the whole channel', async () => {
  const f = fixture(); await f.verify();
  await f.service.updatePreferences('owner', { preferences: { email: { message: true, contact_request: true, outing_request: true } }, locale: 'en' });
  await f.service.enqueueEvent(f.event());
  for (const row of f.models.NotificationToken.rows.values()) delete row.topic;
  f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  const [mail] = f.sent;
  assert.match(mail.text, /Turn off these notifications: https:\/\/www\.baylink\.us\/en\/notifications\/unsubscribe#token=[A-Za-z0-9_-]{43}\n/);
  assert.ok(!mail.text.includes('&kind=')); assert.equal(mail.headers, undefined, 'no one-click header for a whole-channel token');
  assert.deepEqual(await f.service.unsubscribe(f.rawToken(mail)), { ok: true, channel: 'email', topic: null });
  assert.deepEqual((await f.service.preferences('owner')).preferences.email, OFF);
});

test('delivery stays gated: with the defaults on, nothing reaches a provider unless NOTIFICATION_DELIVERY_ENABLED is exactly "true"', async () => {
  // null = the variable is not set at all.
  for (const enabled of [null, 'false', 'TRUE', '1', 'yes']) {
    const f = fixture({ defaults: 'on', enabled, seed: [legacyAccount('owner')] });
    const prefs = await f.service.preferences('owner');
    assert.equal(prefs.deliveryEnabled, false); assert.equal(prefs.emailDeliveryAvailable, false);
    assert.equal(prefs.preferences.email.message, true, 'the preference is stored; only delivery is gated');
    assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 1 });
    f.advance(FIRST_NOTICE_DELAY + HALF_HOUR);
    assert.deepEqual(await f.service.runOnce(), { processed: 0, disabled: true });
    assert.equal(f.sent.length + f.texts.length, 0, String(enabled));
    assert.equal(f.jobs()[0].status, 'queued');
  }
});

test('re-saving a reminder that is already on needs no re-verified address; turning one on still does', async () => {
  const f = fixture({ defaults: 'on' }); await f.verify();
  await f.models.User.updateOne({ id: 'owner' }, { $set: { email: 'owner-new@example.test' } });
  const saved = await f.service.updatePreferences('owner', { preferences: { email: { ...DEFAULTS.email }, sms: { ...OFF, comment: true } } });
  assert.equal(saved.emailVerified, false); assert.equal(saved.preferences.sms.comment, true);
  await assert.rejects(f.service.updatePreferences('owner', { preferences: { email: { ...DEFAULTS.email, comment: true } } }), error => error.code === 'NOTIFICATION_VERIFICATION_REQUIRED');
  assert.deepEqual(await f.service.enqueueEvent(f.event()), { queued: 0 }, 'nothing is sent to an unverified address');
});

test('reminder language follows the page that asked for or confirmed the verification; unknown values are ignored', async () => {
  const f = fixture({ defaults: 'on' });
  await f.service.startEmailVerification('owner', { locale: 'en' }); await f.service.runOnce();
  assert.equal(f.sent[0].subject, 'Verify your BAYLINK email'); assert.equal(f.account('owner').locale, 'en');
  assert.equal((await f.service.verifyEmail(f.rawToken(f.sent[0]), { locale: 'zh-Hant' })).defaultsApplied, true);
  assert.equal(f.account('owner').locale, 'zh-Hant'); assert.equal(f.account('owner').consentRevision, 0, 'a language is not a consent choice');
  await f.service.enqueueEvent(f.event()); f.advance(FIRST_NOTICE_DELAY); await f.service.runOnce();
  assert.equal(f.sent.at(-1).subject, 'BAYLINK 站內通知：新的私訊');
  const g = fixture();
  await g.service.startEmailVerification('owner', { locale: 'fr' }); await g.service.runOnce();
  assert.equal(g.sent[0].subject, '验证你的 BAYLINK 邮箱'); assert.equal(g.account('owner').locale, 'zh-Hans');
  await g.service.verifyEmail(g.rawToken(g.sent[0]), { locale: { $ne: 1 } });
  assert.equal(g.account('owner').locale, 'zh-Hans');
  // A language the member saved with their settings is kept; the verification email still follows the page.
  const h = fixture({ defaults: 'on' });
  await h.service.updatePreferences('owner', { preferences: { sms: { message: true } }, locale: 'zh-Hant' });
  await h.service.startEmailVerification('owner', { locale: 'en' }); await h.service.runOnce();
  assert.equal(h.sent[0].subject, 'Verify your BAYLINK email'); assert.equal(h.account('owner').locale, 'zh-Hant');
  await h.service.verifyEmail(h.rawToken(h.sent[0]), { locale: 'en' });
  assert.equal(h.account('owner').locale, 'zh-Hant');
});

test('the Resend adapter forwards the one-click headers and idempotency key, and reports rejections', async () => {
  const calls = [];
  const resend = { emails: { send: async (payload, options) => { calls.push([payload, options]); return calls.length === 3 ? { data: null, error: { statusCode: 422 } } : { data: { id: `r${calls.length}` }, error: null }; } } };
  const send = resendEmailSender(resend, 'BAYLINK <noreply@example.test>');
  const headers = { 'List-Unsubscribe': '<https://api.example.test/x>', 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' };
  assert.deepEqual(await send({ to: 'a@example.test', subject: 's', text: 't', body: 't', headers, idempotencyKey: 'k1' }), { id: 'r1' });
  assert.deepEqual(calls[0], [{ from: 'BAYLINK <noreply@example.test>', to: 'a@example.test', subject: 's', text: 't', headers }, { idempotencyKey: 'k1' }]);
  await send({ to: 'a@example.test', subject: 's', text: 't', idempotencyKey: 'k2' });
  assert.equal('headers' in calls[1][0], false, 'verification emails carry no unsubscribe header');
  await assert.rejects(send({ to: 'a@example.test', subject: 's', text: 't', idempotencyKey: 'k3' }), error => error.status === 422);
});

test('the one-click origin is the API host; a bad override falls back with one warning', () => {
  assert.equal(notificationApiOrigin({ NODE_ENV: 'production' }), API);
  assert.equal(notificationApiOrigin({ NODE_ENV: 'production', NOTIFICATION_API_URL: 'https://api.baylink.us' }), 'https://api.baylink.us');
  assert.equal(notificationApiOrigin({ NODE_ENV: 'development', NOTIFICATION_API_URL: 'http://localhost:3000' }), 'http://localhost:3000');
  const logs = [];
  for (const value of ['https://evil.test', 'http://baylink-api.onrender.com', 'https://baylink-api.onrender.com/api', 'nope']) {
    assert.equal(notificationApiOrigin({ NODE_ENV: 'production', NOTIFICATION_API_URL: value }, line => logs.push(line)), API);
  }
  assert.equal(logs.length, 4); assert.deepEqual(logs[0], { level: 'warn', event: 'notification_origin_invalid', setting: 'NOTIFICATION_API_URL', fallback: API });
});

// HTTP contract, as WEB-COMMUNITY-2 and mail apps see it.
test('HTTP: preferences expose the preset; one-click POST unsubscribes one kind; GET only opens the confirmation page', async t => {
  const jwt = require('jsonwebtoken');
  const { createApplication } = require('../server');
  const { createMemoryModels } = require('./support/memory-models');
  const SECRET = 'isolated-notify-defaults-secret-with-32-plus-chars';
  const makeUser = id => ({ id, email: `${id}@example.test`, password: 'x', nickname: `Neighbor ${id}`, role: 'user', contactType: 'wechat', contactValue: 'fictional', accountStatus: 'active', isBanned: false });
  const models = { ...createMemoryModels({ User: [makeUser('owner'), makeUser('other')], Conversation: [{ id: 'conversation', userIds: ['owner', 'other'], updatedAt: 100 }] }),
    NotificationAccount: memory([legacyAccount('other', { locale: 'en' })]), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory() };
  const mail = [];
  let offset = 0;
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, NOTIFICATION_DELIVERY_ENABLED: 'true', NOTIFICATION_EMAIL_DEFAULTS: 'on' },
    notificationNow: () => Date.now() + offset, notificationEmail: async value => { mail.push(value); return { id: `mock-${mail.length}` }; } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  // Drop idle keep-alive sockets so closing does not wait for their timeout.
  t.after(() => new Promise(resolve => { application.server.closeAllConnections?.(); application.io.close(resolve); }));
  const base = `http://127.0.0.1:${application.server.address().port}/api`;
  const auth = id => ({ Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` });

  const prefs = await (await fetch(`${base}/notifications/preferences`, { headers: auth('other') })).json();
  assert.deepEqual(prefs.preferences, DEFAULTS); assert.deepEqual(prefs.defaults, DEFAULTS);
  assert.equal(prefs.defaultsActive, true); assert.equal(prefs.defaultsApplied, true); assert.equal(prefs.customized, false); assert.equal(prefs.emailVerified, true);

  const sent = await fetch(`${base}/conversations/conversation/messages`, { method: 'POST', headers: { ...auth('owner'), 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'text', content: 'hello' }) });
  assert.equal(sent.status, 200);
  offset = FIRST_NOTICE_DELAY + 1000;
  assert.equal((await application.notifications.runOnce()).processed, 1);
  const header = mail[0].headers['List-Unsubscribe'], raw = header.match(/one-click\/([A-Za-z0-9_-]{43})>$/)[1];
  assert.equal(header, `<${API}/api/notifications/unsubscribe/one-click/${raw}>`);
  assert.ok(mail[0].text.includes(`https://www.baylink.us/en/notifications/unsubscribe#token=${raw}&kind=message`));

  // A browser GETs (a mail app that only knows RFC 2369, or a link scanner): 303 to the confirmation
  // page with the token in the fragment, the kind and the reminder's language. The token stays unused.
  for (const method of ['GET', 'HEAD']) {
    const opened = await fetch(`${base}/notifications/unsubscribe/one-click/${raw}`, { method, redirect: 'manual' });
    assert.equal(opened.status, 303, method);
    assert.equal(opened.headers.get('location'), `https://www.baylink.us/en/notifications/unsubscribe#token=${raw}&kind=message`);
    assert.equal(opened.headers.get('cache-control'), 'no-store'); assert.equal(opened.headers.get('referrer-policy'), 'no-referrer');
  }
  const unchanged = await (await fetch(`${base}/notifications/preferences`, { headers: auth('other') })).json();
  assert.deepEqual(unchanged.preferences, DEFAULTS, 'a GET changes nothing'); assert.equal(unchanged.customized, false);
  const malformed = await fetch(`${base}/notifications/unsubscribe/one-click/not-a-token`, { redirect: 'manual' });
  assert.equal(malformed.status, 303); assert.equal(malformed.headers.get('location'), 'https://www.baylink.us/notifications/unsubscribe', 'the page explains a missing token');
  const bad = await fetch(`${base}/notifications/unsubscribe/one-click/${'B'.repeat(43)}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'List-Unsubscribe=One-Click' });
  assert.equal(bad.status, 400);
  const oneClick = await fetch(`${base}/notifications/unsubscribe/one-click/${raw}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'List-Unsubscribe=One-Click' });
  assert.equal(oneClick.status, 200); assert.equal(oneClick.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await oneClick.json(), { ok: true, channel: 'email', topic: 'message' });
  const after = await (await fetch(`${base}/notifications/preferences`, { headers: auth('other') })).json();
  assert.deepEqual(after.preferences.email, { ...DEFAULTS.email, message: false }); assert.equal(after.customized, true);
  // The same token from the page link is spent.
  const page = await fetch(`${base}/notifications/unsubscribe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: raw }) });
  assert.equal(page.status, 400);

  // The verification request carries the page language (optional body field).
  const start = await fetch(`${base}/notifications/email/start`, { method: 'POST', headers: { ...auth('owner'), 'Content-Type': 'application/json' }, body: JSON.stringify({ locale: 'en' }) });
  assert.equal(start.status, 200); const started = await start.json();
  assert.equal(started.queued, true); assert.equal(started.defaultsActive, true); assert.deepEqual(started.defaults, DEFAULTS);
  await application.notifications.runOnce();
  assert.equal(mail.at(-1).subject, 'Verify your BAYLINK email');
  const verified = await fetch(`${base}/notifications/email/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: mail.at(-1).text.match(/#token=([A-Za-z0-9_-]{43})/)[1], locale: 'en' }) });
  assert.deepEqual(await verified.json(), { ok: true, emailVerified: true, defaultsApplied: true });
});
