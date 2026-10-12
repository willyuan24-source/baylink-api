// G76 + G104 (API-SEC): who may receive a phone-verification SMS, and when the budget is claimed.
// - United States numbers only (Canada, the non-US Caribbean and toll-free/premium codes refused).
// - A verified e-mail first, whenever the site can send the verification e-mail.
// - Accounts younger than 24 hours share only part of the daily pool.
// - The durable quota is claimed before any send path; nothing is sent without a claim.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { memory } = require('./support/notification-memory');
const { usPhoneProblem, CANADA, CARIBBEAN } = require('../lib/usPhone');

const SECRET = 'sms-verification-gates-secret-0123456789ab';
const hash = bcrypt.hashSync('OnlyMockPassword7', 4);
const sha = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const DAY = 86400000;
const person = (id, extra = {}) => ({ id, email: `${id}@example.test`, password: hash, nickname: `Neighbor ${id}`, role: 'user', accountStatus: 'active', isBanned: false, ...extra });
const verifiedEmail = id => ({ _id: sha(`account:${id}`), userId: id, revision: 1, consentRevision: 1, locale: 'zh-Hans', requests: 0, lastRequestedAt: 0,
  verifiedEmailHash: sha(`email:${id}@example.test`), emailVerifiedAt: 1,
  preferences: { email: { message: false, contact_request: false, outing_request: false, comment: false }, sms: { message: false, contact_request: false, outing_request: false, comment: false } } });

async function start(t, { users, config = {}, notificationDelivery = false, verified = [], ...options }) {
  const models = createMemoryModels({ User: users });
  if (notificationDelivery) {
    Object.assign(models, { NotificationAccount: memory(), NotificationToken: memory(), NotificationJob: memory(), NotificationWindow: memory(), NotificationBudget: memory() });
    for (const id of verified) models.NotificationAccount.rows.set(sha(`account:${id}`), verifiedEmail(id));
  }
  const application = createApplication({ ...options, models,
    ...(notificationDelivery ? { notificationEmail: async () => ({ id: 'mock' }) } : {}),
    config: { NODE_ENV: 'test', JWT_SECRET: SECRET, AUTH_DEV_RETURN_TOKENS: 'true', ...(notificationDelivery ? { NOTIFICATION_DELIVERY_ENABLED: 'true' } : {}), ...config } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const send = async (id, phone) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/users/me/phone/start`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt.sign({ id }, SECRET, { expiresIn: '1h' })}` }, body: JSON.stringify({ phone }) });
    return { status: response.status, data: await response.json() };
  };
  return { models, send, quotaRows: () => models.SmsQuota.rows };
}

test('usPhoneProblem: US states, DC and territories pass; Canada, the non-US Caribbean, Bermuda and non-geographic codes do not', () => {
  const us = [415, 628, 510, 341, 408, 669, 650, 925, 707, 369, 831, 209, 350, 916, 279, 213, 323, 310, 424, 626, 818, 747, 949, 714, 657, 562,
    909, 951, 760, 442, 858, 619, 805, 820, 559, 661, 530, 212, 646, 917, 718, 347, 929, 332, 206, 425, 253, 503, 971, 702, 725, 602, 480, 312, 773,
    872, 617, 857, 305, 786, 404, 470, 678, 770, 214, 469, 972, 945, 713, 281, 832, 346, 512, 737, 202, 771, 808, 907, 989, 380, 463, 464,
    787, 939, 340, 671, 670, 684];
  for (const area of us) assert.equal(usPhoneProblem(`+1${area}5550123`), null, `${area}`);
  for (const area of [...CANADA, ...CARIBBEAN]) assert.equal(usPhoneProblem(`+1${area}5550123`), 'non-us', `${area}`);
  for (const area of [604, 778, 416, 647, 905, 514, 403, 613, 876, 809, 829, 849, 242, 246, 441, 868, 758]) assert.equal(usPhoneProblem(`+1${area}5550123`), 'non-us', `${area}`);
  for (const area of [800, 833, 844, 855, 866, 877, 888, 900, 500, 533, 544, 566, 577, 588, 600, 622, 700, 456, 710, 521, 569]) assert.equal(usPhoneProblem(`+1${area}5550123`), 'non-geographic', `${area}`);
  for (const value of ['+14151230123', '+14159110123', '+19115550123', '+13705550123', '+19605550123', '+14955550123', '+1415555012', '+441415550123', '4155550123', '', null])
    assert.equal(usPhoneProblem(value), 'format', String(value));
  assert.ok(CANADA.every(code => !us.includes(code)) && CARIBBEAN.every(code => !us.includes(code)));
});

test('phone verification refuses non-US numbers (PHONE_NOT_US) and mistyped ones (PHONE_INVALID) before any SMS budget is spent; US and territory numbers proceed', async t => {
  const f = await start(t, { users: [person('owner'), person('second'), person('third')] });
  for (const phone of ['(876) 555-0101', '+1 604 555 0101', '18095550101', '+1 800 555 0101', '+1 441 555 0101']) {
    const refused = await f.send('owner', phone);
    assert.equal(refused.status, 400, phone); assert.equal(refused.data.code, 'PHONE_NOT_US', phone); assert.equal(refused.data.devCode, undefined);
  }
  // A mistyped or impossible number is not a foreign one: PHONE_INVALID, "enter a valid US number".
  for (const phone of ['(415) 911-0101', '0155550101', '1-115-555-0101', '(495) 555-0101', '(370) 555-0101', '415555010', 'not a phone']) {
    const invalid = await f.send('owner', phone);
    assert.equal(invalid.status, 400, phone); assert.equal(invalid.data.code, 'PHONE_INVALID', phone); assert.equal(invalid.data.error, '请输入有效的美国手机号。', phone);
  }
  assert.equal(f.quotaRows().length, 0);
  assert.equal((await f.send('owner', '(415) 555-0101')).status, 200);
  assert.equal((await f.send('second', '+1 787 555 0101')).status, 200, 'Puerto Rico is the United States');
});

test('a verified e-mail comes first whenever the site can send the verification e-mail', async t => {
  const f = await start(t, { users: [person('unverified'), person('verified')], notificationDelivery: true, verified: ['verified'] });
  const refused = await f.send('unverified', '4155550111');
  assert.equal(refused.status, 409); assert.equal(refused.data.code, 'EMAIL_VERIFICATION_REQUIRED');
  assert.match(refused.data.error, /验证邮箱/);
  assert.equal(f.quotaRows().length, 0, 'nothing reserved');
  assert.equal((await f.send('verified', '4155550122')).status, 200);
  // A changed e-mail address is no longer verified.
  f.models.User.rows.find(row => row.id === 'verified').email = 'changed@example.test';
  f.models.User.rows.find(row => row.id === 'verified').phoneVerificationLastSentAt = 0;
  assert.equal((await f.send('verified', '4155550122')).data.code, 'EMAIL_VERIFICATION_REQUIRED');
});

test('SMS_REQUIRE_VERIFIED_EMAIL: unset follows e-mail delivery (off while delivery is off: no lockout), true forces it, false turns it off', async t => {
  const off = await start(t, { users: [person('owner')] });
  assert.equal((await off.send('owner', '4155550133')).status, 200, 'no e-mail delivery: phone verification works as before');
  const forced = await start(t, { users: [person('owner')], config: { SMS_REQUIRE_VERIFIED_EMAIL: 'true' } });
  assert.equal((await forced.send('owner', '4155550144')).data.code, 'EMAIL_VERIFICATION_REQUIRED');
  const disabled = await start(t, { users: [person('owner')], notificationDelivery: true, config: { SMS_REQUIRE_VERIFIED_EMAIL: 'false' } });
  assert.equal((await disabled.send('owner', '4155550155')).status, 200);
});

test('accounts younger than 24 hours share at most 40% of the daily pool; older accounts keep the rest', async t => {
  const now = Date.now();
  const users = [...['n1', 'n2', 'n3'].map(id => person(id, { createdAt: now - 60000 })), ...['o1', 'o2', 'o3'].map(id => person(id, { createdAt: now - 2 * DAY })), person('legacy')];
  const f = await start(t, { users, config: { SMS_VERIFY_DAILY_LIMIT: '5' } });
  assert.equal((await f.send('n1', '4155550201')).status, 200);
  assert.equal((await f.send('n2', '4155550202')).status, 200);
  const third = await f.send('n3', '4155550203');
  assert.equal(third.status, 503); assert.equal(third.data.code, 'SMS_NEW_ACCOUNT_CAPACITY');
  assert.equal((await f.send('o1', '4155550204')).status, 200);
  assert.equal((await f.send('o2', '4155550205')).status, 200);
  assert.equal((await f.send('legacy', '4155550206')).status, 200, 'an account without a creation time counts as old');
  const full = await f.send('o3', '4155550207');
  assert.equal(full.status, 503); assert.equal(full.data.code, 'SMS_DAILY_CAPACITY');
  // The refused new-account request returned its number/account holds and never touched the site count.
  const counts = f.quotaRows().map(row => row.count).sort((a, b) => a - b);
  assert.equal(counts.filter(count => count === 5).length, 1, 'site-wide: 5 sent');
  assert.equal(counts.filter(count => count === 2).length, 1, 'new-account share: 2 sent');
  const custom = await start(t, { users: [person('n4', { createdAt: now })], config: { SMS_VERIFY_DAILY_LIMIT: '5', SMS_NEW_ACCOUNT_DAILY_LIMIT: '0' } });
  assert.equal((await custom.send('n4', '4155550208')).data.code, 'SMS_NEW_ACCOUNT_CAPACITY');
});

test('G104: the quota is claimed before the send branch, and no provider send happens without a claim', async t => {
  const sends = [];
  let models;
  const twilioClient = { messages: { create: async message => {
    const siteRow = models.SmsQuota.rows.reduce((top, row) => (row.count > (top?.count || 0) ? row : top), null);
    sends.push({ to: message.to, claimedBeforeSend: models.SmsQuota.rows.length >= 3 && (siteRow?.count || 0) >= sends.length + 1 });
    return { sid: 'mock' };
  } } };
  const f = await start(t, { users: [person('owner'), person('other')], twilioClient, config: { NODE_ENV: 'test', TWILIO_PHONE_NUMBER: '+14155550000', AUTH_DEV_RETURN_TOKENS: 'false', SMS_VERIFY_DAILY_LIMIT: '1' } });
  models = f.models;
  const sent = await f.send('owner', '4155550301');
  assert.equal(sent.status, 200); assert.equal(sent.data.devCode, undefined);
  assert.deepEqual(sends, [{ to: '+14155550301', claimedBeforeSend: true }]);
  const refused = await f.send('other', '4155550302');
  assert.equal(refused.status, 503); assert.equal(refused.data.code, 'SMS_DAILY_CAPACITY');
  assert.equal(sends.length, 1, 'no claim, no send');
  // Non-US and unverified-email refusals never reach the provider either.
  assert.equal((await f.send('other', '+1 876 555 0303')).data.code, 'PHONE_NOT_US');
  assert.equal(sends.length, 1);
});
