const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { localInstant, parseSlot } = require('../lib/serviceBookings');
const SECRET = 'isolated-service-bookings-not-a-real-secret';
const START = Date.parse('2026-09-30T15:00:00Z'); // 08:00 Pacific
const slot = (date = '2026-10-02', startTime = '09:00', endTime = '10:00') => ({ date, startTime, endTime });
const users = () => [
  { id: 'provider', nickname: '服务者', isPhoneVerified: true, phoneNormalized: '+14155550123' },
  { id: 'official', nickname: '官方店铺', officialVerification: { status: 'approved' } },
  { id: 'unverified', isPhoneVerified: false, isOfficialVerified: true, officialVerification: { status: 'pending' } },
  { id: 'customer' }, { id: 'other' }, { id: 'third' },
].map(row => ({ email: `${row.id}@private.test`, password: 'private', accountStatus: 'active', ...row }));
const posts = () => [
  { id: 'cleaning', authorId: 'provider', title: '家庭清洁', category: '清洁', type: 'provider' },
  { id: 'moving', authorId: 'provider', title: '搬家服务', category: '搬家', type: 'provider' },
  { id: 'official-service', authorId: 'official', title: '翻译服务', category: '翻译', type: 'provider' },
  { id: 'unverified-service', authorId: 'unverified', title: '维修', category: '维修', type: 'provider' },
  { id: 'wanted', authorId: 'provider', title: '找清洁', category: '清洁', type: 'client' },
  { id: 'rental', authorId: 'provider', title: '出租', category: '租屋', type: 'provider' },
].map(row => ({ isDeleted: false, status: 'active', ...row }));
async function fixture(t, options = {}) {
  let current = START;
  const models = createMemoryModels({ User: users(), Post: posts() });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...options.config }, serviceBookingNow: () => current, serviceBookingSms: options.sms });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as, method = 'GET', body } = {}) => {
    const token = as && jwt.sign({ id: as }, SECRET, { expiresIn: '1h' });
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/service-bookings${path}`, {
      method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  let counter = 0;
  const key = () => `request-${++counter}`;
  const configure = (postId = 'cleaning', body = {}, as = 'provider') => request(`/posts/${postId}/settings`, { as, method: 'PATCH', body: { enabled: true, ...body } });
  const add = (postId = 'cleaning', slots = [slot()], as = 'provider') => request(`/posts/${postId}/slots`, { as, method: 'POST', body: { slots, idempotencyKey: key() } });
  const book = (slotId, as = 'customer', postId = 'cleaning', idempotencyKey = key()) => request(`/posts/${postId}/book`, { as, method: 'POST', body: { slotId, idempotencyKey } });
  const action = (booking, action, as = 'provider', idempotencyKey = key()) => request(`/${booking.providerId}/${booking.id}/actions`, { as, method: 'POST', body: { action, idempotencyKey } });
  return { models, request, configure, add, book, action, setNow: value => { current = value; }, key };
}

test('LA wall-clock dates handle seasonal offsets and reject invalid, ambiguous, past and cross-day slots', () => {
  assert.equal(localInstant('2026-10-02', '09:00'), Date.parse('2026-10-02T16:00:00Z'));
  assert.equal(localInstant('2026-12-02', '09:00'), Date.parse('2026-12-02T17:00:00Z'));
  assert.throws(() => localInstant('2026-11-01', '01:30'), /夏令时/);
  assert.throws(() => localInstant('2027-03-14', '02:30'), /夏令时/);
  assert.throws(() => localInstant('2026-02-30', '09:00'), /日期/);
  assert.throws(() => parseSlot(slot('2026-09-29'), START), /未来/);
  assert.throws(() => parseSlot(slot('2026-10-02', '23:00', '01:00'), START), /同一天/);
  assert.throws(() => parseSlot(slot('2026-10-02', '09:00', '09:10'), START), /15分钟/);
});

test('only current service authors with verified phone or approved official review can enable booking', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/posts/cleaning')).data.enabled, false);
  assert.equal((await f.request('/posts/cleaning')).data.mode, 'request');
  assert.equal((await f.configure('cleaning', {}, 'other')).status, 403);
  assert.equal((await f.configure('unverified-service', {}, 'unverified')).status, 403, 'legacy official flag is not approval');
  assert.equal((await f.configure('rental')).status, 409);
  assert.equal((await f.configure('wanted')).status, 409);
  assert.equal((await f.configure('official-service', {}, 'official')).status, 200);
  f.models.User.rows.find(row => row.id === 'unverified').officialVerification.status = 'none';
  assert.equal((await f.configure('unverified-service', {}, 'unverified')).status, 200, 'an existing legacy official badge remains valid until a contrary review');
  const configured = await f.configure();
  assert.equal(configured.status, 200); assert.equal(configured.data.minNoticeMinutes, 120); assert.equal(configured.data.bufferMinutes, 30);
  assert.equal((await f.request('/posts/cleaning/settings', { method: 'PATCH', body: { enabled: true } })).status, 401);
  assert.equal((await f.configure('cleaning', { providerId: 'other' })).status, 400);
});

test('batch availability is atomic, idempotent and rejects overlaps across every post owned by one provider', async t => {
  const f = await fixture(t); await f.configure();
  const body = { slots: [slot(), slot('2026-10-03')], idempotencyKey: 'same-batch' };
  const added = await f.request('/posts/cleaning/slots', { as: 'provider', method: 'POST', body });
  assert.equal(added.status, 200); assert.equal(added.data.slots.length, 2);
  assert.deepEqual((await f.request('/posts/cleaning/slots', { as: 'provider', method: 'POST', body })).data.slotIds, added.data.slotIds);
  assert.equal((await f.add('moving', [slot()])).status, 409);
  assert.equal((await f.add('moving', [slot('2026-10-04'), slot()])).status, 409);
  assert.equal((await f.request('/posts/moving')).data.slots.length, 0, 'failed batch cannot partially add a day');
  assert.equal((await f.request('/posts/cleaning/slots', { as: 'provider', method: 'POST', body: { ...body, slots: [slot('2026-10-05')] } })).status, 409);
});

test('two concurrent requests cannot reserve one slot; retries keep one booking and one private system notice', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add(), slotId = added.data.slots[0].id;
  const attempts = await Promise.all([f.book(slotId, 'customer', 'cleaning', 'customer-one'), f.book(slotId, 'other', 'cleaning', 'other-one')]);
  assert.deepEqual(attempts.map(row => row.status).sort(), [200, 409]);
  const winner = attempts.find(row => row.status === 200), customer = winner.data.booking.customerId;
  const retried = await f.book(slotId, customer, 'cleaning', customer === 'customer' ? 'customer-one' : 'other-one');
  assert.equal(retried.data.booking.id, winner.data.booking.id);
  assert.equal(winner.data.booking.status, 'pending'); assert.equal(winner.data.booking.expiresAt, START + 86400000);
  assert.equal(retried.data.notifications.inApp, 'sent'); assert.equal(retried.data.notifications.sms, 'disabled');
  assert.equal(f.models.ServiceBookingAgenda.rows[0].bookings.length, 1); assert.equal(f.models.Message.rows.length, 1);
  assert.equal(f.models.Message.rows[0].messageType, 'system'); assert.equal(f.models.Conversation.rows.length, 1);
  assert.equal(f.models.Message.rows[0].type, 'text', 'existing chat renderers accept system notices as text');
  assert.deepEqual(f.models.Conversation.rows[0].userIds, [customer, 'provider'].sort());
  const publicData = JSON.stringify((await f.request('/posts/cleaning')).data);
  assert.ok(!publicData.includes('customerId')); assert.ok(!publicData.includes('customerName')); assert.ok(!publicData.includes('phone'));
  assert.equal((await f.request('/me', { as: 'third' })).data.asCustomer.length, 0);
  assert.equal((await f.request('/me', { as: customer })).data.asCustomer.length, 1);
  assert.equal((await f.request('/me', { as: 'provider' })).data.asProvider.length, 1);
});

test('request mode expires durably after 24 hours and at start time, releasing the slot without a scheduler', async t => {
  const f = await fixture(t); await f.configure('cleaning', { minNoticeMinutes: 0 });
  const added = await f.add('cleaning', [slot(), slot('2026-09-30', '09:00', '10:00')]);
  const booking = (await f.book(added.data.slots[0].id)).data.booking;
  const soon = (await f.book(added.data.slots[1].id, 'other')).data.booking;
  assert.equal(soon.expiresAt, localInstant('2026-09-30', '09:00'));
  f.setNow(START + 86400001);
  const availability = await f.request('/posts/cleaning');
  assert.equal(availability.data.slots[0].available, true);
  assert.ok(f.models.ServiceBookingAgenda.rows[0].bookings.every(row => row.status === 'expired'));
  assert.equal((await f.action(booking, 'confirm')).status, 409);
  assert.equal((await f.book(added.data.slots[0].id, 'third')).status, 200);
});

test('instant mode, notice windows and snapshot buffers protect adjacent slots across different service posts', async t => {
  const f = await fixture(t); await f.configure('cleaning', { mode: 'instant', minNoticeMinutes: 120, bufferMinutes: 30 }); await f.configure('moving', { mode: 'instant', bufferMinutes: 0 });
  const a = await f.add('cleaning', [slot(), slot('2026-09-30', '09:00', '10:00')]);
  assert.equal(a.data.slots[1].available, false, 'the two-hour advance notice applies to available slots');
  assert.equal((await f.book(a.data.slots[1].id)).status, 409);
  const b = await f.add('moving', [slot('2026-10-02', '10:15', '11:15')]);
  const booked = await f.book(a.data.slots[0].id); assert.equal(booked.data.booking.status, 'confirmed');
  await f.configure('cleaning', { bufferMinutes: 0 });
  assert.equal((await f.request('/posts/moving')).data.slots[0].available, false, 'existing booking keeps its 30-minute buffer');
  assert.equal((await f.book(b.data.slots[0].id, 'other', 'moving')).status, 409);
  assert.equal((await f.action(booked.data.booking, 'complete')).status, 409);
  f.setNow(localInstant('2026-10-02', '10:00'));
  assert.equal((await f.action(booked.data.booking, 'complete')).status, 200);
  assert.equal((await f.book(b.data.slots[0].id, 'other', 'moving')).status, 409, 'completion does not erase the cooldown');
});

test('only participants can act, customers cannot self-confirm, and cancellation releases occupied slots', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add(), slotId = added.data.slots[0].id;
  const booking = (await f.book(slotId)).data.booking;
  assert.equal((await f.action(booking, 'confirm', 'customer')).status, 403);
  assert.equal((await f.action(booking, 'cancel', 'third')).status, 404);
  assert.equal((await f.request(`/posts/cleaning/slots/${slotId}`, { as: 'provider', method: 'DELETE' })).status, 409);
  assert.equal((await f.action(booking, 'confirm')).data.booking.status, 'confirmed');
  const cancelled = await f.action(booking, 'cancel', 'customer', 'cancel-once'); assert.equal(cancelled.data.booking.status, 'cancelled');
  assert.equal((await f.action(booking, 'cancel', 'customer', 'cancel-once')).status, 200);
  assert.equal(f.models.Message.rows.length, 3, 'request, confirmation and cancellation each create one notice');
  assert.equal((await f.request('/posts/cleaning')).data.slots[0].available, true);
  assert.equal((await f.book(slotId, 'other')).status, 200);
  assert.equal((await f.request('/nobody/fake-booking/actions', { as: 'third', method: 'POST', body: { action: 'cancel', idempotencyKey: 'bad-action' } })).status, 404);
  assert.equal(f.models.ServiceBookingAgenda.rows.some(row => row.providerId === 'nobody'), false);
});

test('block and post/account lifecycle checks stop new requests or confirmations without trapping cancellation', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add(), slotId = added.data.slots[0].id;
  assert.equal((await f.book(slotId, 'provider')).status, 400);
  const booking = (await f.book(slotId)).data.booking;
  await f.models.UserBlock.create({ blockerId: 'customer', blockedUserId: 'provider' });
  assert.equal((await f.action(booking, 'confirm')).status, 403);
  const cancel = await f.action(booking, 'cancel', 'customer'); assert.equal(cancel.status, 200); assert.equal(cancel.data.notifications.inApp, 'skipped');
  assert.equal((await f.book(slotId)).status, 403);
  f.models.Post.rows.find(row => row.id === 'cleaning').status = 'closed';
  assert.equal((await f.book(slotId, 'other')).status, 409); assert.equal((await f.request('/posts/cleaning')).data.enabled, false);
  f.models.Post.rows.find(row => row.id === 'cleaning').status = 'active';
  f.models.User.rows.find(row => row.id === 'provider').isPhoneVerified = false;
  assert.equal((await f.book(slotId, 'other')).status, 409);
});

test('an in-app notice write failure leaves the booking committed and its exact retry repairs one notice', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add(), slotId = added.data.slots[0].id;
  const original = f.models.Message.findOneAndUpdate; let failWrite = true;
  f.models.Message.findOneAndUpdate = (...args) => { if (failWrite) throw new Error('isolated write failure'); return original(...args); };
  const first = await f.book(slotId, 'customer', 'cleaning', 'retry-notice');
  assert.equal(first.status, 200); assert.equal(first.data.notifications.inApp, 'failed');
  assert.equal(f.models.ServiceBookingAgenda.rows[0].bookings.length, 1);
  failWrite = false;
  const retry = await f.book(slotId, 'customer', 'cleaning', 'retry-notice');
  assert.equal(retry.data.booking.id, first.data.booking.id); assert.equal(retry.data.notifications.inApp, 'sent'); assert.equal(f.models.Message.rows.length, 1);
});

test('SMS requires separate scoped consent, verified phone, both config gates and a Messaging Service; retries never double send', async t => {
  const sent = [];
  const f = await fixture(t, { config: { SERVICE_BOOKING_SMS_ENABLED: 'true', SERVICE_BOOKING_SMS_OPT_OUT_CONFIGURED: 'true', TWILIO_MESSAGING_SERVICE_SID: 'MG_fixture' }, sms: async payload => { sent.push(payload); return { sid: 'SM_fixture' }; } });
  await f.configure(); const added = await f.add('cleaning', [slot(), slot('2026-10-03'), slot('2026-10-04')]);
  const first = await f.book(added.data.slots[0].id); assert.equal(first.data.notifications.sms, 'disabled'); assert.equal(sent.length, 0);
  assert.equal((await f.request('/sms-settings', { as: 'official', method: 'PATCH', body: { enabled: true } })).status, 403, 'official verification alone does not opt a phone in');
  const optin = await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } });
  assert.equal(optin.data.sms.enabled, true); assert.equal(optin.data.sms.consentVersion, 'service-booking-sms-v1');
  const booking = await f.book(added.data.slots[1].id, 'customer', 'cleaning', 'sms-book-once');
  assert.equal(booking.data.notifications.sms, 'sent'); assert.equal(sent.length, 1);
  await f.book(added.data.slots[1].id, 'customer', 'cleaning', 'sms-book-once'); assert.equal(sent.length, 1);
  assert.match(sent[0].body, /STOP/); assert.equal(sent[0].to, '+14155550123');
  f.models.User.rows.find(row => row.id === 'provider').phoneNormalized = '+14155550999';
  assert.equal((await f.book(added.data.slots[2].id)).data.notifications.sms, 'not_eligible'); assert.equal(sent.length, 1);
  const publicView = JSON.stringify((await f.request('/me', { as: 'customer' })).data); assert.ok(!publicView.includes('+1415555'));
});

test('unconfigured SMS is honest; provider STOP suppression disables consent and ambiguous sends are not retried', async t => {
  const noConfig = await fixture(t); await noConfig.configure(); const a = await noConfig.add();
  assert.equal((await noConfig.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } })).status, 409);
  assert.equal(noConfig.models.ServiceBookingAgenda.rows[0].sms.enabled, false);
  noConfig.models.ServiceBookingAgenda.rows[0].sms = { enabled: true, verifiedPhone: '+14155550123', consentedAt: START, consentVersion: 'service-booking-sms-v1' };
  assert.equal((await noConfig.book(a.data.slots[0].id)).data.notifications.sms, 'unconfigured');
  let count = 0;
  const f = await fixture(t, { config: { SERVICE_BOOKING_SMS_ENABLED: 'true', SERVICE_BOOKING_SMS_OPT_OUT_CONFIGURED: 'true', TWILIO_MESSAGING_SERVICE_SID: 'MG_fixture' }, sms: async () => { count++; throw Object.assign(new Error('STOP'), { code: 21610 }); } });
  await f.configure(); const b = await f.add(); await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } });
  assert.equal((await f.book(b.data.slots[0].id, 'customer', 'cleaning', 'sms-stopped')).data.notifications.sms, 'failed');
  await f.book(b.data.slots[0].id, 'customer', 'cleaning', 'sms-stopped'); assert.equal(count, 1);
  assert.equal((await f.request('/me', { as: 'provider' })).data.sms.enabled, false);
});

test('My Bookings drains failed and expired in-app notices, updates conversation recency and does not duplicate them', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add(), slotId = added.data.slots[0].id;
  await f.models.Conversation.create({ id: 'old-thread', userIds: ['customer', 'provider'], updatedAt: 1 });
  const original = f.models.Message.findOneAndUpdate;
  f.models.Message.findOneAndUpdate = () => { throw new Error('temporary fixture outage'); };
  await f.book(slotId); assert.equal(f.models.Message.rows.length, 0);
  f.models.Message.findOneAndUpdate = original;
  f.setNow(START + 60000);
  const recovered = await f.request('/me', { as: 'provider' }); assert.equal(recovered.data.asProvider[0].notifications.inApp, 'sent');
  assert.equal(f.models.Message.rows.length, 1); assert.equal(f.models.Conversation.rows[0].updatedAt, START);
  f.setNow(START + 86400001);
  const expired = await f.request('/me', { as: 'customer' }); assert.equal(expired.data.asCustomer[0].status, 'expired');
  assert.equal(expired.data.asCustomer[0].notifications.inApp, 'sent'); assert.equal(f.models.Message.rows.length, 2);
  assert.match(f.models.Message.rows[1].content, /申请已过期/);
  await f.request('/me', { as: 'provider' }); assert.equal(f.models.Message.rows.length, 2);
});

test('parallel idempotent submissions and simultaneous buffered slots do not double book or duplicate notices', async t => {
  const f = await fixture(t); await f.configure('cleaning', { mode: 'instant' }); await f.configure('moving', { mode: 'instant' });
  const a = await f.add(), b = await f.add('moving', [slot('2026-10-02', '10:15', '11:00')]);
  const responses = await Promise.all([f.book(a.data.slots[0].id, 'customer', 'cleaning', 'same-parallel'), f.book(a.data.slots[0].id, 'customer', 'cleaning', 'same-parallel')]);
  assert.ok(responses.every(row => row.status === 200)); assert.equal(responses[0].data.booking.id, responses[1].data.booking.id);
  assert.equal(f.models.ServiceBookingAgenda.rows[0].bookings.length, 1); assert.equal(f.models.Message.rows.length, 1);
  await f.action(responses[0].data.booking, 'cancel', 'customer');
  const race = await Promise.all([f.book(a.data.slots[0].id, 'other'), f.book(b.data.slots[0].id, 'third', 'moving')]);
  assert.deepEqual(race.map(row => row.status).sort(), [200, 409]);
  assert.equal(f.models.ServiceBookingAgenda.rows[0].bookings.filter(row => row.status === 'confirmed').length, 1);
});

test('ambiguous SMS provider failure remains unknown and a history refresh or exact retry never sends twice', async t => {
  let sends = 0;
  const f = await fixture(t, { config: { SERVICE_BOOKING_SMS_ENABLED: 'true', SERVICE_BOOKING_SMS_OPT_OUT_CONFIGURED: 'true', TWILIO_MESSAGING_SERVICE_SID: 'MG_fixture' }, sms: async () => { sends++; throw new Error('unknown transport outcome'); } });
  await f.configure(); const added = await f.add(); await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } });
  const first = await f.book(added.data.slots[0].id, 'customer', 'cleaning', 'unknown-outcome'); assert.equal(first.data.notifications.sms, 'unknown');
  await f.book(added.data.slots[0].id, 'customer', 'cleaning', 'unknown-outcome'); await f.request('/me', { as: 'provider' }); assert.equal(sends, 1);
});

test('a full creation journal blocks new work but preserves bounded idempotent confirmation, cancellation, decline and completion', async t => {
  const f = await fixture(t); await f.configure();
  const added = await f.add('cleaning', [slot(), slot('2026-10-03'), slot('2026-10-04'), slot('2026-10-05')]);
  const a = (await f.book(added.data.slots[0].id, 'customer', 'cleaning', 'original-book')).data.booking;
  const b = (await f.book(added.data.slots[1].id, 'other')).data.booking;
  const c = (await f.book(added.data.slots[2].id, 'third')).data.booking;
  const agenda = f.models.ServiceBookingAgenda.rows[0];
  while (agenda.operations.length < 4000) agenda.operations.push({ id: `capacity-fixture-${agenda.operations.length}`, fingerprint: 'fixture', result: {} });
  assert.equal((await f.add('cleaning', [slot('2026-10-06')])).status, 409);
  assert.equal((await f.book(added.data.slots[3].id)).status, 409);
  assert.equal((await f.book(added.data.slots[0].id, 'customer', 'cleaning', 'original-book')).data.booking.id, a.id, 'prior creation receipts still replay');
  assert.equal((await f.action(a, 'confirm', 'provider', 'capacity-confirm-a')).status, 200);
  assert.equal((await f.action(a, 'confirm', 'provider', 'capacity-confirm-a')).status, 200);
  assert.equal((await f.action(a, 'cancel', 'customer', 'capacity-cancel-a')).data.booking.status, 'cancelled');
  assert.equal((await f.action(a, 'cancel', 'customer', 'capacity-cancel-a')).status, 200);
  assert.equal((await f.action(a, 'cancel', 'customer', 'another-cancel-key')).status, 409);
  assert.equal((await f.action(b, 'confirm', 'provider', 'capacity-confirm-b')).status, 200);
  assert.equal((await f.action(c, 'decline', 'provider', 'capacity-decline-c')).status, 200);
  f.setNow(b.endAt);
  assert.equal((await f.action(b, 'complete', 'provider', 'capacity-complete-b')).data.booking.status, 'completed');
  assert.equal((await f.action(b, 'complete', 'provider', 'capacity-complete-b')).status, 200);
  const stored = f.models.ServiceBookingAgenda.rows[0];
  assert.equal(stored.operations.length, 4000); assert.equal(stored.bookings.length, 3); assert.equal(stored.slots.length, 4);
  assert.deepEqual(stored.bookings.map(row => row.actionOperations.length), [2, 2, 1]);
  const mine = await f.request('/me', { as: 'provider' });
  assert.ok(mine.data.asProvider.every(row => !('actionOperations' in row)), 'internal idempotency receipts stay private');
  assert.equal(f.models.Message.rows.length, 8, 'successful transitions notify once; retries and rejected additions do not add notices');
});

test('a replacement phone cannot reuse the old verification badge, even after the new challenge is exhausted', async t => {
  let sends = 0;
  const f = await fixture(t, { config: { SERVICE_BOOKING_SMS_ENABLED: 'true', SERVICE_BOOKING_SMS_OPT_OUT_CONFIGURED: 'true', TWILIO_MESSAGING_SERVICE_SID: 'MG_fixture' }, sms: async () => { sends++; return { sid: 'SM_fixture' }; } });
  const owner = f.models.User.rows.find(row => row.id === 'provider');
  owner.phoneVerifiedAt = START - 10000; owner.phoneNormalized = '+14155550999';
  owner.phoneVerificationLastSentAt = START; owner.phoneVerificationCodeHash = 'pending-new-phone';
  assert.equal((await f.configure()).status, 403);
  assert.equal((await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } })).status, 403);
  delete owner.phoneVerificationCodeHash;
  assert.equal((await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } })).status, 403, 'clearing a failed challenge does not prove phone ownership');
  owner.phoneVerifiedAt = START + 1;
  assert.equal((await f.configure()).status, 200);
  assert.equal((await f.request('/sms-settings', { as: 'provider', method: 'PATCH', body: { enabled: true } })).status, 200);
  const added = await f.add(); assert.equal((await f.book(added.data.slots[0].id)).data.notifications.sms, 'sent'); assert.equal(sends, 1);
});

test('expiration is checked again after asynchronous authorization before confirming', async t => {
  const f = await fixture(t); await f.configure(); const added = await f.add();
  const booking = (await f.book(added.data.slots[0].id)).data.booking;
  f.setNow(booking.expiresAt - 1);
  const original = f.models.Post.findOne;
  f.models.Post.findOne = (...args) => { f.setNow(booking.expiresAt + 1); return original(...args); };
  assert.equal((await f.action(booking, 'confirm')).status, 409);
  assert.equal((await f.request('/me', { as: 'provider' })).data.asProvider[0].status, 'expired');
});

test('production Mongoose schemas preserve deterministic IDs, revision guards and nested booking receipts without a database', async t => {
  const mongoose = require('mongoose');
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET } });
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const Model = application.models.ServiceBookingAgenda, _id = 'a'.repeat(24);
  const booking = { id: 'test-booking', customerId: 'customer', status: 'pending', updates: [{ id: 'notice', inApp: 'pending', sms: 'disabled' }], actionOperations: [{ id: 'receipt', result: { bookingId: 'test-booking' } }] };
  const doc = new Model({ _id, providerId: 'provider', bookings: [booking] });
  assert.equal(doc.validateSync(), undefined); assert.equal(doc._id.toHexString(), _id); assert.equal(doc.revision, 0);
  assert.equal(doc.bookings[0].actionOperations[0].id, 'receipt');
  const query = Model.findOneAndUpdate({ _id, revision: 7 }, { $set: { bookings: [booking] }, $inc: { revision: 1 } }, { new: true, runValidators: true });
  query.cast(Model);
  assert.equal(query.getFilter()._id.toHexString(), _id); assert.equal(query.getFilter().revision, 7);
  const castUpdate = query._castUpdate(query.getUpdate());
  assert.equal(castUpdate.$inc.revision, 1); assert.equal(castUpdate.$set.bookings[0].actionOperations[0].id, 'receipt');
  const notice = new application.models.Message({ _id, id: 'notice', type: 'text', messageType: 'system', content: 'Booking notice' });
  assert.equal(notice.validateSync(), undefined); assert.equal(mongoose.connection.readyState, 0);
});

test('booking write throttling rejects excess requests without adding agendas', async t => {
  const f = await fixture(t); let last;
  for (let index = 0; index < 41; index++) last = await f.request('/not-a-provider/not-a-booking/actions', { as: 'customer', method: 'POST', body: { action: 'cancel', idempotencyKey: `limited-${index}` } });
  assert.equal(last.status, 429); assert.equal(f.models.ServiceBookingAgenda.rows.length, 0);
});

test('local service aggregation includes pickup rides without including unrelated other-category posts', () => {
  const { publicPostFilters } = require('../lib/postLifecycle');
  for (const category of ['service', '本地服务']) {
    const filter = publicPostFilters({ category, type: 'provider' });
    assert.ok(filter.category.$in.includes('接送')); assert.ok(!filter.category.$in.includes('其他')); assert.equal(filter.type, 'provider');
  }
});
