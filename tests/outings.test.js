const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createMemoryModels } = require('./support/memory-models');
const { createOutingModel, loadOutingCatalog, validateOutingInput } = require('../lib/outings');

const SECRET = 'outing-isolated-test-secret', START = Date.parse('2026-09-30T16:00:00Z');
const catalog = [
  { id: 'weekly', title: '周日公园见面', startDate: '2026-10-01', endDate: '2026-10-30', occurrenceDates: ['2026-10-04', '2026-10-11'], officialUrl: 'https://parks.example.test/weekly' },
  { id: 'continuous', title: '连续展览', startDate: '2026-10-01', endDate: '2026-10-30' },
  { id: 'none-confirmed', title: '场次尚未确认', startDate: '2026-10-01', endDate: '2026-10-30', occurrenceDates: [] },
];
const users = () => ['host', 'alice', 'bob', 'carol', 'dave', 'outsider', 'admin'].map(id => ({ id, nickname: id, email: `${id}@private.test`, password: 'private', role: id === 'admin' ? 'admin' : 'user', accountStatus: 'active', isPhoneVerified: true }));
const input = overrides => ({ title: '周日公园散步', description: '轻松散步并认识邻居', eventId: 'weekly', date: '2026-10-04', startTime: '10:00', endTime: '12:00', city: 'Fremont', venue: 'Central Park 入口', capacity: 3,
  costNote: '各自承担交通和餐饮，免费公共场地', transport: 'own', language: 'any', adultConsent: true, publicPlaceConsent: true, ...overrides });

async function fixture(t, extra = {}) {
  const { createApplication } = require('../server');
  let current = START, serial = 0;
  const models = createMemoryModels({ User: users() });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, outingCatalog: catalog, outingNow: () => current, ...extra });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { as, method = 'GET', body, raw = false } = {}) => {
    const token = as && jwt.sign({ id: as }, SECRET, { expiresIn: '1h' });
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${raw ? path : '/api/outings' + path}`, { method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json(), cache: response.headers.get('cache-control') };
  };
  const key = () => `outing-key-${++serial}`;
  const create = (overrides = {}, as = 'host') => request('', { as, method: 'POST', body: { ...input(overrides), idempotencyKey: key() } });
  const get = (id, as = 'host') => request(`/${id}`, { as });
  const act = async (id, action, as = 'host', fields = {}) => {
    const current = (await get(id, as)).data.outing || models.Outing.rows.find(row => row.id === id);
    return request(`/${id}/actions`, { as, method: 'POST', body: { action, revision: current.revision, idempotencyKey: key(), ...(action === 'request' || action === 'reconfirm' ? { adultConsent: true } : {}), ...fields } });
  };
  const join = async (id, as) => { const result = await act(id, 'request', as, { note: `private-${as}` }); assert.equal(result.status, 200, JSON.stringify(result.data)); return result; };
  const accept = (id, userId) => act(id, 'accept', 'host', { userId });
  const message = async (id, as, value = '你好，周日见！', fields = {}) => request(`/${id}/messages`, { as, method: 'POST', body: { text: value, revision: (await get(id, as)).data.outing.revision, idempotencyKey: key(), ...fields } });
  return { models, request, key, create, get, act, join, accept, message, setNow: value => { current = value; } };
}

test('outing validation enforces exact catalog occurrences, continuous ranges, DST and canonical URLs', () => {
  const rows = loadOutingCatalog(catalog);
  assert.equal(validateOutingInput(input(), rows, START).officialUrl, 'https://parks.example.test/weekly');
  assert.throws(() => validateOutingInput(input({ date: '2026-10-05' }), rows, START), /场次/);
  assert.doesNotThrow(() => validateOutingInput(input({ eventId: 'continuous', date: '2026-10-05' }), rows, START));
  assert.throws(() => validateOutingInput(input({ eventId: 'none-confirmed' }), rows, START), /场次/);
  assert.throws(() => validateOutingInput(input({ eventId: null, date: '2026-11-01', startTime: '01:30' }), rows, START), /夏令时/);
  assert.throws(() => validateOutingInput(input({ eventId: null, endTime: '09:00' }), rows, START), /同一天/);
  assert.throws(() => validateOutingInput(input({ eventId: null, date: '2027-10-01' }), rows, START), /180/);
  assert.equal(loadOutingCatalog([{ ...catalog[0], occurrenceDates: ['2026-10-35'] }]), null);
  assert.equal(loadOutingCatalog([{ ...catalog[0], officialUrl: 'javascript:bad' }]).get('weekly').officialUrl, undefined);
});

test('creation requires authentication, current verification, both explicit declarations and bounded fields', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('', { method: 'POST', body: { ...input(), idempotencyKey: f.key() } })).status, 401);
  assert.equal((await f.create({ adultConsent: false })).status, 400);
  assert.equal((await f.create({ publicPlaceConsent: false })).status, 400);
  assert.equal((await f.create({ capacity: 9 })).status, 400);
  assert.equal((await f.create({ capacity: 1 })).status, 400);
  assert.equal((await f.create({ hostId: 'outsider' })).status, 400);
  const host = f.models.User.rows.find(row => row.id === 'host');
  host.phoneVerificationLastSentAt = START; host.phoneVerifiedAt = START - 1;
  assert.equal((await f.create()).status, 403, 'replacement phone cannot reuse an old badge');
  host.officialVerification = { status: 'approved' };
  assert.equal((await f.create()).status, 200);
  host.officialVerification = { status: 'pending' }; host.isOfficialVerified = true;
  assert.equal((await f.create()).status, 403);
});

test('create is durable and idempotent across concurrent submissions and payload conflicts', async t => {
  const f = await fixture(t), body = { ...input(), idempotencyKey: 'one-creation-key' };
  const results = await Promise.all([1, 2].map(() => f.request('', { as: 'host', method: 'POST', body })));
  assert.deepEqual(results.map(result => result.status), [200, 200]);
  assert.equal(results[0].data.outing.id, results[1].data.outing.id); assert.equal(f.models.Outing.rows.length, 1);
  assert.equal((await f.request('', { as: 'host', method: 'POST', body: { ...body, title: '不同内容' } })).status, 409);
  assert.equal(results[0].data.outing.me.role, 'host'); assert.equal(results[0].data.outing.confirmedCount, 1);
});

test('public cards and detail expose no private members, notes, receipts, emails or phone numbers', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice');
  const publicDetail = await f.request(`/${id}`), list = await f.request('');
  assert.equal(publicDetail.data.outing.me, null); assert.equal(publicDetail.data.outing.members, undefined); assert.equal(publicDetail.data.outing.requestCount, undefined);
  assert.equal(list.data.outings[0].members, undefined); assert.match(publicDetail.cache, /no-store/);
  assert.equal((await f.request('', { as: 'host' })).data.outings[0].members, undefined, 'even a host public card has no private member list');
  assert.doesNotMatch(JSON.stringify(publicDetail.data), /private-alice|receipts|consentVersion|@private|isPhoneVerified/);
  const host = (await f.get(id)).data.outing; assert.equal(host.requestCount, 1); assert.equal(host.members.find(row => row.userId === 'alice').note, 'private-alice');
  assert.equal((await f.get(id, 'alice')).data.outing.members, undefined);
});

test('requests and confirmed membership are separate; requesters cannot read or write discussion', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const joined = await f.join(id, 'alice'); assert.equal(joined.data.outing.me.status, 'requested'); assert.equal(joined.data.outing.confirmedCount, 1);
  assert.equal((await f.request(`/${id}/messages`, { as: 'alice' })).status, 403);
  assert.equal((await f.message(id, 'alice')).status, 403);
  assert.equal((await f.act(id, 'accept', 'alice', { userId: 'alice' })).status, 403);
  const accepted = await f.accept(id, 'alice'); assert.equal(accepted.status, 200); assert.equal(accepted.data.outing.confirmedCount, 2);
  await f.join(id, 'bob');
  const alice = (await f.get(id, 'alice')).data.outing;
  assert.deepEqual(alice.members.map(row => row.userId), ['host', 'alice']); assert.equal(alice.members.some(row => 'note' in row), false);
  assert.equal((await f.message(id, 'alice')).status, 200);
});

test('two simultaneous approvals cannot allocate the same last seat and stale versions cannot overwrite', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.join(id, 'bob');
  const revision = (await f.get(id)).data.outing.revision;
  const results = await Promise.all(['alice', 'bob'].map(userId => f.request(`/${id}/actions`, { as: 'host', method: 'POST', body: { action: 'accept', userId, revision, idempotencyKey: f.key() } })));
  assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
  const saved = (await f.get(id)).data.outing; assert.equal(saved.confirmedCount, 2); assert.equal(saved.members.filter(row => row.status === 'confirmed').length, 2);
  const pending = saved.members.find(row => row.status === 'requested').userId;
  assert.equal((await f.accept(id, pending)).status, 409);
});

test('request retries do not create duplicate membership or notifications, and changed payload conflicts', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const body = { action: 'request', revision: 1, idempotencyKey: 'same-request-key', adultConsent: true, note: 'private note' };
  const first = await f.request(`/${id}/actions`, { as: 'alice', method: 'POST', body });
  const retry = await f.request(`/${id}/actions`, { as: 'alice', method: 'POST', body });
  assert.equal(first.status, 200); assert.equal(retry.status, 200);
  assert.equal(f.models.Outing.rows[0].members.length, 2); assert.equal(f.models.Message.rows.length, 1);
  assert.equal((await f.request(`/${id}/actions`, { as: 'alice', method: 'POST', body: { ...body, note: 'changed' } })).status, 409);
  assert.equal(f.models.Message.rows[0].messageType, 'system'); assert.match(f.models.Message.rows[0].id, /^outing_/);
});

test('critical edits require reconfirmation; previous requests retain their original consent version', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice'); await f.join(id, 'bob');
  const before = (await f.get(id)).data.outing;
  const edited = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { date: '2026-10-11', revision: before.revision, idempotencyKey: f.key() } });
  assert.equal(edited.status, 200); assert.equal(edited.data.outing.planVersion, 2); assert.equal(edited.data.outing.confirmedCount, 2);
  assert.equal((await f.message(id, 'alice')).status, 409);
  assert.equal((await f.request(`/${id}/messages`, { as: 'alice' })).status, 200, 'existing members can read the changed arrangements');
  await f.accept(id, 'bob');
  assert.equal((await f.get(id, 'bob')).data.outing.me.confirmedVersion, 1, 'approval cannot invent acceptance of changed terms');
  assert.equal((await f.act(id, 'reconfirm', 'alice')).status, 200);
  assert.equal((await f.message(id, 'alice')).status, 200);
  const current = (await f.get(id)).data.outing;
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { venue: '新的公共入口', revision: current.revision, idempotencyKey: f.key() } })).status, 400);
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { capacity: 2, revision: current.revision, idempotencyKey: f.key() } })).status, 409);
});

test('noncritical descriptions do not revoke confirmations and stale edits fail', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const edit = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { description: '带水即可', revision: 1, idempotencyKey: f.key() } });
  assert.equal(edit.status, 200); assert.equal(edit.data.outing.planVersion, 1);
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { title: '旧修改', revision: 1, idempotencyKey: f.key() } })).status, 409);
  assert.equal((await f.request(`/${id}`, { as: 'alice', method: 'PATCH', body: { title: '越权修改', revision: 2, idempotencyKey: f.key() } })).status, 403);
});

test('withdrawal and removal atomically revoke private discussion and release seats', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const sent = await f.message(id, 'alice', '旧消息', { idempotencyKey: 'one-message-key' }); assert.equal(sent.status, 200);
  assert.equal((await f.act(id, 'withdraw', 'alice')).status, 200);
  assert.equal((await f.request(`/${id}/messages`, { as: 'alice' })).status, 403);
  assert.equal((await f.message(id, 'alice', '旧消息', { idempotencyKey: 'one-message-key' })).status, 403);
  await f.join(id, 'bob'); await f.accept(id, 'bob'); assert.equal((await f.act(id, 'remove', 'host', { userId: 'bob' })).status, 200);
  assert.equal((await f.request(`/${id}/messages`, { as: 'bob' })).status, 403); assert.equal((await f.get(id)).data.outing.confirmedCount, 1);
  assert.equal((await f.join(id, 'carol')).status, 200);
});

test('blocks in either direction and restricted accounts prevent participation without trapping exits', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  f.models.UserBlock.rows.push({ blockerId: 'host', blockedUserId: 'alice' });
  assert.equal((await f.request(`/${id}/messages`, { as: 'alice' })).status, 403);
  assert.equal((await f.message(id, 'alice')).status, 403);
  assert.equal((await f.act(id, 'withdraw', 'alice')).status, 200);
  assert.equal((await f.act(id, 'request', 'alice')).status, 403);
  f.models.UserBlock.rows.push({ blockerId: 'bob', blockedUserId: 'host' });
  assert.equal((await f.act(id, 'request', 'bob')).status, 403);
  f.models.User.rows.find(row => row.id === 'carol').accountStatus = 'limited';
  assert.equal((await f.act(id, 'request', 'carol')).status, 403);
  assert.equal((await f.act(id, 'cancel')).status, 200);
});

test('cancellation and the real clock prevent new attendance and discussion writes', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  f.setNow(Date.parse('2026-10-04T19:01:00Z'));
  assert.equal((await f.get(id)).data.outing.status, 'completed');
  assert.equal((await f.message(id, 'alice')).status, 409);
  assert.equal((await f.request(`/${id}/messages`, { as: 'alice' })).status, 200);
  assert.equal((await f.act(id, 'request', 'bob')).status, 409);
  assert.equal((await f.act(id, 'withdraw', 'alice')).status, 200);
});

test('message bodies are bounded, idempotent, member only and latest history is capped at 100', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const first = await f.message(id, 'host', '你好', { idempotencyKey: 'message-retry-key' });
  assert.equal(first.status, 200);
  assert.equal((await f.message(id, 'host', '你好', { idempotencyKey: 'message-retry-key' })).data.message.id, first.data.message.id);
  assert.equal((await f.message(id, 'host', '不同内容', { idempotencyKey: 'message-retry-key' })).status, 409);
  assert.equal((await f.message(id, 'host', 'a'.repeat(2001))).status, 400);
  const row = f.models.Outing.rows[0]; row.messages = Array.from({ length: 500 }, (_, i) => ({ id: `m${i}`, outingId: id, senderId: 'host', senderName: 'host', text: `消息${i}`, createdAt: START + i }));
  const history = await f.request(`/${id}/messages`, { as: 'host' }); assert.equal(history.data.messages.length, 100); assert.equal(history.data.messages[0].id, 'm400');
  assert.equal((await f.message(id, 'host')).status, 409); assert.equal((await f.act(id, 'cancel')).status, 200);
});

test('failed notice persistence does not roll back membership; me repairs exactly one message', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const write = f.models.Message.findOneAndUpdate;
  f.models.Message.findOneAndUpdate = async () => { throw new Error('isolated storage failure'); };
  const joined = await f.join(id, 'alice'); assert.ok(joined.data.notificationWarning); assert.equal(joined.data.outing.me.status, 'requested');
  const revision = joined.data.outing.revision;
  f.models.Conversation.rows[0].updatedAt = 1;
  f.models.Message.findOneAndUpdate = write;
  assert.equal((await f.request('/me', { as: 'host' })).status, 200);
  assert.equal(f.models.Message.rows.length, 1); assert.equal((await f.get(id)).data.outing.revision, revision, 'delivery does not invalidate form revisions');
  await f.request('/me', { as: 'host' }); assert.equal(f.models.Message.rows.length, 1);
  assert.equal(f.models.Conversation.rows[0].updatedAt, START);
});

test('reporting captures server evidence, hides private messages from outsiders and supports admin cancellation', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const message = (await f.message(id, 'host', '需要举报的原文')).data.message;
  const report = await f.request(`/${id}/reports`, { as: 'alice', method: 'POST', body: { reason: 'harassment', details: '原因', messageId: message.id } });
  assert.equal(report.status, 200); assert.equal(f.models.Report.rows[0].evidence.message.text, '需要举报的原文');
  assert.equal((await f.request(`/${id}/reports`, { as: 'outsider', method: 'POST', body: { reason: 'other', messageId: message.id } })).status, 403);
  assert.equal((await f.request(`/${id}/reports`, { as: 'alice', method: 'POST', body: { reason: 'other', evidence: 'forged' } })).status, 400);
  const listing = await f.request('/api/admin/reports?type=outing_message', { as: 'admin', raw: true });
  assert.equal(listing.status, 200); assert.equal(listing.data.reports[0].outingId, id); assert.equal(listing.data.reports[0].evidence.message.text, message.text);
  const revision = (await f.get(id)).data.outing.revision;
  const body = { reason: '管理员处理举报', revision, idempotencyKey: 'admin-cancel-key' };
  f.models.User.rows.find(row => row.id === 'host').accountStatus = 'limited';
  const adminView = await f.request(`/api/admin/outings/${id}`, { as: 'admin', raw: true });
  assert.equal(adminView.status, 200); assert.equal(adminView.data.outing.revision, revision); assert.equal(adminView.data.outing.members, undefined);
  assert.equal((await f.request(`/api/admin/outings/${id}`, { as: 'outsider', raw: true })).status, 403);
  assert.equal((await f.request(`/api/admin/outings/${id}/cancel`, { as: 'outsider', raw: true, method: 'POST', body })).status, 403);
  const cancelled = await f.request(`/api/admin/outings/${id}/cancel`, { as: 'admin', raw: true, method: 'POST', body });
  assert.equal(cancelled.status, 200); assert.equal(cancelled.data.outing.status, 'cancelled'); assert.ok(f.models.ModerationLog.rows.some(row => row.action === 'outing_cancelled'));
  assert.equal((await f.request(`/api/admin/outings/${id}/cancel`, { as: 'admin', raw: true, method: 'POST', body })).status, 200);
  assert.equal(f.models.ModerationLog.rows.filter(row => row.action === 'outing_cancelled').length, 1);
});

test('former members can report only previously visible messages; a withdrawn applicant never gains access', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const old = (await f.message(id, 'host', '退出前')).data.message;
  await f.act(id, 'withdraw', 'alice');
  const later = (await f.message(id, 'host', '退出后')).data.message;
  const report = messageId => f.request(`/${id}/reports`, { as: 'alice', method: 'POST', body: { reason: 'other', messageId } });
  assert.equal((await report(old.id)).status, 200); assert.equal((await report(later.id)).status, 403);
  await f.join(id, 'bob'); await f.act(id, 'withdraw', 'bob');
  assert.equal((await f.request(`/${id}/reports`, { as: 'bob', method: 'POST', body: { reason: 'other', messageId: old.id } })).status, 403);
});

test('catalog filters and pagination are bounded, invalid cursors cannot broaden queries', async t => {
  const f = await fixture(t);
  await f.create(); await f.create({ eventId: null, city: 'Oakland' });
  const filtered = await f.request('?eventId=weekly&city=Fremont&date=2026-10-04'); assert.equal(filtered.data.outings.length, 1); assert.equal(filtered.data.nextCursor, null);
  assert.equal((await f.request('?cursor[$gt]=x')).status, 400);
  assert.equal((await f.request('?date=2026-02-30')).status, 400);
  assert.equal((await f.request('?city[$ne]=x')).status, 400);
  f.models.UserBlock.rows.push({ blockerId: 'alice', blockedUserId: 'host' });
  assert.equal((await f.request('', { as: 'alice' })).data.outings.length, 0);
});

test('bounded receipt history does not stop legitimate withdrawal or cancellation', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  f.models.Outing.rows[0].receipts = Array.from({ length: 1000 }, (_, i) => ({ key: `old-${i}`, fingerprint: 'old', result: null }));
  assert.equal((await f.act(id, 'withdraw', 'alice')).status, 200);
  assert.equal(f.models.Outing.rows[0].receipts.length, 1000);
  assert.equal((await f.act(id, 'cancel')).status, 200);
});

test('model casts production revision and member/message fields without connecting MongoDB', () => {
  const mongoose = require('mongoose'), Outing = createOutingModel(mongoose);
  const document = new Outing({ _id: 'a'.repeat(24), id: 'outing-model', hostId: 'host', revision: 4, notificationRevision: 2, planVersion: 2,
    members: [{ userId: 'host', role: 'host', status: 'confirmed', confirmedVersion: 2 }], messages: [{ id: 'msg', text: 'hello' }], notices: [{ id: 'notice', state: 'pending' }] });
  assert.equal(document.validateSync(), undefined);
  assert.equal(document.toObject().members[0].confirmedVersion, 2);
  const query = Outing.findOneAndUpdate({ id: 'outing-model', revision: 4, notificationRevision: 2 }, { $set: { messages: [] }, $inc: { revision: 1 } });
  assert.deepEqual(query.cast(Outing), { id: 'outing-model', revision: 4, notificationRevision: 2 });
});

test('mutation rate limiting is enforced before malformed requests can allocate documents', async t => {
  const f = await fixture(t);
  let last;
  for (let i = 0; i < 41; i++) last = await f.request('', { as: 'alice', method: 'POST', body: {} });
  assert.equal(last.status, 429); assert.equal(f.models.Outing.rows.length, 0);
});

test('async authorization cannot confirm attendance after the outing start deadline', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice');
  const original = f.models.User.findOne;
  let reads = 0;
  f.models.User.findOne = query => {
    if (query.id === 'alice' && ++reads === 2) f.setNow(Date.parse('2026-10-04T17:01:00Z'));
    return original(query);
  };
  const accepted = await f.accept(id, 'alice');
  assert.equal(accepted.status, 409); assert.equal(f.models.Outing.rows[0].members.find(row => row.userId === 'alice').status, 'requested');
});
