const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createMemoryModels } = require('./support/memory-models');
const { createOutingModel, loadOutingCatalog, validateOutingInput, validateOutingCover } = require('../lib/outings');
const { outingSearch, cityRegex } = require('../lib/outingSearch');

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

const pollOptions = () => [{ date: '2026-10-04', startTime: '10:00', endTime: '12:00' }, { date: '2026-10-11', startTime: '14:00', endTime: '16:00' }];
async function pollAction(f, id, action, fields = {}, as = 'host') {
  const current = f.models.Outing.rows.find(row => row.id === id);
  return f.request(`/${id}/time-poll`, { as, method: 'POST', body: { action, revision: current.revision, idempotencyKey: f.key(), ...fields } });
}

test('time poll keeps existing arrangement, exposes only private aggregate availability and explicitly adopts with reconfirmation', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice'); await f.join(id, 'bob');
  const original = (await f.get(id)).data.outing;
  const opened = await pollAction(f, id, 'create', { options: pollOptions() });
  assert.equal(opened.status, 200, JSON.stringify(opened.data));
  const pollId = opened.data.outing.timePoll.id;
  assert.equal(opened.data.outing.planVersion, original.planVersion); assert.equal(opened.data.outing.date, original.date);
  assert.equal(opened.data.outing.timePoll.eligibleCount, 2); assert.equal(opened.data.outing.timePoll.repliedCount, 0);
  for (const who of [undefined, 'outsider', 'bob']) assert.equal((await f.request(`/${id}`, { as: who })).data.outing.timePoll, undefined);
  assert.equal((await f.request('', { as: 'host' })).data.outings[0].timePoll, undefined);
  const vote = await pollAction(f, id, 'vote', { pollId, answers: { 'option-1': 'maybe', 'option-2': 'yes' } }, 'alice');
  assert.equal(vote.status, 200); assert.equal(vote.data.outing.timePoll.repliedCount, 1);
  assert.deepEqual(vote.data.outing.timePoll.myAnswers, { 'option-1': 'maybe', 'option-2': 'yes' });
  const hostPoll = (await f.get(id)).data.outing.timePoll;
  assert.equal(hostPoll.myAnswers, null); assert.deepEqual(hostPoll.options[1].counts, { yes: 1, maybe: 0, no: 0 });
  assert.doesNotMatch(JSON.stringify(hostPoll), /alice|votes|userId/);
  const adopted = await pollAction(f, id, 'adopt', { pollId, optionId: 'option-2' });
  assert.equal(adopted.status, 200); assert.equal(adopted.data.outing.date, '2026-10-11'); assert.equal(adopted.data.outing.startTime, '14:00');
  assert.equal(adopted.data.outing.planVersion, original.planVersion + 1); assert.equal(adopted.data.outing.timePoll.status, 'adopted');
  assert.equal(adopted.data.outing.members.find(row => row.userId === 'alice').confirmedVersion, original.planVersion, 'yes vote never becomes consent to the new arrangement');
  assert.equal((await f.message(id, 'alice')).status, 409);
  assert.equal((await f.act(id, 'reconfirm', 'alice')).status, 200);
  assert.equal((await pollAction(f, id, 'vote', { pollId, answers: { 'option-1': 'no', 'option-2': 'yes' } }, 'alice')).status, 409);
});

test('time poll checks every candidate against actual event dates and rejects injected or incomplete input', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const invalid = [[], [pollOptions()[0]], [...pollOptions(), ...pollOptions()], [pollOptions()[0], pollOptions()[0]],
    [pollOptions()[0], { ...pollOptions()[1], date: '2026-10-05' }], [pollOptions()[0], { ...pollOptions()[1], endTime: '13:00' }],
    [pollOptions()[0], { ...pollOptions()[1], hostId: 'outsider' }], [pollOptions()[0], { date: '2026-10-11' }]];
  for (const options of invalid) assert.equal((await pollAction(f, id, 'create', { options })).status, 400, JSON.stringify(options));
  assert.equal(f.models.Outing.rows[0].timePoll, undefined);
  const created = await pollAction(f, id, 'create', { options: pollOptions() }), pollId = created.data.outing.timePoll.id;
  for (const answers of [{}, { 'option-1': 'yes' }, { 'option-1': 'yes', 'option-2': 'unknown' }, { 'option-1': 'yes', 'option-2': 'no', other: 'yes' }]) {
    assert.equal((await pollAction(f, id, 'vote', { pollId, answers })).status, 400);
  }
  assert.equal((await pollAction(f, id, 'create', { options: pollOptions() })).status, 409);
});

test('time poll denies applicants, non-host adoption, blocked accounts and retries after membership removal', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice'); await f.join(id, 'bob');
  const opened = await pollAction(f, id, 'create', { options: pollOptions() }), pollId = opened.data.outing.timePoll.id;
  for (const who of ['bob', 'outsider']) assert.equal((await pollAction(f, id, 'vote', { pollId, answers: { 'option-1': 'yes', 'option-2': 'yes' } }, who)).status, 403);
  assert.equal((await pollAction(f, id, 'adopt', { pollId, optionId: 'option-2' }, 'alice')).status, 403);
  const body = { action: 'vote', pollId, answers: { 'option-1': 'no', 'option-2': 'yes' }, revision: f.models.Outing.rows[0].revision, idempotencyKey: f.key() };
  assert.equal((await f.request(`/${id}/time-poll`, { as: 'alice', method: 'POST', body })).status, 200);
  f.models.UserBlock.rows.push({ blockerId: 'alice', blockedUserId: 'host' });
  assert.equal((await f.get(id, 'alice')).data.outing.timePoll, undefined);
  assert.equal((await f.request(`/${id}/time-poll`, { as: 'alice', method: 'POST', body })).status, 403, 'replay still checks blocking');
  f.models.UserBlock.rows.length = 0;
  assert.equal((await f.act(id, 'remove', 'host', { userId: 'alice' })).status, 200);
  assert.equal((await f.request(`/${id}/time-poll`, { as: 'alice', method: 'POST', body })).status, 403);
  assert.equal((await f.get(id)).data.outing.timePoll.repliedCount, 0, 'removed availability does not remain in totals');
});

test('time poll votes are idempotent and concurrent operations never silently overwrite a response', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const opened = await pollAction(f, id, 'create', { options: pollOptions() }), pollId = opened.data.outing.timePoll.id, revision = opened.data.outing.revision;
  const bodies = ['host', 'alice'].map(() => ({ action: 'vote', pollId, revision, idempotencyKey: f.key(), answers: { 'option-1': 'yes', 'option-2': 'maybe' } }));
  const votes = await Promise.all(['host', 'alice'].map((as, index) => f.request(`/${id}/time-poll`, { as, method: 'POST', body: bodies[index] })));
  assert.deepEqual(votes.map(result => result.status).sort(), [200, 409]);
  const winner = votes.findIndex(result => result.status === 200), as = ['host', 'alice'][winner], body = bodies[winner];
  assert.equal((await f.request(`/${id}/time-poll`, { as, method: 'POST', body })).status, 200);
  assert.equal((await f.get(id)).data.outing.timePoll.repliedCount, 1);
  assert.equal((await f.request(`/${id}/time-poll`, { as, method: 'POST', body: { ...body, answers: { 'option-1': 'no', 'option-2': 'no' } } })).status, 409);
  const current = f.models.Outing.rows[0].revision;
  const closeOrAdopt = await Promise.all([{ action: 'close' }, { action: 'adopt', optionId: 'option-2' }].map(action => f.request(`/${id}/time-poll`, { as: 'host', method: 'POST', body: { ...action, pollId, revision: current, idempotencyKey: f.key() } })));
  assert.deepEqual(closeOrAdopt.map(result => result.status).sort(), [200, 409]);
});

test('ending polls preserves times; editing arrangements invalidates old polls; cancelled and past outings cannot coordinate', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  const opened = await pollAction(f, id, 'create', { options: pollOptions() }), pollId = opened.data.outing.timePoll.id;
  const closed = await pollAction(f, id, 'close', { pollId });
  assert.equal(closed.data.outing.timePoll.status, 'closed'); assert.equal(closed.data.outing.planVersion, 1); assert.equal(closed.data.outing.date, '2026-10-04');
  await pollAction(f, id, 'create', { options: pollOptions() });
  const revision = f.models.Outing.rows[0].revision;
  const edited = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { city: 'Oakland', revision, idempotencyKey: f.key() } });
  assert.equal(edited.data.outing.timePoll.closeReason, 'arrangement-changed');
  const next = await pollAction(f, id, 'create', { options: pollOptions() });
  await f.act(id, 'cancel');
  assert.equal((await pollAction(f, id, 'adopt', { pollId: next.data.outing.timePoll.id, optionId: 'option-2' })).status, 409);
  const secondId = (await f.create({ eventId: null, date: '2026-10-17' })).data.outing.id;
  const second = await pollAction(f, secondId, 'create', { options: [{ date: '2026-10-16', startTime: '10:00', endTime: '12:00' }, { date: '2026-10-18', startTime: '10:00', endTime: '12:00' }] });
  f.setNow(Date.parse('2026-10-16T18:00:00Z'));
  assert.equal((await pollAction(f, secondId, 'adopt', { pollId: second.data.outing.timePoll.id, optionId: 'option-1' })).status, 409);
  f.setNow(Date.parse('2026-10-17T18:00:00Z'));
  assert.equal((await pollAction(f, secondId, 'adopt', { pollId: second.data.outing.timePoll.id, optionId: 'option-2' })).status, 409, 'cannot revive an already started outing');
});

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

test('outing covers accept bounded editorial references and reject URL or metadata injection', () => {
  assert.equal(validateOutingCover(undefined), undefined);
  for (const cover of [{ kind: 'auto' }, { kind: 'card' }, ...['guide', 'event', 'offer', 'opening'].map(kind => ({ kind, id: 'Bay-area_2026' }))]) {
    assert.deepEqual(validateOutingCover(cover), cover);
    assert.notEqual(validateOutingCover(cover), cover, 'validated references are copied');
  }
  assert.doesNotThrow(() => validateOutingCover({ kind: 'guide', id: 'a'.repeat(140) }));
  for (const cover of [null, [], 'auto', {}, { kind: 'photo', id: 'image' }, { kind: 'card', id: 'image' }, { kind: 'auto', url: 'https://example.test/image' },
    { kind: 'guide' }, { kind: 'guide', id: '' }, { kind: 'guide', id: '_guide' }, { kind: 'event', id: 1 }, { kind: 'event', id: '../other' },
    { kind: 'offer', id: 'https://example.test/image' }, { kind: 'opening', id: 'javascript:alert(1)' }, { kind: 'guide', id: 'a'.repeat(141) },
    { kind: 'guide', id: 'a', credit: 'fake credit' }, { kind: 'guide', id: 'a\n' }, JSON.parse('{"kind":"guide","id":"a","__proto__":{}}')]) {
    assert.throws(() => validateOutingCover(cover), undefined, JSON.stringify(cover));
  }
});

test('cover choices persist across public lists and details without changing event linkage or legacy rows', async t => {
  const f = await fixture(t);
  const legacy = await f.create();
  assert.equal(Object.hasOwn(legacy.data.outing, 'cover'), false);
  for (const cover of [{ kind: 'auto' }, { kind: 'card' }, ...['guide', 'event', 'offer', 'opening'].map(kind => ({ kind, id: `${kind}-reference` }))]) {
    const created = await f.create({ cover });
    assert.equal(created.status, 200, JSON.stringify(created.data));
    assert.deepEqual(f.models.Outing.rows.find(row => row.id === created.data.outing.id).cover, cover);
    const detail = (await f.request(`/${created.data.outing.id}`)).data.outing;
    assert.deepEqual(detail.cover, cover); assert.equal(detail.eventId, 'weekly');
    assert.equal(detail.date, '2026-10-04'); assert.equal(detail.venue, 'Central Park 入口');
    assert.deepEqual((await f.request('')).data.outings.find(row => row.id === detail.id).cover, cover);
  }
  for (const cover of [null, { kind: 'image', id: 'a' }, { kind: 'card', id: 'a' }, { kind: 'guide', id: 'a', src: '/guides/photo.webp' }]) {
    assert.equal((await f.create({ cover })).status, 400);
  }
  assert.equal(f.models.Outing.rows.length, 7, 'invalid cover requests do not allocate outings');
});

test('cover edits keep confirmations and notices unchanged while enforcing revisions, ownership and retries', async t => {
  const f = await fixture(t), id = (await f.create()).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const before = (await f.get(id)).data.outing, messageCount = f.models.Message.rows.length;
  const body = { cover: { kind: 'guide', id: 'coastal-day-guide' }, revision: before.revision, idempotencyKey: f.key() };
  const edited = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body });
  assert.equal(edited.status, 200, JSON.stringify(edited.data));
  assert.deepEqual(edited.data.outing.cover, body.cover);
  assert.equal(edited.data.outing.revision, before.revision + 1);
  assert.equal(edited.data.outing.planVersion, before.planVersion);
  assert.deepEqual(edited.data.outing.members, before.members);
  assert.equal(f.models.Message.rows.length, messageCount);
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body })).status, 200, 'identical retry is idempotent');
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { ...body, cover: { kind: 'card' } } })).status, 409);
  assert.equal((await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { ...body, idempotencyKey: f.key() } })).status, 409, 'stale edits fail');
  assert.equal((await f.request(`/${id}`, { as: 'alice', method: 'PATCH', body: { ...body, revision: edited.data.outing.revision, idempotencyKey: f.key() } })).status, 403);
  const reset = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { cover: { kind: 'auto' }, revision: edited.data.outing.revision, idempotencyKey: f.key() } });
  assert.equal(reset.status, 200); assert.deepEqual(reset.data.outing.cover, { kind: 'auto' });
  assert.equal(reset.data.outing.planVersion, before.planVersion);
  assert.equal((await f.message(id, 'alice')).status, 200, 'members can still discuss without reconfirming');
});

test('production outing schema preserves covers, accepts legacy records and rejects malformed persisted values', () => {
  const Outing = createOutingModel(require('mongoose'));
  const base = { id: 'cover-model', hostId: 'host' };
  for (const cover of [undefined, { kind: 'card' }, { kind: 'guide', id: 'guide-reference' }]) {
    const document = new Outing({ ...base, ...(cover ? { cover } : {}) });
    assert.equal(document.validateSync(), undefined);
    assert.deepEqual(document.toObject().cover, cover);
  }
  for (const cover of [null, { kind: 'photo', id: 'a' }, { kind: 'auto', id: 'a' }, { kind: 'guide', id: 'https://example.test/image' }]) {
    assert.ok(new Outing({ ...base, cover }).validateSync()?.errors.cover, JSON.stringify(cover));
  }
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

test('full teams accept only explicit waitlist consent without seats or discussion access', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  assert.equal((await f.act(id, 'request', 'bob')).status, 409, 'legacy full requests are unchanged');
  assert.equal((await f.act(id, 'request', 'bob', { waitlist: false })).status, 409);
  assert.equal((await f.act(id, 'request', 'bob', { waitlist: 'true' })).status, 400);
  const queued = await f.act(id, 'request', 'bob', { waitlist: true, note: '候补备注' });
  assert.equal(queued.status, 200); assert.equal(queued.data.outing.me.status, 'requested'); assert.equal(queued.data.outing.me.waitlisted, true);
  assert.equal(queued.data.outing.confirmedCount, 2); assert.equal(queued.data.outing.members, undefined); assert.equal(queued.data.outing.waitlistCount, undefined);
  assert.equal((await f.request(`/${id}/messages`, { as: 'bob' })).status, 403);
  assert.equal((await f.message(id, 'bob')).status, 403);
  const host = (await f.get(id)).data.outing;
  assert.equal(host.requestCount, 1); assert.equal(host.waitlistCount, 1); assert.equal(host.waitlistReviewNeeded, false);
  assert.equal(host.members.find(row => row.userId === 'bob').requestedAt, START);
  assert.equal((await f.get(id, 'alice')).data.outing.members.some(row => row.userId === 'bob'), false);
  const publicView = (await f.request(`/${id}`)).data.outing;
  assert.equal(publicView.waitlistCount, undefined); assert.equal(publicView.waitlistReviewNeeded, undefined);
  assert.doesNotMatch(JSON.stringify(publicView), /候补备注/);
  assert.equal((await f.accept(id, 'bob')).status, 409);
});

test('vacancies notify the host but never auto-confirm waitlisted users, including after notice retry', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  const body = { action: 'request', revision: (await f.get(id)).data.outing.revision, idempotencyKey: 'waitlist-retry-key', waitlist: true, adultConsent: true };
  await f.request(`/${id}/actions`, { as: 'bob', method: 'POST', body });
  assert.equal((await f.request(`/${id}/actions`, { as: 'bob', method: 'POST', body })).status, 200);
  const notices = f.models.Message.rows.length;
  await f.request(`/${id}/actions`, { as: 'bob', method: 'POST', body }); assert.equal(f.models.Message.rows.length, notices);
  assert.equal((await f.request(`/${id}/actions`, { as: 'bob', method: 'POST', body: { ...body, waitlist: false } })).status, 409);
  const withdraw = { action: 'withdraw', revision: (await f.get(id)).data.outing.revision, idempotencyKey: 'leave-once-key' };
  await f.request(`/${id}/actions`, { as: 'alice', method: 'POST', body: withdraw });
  assert.ok(f.models.Message.rows.some(message => /有空位请审核候补/.test(message.content)));
  assert.equal((await f.get(id)).data.outing.waitlistReviewNeeded, true);
  assert.equal((await f.get(id, 'bob')).data.outing.me.status, 'requested');
  const count = f.models.Message.rows.length;
  await f.request(`/${id}/actions`, { as: 'alice', method: 'POST', body: withdraw }); assert.equal(f.models.Message.rows.length, count);
  assert.equal((await f.accept(id, 'bob')).status, 200);
  const accepted = (await f.get(id, 'bob')).data.outing;
  assert.equal(accepted.me.status, 'confirmed'); assert.equal(accepted.me.waitlisted, false); assert.equal(accepted.confirmedCount, 2);
  assert.equal((await f.get(id)).data.outing.waitlistReviewNeeded, false);
});

test('waitlist permission, changed plan consent and concurrent last-seat approvals retain existing safeguards', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice');
  assert.equal((await f.act(id, 'request', 'bob', { waitlist: true, adultConsent: false })).status, 400);
  await f.act(id, 'request', 'bob', { waitlist: true }); await f.act(id, 'request', 'carol', { waitlist: true });
  const changed = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { date: '2026-10-11', revision: (await f.get(id)).data.outing.revision, idempotencyKey: f.key() } });
  assert.equal(changed.status, 200);
  await f.act(id, 'withdraw', 'alice');
  f.models.UserBlock.rows.push({ blockerId: 'bob', blockedUserId: 'host' });
  assert.equal((await f.accept(id, 'bob')).status, 403); f.models.UserBlock.rows.length = 0;
  const revision = (await f.get(id)).data.outing.revision;
  const results = await Promise.all(['bob', 'carol'].map(userId => f.request(`/${id}/actions`, { as: 'host', method: 'POST', body: { action: 'accept', userId, revision, idempotencyKey: f.key() } })));
  assert.deepEqual(results.map(row => row.status).sort(), [200, 409]);
  const host = (await f.get(id)).data.outing, accepted = host.members.find(row => row.role !== 'host' && row.status === 'confirmed');
  assert.equal(accepted.confirmedVersion, 1); assert.equal(host.planVersion, 2);
  assert.equal((await f.message(id, accepted.userId)).status, 409);
});

test('host removal or expansion uses review hints without self-DMs, while queued withdrawal stays available', async t => {
  const f = await fixture(t), id = (await f.create({ capacity: 2 })).data.outing.id;
  await f.join(id, 'alice'); await f.accept(id, 'alice'); await f.act(id, 'request', 'bob', { waitlist: true });
  const previousNotices = f.models.Message.rows.length;
  const expanded = await f.request(`/${id}`, { as: 'host', method: 'PATCH', body: { capacity: 3, revision: (await f.get(id)).data.outing.revision, idempotencyKey: f.key() } });
  assert.equal(expanded.status, 200); assert.equal(expanded.data.outing.waitlistReviewNeeded, true);
  assert.equal(f.models.Message.rows.length, previousNotices, 'host expansion does not fabricate a self conversation');
  assert.equal((await f.get(id, 'bob')).data.outing.me.status, 'requested');
  const removed = await f.act(id, 'remove', 'host', { userId: 'alice' }); assert.equal(removed.data.outing.waitlistReviewNeeded, true);
  assert.equal(f.models.Conversation.rows.some(row => new Set(row.userIds).size !== 2), false);
  assert.equal(f.models.Outing.rows[0].notices.some(row => row.actorId === row.targetId), false);
  f.models.User.rows.find(row => row.id === 'bob').accountStatus = 'limited';
  const left = await f.act(id, 'withdraw', 'bob'); assert.equal(left.status, 200); assert.equal(left.data.outing.me.waitlisted, false);
  assert.equal((await f.get(id)).data.outing.waitlistCount, 0);
  const ordinary = await f.act(id, 'request', 'carol', { waitlist: true });
  assert.equal(ordinary.data.outing.me.waitlisted, false, 'explicit fallback is ordinary pending when there is room');
  assert.equal((await f.act(id, 'withdraw', 'carol', { waitlist: false })).status, 400, 'flag is request-only');
});

async function discoverySeed(f, values) {
  const created = await f.create({ eventId: null }); assert.equal(created.status, 200);
  const template = JSON.parse(JSON.stringify(f.models.Outing.rows[0]));
  f.models.Outing.rows.length = 0;
  const rows = values.map((value, i) => {
    const row = { ...JSON.parse(JSON.stringify(template)), _id: (10000 + i).toString(16).padStart(24, '0'), id: `outing_seed_${String(i).padStart(4, '0')}`, ...value };
    if (value.date) { row.startAt = Date.parse(`${value.date}T17:00:00Z`); row.endAt = Date.parse(`${value.date}T19:00:00Z`); }
    return row;
  });
  f.models.Outing.rows.push(...rows); return rows;
}

test('city aliases support English, simplified/traditional Chinese, case and accents without broad matching', async t => {
  const f = await fixture(t);
  await discoverySeed(f, ['San Francisco', 'South San Francisco', 'S.F.', '舊金山', 'San José', 'San Jose', '聖荷西', 'South San Jose'].map(city => ({ city })));
  for (const city of ['SF', '旧金山', '舊金山', 'sAn fRaNcIsCo']) {
    const result = await f.request(`?city=${encodeURIComponent(city)}`);
    assert.equal(result.status, 200); assert.equal(result.data.outings.length, 3);
    assert.equal(result.data.outings.some(row => row.city.includes('South')), false);
  }
  for (const city of ['SAN JOSÉ', 'san jose', '圣荷西', '聖何塞']) assert.equal((await f.request(`?city=${encodeURIComponent(city)}`)).data.outings.length, 3);
  assert.equal((await f.request('?city=South%20SF')).data.outings.length, 1);
  assert.equal(cityRegex('SF').test('South San Francisco'), false);
  assert.equal(cityRegex('San José').test('San Jose\u0301'), true);
});

test('q is a bounded literal across title, description and locations, never executable regular expression', async t => {
  const f = await fixture(t);
  await discoverySeed(f, [{ title: 'Coffee [friends] (A+B).*' }, { description: 'Coffee time' }, { venue: 'Coffee Hall' }, { city: 'Coffee City' }, { title: 'Unrelated' }]);
  assert.equal((await f.request('?q=coffee')).data.outings.length, 4);
  const literal = await f.request(`?q=${encodeURIComponent('[friends] (A+B).*')}`);
  assert.equal(literal.status, 200); assert.equal(literal.data.outings.length, 1);
  assert.equal((await f.request('?q=%2E%2A')).data.outings.length, 1, 'wildcard syntax searches literally');
  assert.equal((await f.request('?q=%5B')).status, 200, 'unbalanced regex metacharacter is still literal text');
  assert.equal((await f.request(`?q=${'x'.repeat(121)}`)).status, 400);
  assert.equal((await f.request('?q[$regex]=.*')).status, 400);
});

test('whole known activity themes expand across languages without turning arbitrary searches into regex', async t => {
  const f = await fixture(t);
  await discoverySeed(f, [{ title: 'Museum afternoon' }, { title: '一起看展' }, { title: '周日展覽' }, { title: 'Morning walking' }, { title: '海边漫步' }, { title: 'Coffee friends' }, { title: '咖啡聊天' }, { title: 'Hiking together' }, { title: '徒步见面' }, { title: 'Unrelated' }].map(row => ({ ...row, description: '一起认识邻居' })));
  for (const [q, count] of [['看展', 3], ['museum', 3], ['散步', 2], ['walking', 2], ['coffee', 2], ['hike', 2], ['Coffee friends', 1], ['.*', 0]]) {
    const result = await f.request(`?q=${encodeURIComponent(q)}`);
    assert.equal(result.status, 200, q); assert.equal(result.data.outings.length, count, q);
  }
});

test('inclusive date ranges and language filters combine without changing the old exact date semantics', async t => {
  const f = await fixture(t);
  await discoverySeed(f, [{ date: '2026-10-03', language: 'zh' }, { date: '2026-10-04', language: 'en' }, { date: '2026-10-05', language: 'any' }, { date: '2026-10-06', language: 'zh' }]);
  const range = await f.request('?dateFrom=2026-10-04&dateTo=2026-10-05&language=en'); assert.equal(range.data.outings.length, 2);
  assert.equal((await f.request('?dateFrom=2026-10-04&dateTo=2026-10-05&language=zh')).data.outings.length, 1);
  assert.equal((await f.request('?dateTo=2026-10-04')).data.outings.length, 2);
  assert.equal((await f.request('?dateFrom=2026-10-05')).data.outings.length, 2);
  assert.equal((await f.request('?date=2026-10-04')).data.outings.length, 1);
  for (const query of ['date=2026-10-04&dateFrom=2026-10-04', 'dateFrom=2026-10-05&dateTo=2026-10-04', 'dateTo=2026-02-30', 'language=any', 'sort=random', 'seats=2']) assert.equal((await f.request(`?${query}`)).status, 400, query);
});

test('soonest pagination is stable on timestamp ties and bound to normalized filters with a signed v2 cursor', async t => {
  const f = await fixture(t);
  const rows = await discoverySeed(f, Array.from({ length: 45 }, (_, i) => ({ city: i % 2 ? 'SF' : 'San Francisco', date: i < 10 ? '2026-10-06' : '2026-10-04', title: 'Coffee meet' })));
  const expected = [...rows].sort((a, b) => a.startAt - b.startAt || a.id.localeCompare(b.id)).map(row => row.id);
  const first = await f.request('?sort=soonest&city=SF&q=coffee'); assert.equal(first.status, 200); assert.equal(first.data.outings.length, 20); assert.match(first.data.nextCursor, /^v2\./);
  const next = await f.request(`?sort=soonest&city=${encodeURIComponent('舊金山')}&q=COFFEE&cursor=${first.data.nextCursor}`);
  assert.equal(next.status, 200); assert.equal(next.data.outings.length, 20);
  const final = await f.request(`?sort=soonest&city=San%20Francisco&q=coffee&cursor=${next.data.nextCursor}`);
  assert.equal(final.status, 200); assert.equal(final.data.outings.length, 5); assert.equal(final.data.nextCursor, null);
  assert.deepEqual([...first.data.outings, ...next.data.outings, ...final.data.outings].map(row => row.id), expected);
  for (const changed of ['sort=soonest&city=South%20SF&q=coffee', 'city=SF&q=coffee', 'sort=soonest&city=SF&q=tea', 'sort=soonest&city=SF&q=coffee&language=en']) {
    assert.equal((await f.request(`?${changed}&cursor=${first.data.nextCursor}`)).status, 400, changed);
  }
  const [prefix, encoded, sig] = first.data.nextCursor.split('.');
  const tampered = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); tampered.startAt = 0;
  const forged = `${prefix}.${Buffer.from(JSON.stringify(tampered)).toString('base64url')}.${sig}`;
  assert.equal((await f.request(`?sort=soonest&city=SF&q=coffee&cursor=${forged}`)).status, 400);
  assert.equal((await f.request(`?sort=soonest&city=SF&q=coffee&cursor=${first.data.nextCursor}=`)).status, 400);
  assert.equal((await f.request('?sort=soonest&cursor=outing_seed_0010')).status, 400, 'legacy cursor cannot enter a v2 filter');
});

test('open-seat scan stays bounded and advances across a fully excluded page without dropping later matches', async t => {
  const f = await fixture(t);
  const fullMembers = ['host', 'alice'].map(userId => ({ userId, role: userId === 'host' ? 'host' : 'member', status: 'confirmed', confirmedVersion: 1 }));
  const rows = await discoverySeed(f, Array.from({ length: 87 }, (_, i) => ({ capacity: 2, ...(i < 85 ? { members: fullMembers } : {}) })));
  const find = f.models.Outing.find, observed = [];
  f.models.Outing.find = query => { const result = find(query), limit = result.limit.bind(result); result.limit = value => { observed.push(value); return limit(value); }; return result; };
  const first = await f.request('?seats=open&sort=soonest');
  assert.equal(first.status, 200); assert.equal(first.data.outings.length, 0); assert.match(first.data.nextCursor, /^v2\./);
  const second = await f.request(`?seats=open&sort=soonest&cursor=${first.data.nextCursor}`);
  assert.equal(second.status, 200); assert.deepEqual(second.data.outings.map(row => row.id), rows.slice(85).map(row => row.id)); assert.equal(second.data.nextCursor, null);
  assert.deepEqual(observed, [81, 81]);
});

test('default id pagination remains compatible while new id-ordered filters use bound v2 cursors', async t => {
  const f = await fixture(t); await discoverySeed(f, Array.from({ length: 23 }, () => ({})));
  const first = await f.request(''); assert.equal(first.data.nextCursor, 'outing_seed_0019');
  const next = await f.request(`?cursor=${first.data.nextCursor}`); assert.equal(next.data.outings.length, 3); assert.equal(next.data.nextCursor, null);
  const filtered = await f.request('?language=en'); assert.match(filtered.data.nextCursor, /^v2\./);
  assert.equal((await f.request(`?language=en&cursor=${filtered.data.nextCursor}`)).data.outings.length, 3);
  assert.equal((await f.request(`?language=zh&cursor=${filtered.data.nextCursor}`)).status, 400);
  assert.throws(() => outingSearch({ cursor: 'v2.invalid.invalid', language: 'en' }, START, SECRET), /分页/);
});
