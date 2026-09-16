const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadEventCatalog, bayAreaDate } = require('../lib/eventEngagement');

const SECRET = 'isolated-event-test-secret-with-more-than-32-characters';
const NOW = Date.parse('2026-10-15T19:00:00Z');
const CATALOG = [
  { id: 'future-festival', title: 'Official future event', startDate: '2026-10-17', endDate: '2026-10-18' },
  { id: 'today-event', title: 'Official event today', startDate: '2026-10-15', endDate: '2026-10-15' },
  { id: 'ended-event', title: 'Official ended event', startDate: '2026-10-13', endDate: '2026-10-14' },
];
const user = (id, fields = {}) => ({ id, nickname: `Neighbor ${id}`, email: `${id}@private.test`, phone: 'private-phone', contactValue: 'private-contact', password: '$2-fake', accountStatus: 'active', city: 'Oakland', avatar: 'https://example.test/avatar.webp', ...fields });
const interest = (userId, fields = {}) => ({ eventId: 'future-festival', userId, interested: true, lookingForBuddy: false, ...fields });

async function fixture(t, options = {}) {
  const models = options.models || createMemoryModels({ User: options.users || [user('owner'), user('other'), user('third')], EventInterest: options.interests || [], UserBlock: options.blocks || [] });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, eventCatalog: options.catalog === undefined ? CATALOG : options.catalog, eventNow: options.now || (() => NOW) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${application.server.address().port}/api`;
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = id => jwt.sign({ id, sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  const request = async (path, { as, method = 'GET', body, auth } = {}) => {
    const response = await fetch(url + path, { method, headers: { ...(as ? { Authorization: `Bearer ${token(as)}` } : {}), ...(auth !== undefined ? { Authorization: auth } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  const put = (body, as = 'owner', eventId = 'future-festival') => request(`/events/${eventId}/interest`, { as, method: 'PUT', body });
  return { ...application, models, request, put };
}

test('public event counts start at zero, optional auth reveals only its own state, and anonymous writes are refused', async t => {
  const { request, put, models } = await fixture(t);
  const anonymous = await request('/events/engagement?ids=future-festival,today-event,future-festival');
  assert.equal(anonymous.status, 200);
  assert.equal(anonymous.headers.get('cache-control'), 'no-store');
  assert.deepEqual(anonymous.data, { events: [
    { eventId: 'future-festival', interestedCount: 0, buddyCount: 0, me: null },
    { eventId: 'today-event', interestedCount: 0, buddyCount: 0, me: null },
  ] });
  assert.equal((await put({ interested: true, lookingForBuddy: false }, null)).status, 401);
  assert.equal(models.EventInterest.rows.length, 0);
  assert.deepEqual((await request('/events/engagement?ids=future-festival', { as: 'owner' })).data.events[0].me, { interested: false, lookingForBuddy: false });
  assert.deepEqual((await request('/events/future-festival/buddies')).data, { eventId: 'future-festival', buddies: [], nextCursor: null });
  for (const endpoint of ['/events/engagement?ids=future-festival', '/events/future-festival/buddies']) assert.equal((await request(endpoint, { auth: 'Bearer invalid' })).status, 401);
});

test('interest writes are idempotent, distinct per member, private until buddy opt-in, and survive a new application instance', async t => {
  const first = await fixture(t);
  for (let n = 0; n < 3; n++) {
    const saved = await first.put({ interested: true, lookingForBuddy: false });
    assert.equal(saved.status, 200);
    assert.deepEqual(saved.data, { eventId: 'future-festival', interestedCount: 1, buddyCount: 0, me: { interested: true, lookingForBuddy: false } });
  }
  assert.equal(first.models.EventInterest.rows.length, 1);
  assert.equal((await first.request('/events/future-festival/buddies')).data.buddies.length, 0);
  await first.put({ interested: true, lookingForBuddy: true }, 'other');
  const second = await fixture(t, { models: first.models });
  const other = (await second.request('/events/engagement?ids=future-festival', { as: 'other' })).data.events[0];
  assert.deepEqual(other, { eventId: 'future-festival', interestedCount: 2, buddyCount: 1, me: { interested: true, lookingForBuddy: true } });
  assert.deepEqual((await second.request('/events/engagement?ids=future-festival', { as: 'third' })).data.events[0].me, { interested: false, lookingForBuddy: false });
  await second.put({ interested: true, lookingForBuddy: true });
  assert.equal((await second.put({ interested: true, lookingForBuddy: false })).data.buddyCount, 1);
  assert.equal((await second.put({ interested: false, lookingForBuddy: false })).data.interestedCount, 1);
  assert.equal((await second.put({ interested: false, lookingForBuddy: false })).data.interestedCount, 1);
  assert.equal(second.models.EventInterest.rows.filter(row => row.userId === 'owner').length, 1);
  await second.put({ interested: false, lookingForBuddy: false }, 'third');
  assert.equal(second.models.EventInterest.rows.filter(row => row.userId === 'third').length, 0, 'withdrawing a nonexistent interest need not insert a row');
});

test('concurrent first joins, duplicate-key recovery and duplicate historical rows cannot inflate counts', async t => {
  const { put, request, models } = await fixture(t);
  const responses = await Promise.all(Array.from({ length: 8 }, () => put({ interested: true, lookingForBuddy: true })));
  assert.ok(responses.every(response => response.status === 200));
  assert.equal(models.EventInterest.rows.length, 1);
  const update = models.EventInterest.updateOne;
  let raced = false;
  models.EventInterest.updateOne = async (query, values, options) => {
    if (!raced && query.userId === 'other' && options.upsert) {
      raced = true;
      await update(query, values, options);
      throw Object.assign(new Error('another writer inserted the member'), { code: 11000 });
    }
    return update(query, values, options);
  };
  assert.equal((await put({ interested: true, lookingForBuddy: true }, 'other')).status, 200);
  models.EventInterest.rows.push(interest('owner', { lookingForBuddy: false }), interest('owner', { lookingForBuddy: true }));
  const result = (await request('/events/engagement?ids=future-festival')).data.events[0];
  assert.equal(result.interestedCount, 2);
  assert.equal(result.buddyCount, 2);
  assert.equal((await request('/events/future-festival/buddies')).data.buddies.length, 2);
});

test('unknown events, Mongo-shaped input, forged identity and non-booleans cannot write any rows', async t => {
  const { request, put, models } = await fixture(t);
  const invalid = [null, [], {}, { interested: true }, { interested: 'true', lookingForBuddy: false }, { interested: 1, lookingForBuddy: false }, { interested: false, lookingForBuddy: true }, { interested: { $ne: false }, lookingForBuddy: false }, { interested: true, lookingForBuddy: true, userId: 'other' }];
  for (const body of invalid) assert.equal((await put(body)).status, 400);
  assert.equal((await put({ interested: true, lookingForBuddy: false }, 'owner', 'fake-event')).status, 404);
  for (const path of ['/events/engagement', '/events/engagement?ids=', '/events/engagement?ids[$ne]=x', '/events/engagement?ids=a&ids=b', '/events/engagement?ids=future-festival,', `/events/engagement?ids=${Array(101).fill('today-event').join(',')}`]) assert.equal((await request(path)).status, 400, path);
  assert.equal((await request('/events/engagement?ids=fake-event')).status, 404);
  assert.equal((await request('/events/fake-event/buddies')).status, 404);
  assert.equal(models.EventInterest.rows.length, 0);
});

test('Pacific end dates include the final local day and allow cancellation after an event ends', async t => {
  let now = Date.parse('2026-10-16T06:59:59Z'); // Oct 15 23:59:59 PDT.
  const { put, models } = await fixture(t, { now: () => now, interests: [interest('owner', { eventId: 'ended-event', lookingForBuddy: true })] });
  assert.equal(bayAreaDate(now), '2026-10-15');
  assert.equal((await put({ interested: true, lookingForBuddy: true }, 'owner', 'today-event')).status, 200);
  now += 1000;
  assert.equal(bayAreaDate(now), '2026-10-16');
  assert.equal((await put({ interested: true, lookingForBuddy: false }, 'owner', 'today-event')).status, 200, 'existing members may leave the public list while retaining private interest');
  assert.equal((await put({ interested: true, lookingForBuddy: true }, 'other', 'ended-event')).status, 410);
  assert.equal((await put({ interested: false, lookingForBuddy: false }, 'owner', 'ended-event')).status, 200);
  assert.equal(models.EventInterest.rows.find(row => row.eventId === 'ended-event').interested, false);
  assert.equal((await put({ interested: false, lookingForBuddy: false }, 'owner', 'today-event')).data.interestedCount, 0);
});

test('buddy profiles are opt-in allowlists; both block directions and restricted or deleted accounts stay out', async t => {
  const { request, models } = await fixture(t, {
    users: [user('owner'), user('visible', { passwordResetTokenHash: 'secret-reset', phoneVerificationCodeHash: 'secret-code' }), user('private'), user('blocked-by-viewer'), user('blocks-viewer'), user('banned', { isBanned: true }), user('suspended', { accountStatus: 'suspended' }), user('limited', { accountStatus: 'limited' }), user('legacy', { accountStatus: undefined })],
    interests: ['visible', 'blocked-by-viewer', 'blocks-viewer', 'banned', 'suspended', 'limited', 'missing', 'legacy'].map(id => interest(id, { lookingForBuddy: true })).concat([interest('private'), interest('owner', { interested: false, lookingForBuddy: true })]),
    blocks: [{ blockerId: 'owner', blockedUserId: 'blocked-by-viewer' }, { blockerId: 'blocks-viewer', blockedUserId: 'owner' }],
  });
  const publicList = await request('/events/future-festival/buddies');
  assert.deepEqual(publicList.data.buddies.map(row => row.id), ['blocked-by-viewer', 'blocks-viewer', 'legacy', 'visible']);
  const personalList = await request('/events/future-festival/buddies', { as: 'owner' });
  assert.deepEqual(personalList.data.buddies.map(row => row.id), ['legacy', 'visible']);
  for (const row of publicList.data.buddies) assert.deepEqual(Object.keys(row).sort(), ['avatar', 'city', 'id', 'nickname']);
  const serialized = JSON.stringify(personalList.data);
  for (const secret of ['private.test', 'private-phone', 'private-contact', 'secret-reset', 'secret-code', 'password']) assert.equal(serialized.includes(secret), false, secret);
  const count = (await request('/events/engagement?ids=future-festival', { as: 'owner' })).data.events[0];
  assert.equal(count.interestedCount, 5, 'global anonymous aggregate includes interested-only members but not restricted/deleted accounts');
  assert.equal(count.buddyCount, 4, 'global count does not reveal a viewer-specific block relation');
  models.UserBlock.rows.push({ blockerId: 'visible', blockedUserId: 'owner' });
  assert.deepEqual((await request('/events/future-festival/buddies', { as: 'owner' })).data.buddies.map(row => row.id), ['legacy']);
});

test('buddy pagination is bounded, stable, and filters blocks before choosing a page', async t => {
  const people = Array.from({ length: 25 }, (_, i) => user(`person-${String(i).padStart(2, '0')}`));
  const { request } = await fixture(t, { users: [user('owner'), ...people], interests: people.map(person => interest(person.id, { lookingForBuddy: true })), blocks: [{ blockerId: 'owner', blockedUserId: 'person-00' }] });
  const first = await request('/events/future-festival/buddies', { as: 'owner' });
  assert.equal(first.data.buddies.length, 20);
  assert.equal(first.data.buddies[0].id, 'person-01');
  assert.equal(first.data.buddies.at(-1).id, 'person-20');
  const second = await request(`/events/future-festival/buddies?cursor=${first.data.nextCursor}`, { as: 'owner' });
  assert.deepEqual(second.data.buddies.map(row => row.id), ['person-21', 'person-22', 'person-23', 'person-24']);
  assert.equal(second.data.nextCursor, null);
  assert.equal((await request('/events/future-festival/buddies?limit=1')).data.buddies.length, 1);
  for (const suffix of ['limit=21', 'limit=0', 'limit=-1', 'limit=1.5', 'limit[$gt]=1', 'cursor=***', 'cursor=%00', 'cursor=AA', 'cursor[x]=abc']) assert.equal((await request(`/events/future-festival/buddies?${suffix}`)).status, 400, suffix);
});

test('restricted accounts cannot opt in, limited members can withdraw, and reads/writes honor rate limits', async t => {
  const { request, put, models } = await fixture(t, { users: [user('owner', { accountStatus: 'limited' }), user('other'), user('third', { accountStatus: 'suspended' })], interests: [interest('owner', { lookingForBuddy: true })] });
  assert.equal((await put({ interested: true, lookingForBuddy: true })).status, 403);
  assert.equal((await put({ interested: false, lookingForBuddy: false })).status, 200);
  assert.equal((await put({ interested: true, lookingForBuddy: false }, 'third')).status, 403);
  assert.equal(models.EventInterest.rows.length, 1);
  for (let i = 0; i < 40; i++) assert.equal((await put({ interested: true, lookingForBuddy: false }, 'other')).status, 200);
  assert.equal((await put({ interested: true, lookingForBuddy: true }, 'other')).status, 429);
  assert.equal(models.EventInterest.rows.find(row => row.userId === 'other').lookingForBuddy, false);
  for (let i = 0; i < 180; i++) assert.equal((await request('/events/engagement?ids=future-festival')).status, 200);
  assert.equal((await request('/events/engagement?ids=future-festival')).status, 429);
});

test('limited and expired members can withdraw public buddy visibility without losing private interest', async t => {
  for (const [status, eventId] of [['limited', 'future-festival'], ['active', 'ended-event'], ['limited', 'ended-event']]) {
    const { put, models } = await fixture(t, {
      users: [user('owner', { accountStatus: status })],
      interests: [interest('owner', { eventId, lookingForBuddy: true })],
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await put({ interested: true, lookingForBuddy: false }, 'owner', eventId);
      assert.equal(result.status, 200);
      assert.deepEqual(result.data.me, { interested: true, lookingForBuddy: false });
      assert.equal(models.EventInterest.rows.length, 1);
    }
    const denied = eventId === 'ended-event' ? 410 : 403;
    assert.equal((await put({ interested: true, lookingForBuddy: true }, 'owner', eventId)).status, denied);
    assert.equal((await put({ interested: false, lookingForBuddy: false }, 'owner', eventId)).status, 200);
    assert.equal((await put({ interested: true, lookingForBuddy: false }, 'owner', eventId)).status, denied, 'withdrawal cannot restore a cancelled interest');
    assert.equal(models.EventInterest.rows[0].interested, false);
  }
});

test('restricted withdrawal cannot create absent interest or override a concurrent full cancellation', async t => {
  for (const [status, eventId, denied] of [['limited', 'future-festival', 403], ['active', 'ended-event', 410]]) {
    const { put, models } = await fixture(t, { users: [user('owner', { accountStatus: status })] });
    assert.equal((await put({ interested: true, lookingForBuddy: false }, 'owner', eventId)).status, denied);
    assert.equal(models.EventInterest.rows.length, 0, 'a restricted withdrawal never upserts a membership');
    models.EventInterest.rows.push(interest('owner', { eventId, lookingForBuddy: true }));
    const update = models.EventInterest.findOneAndUpdate;
    let calls = 0;
    models.EventInterest.findOneAndUpdate = async (query, values, options) => {
      calls++;
      assert.deepEqual(query, { eventId, userId: 'owner', interested: true });
      assert.equal(options.upsert, false);
      assert.equal(Object.hasOwn(values.$set, 'interested'), false, 'public withdrawal must never set interest back to true');
      models.EventInterest.rows[0].interested = false;
      models.EventInterest.rows[0].lookingForBuddy = false;
      return update(query, values, options);
    };
    assert.equal((await put({ interested: true, lookingForBuddy: false }, 'owner', eventId)).status, denied);
    assert.equal(calls, 1);
    assert.equal(models.EventInterest.rows.length, 1);
    assert.equal(models.EventInterest.rows[0].interested, false);
    assert.equal(models.EventInterest.rows[0].lookingForBuddy, false);
  }
});

test('catalog and database failures are explicit service failures, never invented zero counts or successful joins', async t => {
  const brokenCatalog = await fixture(t, { catalog: [{ id: 'future-festival', title: 'bad date', startDate: '2026-02-30', endDate: '2026-10-31' }] });
  for (const path of ['/events/engagement?ids=future-festival', '/events/future-festival/buddies']) assert.equal((await brokenCatalog.request(path)).status, 503);
  assert.equal((await brokenCatalog.put({ interested: true, lookingForBuddy: false })).status, 503);
  assert.equal(brokenCatalog.models.EventInterest.rows.length, 0);
  const db = await fixture(t);
  db.models.EventInterest.aggregate = async () => { throw new Error('storage unavailable'); };
  assert.equal((await db.request('/events/engagement?ids=future-festival')).status, 503);
  assert.equal((await db.request('/events/future-festival/buddies')).status, 503);
  db.models.EventInterest.updateOne = async () => { throw new Error('storage unavailable'); };
  assert.equal((await db.put({ interested: true, lookingForBuddy: false })).status, 503);
  assert.equal(db.models.EventInterest.rows.length, 0);
  for (const catalog of [[], {}, null, [CATALOG[0], CATALOG[0]], [{ ...CATALOG[0], id: '$evil' }], [{ ...CATALOG[0], startDate: '2026-11-01' }]]) assert.equal(loadEventCatalog(catalog), null);
});

test('Mongoose validates the buddy invariant and declares a unique event/member identity', async t => {
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, eventCatalog: CATALOG });
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const Model = application.models.EventInterest;
  assert.equal(new Model(interest('member', { lookingForBuddy: true })).validateSync(), undefined);
  assert.ok(new Model(interest('member', { interested: false, lookingForBuddy: true })).validateSync()?.errors.lookingForBuddy);
  assert.ok(new Model({ interested: false, lookingForBuddy: false }).validateSync()?.errors.userId);
  assert.ok(Model.schema.indexes().some(([keys, options]) => keys.eventId === 1 && keys.userId === 1 && Object.keys(keys).length === 2 && options.unique === true));
  // Run Mongoose's actual query validation and casting without a database:
  // this exercises the query-bound validator that the memory adapter skips.
  const writes = [];
  t.mock.method(Model.collection, 'updateOne', async (query, values) => { writes.push({ query, values }); return { acknowledged: true, matchedCount: 1, modifiedCount: 1 }; });
  await Model.updateOne({ eventId: 'future-festival', userId: 'member' }, { $set: { interested: true, lookingForBuddy: true } }, { upsert: true, runValidators: true });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].values.$set.interested, true);
  await assert.rejects(Model.updateOne({ eventId: 'future-festival', userId: 'member' }, { $set: { interested: false, lookingForBuddy: true } }, { runValidators: true }), /requires interest/);
  assert.equal(writes.length, 1, 'invalid state must fail before reaching the database adapter');
});

test('the exported official catalog is accepted as one complete frontend engagement batch', async t => {
  const catalog = require('../data/event-catalog.json');
  const checked = loadEventCatalog();
  assert.ok(checked);
  assert.equal(checked.size, catalog.length);
  assert.ok(catalog.length <= 100, 'the current frontend requests its calendar in one batch');
  const { request } = await fixture(t, { catalog });
  const result = await request(`/events/engagement?ids=${encodeURIComponent(catalog.map(row => row.id).join(','))}`);
  assert.equal(result.status, 200);
  assert.deepEqual(result.data.events.map(row => row.eventId), catalog.map(row => row.id));
  assert.ok(result.data.events.every(row => row.interestedCount === 0 && row.buddyCount === 0 && row.me === null));
});
