const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createContactAccessQuota, verifiedContactPhone, DAILY_LIMIT } = require('../lib/contactAccessQuota');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');
const SECRET = 'isolated-contact-access-quota-secret';
const NOW = Date.parse('2026-10-07T06:59:59Z');
const user = (id, phone = '+14155550123') => ({ id, email: `${id}@example.test`, nickname: 'Synthetic neighbor', role: 'user', isPhoneVerified: true, phoneNormalized: phone });

test('shared verified numbers share an atomic daily cap across quota instances and accounts', async () => {
  const Model = createMemoryModels().ContactAccessQuota;
  const quotas = [0, 1].map(() => createContactAccessQuota({ Model, secret: SECRET, now: () => NOW }));
  const results = await Promise.allSettled(Array.from({ length: 40 }, (_, index) => quotas[index % 2].claim(user(`synthetic-${index}`), { requirePhone: true })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, DAILY_LIMIT);
  assert.ok(results.filter(result => result.status === 'rejected').every(result => result.reason.code === 'CONTACT_DAILY_LIMIT'));
  assert.ok(Model.rows.every(row => row.count <= DAILY_LIMIT));
  assert.doesNotMatch(JSON.stringify(Model.rows), /14155550123|synthetic-|isolated-contact/);
});

test('account cap persists through instance restart and changing verified numbers, resets at Pacific midnight', async () => {
  const Model = createMemoryModels().ContactAccessQuota;
  let now = NOW;
  const quota = () => createContactAccessQuota({ Model, secret: SECRET, now: () => now });
  for (let index = 0; index < DAILY_LIMIT; index++) await quota().claim(user('same-account', `+14155550${String(index).padStart(3, '0')}`));
  await assert.rejects(quota().claim(user('same-account', '+14155550999')), error => error.code === 'CONTACT_DAILY_LIMIT');
  now += 1000;
  await quota().claim(user('same-account', '+14155550999'));
  assert.ok(Model.rows.some(row => row._id.startsWith('2026-10-06:')));
  assert.ok(Model.rows.some(row => row._id.startsWith('2026-10-07:')));
});

test('legacy verified numbers normalize without account migration, while stale or malformed badges do not unlock auto sharing', async () => {
  assert.equal(verifiedContactPhone({ isPhoneVerified: true, phone: '(415) 555-0123' }), '+14155550123');
  assert.equal(verifiedContactPhone({ isPhoneVerified: true, phoneNormalized: '+1 (415) 555-0123' }), '+14155550123');
  for (const account of [{ id: 'missing', isPhoneVerified: true }, { ...user('unverified'), isPhoneVerified: false }, user('invalid', 'letters4155550123')]) {
    const Model = createMemoryModels().ContactAccessQuota;
    const quota = createContactAccessQuota({ Model, secret: SECRET, now: () => NOW });
    await assert.rejects(quota.claim(account, { requirePhone: true }), error => error.code === 'VERIFIED_CONTACT_REQUIRED');
    assert.equal(Model.rows.length, 0);
  }
});

test('quota storage failure denies before any contact can be disclosed; contention duplicates are recovered safely', async () => {
  const Model = createMemoryModels().ContactAccessQuota;
  const quota = createContactAccessQuota({ Model, secret: SECRET, now: () => NOW });
  const insert = Model.updateOne;
  let conflict = true;
  Model.updateOne = async (...args) => { await insert(...args); if (conflict) { conflict = false; throw Object.assign(new Error('concurrent insert'), { code: 11000 }); } };
  await quota.claim(user('one'));
  Model.findOneAndUpdate = async () => { throw new Error('Database unavailable: sensitive implementation detail'); };
  await assert.rejects(quota.claim(user('two')), error => error.status === 503 && error.code === 'CONTACT_QUOTA_UNAVAILABLE' && !error.message.includes('Database'));
});

async function fixture(t) {
  const models = createMemoryModels({
    User: [user('owner'), ...Array.from({ length: 14 }, (_, index) => user(`neighbor-${index}`))],
    Post: Array.from({ length: 14 }, (_, index) => ({ id: `post-${index}`, authorId: 'owner', status: 'active', isDeleted: false,
      contactPreference: { mode: 'auto_send', methods: [{ type: 'wechat', value: 'synthetic-contact', enabled: true }] } })),
  });
  const app = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, contactAccessNow: () => NOW });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const request = async (index, post = index) => {
    const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/posts/post-${post}/contact-requests`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt.sign({ id: `neighbor-${index}` }, SECRET, { expiresIn: '1h' })}` }, body: '{}',
    });
    return { status: response.status, body: await response.json() };
  };
  return { models, request };
}

test('concurrent contact routes sharing a verified number disclose at most ten contacts and existing results remain accessible', async t => {
  const { models, request } = await fixture(t);
  const results = await Promise.all(Array.from({ length: 12 }, (_, index) => request(index)));
  assert.equal(results.filter(result => result.status === 200).length, 10, JSON.stringify(results));
  assert.equal(results.filter(result => result.status === 429 && result.body.code === 'CONTACT_DAILY_LIMIT').length, 2);
  assert.equal(models.ContactRequest.rows.length, 10);
  assert.equal(models.Message.rows.length, 10);
  const allowed = results.findIndex(result => result.status === 200);
  const before = JSON.stringify(models.ContactAccessQuota.rows);
  const repeated = await request(allowed);
  assert.equal(repeated.status, 200);
  assert.equal(repeated.body.request.id, results[allowed].body.request.id);
  assert.equal(JSON.stringify(models.ContactAccessQuota.rows), before);
});

test('contact routes fail closed on quota failure and retain unverified manual approval without automatic disclosure', async t => {
  const { models, request } = await fixture(t);
  models.User.rows.find(row => row.id === 'neighbor-0').isPhoneVerified = false;
  assert.equal((await request(0)).body.code, 'VERIFIED_CONTACT_REQUIRED');
  models.Post.rows[0].contactPreference.mode = 'manual_approve';
  const manual = await request(0);
  assert.equal(manual.status, 200); assert.equal(manual.body.status, 'pending');
  assert.equal(models.Message.rows.length, 0);
  models.ContactAccessQuota.findOneAndUpdate = async () => { throw new Error('offline'); };
  const failed = await request(1);
  assert.equal(failed.status, 503); assert.equal(failed.body.code, 'CONTACT_QUOTA_UNAVAILABLE');
  assert.equal(models.ContactRequest.rows.length, 1); assert.equal(models.Message.rows.length, 0);
});
