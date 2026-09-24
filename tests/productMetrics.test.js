const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { PRODUCT_EVENTS, createProductMetricModel } = require('../lib/productMetrics');

const SECRET = 'isolated-product-metrics-test-secret';
const NOW = Date.parse('2026-09-23T19:00:00Z');
const copy = value => structuredClone(value);
function metricModel(seed = []) {
  const rows = seed.map(copy); const writes = [];
  return {
    rows, writes,
    async updateOne(query, update, options = {}) {
      writes.push(copy({ query, update, options }));
      let row = rows.find(item => Object.entries(query).every(([key, value]) => item[key] === value));
      const existing = !!row;
      if (!row && options.upsert) { row = copy(update.$setOnInsert); row.count = 0; rows.push(row); }
      if (row) row.count += update.$inc.count;
      return { acknowledged: true, matchedCount: existing ? 1 : 0, upsertedCount: !existing && row ? 1 : 0 };
    },
    find(query) {
      let maximum = Infinity;
      const chain = {
        select() { return chain; }, sort() { return chain; }, limit(value) { maximum = value; return chain; },
        async lean() { return rows.filter(row => row.day >= query.day.$gte && row.day <= query.day.$lte).sort((a, b) => a.day.localeCompare(b.day)).slice(0, maximum).map(copy); },
      };
      return chain;
    },
    init: async () => {},
  };
}
async function fixture(t, options = {}) {
  const ProductMetric = options.model || metricModel(options.rows);
  const models = { ...createMemoryModels({ User: [
    { id: 'admin', email: 'admin@private.test', role: 'admin', password: 'not-public' },
    { id: 'member', email: 'member@private.test', role: 'user', password: 'not-public' },
  ] }), ProductMetric };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, productMetricsNow: options.now || (() => NOW) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, as, auth } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method,
      headers: { ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...(auth ? { Authorization: auth } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  const post = (body, extras = {}) => request('/product-events', { method: 'POST', body, ...extras });
  return { ProductMetric, request, post };
}

test('public product events persist only daily event/locale buckets with no identity or action timestamps', async t => {
  const { post, ProductMetric } = await fixture(t);
  for (const event of PRODUCT_EVENTS) {
    assert.equal((await post({ event })).status, 200);
    assert.equal((await post({ event, locale: 'en' }, { as: 'member' })).status, 200);
  }
  // Public ingestion has no authentication dependency, including expired UI sessions.
  assert.deepEqual((await post({ event: 'plan_saved', locale: 'zh-Hant' }, { auth: 'Bearer invalid' })).data, { ok: true });
  assert.equal(ProductMetric.rows.length, 13);
  for (const row of ProductMetric.rows) {
    assert.deepEqual(Object.keys(row).sort(), ['_id', 'count', 'day', 'event', 'expiresAt', 'locale']);
    assert.equal(row._id, `${row.day}:${row.event}:${row.locale}`);
    assert.equal(row.day, '2026-09-23');
    assert.equal(row.count, 1);
    assert.equal(new Date(row.expiresAt).toISOString(), '2027-03-22T00:00:00.000Z');
  }
  assert.ok(!JSON.stringify(ProductMetric.writes).includes('member'));
  assert.ok(!JSON.stringify(ProductMetric.writes).includes('127.0.0.1'));
});

test('unknown dimensions, injected fields and invalid event or locale types cannot be persisted', async t => {
  const { post, ProductMetric } = await fixture(t);
  const invalid = [null, [], {}, { event: 'page_view' }, { event: { $ne: '' } }, { event: 'plan_saved', locale: null }, { event: 'plan_saved', locale: ['en'] }, { event: 'plan_saved', locale: 'fr' },
    ...['userId', 'session', 'ip', 'message', 'url', 'content', 'day', 'count'].map(field => ({ event: 'plan_saved', [field]: 'private' })),
  ];
  for (const body of invalid) assert.equal((await post(body)).status, 400, JSON.stringify(body));
  assert.equal(ProductMetric.rows.length, 0);
  assert.equal(ProductMetric.writes.length, 0);
});

test('atomic increments preserve concurrent actions and recover a unique-key insertion race once', async t => {
  const { post, ProductMetric } = await fixture(t);
  const responses = await Promise.all(Array.from({ length: 20 }, () => post({ event: 'planner_recommendation', locale: 'en' })));
  assert.ok(responses.every(row => row.status === 200));
  assert.equal(ProductMetric.rows.length, 1);
  assert.equal(ProductMetric.rows[0].count, 20);
  const original = ProductMetric.updateOne; let raced = false;
  ProductMetric.updateOne = async (query, update, options) => {
    if (query.event === 'plan_saved' && !raced) { raced = true; await original(query, update, options); throw Object.assign(new Error('competing insertion'), { code: 11000 }); }
    return original(query, update, options);
  };
  assert.equal((await post({ event: 'plan_saved' })).status, 200);
  assert.equal(ProductMetric.rows.find(row => row.event === 'plan_saved').count, 2, 'one competing action and the accepted current action');
});

test('Pacific midnight selects a new bucket without storing exact action time', async t => {
  let now = Date.parse('2026-09-24T06:59:59Z');
  const { post, ProductMetric } = await fixture(t, { now: () => now });
  await post({ event: 'plan_shared' }); now += 1000; await post({ event: 'plan_shared' });
  assert.deepEqual(ProductMetric.rows.map(row => row.day), ['2026-09-23', '2026-09-24']);
  assert.equal(ProductMetric.rows[0].count, 1); assert.equal(ProductMetric.rows[1].count, 1);
});

test('admin metrics require real admin auth, expose only the last 30 daily aggregates and include zero totals', async t => {
  const { request } = await fixture(t, { rows: [
    { day: '2026-08-24', event: 'plan_saved', locale: 'en', count: 1000 },
    { day: '2026-08-25', event: 'plan_saved', locale: 'en', count: 2, privateField: 'must-not-leak' },
    { day: '2026-09-23', event: 'plan_saved', locale: 'zh-Hans', count: 3 },
    { day: '2026-09-23', event: 'plan_shared', locale: 'en', count: 4 },
    { day: '2026-09-24', event: 'plan_saved', locale: 'en', count: 1000 },
  ] });
  assert.equal((await request('/admin/product-metrics')).status, 401);
  assert.equal((await request('/admin/product-metrics', { as: 'member' })).status, 403);
  assert.equal((await request('/admin/product-metrics', { auth: 'Bearer invalid' })).status, 401);
  const result = await request('/admin/product-metrics', { as: 'admin' });
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(result.data.days, 30);
  assert.equal(result.data.from, '2026-08-25'); assert.equal(result.data.through, '2026-09-23');
  assert.equal(result.data.counts.plan_saved, 5); assert.equal(result.data.counts.plan_shared, 4);
  assert.equal(result.data.counts.planner_recommendation, 0);
  assert.deepEqual(Object.keys(result.data.counts), PRODUCT_EVENTS);
  assert.equal(result.data.daily.length, 3);
  for (const row of result.data.daily) assert.deepEqual(Object.keys(row), ['day', 'event', 'locale', 'count']);
  assert.ok(!JSON.stringify(result.data).includes('must-not-leak'));
  assert.equal((await request('/admin/product-metrics?from=2000-01-01', { as: 'admin' })).status, 400);
});

test('in-memory request limits reject excess ingestion before touching aggregate storage', async t => {
  const { post, ProductMetric } = await fixture(t);
  for (let index = 0; index < 60; index++) assert.equal((await post({ event: 'planner_map_opened' })).status, 200);
  assert.equal((await post({ event: 'planner_map_opened' })).status, 429);
  assert.equal(ProductMetric.rows[0].count, 60);
});

test('storage failures return 503 and uncertain writes are never retried or logged with personal data', async t => {
  const model = metricModel(); let writes = 0;
  model.updateOne = async () => { writes++; throw new Error('uncertain acknowledgement'); };
  model.find = () => { throw new Error('offline'); };
  const { post, request } = await fixture(t, { model });
  const result = await post({ event: 'favorite_saved' });
  assert.equal(result.status, 503); assert.equal(result.data.ok, false); assert.equal(writes, 1);
  assert.equal((await request('/admin/product-metrics', { as: 'admin' })).status, 503);
});

test('Mongo model enforces one bucket per day/event/locale and expiration with a strict field allowlist', () => {
  const Model = createProductMetricModel(mongoose);
  const indexes = Model.schema.indexes();
  assert.ok(indexes.some(([keys, options]) => JSON.stringify(keys) === JSON.stringify({ day: 1, event: 1, locale: 1 }) && options.unique));
  assert.ok(indexes.some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.deepEqual(Object.keys(Model.schema.paths).sort(), ['_id', 'count', 'day', 'event', 'expiresAt', 'locale']);
  assert.equal(Model.schema.path('_id').instance, 'String');
  assert.throws(() => new Model({ day: '2026-09-23', event: 'plan_saved', locale: 'en', count: 1, expiresAt: new Date(), ip: 'must-not-be-stored' }), /not in schema/);
});
