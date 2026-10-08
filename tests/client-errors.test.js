const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { runPipeline } = require('./support/aggregate-pipeline');
const { MAX_BUCKETS_PER_DAY, REPORT_GROUPS, releaseLabel, createClientErrorMetricModel, registerClientErrors } = require('../lib/clientErrors');

const SECRET = 'isolated-client-error-test-secret';
const NOW = Date.parse('2026-10-08T19:00:00Z');
const copy = value => structuredClone(value);
const COMMIT = 'a5d63fbe3e1733fd94f4071ab3f0c94a49b2e222';

function errorModel(seed = []) {
  const rows = seed.map(copy); const writes = [];
  return {
    rows, writes,
    async updateOne(query, update, options = {}) {
      writes.push(copy({ query, update, options }));
      let row = rows.find(item => Object.entries(query).every(([key, value]) => item[key] === value));
      const existing = !!row;
      if (!row && options.upsert) { row = copy(update.$setOnInsert); row.count = 0; rows.push(row); }
      if (row) row.count += update.$inc.count;
      return { acknowledged: true, matchedCount: existing ? 1 : 0 };
    },
    aggregate: async pipeline => runPipeline(rows, pipeline),
    init: async () => {},
  };
}

async function fixture(t, options = {}) {
  const ClientErrorMetric = options.model || errorModel(options.rows);
  const models = { ...createMemoryModels({ User: [
    { id: 'admin', email: 'admin@private.test', role: 'admin', password: 'not-public' },
    { id: 'member', email: 'member@private.test', role: 'user', password: 'not-public' },
  ] }), ClientErrorMetric };
  let now = options.now || NOW;
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, productMetricsNow: () => now });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, as, headers = {} } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method,
      headers: { ...headers, ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  return { ClientErrorMetric, request, post: (body, extras) => request('/client-errors', { method: 'POST', body, ...extras }), setNow: value => { now = value; } };
}

test('beacons become one daily bucket per kind, route template, release and fingerprint', async t => {
  const { post, ClientErrorMetric } = await fixture(t);
  const beacon = { kind: 'render', route: '/en/events/fleet-week-secret?date=2026-10-10', release: COMMIT, fp: '3fa9c01b' };
  for (let index = 0; index < 3; index++) assert.deepEqual((await post(beacon, { as: 'member' })).data, { ok: true });
  assert.equal((await post({ ...beacon, kind: 'chunk' })).status, 200);
  assert.equal(ClientErrorMetric.rows.length, 2);
  const [row] = ClientErrorMetric.rows;
  assert.deepEqual(Object.keys(row).sort(), ['_id', 'count', 'day', 'expiresAt', 'fp', 'kind', 'release', 'route']);
  assert.deepEqual({ ...row, expiresAt: new Date(row.expiresAt).toISOString() }, {
    _id: '2026-10-08:render:/events/:id:a5d63fbe3e17:3fa9c01b', day: '2026-10-08', kind: 'render', route: '/events/:id',
    release: 'a5d63fbe3e17', fp: '3fa9c01b', count: 3, expiresAt: '2026-11-07T00:00:00.000Z' });
  const written = JSON.stringify(ClientErrorMetric.writes);
  for (const secret of ['fleet-week-secret', '2026-10-10', 'member', '127.0.0.1', '/en/']) assert.ok(!written.includes(secret), secret);
});

test('route and release are optional; unknown values never reach storage raw', async t => {
  const { post, ClientErrorMetric } = await fixture(t);
  assert.equal((await post({ kind: 'error', fp: 'abcdef12' })).status, 200);
  assert.equal((await post({ kind: 'rejection', fp: 'abcdef12', route: 'https://evil.example/x', release: 'build with spaces <script>' })).status, 200);
  assert.equal((await post({ kind: 'error', fp: 'abcdef12', release: 'dev' })).status, 200);
  assert.deepEqual(ClientErrorMetric.rows.map(row => [row.kind, row.route, row.release]), [['error', 'other', 'unknown'], ['rejection', 'other', 'unknown'], ['error', 'other', 'dev']]);
  assert.equal(releaseLabel('ABCDEF1'), 'abcdef1');
  assert.equal(releaseLabel(`v${'1'.repeat(40)}`), 'unknown');
});

test('stacks, messages, URLs and malformed beacons are rejected before any write', async t => {
  const { post, ClientErrorMetric } = await fixture(t);
  const valid = { kind: 'render', route: '/', release: 'dev', fp: 'abcdef12' };
  const invalid = [null, [], {}, { ...valid, kind: 'warning' }, { ...valid, fp: 'TypeError: x is undefined' }, { ...valid, fp: 'abc' },
    { ...valid, fp: 'a'.repeat(17) }, { ...valid, fp: 12345678 }, { ...valid, route: 42 }, { ...valid, release: { $ne: '' } },
    ...['stack', 'message', 'url', 'userAgent', 'userId', 'day', 'count'].map(field => ({ ...valid, [field]: 'private' }))];
  for (const body of invalid) assert.equal((await post(body)).status, 400, JSON.stringify(body));
  assert.equal(ClientErrorMetric.writes.length, 0);
});

test('Do Not Track and GPC skip the beacon', async t => {
  const { post, ClientErrorMetric } = await fixture(t);
  for (const headers of [{ DNT: '1' }, { 'Sec-GPC': '1' }]) assert.deepEqual((await post({ kind: 'error', fp: 'abcdef12' }, { headers })).data, { ok: true, skipped: true });
  assert.equal(ClientErrorMetric.writes.length, 0);
});

test('a visitor gets 30 beacons a minute; a storage failure answers 503 without a retry', async t => {
  const { post } = await fixture(t);
  for (let index = 0; index < 30; index++) assert.equal((await post({ kind: 'error', fp: 'abcdef12' })).status, 200);
  assert.equal((await post({ kind: 'error', fp: 'abcdef12' })).status, 429);
  const model = errorModel(); let writes = 0;
  model.updateOne = async () => { writes++; throw new Error('uncertain acknowledgement'); };
  const failing = await fixture(t, { model });
  assert.equal((await failing.post({ kind: 'error', fp: 'abcdef12' })).status, 503);
  assert.equal(writes, 1);
});

test('after the daily cap of distinct buckets, new combinations share one overflow bucket per kind and route', async () => {
  const model = errorModel();
  const handlers = {};
  const app = { post: (path, handler) => { handlers[path] = handler; }, get: () => {} };
  registerClientErrors(app, { mongoose, models: { ClientErrorMetric: model }, getClientIp: () => 'k', now: () => NOW, limiter: { check: () => true } });
  const call = body => new Promise(resolve => handlers['/api/client-errors']({ headers: {}, body }, { set() {}, status() { return this; }, json: resolve }));
  for (let index = 0; index < MAX_BUCKETS_PER_DAY; index++) assert.deepEqual(await call({ kind: 'error', route: '/', release: 'dev', fp: `f${String(index).padStart(7, '0')}` }), { ok: true });
  await call({ kind: 'error', route: '/guides/:slug', release: 'dev', fp: 'ffffffff' });
  await call({ kind: 'error', route: '/guides/:slug', release: 'another', fp: 'eeeeeeee' });
  await call({ kind: 'error', route: '/', release: 'dev', fp: 'f0000001' });
  assert.equal(model.rows.length, MAX_BUCKETS_PER_DAY + 1);
  const overflow = model.rows.at(-1);
  assert.deepEqual([overflow._id, overflow.kind, overflow.route, overflow.release, overflow.fp, overflow.count], ['2026-10-08:error:/guides/:slug:overflow:overflow', 'error', '/guides/:slug', 'overflow', 'overflow', 2]);
  assert.equal(model.rows.find(row => row.fp === 'f0000001').count, 2, 'a bucket seen before the cap keeps counting');
});

test('admin report groups 30 days by fingerprint with first/last day and per-day totals', async t => {
  const rows = [
    { day: '2026-10-01', kind: 'render', route: '/events/:id', release: 'a5d63fbe3e17', fp: 'abcdef12', count: 2 },
    { day: '2026-10-08', kind: 'render', route: '/events/:id', release: 'a5d63fbe3e17', fp: 'abcdef12', count: 5 },
    { day: '2026-10-08', kind: 'chunk', route: '/', release: 'a5d63fbe3e17', fp: '99999999', count: 1 },
    { day: '2026-10-08', kind: 'render', route: '/not/a/template', release: 'x', fp: 'abcdef12', count: 50 },
    { day: '2026-09-01', kind: 'render', route: '/', release: 'old', fp: 'abcdef12', count: 1000 },
  ];
  const { request } = await fixture(t, { rows });
  assert.equal((await request('/admin/client-errors')).status, 401);
  assert.equal((await request('/admin/client-errors', { as: 'member' })).status, 403);
  const report = await request('/admin/client-errors', { as: 'admin' });
  assert.equal(report.status, 200);
  assert.equal(report.data.from, '2026-09-09'); assert.equal(report.data.through, '2026-10-08');
  assert.equal(report.data.total, 8);
  assert.deepEqual(report.data.groups[0], { kind: 'render', route: '/events/:id', release: 'a5d63fbe3e17', fp: 'abcdef12', count: 7, firstDay: '2026-10-01', lastDay: '2026-10-08' });
  assert.equal(report.data.groups.length, 2);
  assert.deepEqual(report.data.daily, [{ day: '2026-10-01', kind: 'render', count: 2 }, { day: '2026-10-08', kind: 'chunk', count: 1 }, { day: '2026-10-08', kind: 'render', count: 5 }]);
  assert.equal((await request('/admin/client-errors?days=90', { as: 'admin' })).status, 400);
});

test('a flood of old fingerprints never hides the newest days: every row counts and only groups are capped', async t => {
  const rows = [];
  // 25,000 distinct one-off buckets over 25 old days: more than the old 20,000-row read.
  for (let day = 0; day < 25; day++) {
    const date = new Date(Date.parse('2026-09-09T12:00:00Z') + day * 86400000).toISOString().slice(0, 10);
    for (let index = 0; index < 1000; index++) rows.push({ day: date, kind: 'error', route: '/', release: 'old', fp: `f${String(day).padStart(2, '0')}${String(index).padStart(4, '0')}`, count: 1 });
  }
  // A release that broke one page today.
  rows.push({ day: '2026-10-08', kind: 'render', route: '/events/:id', release: 'b1d2e3f4a5c6', fp: 'deadbeef', count: 40 });
  rows.push({ day: '2026-10-07', kind: 'render', route: '/events/:id', release: 'b1d2e3f4a5c6', fp: 'deadbeef', count: 10 });
  rows.push({ day: '2026-10-08', kind: 'error', route: '/', release: 'x', fp: 'abcdef12', count: 'corrupt' });
  const { request } = await fixture(t, { rows });
  const { data } = await request('/admin/client-errors', { as: 'admin' });
  assert.equal(data.total, 25050, 'every valid stored row of the window is counted');
  assert.deepEqual(data.groups[0], { kind: 'render', route: '/events/:id', release: 'b1d2e3f4a5c6', fp: 'deadbeef', count: 50, firstDay: '2026-10-07', lastDay: '2026-10-08' });
  assert.equal(data.groups.length, REPORT_GROUPS);
  assert.equal(data.groupsTruncated, true);
  assert.deepEqual(data.daily.slice(-2), [{ day: '2026-10-07', kind: 'render', count: 10 }, { day: '2026-10-08', kind: 'render', count: 40 }]);
  assert.equal(data.daily.length, 27);
});

test('ClientErrorMetric is a strict bucket with a unique key and a 30-day TTL', () => {
  const Model = createClientErrorMetricModel(mongoose);
  const indexes = Model.schema.indexes();
  assert.ok(indexes.some(([keys, options]) => JSON.stringify(keys) === JSON.stringify({ day: 1, kind: 1, route: 1, release: 1, fp: 1 }) && options.unique));
  assert.ok(indexes.some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.deepEqual(Object.keys(Model.schema.paths).sort(), ['_id', 'count', 'day', 'expiresAt', 'fp', 'kind', 'release', 'route']);
  assert.throws(() => new Model({ _id: 'x', day: '2026-10-08', kind: 'error', route: '/', release: 'dev', fp: 'abcdef12', count: 1, expiresAt: new Date(), stack: 'at x' }), /not in schema/);
  assert.ok(new Model({ _id: 'x', day: '2026-10-08', kind: 'error', route: '/', release: 'dev', fp: 'Error: secret', count: 1, expiresAt: new Date() }).validateSync()?.errors?.fp);
});
