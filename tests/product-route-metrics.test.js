const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { ROUTE_TEMPLATES, routeTemplate } = require('../lib/routeTemplates');
const { PRODUCT_EVENTS, createProductRouteMetricModel, registerProductMetrics } = require('../lib/productMetrics');

const SECRET = 'isolated-product-route-metrics-test-secret';
const NOW = Date.parse('2026-10-08T19:00:00Z');
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
      const chain = { select() { return chain; }, sort() { return chain; }, limit() { return chain; },
        async lean() { return rows.filter(row => row.day >= query.day.$gte && row.day <= query.day.$lte).map(copy); } };
      return chain;
    },
    init: async () => {},
  };
}

async function fixture(t, options = {}) {
  const ProductMetric = options.model || metricModel(options.rows);
  const ProductRouteMetric = options.routeModel || metricModel(options.routeRows);
  const models = { ...createMemoryModels({ User: [
    { id: 'admin', email: 'admin@private.test', role: 'admin', password: 'not-public' },
    { id: 'member', email: 'member@private.test', role: 'user', password: 'not-public' },
  ] }), ProductMetric, ProductRouteMetric };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, productMetricsNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, as, headers = {} } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method,
      headers: { ...headers, ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  return { ProductMetric, ProductRouteMetric, request, post: (body, extras) => request('/product-events', { method: 'POST', body, ...extras }) };
}

test('route strings map to locale-free allowlisted templates and never to a raw path', () => {
  const cases = {
    '/': '/', '/en': '/', '/zh-Hant/': '/', '/events': '/events', '/events/': '/events', '/zh-Hans/events': '/events',
    '/events/fleet-week-2026': '/events/:id', '/events/:id': '/events/:id', '/en/events/fleet-week?date=2026-10-10#map': '/events/:id',
    '/offers/free-pumpkin-oct10': '/offers/:id', '/openings/new-noodle-house': '/openings/:id',
    '/guides/:slug': '/guides/:slug', '/en/guides/dmv-real-id-guide': '/guides/:slug', '/category/:categorySlug': '/category/:slug',
    '/messages/:threadId': '/messages/:id', '/me/bookings': '/me/bookings', '/posts/:postId': '/posts/:id', '/users/abc123': '/users/:id',
    '/opus-bay?from=nav': '/opus-bay', '/calendar?region=sf': '/calendar', '/this-week': '/this-week', '/my-week': '/my-week',
    other: 'other', '/play': 'other', '/recommend': 'other', '/events/a/b': 'other', '/unknown-page': 'other', '/EN/events': 'other',
    'https://www.baylink.us/events': 'other', '//evil.example/events': 'other', 'events': 'other', '': 'other', '/events/a b': 'other',
    '/guides/\\..\\x': 'other', [`/events/${'x'.repeat(161)}`]: 'other', [`/${'a'.repeat(400)}`]: 'other',
  };
  for (const [input, expected] of Object.entries(cases)) assert.equal(routeTemplate(input), expected, input);
  for (const value of [undefined, null, 42, {}, ['/'], true]) assert.equal(routeTemplate(value), null);
  for (const template of ROUTE_TEMPLATES) assert.equal(routeTemplate(template), template, `${template} round-trips`);
  assert.ok(ROUTE_TEMPLATES.length >= 25 && ROUTE_TEMPLATES.length <= 40);
});

test('old payloads without a route still count only in the event/locale totals', async t => {
  const { post, ProductMetric, ProductRouteMetric } = await fixture(t);
  assert.deepEqual((await post({ event: 'page_view', locale: 'en' })).data, { ok: true });
  assert.deepEqual((await post({ event: 'plan_saved' })).data, { ok: true });
  assert.equal(ProductMetric.rows.length, 2);
  assert.equal(ProductRouteMetric.writes.length, 0);
});

test('a route adds one route-template bucket with no path, id, query or identity', async t => {
  const { post, ProductMetric, ProductRouteMetric } = await fixture(t);
  for (const route of ['/events/:id', '/en/events/fleet-week-secret-id?date=2026-10-10', '/events/another-id']) {
    assert.equal((await post({ event: 'page_view', locale: 'en', route }, { as: 'member' })).status, 200);
  }
  assert.equal((await post({ event: 'page_view', locale: 'en', route: '/totally/unknown?email=a@b.c' })).status, 200);
  assert.equal(ProductMetric.rows.length, 1);
  assert.equal(ProductMetric.rows[0].count, 4);
  assert.deepEqual(ProductRouteMetric.rows.map(row => [row.route, row.count]), [['/events/:id', 3], ['other', 1]]);
  for (const row of ProductRouteMetric.rows) {
    assert.deepEqual(Object.keys(row).sort(), ['_id', 'count', 'day', 'event', 'expiresAt', 'locale', 'route']);
    assert.equal(row._id, `2026-10-08:page_view:en:${row.route}`);
    assert.equal(new Date(row.expiresAt).toISOString(), '2027-04-06T00:00:00.000Z');
  }
  const written = JSON.stringify([ProductMetric.writes, ProductRouteMetric.writes]);
  for (const secret of ['fleet-week-secret-id', 'another-id', 'email', '2026-10-10', 'member', '127.0.0.1']) assert.ok(!written.includes(secret), secret);
});

test('a route that is not a string is rejected before any write', async t => {
  const { post, ProductMetric, ProductRouteMetric } = await fixture(t);
  for (const route of [null, 42, { $ne: '' }, ['/'], true]) assert.equal((await post({ event: 'page_view', route })).status, 400, JSON.stringify(route));
  assert.equal((await post({ event: 'page_view', route: '/', url: 'https://x' })).status, 400);
  assert.equal(ProductMetric.writes.length + ProductRouteMetric.writes.length, 0);
});

test('Do Not Track and GPC skip route payloads too', async t => {
  const { post, ProductMetric, ProductRouteMetric } = await fixture(t);
  for (const headers of [{ DNT: '1' }, { 'Sec-GPC': '1' }]) assert.deepEqual((await post({ event: 'page_view', route: '/' }, { headers })).data, { ok: true, skipped: true });
  assert.equal(ProductMetric.writes.length + ProductRouteMetric.writes.length, 0);
});

test('the new latency and feedback events are allowlisted for clients', async t => {
  const { post } = await fixture(t);
  for (const event of ['baybay_latency_lt3', 'baybay_latency_3to8', 'baybay_latency_8to15', 'baybay_latency_gt15', 'feedback_open', 'feedback_sent']) {
    assert.ok(PRODUCT_EVENTS.includes(event));
    assert.equal((await post({ event, route: '/guides/:slug' })).status, 200, event);
  }
});

test('a 20-page journey stays under the per-minute limit with one page_view per route template', async t => {
  const { post, ProductRouteMetric } = await fixture(t);
  const journey = ['/', '/events', '/events/a', '/events/b', '/calendar', '/offers/x', '/openings/y', '/guides', '/guides/a', '/guides/b',
    '/plan', '/my-week', '/me', '/messages', '/together', '/explore', '/tools', '/about', '/archive', '/opus-bay'];
  const statuses = [];
  for (const route of journey) {
    statuses.push((await post({ event: 'page_view', locale: 'zh-Hans', route })).status);
    statuses.push((await post({ event: 'nav_click', locale: 'zh-Hans', route })).status);
  }
  assert.deepEqual([...new Set(statuses)], [200]);
  const pageViews = ProductRouteMetric.rows.filter(row => row.event === 'page_view');
  assert.equal(pageViews.reduce((sum, row) => sum + row.count, 0), 20);
  assert.equal(pageViews.find(row => row.route === '/events/:id').count, 2);
});

test('ingestion has its own limiter: a full auth limiter no longer blocks product events', async t => {
  const app = express(); app.use(express.json());
  const ProductMetric = metricModel(), ProductRouteMetric = metricModel();
  let authChecks = 0;
  registerProductMetrics(app, { ProductMetric, ProductRouteMetric, authenticateToken: (_req, res) => res.status(401).json({}), requireAdmin: () => {},
    checkRateLimit: () => { authChecks++; return false; }, getClientIp: () => 'visitor-key', now: () => NOW });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/product-events`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event: 'page_view', route: '/' }) });
  assert.equal(response.status, 200);
  assert.equal(authChecks, 0);
  assert.equal(ProductRouteMetric.rows.length, 1);
});

test('admin report adds 30-day route totals and per-day route rows; totals survive a route read failure', async t => {
  const rows = [{ day: '2026-10-08', event: 'page_view', locale: 'en', count: 5 }];
  const routeRows = [
    { day: '2026-10-07', event: 'page_view', locale: 'en', route: '/events/:id', count: 2 },
    { day: '2026-10-08', event: 'page_view', locale: 'zh-Hans', route: '/events/:id', count: 3 },
    { day: '2026-10-08', event: 'page_view', locale: 'en', route: '/', count: 4 },
    { day: '2026-10-08', event: 'nav_click', locale: 'en', route: '/', count: 1 },
    { day: '2026-10-08', event: 'page_view', locale: 'en', route: '/raw/path?leak=1', count: 99 },
    { day: '2026-09-01', event: 'page_view', locale: 'en', route: '/', count: 1000 },
  ];
  const { request } = await fixture(t, { rows, routeRows });
  const report = await request('/admin/product-metrics', { as: 'admin' });
  assert.equal(report.status, 200);
  assert.equal(report.data.counts.page_view, 5);
  assert.deepEqual(report.data.routes, [
    { event: 'nav_click', route: '/', count: 1 },
    { event: 'page_view', route: '/events/:id', count: 5 },
    { event: 'page_view', route: '/', count: 4 },
  ]);
  assert.deepEqual(report.data.routeDaily.find(row => row.day === '2026-10-08' && row.route === '/events/:id'), { day: '2026-10-08', event: 'page_view', route: '/events/:id', count: 3 });
  assert.equal(report.data.routesTruncated, false);
  assert.ok(!JSON.stringify(report.data).includes('leak'));
  assert.equal((await request('/admin/product-metrics', { as: 'member' })).status, 403);

  const broken = metricModel(); broken.find = () => { throw new Error('offline'); };
  const degraded = await fixture(t, { rows, routeModel: broken });
  const result = await degraded.request('/admin/product-metrics', { as: 'admin' });
  assert.equal(result.status, 200);
  assert.equal(result.data.counts.page_view, 5);
  assert.equal(result.data.routes, null);
});

test('a route write failure answers 503 like any other storage failure', async t => {
  const routeModel = metricModel(); routeModel.updateOne = async () => { throw new Error('uncertain acknowledgement'); };
  const { post } = await fixture(t, { routeModel });
  assert.equal((await post({ event: 'page_view', route: '/' })).status, 503);
  assert.equal((await post({ event: 'page_view' })).status, 200);
});

test('ProductRouteMetric is a strict deterministic bucket with a unique route key and a TTL', () => {
  const Model = createProductRouteMetricModel(mongoose);
  const indexes = Model.schema.indexes();
  assert.ok(indexes.some(([keys, options]) => JSON.stringify(keys) === JSON.stringify({ day: 1, event: 1, locale: 1, route: 1 }) && options.unique));
  assert.ok(indexes.some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.deepEqual(Object.keys(Model.schema.paths).sort(), ['_id', 'count', 'day', 'event', 'expiresAt', 'locale', 'route']);
  assert.throws(() => new Model({ _id: 'x', day: '2026-10-08', event: 'page_view', locale: 'en', route: '/', count: 1, expiresAt: new Date(), path: '/events/secret' }), /not in schema/);
  const invalid = new Model({ _id: 'x', day: '2026-10-08', event: 'page_view', locale: 'en', route: '/events/secret', count: 1, expiresAt: new Date() });
  assert.ok(invalid.validateSync()?.errors?.route);
});
