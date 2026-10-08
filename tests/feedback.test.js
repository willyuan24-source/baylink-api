const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { FEEDBACK_REASONS, GLOBAL_DAILY_LIMIT, createFeedbackModels, registerFeedback } = require('../lib/feedback');

const SECRET = 'isolated-feedback-test-secret';
const NOW = Date.parse('2026-10-08T19:00:00Z');
const copy = value => structuredClone(value);

function feedbackModel({ failCreate = false } = {}) {
  const rows = [];
  const matches = (row, filter) => (!filter.kind || row.kind === filter.kind) && (!filter.createdAt || row.createdAt < filter.createdAt.$lt);
  return {
    rows,
    async create(document) { if (failCreate) throw new Error('write concern timeout'); rows.push(copy(document)); return document; },
    find(filter) {
      let maximum = Infinity;
      const chain = { select() { return chain; }, sort() { return chain; }, limit(value) { maximum = value; return chain; },
        async lean() { return rows.filter(row => matches(row, filter)).sort((a, b) => b.createdAt - a.createdAt).slice(0, maximum).map(copy); } };
      return chain;
    },
    async deleteOne({ _id }) { const index = rows.findIndex(row => row._id === _id); if (index >= 0) rows.splice(index, 1); return { deletedCount: index >= 0 ? 1 : 0 }; },
    init: async () => {},
  };
}
function quotaModel(seed = []) {
  const rows = seed.map(copy);
  return {
    rows,
    async updateOne({ _id }, update, options) { if (!rows.some(row => row._id === _id) && options.upsert) rows.push({ _id, ...copy(update.$setOnInsert) }); return {}; },
    async findOneAndUpdate({ _id, count }, update) {
      const row = rows.find(item => item._id === _id && item.count < count.$lt);
      if (!row) return null;
      row.count += update.$inc.count;
      return copy(row);
    },
    init: async () => {},
  };
}

async function fixture(t, options = {}) {
  const Feedback = options.feedback || feedbackModel(), FeedbackQuota = options.quota || quotaModel();
  const models = { ...createMemoryModels({ User: [
    { id: 'admin', email: 'admin@private.test', role: 'admin', password: 'not-public' },
    { id: 'member', email: 'member@private.test', role: 'user', password: 'not-public' },
  ] }), Feedback, FeedbackQuota };
  let now = NOW;
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, feedbackNow: () => now });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, { method = 'GET', body, as } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method,
      headers: { ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, data: await response.json() };
  };
  return { Feedback, FeedbackQuota, request, post: body => request('/feedback', { method: 'POST', body }), setNow: value => { now = value; } };
}

/** registerFeedback on a bare app with the per-minute limiter disabled, to exercise the daily quotas. */
async function quotaFixture(t, { quota = quotaModel(), visitor = () => '203.0.113.7', now = () => NOW } = {}) {
  const app = express(); app.use(express.json());
  const Feedback = feedbackModel();
  registerFeedback(app, { mongoose, models: { Feedback, FeedbackQuota: quota }, secret: SECRET, authenticateToken: (_req, res) => res.status(401).json({}),
    requireAdmin: () => {}, getClientIp: req => visitor(req), now, limiter: { check: () => true } });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async body => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/feedback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  return { Feedback, quota, post };
}

const page = { kind: 'page', routeTemplate: '/guides/:slug', reason: 'get-help', text: '找不到 Medi-Cal 申请入口', locale: 'zh-Hans', readingSize: 'large', release: 'a5d63fbe3e1733fd94f4071ab3f0c94a49b2e222', website: '' };

test('page, content and BayBay feedback are stored with allowlisted fields and answer 202', async t => {
  const { post, Feedback } = await fixture(t);
  assert.deepEqual((await post(page)).data, { ok: true });
  assert.equal((await post({ kind: 'content', routeTemplate: '/en/events/fleet-week-2026?date=2026-10-10', reason: 'wrong-time', text: '  Parade starts at 11, not 12.\r\nSee official page.  ',
    contact: ' reader@example.com ', entity: { kind: 'event', id: 'fleet-week-2026' }, locale: 'en' })).status, 202);
  assert.equal((await post({ kind: 'baybay', reason: 'too-slow' })).status, 202);
  assert.equal(Feedback.rows.length, 3);
  const [first, second, third] = Feedback.rows;
  assert.deepEqual(Object.keys(first).sort(), ['_id', 'createdAt', 'expiresAt', 'kind', 'locale', 'readingSize', 'reason', 'release', 'route', 'text']);
  assert.equal(first.route, '/guides/:slug'); assert.equal(first.release, 'a5d63fbe3e17'); assert.equal(first.readingSize, 'large');
  assert.match(first._id, /^[0-9a-f-]{36}$/);
  assert.equal(new Date(first.expiresAt) - new Date(first.createdAt), 90 * 86400000);
  assert.equal(second.route, '/events/:id');
  assert.equal(second.text, 'Parade starts at 11, not 12.\nSee official page.');
  assert.equal(second.contact, 'reader@example.com');
  assert.deepEqual(second.entity, { kind: 'event', id: 'fleet-week-2026' });
  assert.deepEqual([third.route, third.text, third.locale, third.readingSize, third.release, third.contact, third.entity], ['other', '', 'zh-Hans', 'standard', 'unknown', undefined, undefined]);
  const stored = JSON.stringify(Feedback.rows);
  for (const secret of ['127.0.0.1', '2026-10-10', '/en/', 'website']) assert.ok(!stored.includes(secret), secret);
});

test('every documented reason is accepted only under its own kind', () => {
  const { normalizeFeedback } = require('../lib/feedback');
  for (const [kind, reasons] of Object.entries(FEEDBACK_REASONS)) {
    for (const reason of reasons) assert.ok(normalizeFeedback({ kind, reason }), `${kind}/${reason}`);
    for (const other of Object.values(FEEDBACK_REASONS).flat().filter(reason => !reasons.includes(reason))) assert.equal(normalizeFeedback({ kind, reason: other }), null, `${kind}/${other}`);
  }
});

test('unknown fields, wrong types and overlong text are rejected before any write', async t => {
  const { post, Feedback, quota } = await quotaFixture(t);
  const invalid = [[], {}, { ...page, kind: 'bug' }, { ...page, reason: 'wrong-answer' }, { ...page, reason: undefined },
    ...['url', 'userId', 'ip', 'email', 'stack', 'createdAt', '_id', 'route'].map(field => ({ ...page, [field]: 'private' })),
    { ...page, text: 'x'.repeat(501) }, { ...page, text: 42 }, { ...page, contact: 'c'.repeat(81) }, { ...page, contact: { email: 'a@b.c' } },
    { ...page, entity: { kind: 'user', id: 'abc' } }, { ...page, entity: { kind: 'event', id: '../etc' } }, { ...page, entity: { kind: 'event', id: 'ok', title: 'extra' } }, { ...page, entity: ['event', 'x'] },
    { ...page, locale: 'fr' }, { ...page, readingSize: 'huge' }, { ...page, routeTemplate: 42 }, { ...page, release: ['x'] }, { ...page, website: 1 },
  ];
  for (const body of invalid) {
    const response = await post(body);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(response.data.code, 'FEEDBACK_INVALID');
  }
  assert.equal(Feedback.rows.length, 0);
  assert.equal(quota.rows.length, 0);
  // Non-object JSON is refused by the strict body parser of the real server.
  const server = await fixture(t);
  for (const body of [null, 'text']) assert.equal((await server.post(body)).status, 400, JSON.stringify(body));
  assert.equal(server.Feedback.rows.length, 0);
});

test('text counts characters, keeps line breaks and drops control and bidi-override characters', async t => {
  const { post, Feedback } = await fixture(t);
  assert.equal((await post({ ...page, text: '😀'.repeat(500) })).status, 202, '500 emoji are 500 characters');
  assert.equal((await post({ ...page, text: 'ok\u0000\u0007 line‮⁦ two\n三' })).status, 202);
  assert.equal(Feedback.rows[1].text, 'ok line two\n三');
});

test('a filled honeypot looks accepted but writes nothing, not even a quota row', async t => {
  const { post, Feedback, FeedbackQuota } = await fixture(t);
  assert.deepEqual(await post({ ...page, website: 'http://spam.example' }), { status: 202, data: { ok: true } });
  assert.equal(Feedback.rows.length, 0);
  assert.equal(FeedbackQuota.rows.length, 0);
});

test('a visitor gets 5 submissions a minute', async t => {
  const { post } = await fixture(t);
  for (let index = 0; index < 5; index++) assert.equal((await post(page)).status, 202);
  const limited = await post(page);
  assert.equal(limited.status, 429);
  assert.equal(limited.data.code, 'FEEDBACK_RATE_LIMIT');
});

test('a visitor gets 10 a day, keyed only by an HMAC of the day and visitor key', async t => {
  let now = NOW;
  const { post, quota, Feedback } = await quotaFixture(t, { now: () => now });
  for (let index = 0; index < 10; index++) assert.equal((await post(page)).status, 202);
  const limited = await post(page);
  assert.equal(limited.status, 429);
  assert.equal(limited.data.code, 'FEEDBACK_DAILY_LIMIT');
  assert.equal(Feedback.rows.length, 10);
  const expected = crypto.createHmac('sha256', SECRET).update('feedback:v1:2026-10-08:203.0.113.7').digest('hex');
  assert.deepEqual(quota.rows.map(row => [row._id, row.count]), [[`2026-10-08:visitor:${expected}`, 10], ['2026-10-08:global', 10]]);
  assert.ok(!JSON.stringify([quota.rows, Feedback.rows]).includes('203.0.113'), 'the visitor key itself is never stored');
  // The next Pacific day is a new, unlinkable bucket.
  now = Date.parse('2026-10-09T08:00:00Z');
  assert.equal((await post(page)).status, 202);
  assert.ok(quota.rows.some(row => row._id.startsWith('2026-10-09:visitor:') && !row._id.endsWith(expected)));
});

test('the global daily cap answers 429 once 500 entries were accepted', async t => {
  const quota = quotaModel([{ _id: '2026-10-08:global', count: GLOBAL_DAILY_LIMIT, expiresAt: new Date(NOW + 2 * 86400000) }]);
  const { post, Feedback } = await quotaFixture(t, { quota });
  const response = await post(page);
  assert.equal(response.status, 429);
  assert.equal(response.data.code, 'FEEDBACK_GLOBAL_LIMIT');
  assert.equal(Feedback.rows.length, 0);
});

test('storage failures answer 503 without echoing the error', async t => {
  const { post } = await fixture(t, { feedback: feedbackModel({ failCreate: true }) });
  const response = await post(page);
  assert.equal(response.status, 503);
  assert.equal(response.data.code, 'FEEDBACK_UNAVAILABLE');
  assert.ok(!JSON.stringify(response.data).includes('write concern'));
});

test('admins page through feedback newest first, filter by kind and delete entries', async t => {
  const { post, request, setNow, Feedback } = await fixture(t);
  setNow(Date.parse('2026-10-08T10:00:00Z')); await post({ ...page, text: 'first' });
  setNow(Date.parse('2026-10-08T11:00:00Z')); await post({ kind: 'content', reason: 'closed', entity: { kind: 'opening', id: 'new-noodle-house' }, contact: 'wechat: reader88' });
  setNow(Date.parse('2026-10-08T12:00:00Z')); await post({ kind: 'baybay', reason: 'wrong-answer', text: 'third' });
  assert.equal((await request('/admin/feedback')).status, 401);
  assert.equal((await request('/admin/feedback', { as: 'member' })).status, 403);
  const all = await request('/admin/feedback', { as: 'admin' });
  assert.equal(all.status, 200);
  assert.deepEqual(all.data.items.map(item => item.text || item.reason), ['third', 'closed', 'first']);
  assert.deepEqual(Object.keys(all.data.items[1]), ['id', 'kind', 'reason', 'route', 'text', 'contact', 'entity', 'locale', 'readingSize', 'release', 'createdAt']);
  assert.equal(all.data.items[1].contact, 'wechat: reader88');
  assert.equal(all.data.retentionDays, 90);
  const content = await request('/admin/feedback?kind=content', { as: 'admin' });
  assert.deepEqual(content.data.items.map(item => item.kind), ['content']);
  const firstPage = await request('/admin/feedback?limit=2', { as: 'admin' });
  assert.equal(firstPage.data.items.length, 2);
  assert.equal(firstPage.data.nextBefore, '2026-10-08T11:00:00.000Z');
  const secondPage = await request(`/admin/feedback?limit=2&before=${encodeURIComponent(firstPage.data.nextBefore)}`, { as: 'admin' });
  assert.deepEqual(secondPage.data.items.map(item => item.text), ['first']);
  assert.equal(secondPage.data.nextBefore, undefined);
  for (const query of ['?kind=spam', '?limit=0', '?limit=201', '?before=yesterday', '?userId=x']) assert.equal((await request(`/admin/feedback${query}`, { as: 'admin' })).status, 400, query);
  const id = all.data.items[0].id;
  assert.equal((await request(`/admin/feedback/${id}`, { method: 'DELETE', as: 'member' })).status, 403);
  assert.deepEqual((await request(`/admin/feedback/${id}`, { method: 'DELETE', as: 'admin' })).data, { ok: true });
  assert.equal((await request(`/admin/feedback/${id}`, { method: 'DELETE', as: 'admin' })).status, 404);
  assert.equal((await request('/admin/feedback/not-an-id', { method: 'DELETE', as: 'admin' })).status, 400);
  assert.equal(Feedback.rows.length, 2);
});

test('Feedback and FeedbackQuota are strict with a 90-day and 2-day TTL; entity is strict too', () => {
  const { Feedback, FeedbackQuota } = createFeedbackModels(mongoose);
  assert.ok(Feedback.schema.indexes().some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  assert.ok(FeedbackQuota.schema.indexes().some(([keys, options]) => keys.expiresAt === 1 && options.expireAfterSeconds === 0));
  const base = { _id: crypto.randomUUID(), kind: 'page', reason: 'other', route: '/', locale: 'en', readingSize: 'standard', release: 'dev', createdAt: new Date(), expiresAt: new Date() };
  assert.equal(new Feedback(base).validateSync(), undefined);
  assert.throws(() => new Feedback({ ...base, ip: '203.0.113.7' }), /not in schema/);
  assert.ok(new Feedback({ ...base, entity: { kind: 'event', id: 'x', url: 'https://x' } }).validateSync()?.errors?.entity, 'extra entity keys fail validation');
  assert.ok(new Feedback({ ...base, route: '/events/fleet-week' }).validateSync()?.errors?.route);
  assert.throws(() => new FeedbackQuota({ _id: 'x', count: 1, expiresAt: new Date(), ip: 'x' }), /not in schema/);
});
