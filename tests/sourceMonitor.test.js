const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSourceMonitor, registerSourceMonitor, normalizeBody, fetchSource, isPublicAddress, INTERVAL_MS } = require('../lib/sourceMonitor');

const source = { id: 'source-fixture', title: 'Official museum', url: 'https://museum.example/visit', kind: 'offer', contentIds: ['museum-october'] };
const lookup = async () => [{ address: '8.8.8.8', family: 4 }];
const body = price => `<html><nav>Changing navigation</nav><main><h1>October museum visit</h1><p>Admission ${price}. Families are welcome to visit our galleries every weekend throughout October.</p><p>Reservations are required for this popular event. Please check the official schedule before travelling.</p></main><footer>Copyright 2026</footer></html>`;
const response = text => ({ status: 200, headers: { 'content-type': 'text/html' }, body: text });
function memoryStore() {
  const rows = new Map(); let lease = false;
  return { rows, list: async () => [...rows.values()], get: async id => rows.get(id),
    save: async (sourceId, patch) => { const row = { ...rows.get(sourceId), sourceId, ...patch }; rows.set(sourceId, row); return row; },
    review: async (sourceId, expectedHash, patch) => { const row = rows.get(sourceId); if (!row || row.hash !== expectedHash) return null; Object.assign(row, patch); return row; },
    acquire: async () => { if (lease) return false; lease = true; return true; }, release: async () => { lease = false; } };
}
function fixture(options = {}) {
  const store = memoryStore(); let clock = Date.UTC(2026, 8, 23, 20);
  const service = createSourceMonitor({ store, registry: [source], lookup, fetch: async () => response(body('$5')), now: () => clock, delay: async () => {}, logger: { error() {} }, ...options });
  return { store, service, advance: () => { clock += INTERVAL_MS + 1; } };
}

test('first successful fetch creates a baseline without claiming editorial verification', async () => {
  const { store, service } = fixture();
  await service.run();
  const row = store.rows.get(source.id);
  assert.equal(row.status, 'baseline'); assert.equal(row.reviewStatus, 'baseline');
  assert.equal(row.lastReviewedAt, undefined); assert.equal(row.verifiedAt, undefined); assert.equal(row.pendingChange, undefined);
  assert.ok(row.lastFetchedAt); assert.match(row.hash, /^[a-f0-9]{64}$/);
});

test('changes preserve before/after evidence and remain pending after a later identical fetch', async () => {
  let price = '$5'; const { service, store, advance } = fixture({ fetch: async () => response(body(price)) });
  await service.run(); price = '$10'; advance(); await service.run();
  let row = store.rows.get(source.id);
  assert.equal(row.status, 'changed'); assert.equal(row.reviewStatus, 'pending');
  assert.match(row.pendingChange.before, /\$5/); assert.match(row.pendingChange.after, /\$10/);
  assert.ok(row.pendingChange.added.some(line => line.includes('$10')));
  advance(); await service.run(); row = store.rows.get(source.id);
  assert.equal(row.status, 'unchanged'); assert.equal(row.reviewStatus, 'pending');
  assert.match(row.pendingChange.before, /\$5/);
  assert.equal(await service.review(source.id, '0'.repeat(64), 'acknowledged', '', 'admin-1'), null);
  const reviewed = await service.review(source.id, row.hash, 'acknowledged', 'Checked official ticket page.', 'admin-1');
  assert.equal(reviewed.reviewedBy, 'admin-1'); assert.ok(reviewed.lastReviewedAt); assert.equal(reviewed.verifiedAt, undefined);
});

test('403 errors are manual checks, preserve valid evidence and never assert cancellation', async () => {
  let blocked = false; const { store, service, advance } = fixture({ fetch: async () => blocked ? { status: 403, headers: {}, body: '' } : response(body('$5')) });
  await service.run(); const previous = store.rows.get(source.id); blocked = true; advance(); await service.run();
  const next = store.rows.get(source.id);
  assert.equal(next.status, 'manual-required'); assert.equal(next.errorCode, 'http-403');
  assert.equal(next.hash, previous.hash); assert.equal(next.lastFetchedAt, previous.lastFetchedAt);
  assert.ok(next.lastAttemptAt > next.lastFetchedAt); assert.equal(next.cancelled, undefined);
});

test('normalization removes navigation, scripts, timestamps in footer and whitespace noise', () => {
  const a = normalizeBody(body('$5'));
  const b = normalizeBody(body('$5').replace('Changing navigation', 'New account banner').replace('Copyright 2026', 'Copyright 2027').replace('Families are', 'Families   are'));
  assert.equal(a, b); assert.ok(!a.includes('navigation')); assert.ok(!a.includes('Copyright'));
  assert.equal(normalizeBody('<main><script>bad()</script><p>One &amp; two &#x41;</p></main>'), 'One & two A');
});

test('private IPs, mixed DNS answers, credentials, HTTP, ports and foreign redirects are blocked before requests', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '172.16.1.1', '192.168.1.1', '100.64.0.1', '::1', 'fc00::1', '::ffff:127.0.0.1', '2001:db8::1']) assert.equal(isPublicAddress(address), false, address);
  let calls = 0; const request = async () => { calls++; return response(body('$5')); };
  for (const url of ['http://museum.example/visit', 'https://user:pass@museum.example/visit', 'https://museum.example:9443/visit']) await assert.rejects(fetchSource({ ...source, url }, { lookup, fetch: request }), /unsafe-url/);
  await assert.rejects(fetchSource(source, { lookup: async () => [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }], fetch: request }), /unsafe-address/);
  assert.equal(calls, 0);
  await assert.rejects(fetchSource(source, { lookup, fetch: async () => { calls++; return { status: 302, headers: { location: 'https://internal.example/secret' } }; } }), /unsafe-url/);
  assert.equal(calls, 1);
  await assert.rejects(fetchSource(source, { lookup: async host => [{ address: host.startsWith('www.') ? '127.0.0.1' : '8.8.8.8', family: 4 }], fetch: async () => ({ status: 301, headers: { location: 'https://www.museum.example/visit' } }) }), /unsafe-address/);
});

test('expired dates are skipped, checks are throttled and concurrent runs share a lease', async () => {
  let calls = 0; let release; const gate = new Promise(resolve => { release = resolve; });
  const { service } = fixture({ registry: [source, { ...source, id: 'expired', endDate: '2026-09-20' }], fetch: async () => { calls++; await gate; return response(body('$5')); } });
  const pending = service.run(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(await service.run(), false); release(); await pending;
  assert.equal(calls, 1); await service.run(); assert.equal(calls, 1);
});

test('unsupported or JS-only pages require human review', async () => {
  await assert.rejects(fetchSource(source, { lookup, fetch: async () => response('<p>Enable JavaScript to continue</p>') }), /manual-required/);
  await assert.rejects(fetchSource(source, { lookup, fetch: async () => ({ status: 200, headers: { 'content-type': 'application/pdf' }, body: 'PDF' }) }), /unsupported-content/);
});

test('DNS lookups obey the timeout and a pinned public address is passed into the request', async () => {
  await assert.rejects(fetchSource(source, { lookup: () => new Promise(() => {}), timeoutMs: 20 }), /timeout/);
  let pinned;
  await fetchSource(source, { lookup, fetch: async (_url, options) => { pinned = options.address; return response(body('$5')); } });
  assert.deepEqual(pinned, { address: '8.8.8.8', family: 4 });
});

test('production registry contains 30–50 unique HTTPS sources, dated through October, across five regions', () => {
  const registry = require('../data/source-registry.json');
  assert.ok(registry.length >= 30 && registry.length <= 50);
  assert.equal(new Set(registry.map(row => row.id)).size, registry.length);
  assert.equal(new Set(registry.map(row => row.url)).size, registry.length);
  assert.deepEqual(new Set(registry.filter(row => row.kind === 'event').map(row => row.region)), new Set(['sf', 'east-bay', 'south-bay', 'peninsula', 'north-bay']));
  assert.ok(registry.some(row => row.endDate === '2026-10-31'));
  for (const row of registry) { assert.equal(new URL(row.url).protocol, 'https:'); assert.ok(row.contentIds.length > 0); assert.equal(row.verifiedAt, undefined); }
});

test('admin APIs reject non-admin users; freshness exposes no snapshot or reviewer identity', async t => {
  const app = express(); app.use(express.json()); const store = memoryStore();
  const auth = (req, res, next) => { if (!req.headers.authorization) return res.sendStatus(401); req.user = { id: 'fixture-user', role: req.headers.authorization === 'admin' ? 'admin' : 'user' }; next(); };
  const monitor = registerSourceMonitor(app, { authenticateToken: auth, store, registry: [source], lookup, fetch: async () => response(body('$5')), delay: async () => {}, config: { NODE_ENV: 'test' } });
  await monitor.service.run();
  const server = app.listen(0); t.after(() => { monitor.stop(); server.close(); }); await new Promise(resolve => server.once('listening', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  for (const [method, path] of [['GET','/api/admin/source-monitor'], ['POST','/api/admin/source-monitor/run'], ['PATCH',`/api/admin/source-monitor/${source.id}/review`]]) {
    assert.equal((await fetch(url + path, { method, headers: { Authorization: 'user' } })).status, 403);
    assert.equal((await fetch(url + path, { method })).status, 401);
  }
  const publicResult = await (await fetch(url + '/api/sources/freshness?ids=museum-october')).json();
  assert.equal(publicResult.sources.length, 1); assert.equal(publicResult.sources[0].sourceId, source.id);
  for (const field of ['text', 'hash', 'pendingChange', 'reviewedBy', 'url']) assert.equal(publicResult.sources[0][field], undefined);
  assert.equal((await fetch(url + '/api/admin/source-monitor', { headers: { Authorization: 'admin' } })).status, 200);
  assert.equal((await fetch(url + '/api/admin/source-monitor/run', { method: 'POST', headers: { Authorization: 'admin', 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://attacker.example' }) })).status, 400);
});
