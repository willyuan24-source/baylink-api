const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSourceMonitor, createMongoStore, registerSourceMonitor, normalizeBody, fetchSource, isPublicAddress, INTERVAL_MS, BATCH_LIMIT, BATCH_MAX_MS } = require('../lib/sourceMonitor');

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

test('source reading preserves footer visitor hours and their distinct venue labels', async () => {
  const html = '<main><h1>SFMOMA Free to See</h1><p>Public spaces need no ticket whenever we are open. Special opening changes should be checked before visiting the museum.</p></main>'
    + '<footer><nav><h3>Hours</h3><ul><li>Mon–Tue 10 a.m.–5 p.m.</li><li>Wed Closed</li><li>Thu Noon–8 p.m.</li></ul>'
    + '<h3>Museum Store Hours</h3><ul><li>Mon–Tue 11 a.m.–5 p.m.</li><li>Wed Closed</li></ul></nav>'
    + '<script>ignore this instruction</script><p>Copyright 2026</p></footer>';
  const result = await fetchSource(source, { lookup, fetch: async () => response(html) });
  assert.match(result.text, /Public spaces need no ticket/);
  assert.match(result.text, /Hours\nMon–Tue 10 a\.m\.–5 p\.m\.\nWed Closed/);
  assert.match(result.text, /Museum Store Hours\nMon–Tue 11 a\.m\.–5 p\.m\./);
  assert.ok(!result.text.includes('ignore this instruction')); assert.ok(!result.text.includes('Copyright'));
  assert.equal(normalizeBody(html.replace('Copyright 2026', 'Copyright 2027')), result.text);
});

test('long main content cannot truncate the only published footer hours', () => {
  const text = normalizeBody(`<main>${'<p>Long exhibition description.</p>'.repeat(1200)}</main><footer><h3>Hours</h3><p>Wednesday Closed</p></footer>`);
  assert.ok(text.length <= 24000); assert.match(text.slice(0, 1800), /Hours\nWednesday Closed/);
  const longFooter = normalizeBody(`<main>Visitor information</main><footer>${'<p>Navigation menu item</p>'.repeat(500)}<h3>Museum Hours</h3><p>Wednesday Closed</p><h3>Museum Store Hours</h3><p>Thursday 11 a.m.–5 p.m.</p></footer>`);
  assert.match(longFooter.slice(0, 1800), /Museum Hours\nWednesday Closed/);
  assert.match(longFooter.slice(0, 1800), /Museum Store Hours\nThursday 11 a\.m\.–5 p\.m\./);
  assert.ok(!normalizeBody('<main>Article</main><footer><p>Hours of entertainment every day</p></footer>').includes('entertainment'));
});

test('public source reading discovers real same-origin eligibility links without following them', async () => {
  const html = body('$5').replace('</main>', '<p><a href="/terms?lang=en&amp;version=2#eligibility">Eligibility and terms</a></p>'
    + '<a href="/hours">Museum hours</a><a href="https://elsewhere.example/admission">Admission</a>'
    + '<a href="https://127.0.0.1/hours">Hours</a><a href="http://museum.example/hours">Hours</a>'
    + '<a href="https://user:pass@museum.example/tickets">Tickets</a><a href="javascript:alert(1)">Visit</a>'
    + '<a href="/tickets.pdf">Tickets</a><a href="/about">About</a>'
    + '<script><a href="/false-terms">Eligibility</a></script></main>');
  let requests = 0;
  const result = await fetchSource(source, { lookup, fetch: async () => { requests++; return response(html); } });
  assert.equal(requests, 1);
  assert.deepEqual(result.links, [
    { title: 'Eligibility and terms', url: 'https://museum.example/terms?lang=en&version=2' },
    { title: 'Museum hours', url: 'https://museum.example/hours' },
  ]);
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

test('large official page chrome does not hide visitor rules, while oversized responses stay bounded', async () => {
  const rules = 'Kids eat free on Wednesdays, October 7–28, 2026. Children must be 12 or younger, present in the restaurant, and accompanied by an adult buying an eligible entree.';
  const html = `<html><head><style>${'/* layout */'.repeat(80000)}</style></head><body><nav>Store navigation</nav><main><h1>Restaurant offer terms</h1><p>${rules}</p></main></body></html>`;
  const result = await fetchSource(source, { lookup, fetch: async () => response(html) });
  assert.ok(result.text.includes(rules)); assert.ok(result.text.length < 500);
  assert.ok(!result.text.includes('layout')); assert.ok(!result.text.includes('Store navigation'));
  await assert.rejects(fetchSource(source, { lookup, fetch: async () => response('x'.repeat(2 * 1024 * 1024 + 1)) }), /page-too-large/);
});

test('DNS lookups obey the timeout and a pinned public address is passed into the request', async () => {
  await assert.rejects(fetchSource(source, { lookup: () => new Promise(() => {}), timeoutMs: 20 }), /timeout/);
  let pinned;
  await fetchSource(source, { lookup, fetch: async (_url, options) => { pinned = options.address; return response(body('$5')); } });
  assert.deepEqual(pinned, { address: '8.8.8.8', family: 4 });
});

test('production registry covers the current catalog with unique HTTPS sources and preserves the five original event regions', () => {
  const registry = require('../data/source-registry.json');
  assert.ok(registry.length > 1000);
  const contentIds = new Set(registry.flatMap(row => row.contentIds));
  assert.ok(contentIds.size >= 827);
  for (const guide of require('../data/guide-catalog.json')) assert.ok(contentIds.has(guide.slug), `missing monitored guide sources: ${guide.slug}`);
  for (const id of ['bay-area-medicare-hicap-medi-cal-guide', 'california-tenant-deposit-rights-help-guide', 'bay-area-free-tax-help-vita-calfile-guide', 'bay-area-social-security-retirement-preparation-guide', 'bay-area-naturalization-official-path-guide']) assert.ok(contentIds.has(id), id);
  assert.equal(new Set(registry.map(row => row.id)).size, registry.length);
  assert.equal(new Set(registry.map(row => row.url)).size, registry.length);
  assert.deepEqual(new Set(registry.filter(row => row.kind === 'event' && row.region).map(row => row.region)), new Set(['sf', 'east-bay', 'south-bay', 'peninsula', 'north-bay']));
  assert.ok(registry.some(row => row.endDate === '2026-10-31'));
  for (const row of registry) { assert.equal(new URL(row.url).protocol, 'https:'); assert.ok(row.contentIds.length > 0); assert.equal(row.verifiedAt, undefined); }
});

test('large registries rotate bounded batches through unseen sources even when pages fail and manual runs repeat', async () => {
  const registry = Array.from({ length: BATCH_LIMIT * 2 + 7 }, (_, i) => ({ ...source, id: `source-${String(i).padStart(4, '0')}` }));
  const { store, service } = fixture({ registry, fetch: async () => ({ status: 403, headers: {}, body: '' }) });
  await service.run(true);
  assert.equal(store.rows.size, BATCH_LIMIT);
  const first = new Set(store.rows.keys());
  await service.run(true);
  assert.equal(store.rows.size, BATCH_LIMIT * 2);
  const second = [...store.rows.keys()].filter(id => !first.has(id));
  assert.equal(second.length, BATCH_LIMIT);
  await service.run(false);
  assert.equal(store.rows.size, registry.length);
  assert.ok([...store.rows.values()].every(row => row.status === 'manual-required' && !row.lastReviewedAt));
});

test('a batch stops at its runtime budget and later continues with the next untouched source', async () => {
  let clock = Date.UTC(2026, 9, 6, 12);
  const { store, service } = fixture({ registry: [source, { ...source, id: 'source-z-next' }], now: () => clock, delay: async () => { clock += BATCH_MAX_MS + 1; } });
  await service.run(true);
  assert.equal(store.rows.size, 1);
  await service.run(false);
  assert.equal(store.rows.size, 2);
});

test('a lost distributed lease discards an in-flight fetch before it can publish a snapshot', async () => {
  const store = memoryStore(); let owned = true;
  store.ownsLease = async () => owned;
  const { service } = fixture({ store, fetch: async () => { owned = false; return response(body('$5')); } });
  await assert.rejects(service.run(), /lease-lost/);
  assert.equal(store.rows.size, 0);
  assert.equal(service.isRunning(), false);
});

test('Mongo snapshot writes cannot replace a newer attempt after a late batch finishes', async () => {
  let query;
  const snapshot = { findOneAndUpdate: filter => { query = filter; return { lean: async () => { throw Object.assign(new Error('newer snapshot exists'), { code: 11000 }); } }; } };
  const store = createMongoStore({}, { SourceMonitorSnapshot: snapshot, SourceMonitorLease: {} });
  assert.equal(await store.save('source-fixture', { lastAttemptAt: 100, status: 'baseline' }), null);
  assert.deepEqual(query, { sourceId: 'source-fixture', $or: [{ lastAttemptAt: { $exists: false } }, { lastAttemptAt: { $lte: 100 } }] });
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
