const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { CLOUDFLARE_IP_CIDRS, parseIp, clientKey, addressPrefix, cloudflareRanges, clientIpSource, forwardedFor, resolveClientIp, diagnosticWindow, createClientIp } = require('../lib/clientIp');
const SECRET = 'isolated-client-ip-secret';
const NOW = Date.parse('2026-10-08T19:00:00Z');
const VISITOR = '203.0.113.9';
const OTHER_VISITOR = '203.0.113.10';
// Published Cloudflare addresses (162.158.0.0/15, 172.64.0.0/13, 104.16.0.0/13) and one that is not.
const EDGES = ['162.158.1.2', '172.70.3.4', '104.23.0.9'];
const NOT_CLOUDFLARE = '198.51.100.20';
const MESSAGES = ['周末带孩子去哪里玩比较好？', '湾区有什么适合老人散步的公园？', '推荐几个圣何塞的亲子景点', '弗里蒙特有什么好吃的早餐', '雨天在湾区可以去哪些室内地方？', '有哪些适合拍照的海边步道？'];
const final = answer => ({ model: 'fixture-baybay', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
// What Render receives behind Cloudflare: Cloudflare appends the visitor, Render appends the edge.
const viaCloudflare = (edge, visitor = VISITOR, extra = {}) => ({ 'X-Forwarded-For': `${visitor}, ${edge}`, 'CF-Connecting-IP': visitor, 'CF-Ray': '8c0000000000abcd-SJC', ...extra });
// CLIENT_IP_SOURCE settings that mean "cloudflare": the default (key absent), empty, and explicit.
const UNSET = Symbol('unset');
const ON = [UNSET, '', '  ', 'cloudflare'];
const OFF = ['off', ' OFF ', 'express'];
const sourceConfig = source => (source === UNSET ? {} : { CLIENT_IP_SOURCE: source });
const label = source => (source === UNSET ? 'unset' : JSON.stringify(source));

async function fixture(t, options = {}) {
  const models = options.models || createMemoryModels();
  const lines = [];
  let calls = 0, asked = 0;
  const app = createApplication({ ...options, models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, OPENAI_API_KEY: 'test-key-never-print', TRUST_PROXY_HOPS: 1, ...options.config },
    plannerNow: options.plannerNow || (() => NOW), clientIpLog: line => lines.push(line),
    ai: { baybay: async () => { calls++; return final('已参考站内资料，这是测试回答。'); } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const raw = (path, { body, headers = {} } = {}) => fetch(`http://127.0.0.1:${app.server.address().port}/api${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const request = async (path, options) => { const response = await raw(path, options); return { status: response.status, data: await response.json(), headers: response.headers }; };
  const read = async headers => { const result = await request('/ai/usage', { headers }); assert.equal(result.status, 200); return result.data.remaining; };
  // A guest BayBay ask that really reaches the (stubbed) provider, so it reserves exactly one unit.
  const ask = async headers => {
    const before = calls;
    const result = await request('/ai/guide-chat', { headers, body: { assistantVersion: 2, searchMode: 'site', message: MESSAGES[asked++ % MESSAGES.length] } });
    assert.equal(result.status, 200); assert.equal(result.data.responseMode, 'assistant'); assert.equal(result.data.degraded, false);
    assert.equal(calls, before + 1, 'the ask must call the provider once, so it reserves quota');
    return result;
  };
  const identities = () => Object.values(models.AiGovernance.rows[0]?.identities || {});
  return { raw, request, read, ask, models, lines, identities };
}

// Mirrors the Express request shape: ip from the trust setting, ips = trusted XFF hops.
const fakeRequest = ({ ip, ips = [ip], socket = '10.1.2.3', headers = {}, path = '/api/health', method = 'GET', query = {} }) => ({ ip, ips, socket: { remoteAddress: socket }, headers, path, method, query });
const untouchable = () => new Proxy({}, { get() { throw new Error('request must not be read'); }, defineProperty() { throw new Error('request must not be modified'); } });

test('keys: IPv4 as-is, IPv6 per /64, IPv4-mapped unwrapped, pseudo-IPv4 accepted, malformed rejected', () => {
  assert.equal(clientKey(VISITOR), VISITOR);
  assert.equal(clientKey('::ffff:203.0.113.9'), VISITOR);
  assert.equal(clientKey('::FFFF:cb00:7109'), VISITOR);
  assert.equal(clientKey('0:0:0:0:0:ffff:cb00:7109'), VISITOR);
  assert.equal(clientKey('2001:db8:abcd:12::1'), '2001:db8:abcd:12::/64');
  assert.equal(clientKey('2001:db8:abcd:12::ffff'), '2001:db8:abcd:12::/64');
  assert.equal(clientKey('2001:DB8:ABCD:0012:0:0:0:1'), '2001:db8:abcd:12::/64');
  assert.notEqual(clientKey('2001:db8:abcd:13::1'), clientKey('2001:db8:abcd:12::1'));
  assert.equal(clientKey('::'), '0:0:0:0::/64');
  assert.equal(clientKey('64:ff9b::203.0.113.9'), '64:ff9b:0:0::/64');
  assert.equal(clientKey('240.12.34.56'), '240.12.34.56', 'Cloudflare pseudo-IPv4 (Class E) is a valid key');
  for (const bad of ['forged', '1.2.3.4, 5.6.7.8', '', ' 203.0.113.9', '203.0.113.9 ', '01.2.3.4', '203.0.113.9:443', 'fe80::1%eth0', `${'1'.repeat(40)}::1`, undefined, null, ['203.0.113.9'], 203]) {
    assert.equal(clientKey(bad), null, String(bad));
    assert.equal(parseIp(bad), null, String(bad));
  }
  assert.equal(addressPrefix(VISITOR), '203.0.113.0/24');
  assert.equal(addressPrefix('::ffff:203.0.113.9'), '203.0.113.0/24');
  assert.equal(addressPrefix('2001:db8:abcd:12::1'), '2001:db8:abcd::/48');
  assert.equal(addressPrefix('forged'), null);
  assert.deepEqual(forwardedFor({ headers: { 'x-forwarded-for': ' a ,, b,  ,c ' } }), ['a', 'b', 'c']);
  assert.deepEqual(forwardedFor({ headers: {} }), []);
});

test('Cloudflare ranges: dated published list, IPv4-mapped edges and an explicit override', () => {
  assert.ok(Object.isFrozen(CLOUDFLARE_IP_CIDRS));
  assert.equal(CLOUDFLARE_IP_CIDRS.length, 22);
  const published = cloudflareRanges();
  for (const edge of EDGES) assert.equal(published.check(edge, 'ipv4'), true, edge);
  assert.equal(published.check('2606:4700:10::6816:1', 'ipv6'), true);
  assert.equal(published.check(NOT_CLOUDFLARE, 'ipv4'), false);
  // A mapped edge address must still pass the Cloudflare gate.
  const mapped = resolveClientIp(fakeRequest({ ip: '::ffff:172.70.3.4', headers: { 'cf-connecting-ip': VISITOR } }), { source: 'cloudflare' });
  assert.deepEqual(mapped, { key: VISITOR, from: 'cf-connecting-ip', address: VISITOR });
  const override = cloudflareRanges(' 198.51.100.0/24, 2001:db8::/32 ');
  assert.equal(override.check(NOT_CLOUDFLARE, 'ipv4'), true);
  assert.equal(override.check('2001:db8::1', 'ipv6'), true);
  assert.equal(override.check(EDGES[0], 'ipv4'), false, 'the override replaces the published list');
  assert.equal(cloudflareRanges('').check(EDGES[0], 'ipv4'), true, 'empty override keeps the published list');
  for (const bad of ['198.51.100.0/33', '198.51.100.0', 'not-a-cidr/8', '2001:db8::/129', '198.51.100.0/24/1']) assert.throws(() => cloudflareRanges(bad), /CLOUDFLARE_IP_CIDRS/, bad);
});

test('CLIENT_IP_SOURCE: unset or empty means cloudflare, off/express disable it, anything else stops startup', () => {
  for (const source of ON) assert.equal(clientIpSource(sourceConfig(source)), 'cloudflare', label(source));
  assert.equal(clientIpSource(), 'cloudflare');
  assert.equal(clientIpSource({ CLIENT_IP_SOURCE: undefined }), 'cloudflare');
  assert.equal(clientIpSource({ CLIENT_IP_SOURCE: null }), 'cloudflare');
  assert.equal(clientIpSource({ CLIENT_IP_SOURCE: ' Cloudflare ' }), 'cloudflare');
  for (const source of [...OFF, 'Off', 'EXPRESS']) assert.equal(clientIpSource({ CLIENT_IP_SOURCE: source }), null, source);
  for (const bad of ['true', 'false', 'on', '0', '1', 'none', 'disabled', 'cloudflare-xff', 'x-forwarded-for', 'cf-connecting-ip', 'cloudflare,off', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.throws(() => clientIpSource({ CLIENT_IP_SOURCE: bad }), /CLIENT_IP_SOURCE must be empty, "cloudflare", "off" or "express"/, bad);
  }
  for (const bad of ['yes', 'disabled']) assert.throws(() => createApplication({ models: createMemoryModels(), config: { NODE_ENV: 'test', JWT_SECRET: SECRET, CLIENT_IP_SOURCE: bad } }), /CLIENT_IP_SOURCE/, bad);
});

test('resolver honours client headers only behind a published Cloudflare hop', () => {
  const on = { source: 'cloudflare' };
  const resolve = (shape, settings = on) => resolveClientIp(fakeRequest(shape), settings);
  // Source off (null): Express req.ip verbatim, including IPv6 and mapped forms.
  for (const ip of ['2001:db8:abcd:12::1', '::ffff:203.0.113.9', 'forged']) assert.deepEqual(resolve({ ip, headers: { 'cf-connecting-ip': VISITOR } }, {}), { key: ip, from: 'express', address: ip });
  assert.equal(resolve({ ip: EDGES[0], headers: { 'cf-connecting-ip': VISITOR } }).key, VISITOR);
  assert.equal(resolve({ ip: '2606:4700:10::6816:1', headers: { 'cf-connecting-ip': '2001:db8:abcd:12::1' } }).key, '2001:db8:abcd:12::/64');
  assert.equal(resolve({ ip: EDGES[0], headers: { 'cf-connecting-ip': '240.12.34.56' } }).key, '240.12.34.56');
  // Not a Cloudflare hop: forged CF-Connecting-IP and leftmost XFF are ignored.
  assert.deepEqual(resolve({ ip: NOT_CLOUDFLARE, headers: { 'cf-connecting-ip': VISITOR, 'x-forwarded-for': `${VISITOR}, ${NOT_CLOUDFLARE}` } }), { key: NOT_CLOUDFLARE, from: 'edge-not-cloudflare', address: NOT_CLOUDFLARE });
  assert.deepEqual(resolve({ ip: '10.0.0.5', headers: { 'cf-connecting-ip': VISITOR, 'x-forwarded-for': `${VISITOR}, ${EDGES[0]}, 10.0.0.5` } }), { key: '10.0.0.5', from: 'edge-not-cloudflare', address: '10.0.0.5' }, 'a Render-internal hop needs TRUST_PROXY_HOPS=2');
  // No CF-Connecting-IP: the entry Cloudflare appended immediately left of the edge, never further left.
  assert.deepEqual(resolve({ ip: EDGES[0], headers: { 'x-forwarded-for': `forged, 198.18.0.1, ${VISITOR}, ${EDGES[0]}` } }), { key: VISITOR, from: 'xff-left-of-edge', address: VISITOR });
  // TRUST_PROXY_HOPS=2 shape: Render's own hop is trusted, the Cloudflare edge becomes req.ip.
  assert.equal(resolve({ ip: EDGES[0], ips: [EDGES[0], '10.0.0.5'], headers: { 'x-forwarded-for': `${VISITOR}, ${EDGES[0]}, 10.0.0.5` } }).key, VISITOR);
  // Trust disabled and Cloudflare connected directly: the socket is the edge.
  assert.equal(resolve({ ip: EDGES[0], ips: [], socket: EDGES[0], headers: { 'x-forwarded-for': VISITOR } }).key, VISITOR);
  // Malformed client headers are ignored and fall back to the next source, then the edge.
  for (const header of ['forged', `${VISITOR}, ${OTHER_VISITOR}`, '', 'x'.repeat(200), ` ${VISITOR}`]) {
    assert.deepEqual(resolve({ ip: EDGES[0], headers: { 'cf-connecting-ip': header, 'x-forwarded-for': EDGES[0] } }), { key: EDGES[0], from: 'edge-without-client', address: EDGES[0] }, header);
    assert.equal(resolve({ ip: EDGES[0], headers: { 'cf-connecting-ip': header, 'x-forwarded-for': `${VISITOR}, ${EDGES[0]}` } }).key, VISITOR, header);
  }
  // An invalid entry left of the edge never falls further left, into client-controlled entries.
  assert.deepEqual(resolve({ ip: EDGES[0], headers: { 'x-forwarded-for': `${VISITOR}, forged, ${EDGES[0]}` } }), { key: EDGES[0], from: 'edge-without-client', address: EDGES[0] });
  // A chain that does not line up with Express's own result is not trusted.
  assert.equal(resolve({ ip: EDGES[0], ips: [EDGES[1]], headers: { 'x-forwarded-for': `${VISITOR}, ${EDGES[1]}` } }).from, 'edge-without-client');
});

test('one visitor behind rotating Cloudflare edges keeps one quota bucket by default; off makes the key jump', async t => {
  const cases = [...ON.map(source => [source, [13, 13, 13, 13]]), ...OFF.map(source => [source, [15, 15, 13, 15]])];
  for (const [source, expected] of cases) {
    const f = await fixture(t, { config: sourceConfig(source) });
    await f.ask(viaCloudflare(EDGES[0]));
    await f.ask(viaCloudflare(EDGES[0]));
    const reads = [await f.read(viaCloudflare(EDGES[1])), await f.read(viaCloudflare(EDGES[2])), await f.read(viaCloudflare(EDGES[0])), await f.read(viaCloudflare('162.158.200.7'))];
    assert.deepEqual(reads, expected, `${label(source)}${expected[0] === 15 ? ': off reproduces the 9/1/4 jumps' : ''}`);
  }
});

test('remaining decreases by exactly one per ask and never jumps across five interleaved reads', async t => {
  const f = await fixture(t);
  const reads = [];
  reads.push(await f.read(viaCloudflare(EDGES[0])));
  await f.ask(viaCloudflare(EDGES[1]));
  reads.push(await f.read(viaCloudflare(EDGES[2])));
  await f.ask(viaCloudflare(EDGES[0]));
  reads.push(await f.read(viaCloudflare(EDGES[1])));
  reads.push(await f.read(viaCloudflare(EDGES[2])));
  await f.ask(viaCloudflare(EDGES[2]));
  reads.push(await f.read(viaCloudflare(EDGES[0])));
  assert.deepEqual(reads, [15, 14, 13, 13, 12]);
  assert.deepEqual(f.identities(), [3], 'one visitor, one HMAC identity');
  assert.equal(f.models.AiGovernance.rows[0].count, 3);
});

test('forged X-Forwarded-For and CF-Connecting-IP never change the counting key', async t => {
  for (const source of [UNSET, 'cloudflare']) {
    const f = await fixture(t, { config: sourceConfig(source) });
    await f.ask(viaCloudflare(EDGES[0]));
    // Behind Cloudflare: forged leftmost XFF entries, with and without the CF header.
    for (let i = 1; i <= 4; i++) {
      assert.equal(await f.read({ 'X-Forwarded-For': `198.18.0.${i}, ${VISITOR}, ${EDGES[i % 3]}`, 'CF-Connecting-IP': VISITOR }), 14, label(source));
      assert.equal(await f.read({ 'X-Forwarded-For': `198.18.0.${i}, 198.18.1.${i}, ${VISITOR}, ${EDGES[i % 3]}` }), 14, label(source));
    }
    // Not behind Cloudflare (fail closed): the forged header and leftmost XFF cannot pick a key, the edge is the key.
    await f.ask({ 'X-Forwarded-For': `203.0.113.1, ${NOT_CLOUDFLARE}`, 'CF-Connecting-IP': '203.0.113.1' });
    for (let i = 2; i <= 6; i++) {
      assert.equal(await f.read({ 'X-Forwarded-For': `203.0.113.${i}, ${NOT_CLOUDFLARE}`, 'CF-Connecting-IP': `203.0.113.${i}`, 'True-Client-IP': `203.0.113.${i}` }), 14, label(source));
    }
    assert.equal(await f.read({ 'X-Forwarded-For': '203.0.113.1, 198.51.100.21' }), 15, 'a different non-Cloudflare edge is a different key');
    assert.deepEqual(f.identities(), [1, 1], `${label(source)}: forged values never minted new identities`);
  }
});

test('forged headers at a non-Cloudflare hop still cannot evade the login limit, on by default or explicitly', async t => {
  for (const source of [UNSET, 'cloudflare']) {
    const f = await fixture(t, { config: sourceConfig(source) });
    for (let i = 0; i < 10; i++) {
      const result = await f.request('/auth/login', { body: { email: `unknown${i}@example.test`, password: 'bad' }, headers: { 'X-Forwarded-For': `203.0.113.${i + 1}, ${NOT_CLOUDFLARE}`, 'CF-Connecting-IP': `203.0.113.${i + 1}` } });
      assert.equal(result.status, 401, label(source));
    }
    assert.equal((await f.request('/auth/login', { body: { email: 'another@example.test', password: 'bad' }, headers: { 'X-Forwarded-For': `203.0.113.99, ${NOT_CLOUDFLARE}` } })).status, 429, label(source));
  }
});

test('two visitors behind the same Cloudflare edge are counted independently unless the source is off', async t => {
  for (const [source, otherRemaining] of [[UNSET, 15], ['cloudflare', 15], ['off', 13], ['express', 13]]) {
    const f = await fixture(t, { config: sourceConfig(source) });
    await f.ask(viaCloudflare(EDGES[0]));
    await f.ask(viaCloudflare(EDGES[0]));
    assert.equal(await f.read(viaCloudflare(EDGES[0], OTHER_VISITOR)), otherRemaining, `${label(source)}${otherRemaining === 13 ? ': off shares one bucket between strangers' : ''}`);
    assert.equal(await f.read(viaCloudflare(EDGES[0])), 13);
  }
});

test('login and register limits are per visitor behind one Cloudflare edge', async t => {
  const f = await fixture(t);
  const login = (visitor, i) => f.request('/auth/login', { body: { email: `nobody${i}@example.test`, password: 'bad' }, headers: viaCloudflare(EDGES[i % 3], visitor) });
  for (let i = 0; i < 10; i++) assert.equal((await login(VISITOR, i)).status, 401);
  assert.equal((await login(OTHER_VISITOR, 10)).status, 401, 'another visitor at the same edges keeps its own 10/15min');
  assert.equal((await login(VISITOR, 11)).status, 429);
  const register = (visitor, i) => f.request('/auth/register', { body: { email: 'not-an-email', password: 'Password1', nickname: `n${i}` }, headers: viaCloudflare(EDGES[i % 3], visitor) });
  for (let i = 0; i < 5; i++) assert.equal((await register(VISITOR, i)).status, 400);
  assert.equal((await register(OTHER_VISITOR, 5)).status, 400);
  assert.equal((await register(VISITOR, 6)).status, 429);
});

test('IPv6 visitors share one key per /64 and IPv4-mapped equals IPv4', async t => {
  const f = await fixture(t);
  await f.ask(viaCloudflare('2606:4700:10::6816:1', '2001:db8:abcd:12::1'));
  assert.equal(await f.read(viaCloudflare(EDGES[0], '2001:db8:abcd:12::ffff')), 14);
  assert.equal(await f.read(viaCloudflare(EDGES[1], '2001:db8:abcd:13::1')), 15);
  await f.ask(viaCloudflare(EDGES[1], '203.0.113.50'));
  assert.equal(await f.read(viaCloudflare(EDGES[2], '::ffff:203.0.113.50')), 14);
});

test('CLIENT_IP_SOURCE=off is a strict no-op that leaves Express req.ip untouched', async t => {
  let passed = 0;
  for (const source of OFF) createClientIp({ JWT_SECRET: SECRET, CLIENT_IP_SOURCE: source }, { log: () => assert.fail('no log line while off') }).middleware(untouchable(), untouchable(), () => passed++);
  assert.equal(passed, OFF.length, 'no read, normalisation or defineProperty on the request');
  // Raw hop strings stay distinct keys: no /64 collapse and no ::ffff: unwrapping.
  const f = await fixture(t, { config: { CLIENT_IP_SOURCE: 'off' } });
  await f.ask({ 'X-Forwarded-For': `${VISITOR}, 2001:db8:abcd:12::1` });
  assert.equal(await f.read({ 'X-Forwarded-For': `${VISITOR}, 2001:db8:abcd:12::ffff` }), 15);
  assert.equal(await f.read({ 'X-Forwarded-For': `${VISITOR}, 2001:db8:abcd:12::1` }), 14);
  await f.ask({ 'X-Forwarded-For': `${VISITOR}, ::ffff:198.51.100.30` });
  assert.equal(await f.read({ 'X-Forwarded-For': `${VISITOR}, 198.51.100.30` }), 15);
  assert.deepEqual(f.lines, []);
});

test('unset, empty or "cloudflare" shadows req.ip with the resolved key only', () => {
  for (const source of ON) {
    const { middleware } = createClientIp({ JWT_SECRET: SECRET, ...sourceConfig(source) }, { log: () => assert.fail('no diagnostics without a window') });
    const proto = { get ip() { return EDGES[0]; } };
    const req = Object.assign(Object.create(proto), { ips: [EDGES[0]], socket: { remoteAddress: '10.1.2.3' }, headers: { 'cf-connecting-ip': '2001:db8:abcd:12::1', 'x-forwarded-for': `2001:db8:abcd:12::1, ${EDGES[0]}` }, method: 'GET', path: '/api/ai/usage', query: {} });
    let passed = 0;
    middleware(req, {}, () => passed++);
    assert.equal(passed, 1, label(source));
    assert.equal(req.ip, '2001:db8:abcd:12::/64', label(source));
    assert.equal(Object.getOwnPropertyDescriptor(req, 'ip').configurable, true);
    assert.equal(proto.ip, EDGES[0], 'the Express getter itself is not changed');
  }
});

test('unset source fails closed at a non-Cloudflare hop and changes keys only by normalising them', () => {
  const { middleware } = createClientIp({ JWT_SECRET: SECRET });
  const run = shape => { const req = fakeRequest(shape); middleware(req, {}, () => {}); return req.ip; };
  // A forged CF-Connecting-IP or leftmost XFF entry is ignored when the trusted hop is not Cloudflare.
  assert.equal(run({ ip: NOT_CLOUDFLARE, headers: { 'cf-connecting-ip': VISITOR, 'x-forwarded-for': `${VISITOR}, ${NOT_CLOUDFLARE}` } }), NOT_CLOUDFLARE);
  assert.equal(run({ ip: '127.0.0.1', ips: [], socket: '127.0.0.1', headers: { 'cf-connecting-ip': VISITOR, 'x-forwarded-for': VISITOR } }), '127.0.0.1', 'trust disabled: the socket is the key');
  // Today's hop key, normalised: IPv4-mapped unwrapped and IPv6 per /64.
  assert.equal(run({ ip: '::ffff:198.51.100.30', headers: { 'cf-connecting-ip': VISITOR } }), '198.51.100.30');
  assert.equal(run({ ip: '2001:db8:abcd:12::1', headers: { 'cf-connecting-ip': VISITOR } }), '2001:db8:abcd:12::/64');
  // A value Express would never produce is kept as-is rather than dropped.
  assert.equal(run({ ip: 'unknown', ips: [], socket: undefined }), 'unknown');
});

test('diagnostics: time-boxed, probe-first, sampled, capped and never a full address', () => {
  let now = NOW - 1800000;
  const lines = [];
  const until = new Date(NOW + 1800000).toISOString();
  // The default mode is named in the window-open line.
  createClientIp({ JWT_SECRET: SECRET, CLIENT_IP_DIAGNOSTIC_UNTIL: until }, { now: () => now, log: line => lines.push(line) });
  assert.deepEqual(lines.splice(0), ['[client-ip-diag] window open until 2026-10-08T19:30:00.000Z; mode cloudflare']);
  // Off, so the assertions below can show that diagnostics alone never change req.ip.
  const { middleware } = createClientIp({ JWT_SECRET: SECRET, CLIENT_IP_SOURCE: 'off', CLIENT_IP_DIAGNOSTIC_UNTIL: until }, { now: () => now, log: line => lines.push(line) });
  assert.match(lines.shift(), /^\[client-ip-diag\] window open until 2026-10-08T19:30:00\.000Z; mode express$/);
  const run = shape => { const req = fakeRequest({ ip: EDGES[0], headers: viaCloudflare(EDGES[0]), ...shape }); const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), v])); req.headers = headers; middleware(req, {}, () => {}); return req; };
  const req = run({ query: { probe: 'abcd1234efgh' } });
  assert.equal(req.ip, EDGES[0], 'diagnostics never change req.ip');
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[client-ip-diag\] \{/);
  const line = JSON.parse(lines[0].slice('[client-ip-diag] '.length));
  assert.equal(line.probe, 'abcd1234efgh'); assert.equal(line.path, '/api/health'); assert.equal(line.mode, 'express');
  assert.equal(line.socket.class, 'private'); assert.equal(line.xffLength, 2);
  assert.deepEqual(line.xffRightToLeft, [{ class: 'cloudflare', family: 4, prefix: '162.158.1.0/24' }, { class: 'public', family: 4, prefix: '203.0.113.0/24' }]);
  assert.equal(line.reqIpFrom, 'xff[-1]'); assert.equal(line.reqIp.class, 'cloudflare');
  assert.deepEqual(line.cfConnectingIp, { class: 'public', family: 4, prefix: '203.0.113.0/24', xffMatch: 'xff[-2]' });
  assert.equal(line.cfConnectingIpEqualsXffMinus2, true);
  assert.deepEqual(line.headers, { 'cf-connecting-ip': true, 'true-client-ip': false, 'x-real-ip': false, 'cf-connecting-ipv6': false, 'cf-pseudo-ipv4': false, forwarded: false });
  assert.equal(line.cfColo, 'SJC');
  assert.deepEqual(line.cloudflareMode, { keyFrom: 'cf-connecting-ip', keyPrefix: '203.0.113.0/24' });
  assert.doesNotMatch(lines[0], /203\.0\.113\.9|162\.158\.1\.2|10\.1\.2\.3|8c0000000000abcd/, 'only /24 prefixes, never a full address or ray id');
  // Only GET /api/health and GET /api/ai/usage are logged.
  run({ path: '/api/posts', query: { probe: 'abcd1234efgh' } });
  run({ path: '/api/ai/usage', method: 'POST', query: { probe: 'abcd1234efgh' } });
  assert.equal(lines.length, 1);
  run({ path: '/api/ai/usage', query: { probe: 'abcd1234efgh' }, headers: { 'X-Forwarded-For': '2001:db8:abcd:12::1, 2606:4700:10::6816:1', 'CF-Connecting-IP': 'forged' }, ip: '2606:4700:10::6816:1' });
  const ipv6 = JSON.parse(lines[1].slice('[client-ip-diag] '.length));
  assert.deepEqual(ipv6.xffRightToLeft.map(entry => entry.prefix), ['2606:4700:10::/48', '2001:db8:abcd::/48']);
  assert.deepEqual(ipv6.cfConnectingIp, { class: 'invalid', xffMatch: null });
  assert.equal(ipv6.cloudflareMode.keyFrom, 'xff-left-of-edge');
  assert.doesNotMatch(lines[1], /forged|2001:db8:abcd:12::1/);
  lines.length = 0;
  // Unprobed or invalid probes are sampled (1 in 20) and the token is never echoed.
  for (let i = 0; i < 100; i++) run({ query: i % 2 ? { probe: 'NOT-VALID!' } : { probe: ['abcd1234efgh'] } });
  assert.equal(lines.length, 5);
  assert.ok(lines.every(entry => JSON.parse(entry.slice(17)).probe === null));
  // Sampled lines are capped so probes keep most of the hourly budget.
  for (let i = 0; i < 2000; i++) run({});
  assert.equal(lines.length, 60);
  for (let i = 0; i < 700; i++) run({ query: { probe: 'abcd1234efgh' } });
  assert.equal(lines.length, 600 - 2, 'hard cap of 600 lines per hour, including the two lines above');
  now = NOW - 1;
  run({ query: { probe: 'abcd1234efgh' } });
  assert.equal(lines.length, 598, 'still capped within the hour');
  now = NOW;
  run({ query: { probe: 'abcd1234efgh' } });
  assert.equal(lines.length, 599, 'a new hour resets the budget');
  now = Date.parse(until);
  run({ query: { probe: 'abcd1234efgh' } });
  assert.equal(lines.length, 599, 'nothing after CLIENT_IP_DIAGNOSTIC_UNTIL');
});

test('diagnostic window is ignored when malformed, in the past or more than 2h after start', () => {
  assert.deepEqual(diagnosticWindow(undefined, NOW), { end: null, reason: null });
  assert.deepEqual(diagnosticWindow('', NOW), { end: null, reason: null });
  assert.deepEqual(diagnosticWindow('2026-10-08T21:00:00Z', NOW), { end: NOW + 7200000, reason: null });
  assert.deepEqual(diagnosticWindow('2026-10-08T19:30Z', NOW), { end: NOW + 1800000, reason: null });
  assert.equal(diagnosticWindow('2026-10-08T21:00:01Z', NOW).reason, 'more-than-2h-after-start');
  assert.equal(diagnosticWindow('2026-10-08T19:00:00Z', NOW).reason, 'past');
  for (const bad of ['2026-10-08 20:00', '2026-10-08T20:00:00+00:00', '2026-10-08T20:00:00', '2026-02-30T20:00Z', 'tomorrow', 1791435600000]) assert.equal(diagnosticWindow(bad, NOW).reason, 'malformed', String(bad));
  for (const [until, reason] of [['2026-10-08T23:00:00Z', 'more-than-2h-after-start'], ['2026-10-08T18:00:00Z', 'past'], ['soon', 'malformed']]) {
    const lines = [];
    const { middleware } = createClientIp({ JWT_SECRET: SECRET, CLIENT_IP_SOURCE: 'off', CLIENT_IP_DIAGNOSTIC_UNTIL: until }, { now: () => NOW, log: line => lines.push(line) });
    assert.deepEqual(lines, [`[client-ip-diag] CLIENT_IP_DIAGNOSTIC_UNTIL ignored: ${reason}`]);
    let passed = 0;
    middleware(untouchable(), untouchable(), () => passed++);
    assert.equal(passed, 1);
  }
});

test('diagnostic endpoint: 404 outside the window, key fingerprints inside, rate limited, nothing stored', async t => {
  const closed = await fixture(t);
  assert.equal((await closed.raw('/_diag/client-ip', { headers: viaCloudflare(EDGES[0]) })).status, 404);
  let now = NOW;
  const until = new Date(NOW + 3600000).toISOString();
  // Off: the live ("current") key follows the edge, as it did before the default changed.
  const f = await fixture(t, { config: { CLIENT_IP_SOURCE: 'off', CLIENT_IP_DIAGNOSTIC_UNTIL: until }, clientIpNow: () => now });
  const diag = async headers => { const result = await f.request('/_diag/client-ip', { headers }); assert.equal(result.status, 200); assert.equal(result.headers.get('cache-control'), 'no-store'); return result.data; };
  const rotated = [await diag(viaCloudflare(EDGES[0])), await diag(viaCloudflare(EDGES[1])), await diag(viaCloudflare(EDGES[2], VISITOR, { 'X-Forwarded-For': `198.18.0.1, ${VISITOR}, ${EDGES[2]}` }))];
  assert.equal(new Set(rotated.map(row => row.fingerprints.cloudflare)).size, 1, 'cloudflare mode: one key across edges and forged leftmost XFF');
  assert.equal(new Set(rotated.map(row => row.fingerprints.current)).size, 3, 'current mode: the key follows the edge');
  assert.match(rotated[0].fingerprints.cloudflare, /^[a-f0-9]{12}$/);
  assert.notEqual((await diag(viaCloudflare(EDGES[0], OTHER_VISITOR))).fingerprints.cloudflare, rotated[0].fingerprints.cloudflare);
  const spoofed = await diag({ 'X-Forwarded-For': `${VISITOR}, ${NOT_CLOUDFLARE}`, 'CF-Connecting-IP': VISITOR });
  assert.equal(spoofed.fingerprints.cloudflare, spoofed.fingerprints.current, 'a forged header behind a non-Cloudflare hop does not change the key');
  assert.equal(spoofed.cloudflareMode.keyFrom, 'edge-not-cloudflare');
  assert.equal(rotated[0].until, until);
  assert.equal(rotated[0].cloudflareRanges, '2026-10-08');
  assert.doesNotMatch(JSON.stringify([...rotated, spoofed]), /203\.0\.113\.9\b|162\.158\.1\.2|172\.70\.3\.4|104\.23\.0\.9|198\.51\.100\.20|127\.0\.0\.1/);
  // 30 per key per minute.
  for (let i = 0; i < 28; i++) await diag(viaCloudflare(EDGES[0]));
  const limited = await f.request('/_diag/client-ip', { headers: viaCloudflare(EDGES[0]) });
  assert.equal(limited.status, 429); assert.equal(limited.data.code, 'CLIENT_IP_DIAG_RATE_LIMIT'); assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal((await f.request('/health?probe=abcd1234efgh', { headers: viaCloudflare(EDGES[1]) })).status, 200);
  assert.equal(f.lines.filter(line => line.includes('"probe":"abcd1234efgh"')).length, 1);
  for (const [name, model] of Object.entries(f.models)) if (Array.isArray(model?.rows)) assert.equal(model.rows.length, 0, `${name} must stay empty`);
  now = Date.parse(until);
  assert.equal((await f.raw('/_diag/client-ip', { headers: viaCloudflare(EDGES[1]) })).status, 404, 'closes at CLIENT_IP_DIAGNOSTIC_UNTIL');
  // On (by default or explicitly), the current key is the Cloudflare-mode key.
  for (const source of [UNSET, 'cloudflare']) {
    const on = await fixture(t, { config: { ...sourceConfig(source), CLIENT_IP_DIAGNOSTIC_UNTIL: until }, clientIpNow: () => NOW });
    const flagged = (await on.request('/_diag/client-ip', { headers: viaCloudflare(EDGES[0]) })).data;
    assert.equal(flagged.mode, 'cloudflare', label(source));
    assert.equal(flagged.fingerprints.current, flagged.fingerprints.cloudflare);
    assert.equal(flagged.fingerprints.cloudflare, rotated[0].fingerprints.cloudflare, 'fingerprints are stable across processes sharing JWT_SECRET');
  }
});
