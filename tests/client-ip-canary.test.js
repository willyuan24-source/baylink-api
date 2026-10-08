const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const CANARY = path.join(__dirname, '..', 'scripts', 'canary-ai-usage.mjs');
const SECRET = 'isolated-client-ip-canary-secret';
const NOW = Date.parse('2026-10-08T19:00:00Z');
const VISITOR = '203.0.113.9';
// Published Cloudflare addresses (162.158.0.0/15, 172.64.0.0/13, 104.16.0.0/13).
const EDGES = ['162.158.1.2', '172.70.3.4', '104.23.0.9'];
const final = answer => ({ model: 'fixture-baybay', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
// What production's edge did on 2026-10-08 with a client-sent CF-Connecting-IP.
const CLOUDFLARE_1000 = { status: 403, body: 'error code: 1000' };
const rejectClientHeaders = (...names) => req => (names.some(name => req.headers[name] !== undefined) ? CLOUDFLARE_1000 : null);

/**
 * The fixture API behind a stand-in for Cloudflare and Render: Cloudflare
 * overwrites CF-Connecting-IP and appends the visitor to X-Forwarded-For,
 * then Render appends the Cloudflare edge, which rotates on every request.
 * With renderHops, a Render-internal proxy then appends its own rotating
 * private hop, as production did on 2026-10-08 (the socket is loopback in
 * both). Responses from the API carry Render's headers. `edge(req)` may
 * answer a request at Cloudflare instead; by default it rejects a
 * client-sent CF-Connecting-IP, as production did.
 */
async function behindCloudflare(t, config = {}, { edge = rejectClientHeaders('cf-connecting-ip'), renderHops = [] } = {}) {
  let calls = 0;
  const app = createApplication({ models: createMemoryModels(), config: { NODE_ENV: 'test', JWT_SECRET: SECRET, OPENAI_API_KEY: 'test-key-never-print', TRUST_PROXY_HOPS: 1, ...config },
    plannerNow: () => NOW, clientIpLog: () => {}, ai: { baybay: async () => { calls++; return final('已参考站内资料，这是测试回答。'); } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  let requests = 0;
  const front = http.createServer((req, res) => {
    const answer = edge(req);
    if (answer) {
      res.writeHead(answer.status, { 'Content-Type': 'text/plain; charset=UTF-8', Server: 'cloudflare', 'CF-RAY': 'fixture-SJC' });
      return res.end(answer.body);
    }
    const n = requests++;
    const hop = EDGES[n % EDGES.length];
    // Rotates out of step with the edge, so edge and hop pairs vary.
    const internal = renderHops.length ? `, ${renderHops[Math.floor(n / 2) % renderHops.length]}` : '';
    const forwarded = req.headers['x-forwarded-for'];
    const headers = { ...req.headers, 'cf-connecting-ip': VISITOR, 'x-forwarded-for': `${forwarded ? `${forwarded}, ` : ''}${VISITOR}, ${hop}${internal}` };
    const upstream = http.request({ host: '127.0.0.1', port: app.server.address().port, method: req.method, path: req.url, headers }, response => {
      res.writeHead(response.statusCode, { ...response.headers, server: 'cloudflare', 'rndr-id': `fixture-${requests}`, 'x-render-origin-server': 'Render' });
      response.pipe(res);
    });
    upstream.on('error', error => res.destroy(error));
    req.pipe(upstream);
  });
  await new Promise(resolve => front.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => front.close(() => app.io.close(resolve))));
  return { base: `http://127.0.0.1:${front.address().port}/api`, calls: () => calls };
}

// Asynchronous on purpose: the in-process fixture must keep serving while the canary runs.
const canary = args => new Promise(resolve => {
  execFile(process.execPath, [CANARY, ...args], { timeout: 60000 }, (error, stdout, stderr) => {
    const rows = Object.fromEntries(stdout.split('\n').map(line => /^(\S+)\s+(\S+)\s{2}/.exec(line)).filter(Boolean).map(([, result, check]) => [check, result]));
    resolve({ code: error ? error.code : 0, stdout, stderr, rows, result: /^RESULT: (\w+)/m.exec(stdout)?.[1] });
  });
});
const PAID = ['--reads', '5', '--consume', '2', '--i-approve-spend'];
// Render-internal hops seen in production on 2026-10-08 (/24s; host parts invented).
const RENDER_HOPS = ['10.27.25.14', '10.28.103.2', '10.30.203.99'];

test('canary without the diagnostic window: two paid asks prove the default key, with CF-Connecting-IP rejected at the edge', async t => {
  const api = await behindCloudflare(t);
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 0, run.stdout);
  assert.equal(run.result, 'PASS');
  assert.deepEqual(run.rows, {
    'diag-window': 'SKIP',
    'usage-reads-stable': 'INCONCLUSIVE', 'usage-forged-reads': 'INCONCLUSIVE',
    'consume-monotonic': 'PASS', 'consume-exact-drop': 'PASS',
    'after-ask-reads-stable': 'PASS', 'after-ask-forged-reads': 'PASS',
    'forged-edge-rejected': 'INFO',
  });
  assert.match(run.stdout, /r15 r15 ask\(200\) r14 r14 ask\(200\) r13 r13/);
  assert.match(run.stdout, /after-ask-reads-stable\s+remaining 13 13 13 13 13 \/ limit 15/);
  assert.match(run.stdout, /after-ask-forged-reads\s+plain 13 vs forged x-forwarded-for 13, cf-connecting-ip edge-403, true-client-ip 13, x-real-ip 13, xff\+true-client-ip\+x-real-ip 13\r?$/m);
  assert.match(run.stdout, /forged-edge-rejected\s+cf-connecting-ip x2: 403 "error code: 1000" \(answered by Cloudflare/);
  assert.equal(api.calls(), 2, 'exactly the two approved asks reached the provider');
});

test('canary read-only run is INCONCLUSIVE, never PASS, and makes no ask, with CF-Connecting-IP rejected at the edge', async t => {
  const api = await behindCloudflare(t);
  const run = await canary(['--base', api.base, '--reads', '5']);
  assert.equal(run.code, 3, run.stdout);
  assert.equal(run.result, 'INCONCLUSIVE');
  assert.ok(!Object.values(run.rows).includes('PASS'), run.stdout);
  assert.equal(run.rows['after-ask-reads-stable'], 'INCONCLUSIVE');
  assert.equal(run.rows['forged-edge-rejected'], 'INFO');
  assert.match(run.stdout, /usage-forged-reads\s+plain 15 vs forged x-forwarded-for 15, cf-connecting-ip edge-403, true-client-ip 15/);
  assert.match(run.stdout, /RESULT: INCONCLUSIVE \(read-only run/);
  assert.equal(api.calls(), 0);
});

test('canary passes when every forged header reaches the API', async t => {
  const api = await behindCloudflare(t, {}, { edge: () => null });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 0, run.stdout);
  assert.equal(run.rows['after-ask-forged-reads'], 'PASS');
  assert.equal(run.rows['forged-edge-rejected'], undefined);
  assert.match(run.stdout, /after-ask-forged-reads\s+plain 13 vs forged x-forwarded-for 13, cf-connecting-ip 13, true-client-ip 13/);
});

test('canary is INCONCLUSIVE, not PASS, when no forged header reaches the API', async t => {
  const api = await behindCloudflare(t, {}, { edge: rejectClientHeaders('x-forwarded-for', 'cf-connecting-ip', 'true-client-ip', 'x-real-ip') });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 3, run.stdout);
  assert.equal(run.result, 'INCONCLUSIVE');
  assert.equal(run.rows['consume-exact-drop'], 'PASS');
  assert.equal(run.rows['after-ask-reads-stable'], 'PASS');
  assert.equal(run.rows['after-ask-forged-reads'], 'INCONCLUSIVE');
  assert.match(run.stdout, /every forged request was rejected by Cloudflare before the API/);
});

test('canary fails when the key rotates with the Cloudflare edge (CLIENT_IP_SOURCE=off)', async t => {
  const api = await behindCloudflare(t, { CLIENT_IP_SOURCE: 'off' });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.result, 'FAIL');
  assert.equal(run.rows['consume-exact-drop'], 'FAIL');
});

test('canary fails when a forged header can pick the key', async t => {
  // Trusting four hops lets the leftmost forged XFF entry become req.ip, while
  // plain reads (two entries) stay on the visitor: only forged XFF reads move.
  const api = await behindCloudflare(t, { CLIENT_IP_SOURCE: 'off', TRUST_PROXY_HOPS: 4 });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.rows['consume-exact-drop'], 'PASS');
  assert.equal(run.rows['after-ask-reads-stable'], 'PASS');
  assert.equal(run.rows['after-ask-forged-reads'], 'FAIL');
  assert.match(run.stdout, /after-ask-forged-reads\s+plain 13 vs forged x-forwarded-for 15, cf-connecting-ip edge-403, true-client-ip 13, x-real-ip 13, xff\+true-client-ip\+x-real-ip 15\r?$/m);
});

test('canary reports ERROR, not FAIL, when the run cannot finish', async t => {
  // A Cloudflare 5xx means the origin failed; it is not an edge rejection of the header.
  const api = await behindCloudflare(t, {}, { edge: req => (req.headers['x-real-ip'] ? { status: 520, body: 'error code: 520' } : null) });
  const run = await canary(['--base', api.base, '--reads', '5']);
  assert.equal(run.code, 4, run.stdout);
  assert.equal(run.result, 'ERROR');
  assert.equal(run.rows.run, 'ERROR');
  assert.ok(!Object.values(run.rows).includes('FAIL'), run.stdout);
  assert.match(run.stdout, /run\s+forged x-real-ip GET \/ai\/usage returned 520 "error code: 520"/);
  assert.match(run.stdout, /not a rollback signal/);
});

test('canary refuses paid asks without approval and keeps reads within the usage-read limit', async () => {
  for (const args of [['--consume', '2'], ['--reads', '21'], ['--reads', '4'], ['--consume', '5', '--i-approve-spend']]) {
    const run = await canary(['--base', 'http://127.0.0.1:9/api', ...args]);
    assert.equal(run.code, 2, args.join(' '));
    assert.equal(run.stdout, '', 'nothing is requested before the arguments are valid');
  }
});

test('canary passes behind a rotating Render-internal hop, the production chain since 2026-10-08', async t => {
  // A diagnostic window open for this process, so the diag-* rows run too.
  const api = await behindCloudflare(t, { CLIENT_IP_DIAGNOSTIC_UNTIL: new Date(Date.now() + 3600000).toISOString() }, { renderHops: RENDER_HOPS });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 0, run.stdout);
  assert.equal(run.result, 'PASS');
  assert.equal(run.rows['consume-exact-drop'], 'PASS');
  assert.equal(run.rows['after-ask-reads-stable'], 'PASS');
  assert.equal(run.rows['after-ask-forged-reads'], 'PASS');
  assert.match(run.stdout, /r15 r15 ask\(200\) r14 r14 ask\(200\) r13 r13/);
  assert.match(run.stdout, /diag-window\s+mode=cloudflare reqIp=xff\[-1\]:private xffLength=3 cf-connecting-ip=public cf==xff\[-2\]=false cloudflareKeyFrom=cf-connecting-ip cloudflareEdgeFrom=xff\[-2\] colo=/);
  assert.equal(run.rows['diag-cloudflare-key-stable'], 'PASS');
  assert.equal(run.rows['diag-cloudflare-key-forged'], 'PASS');
  assert.equal(run.rows['diag-current-key'], 'PASS');
  assert.equal(api.calls(), 2, 'exactly the two approved asks reached the provider');
});

test('canary fails behind a rotating Render-internal hop when the source is off: the key follows the hop', async t => {
  const api = await behindCloudflare(t, { CLIENT_IP_SOURCE: 'off' }, { renderHops: RENDER_HOPS });
  const run = await canary(['--base', api.base, ...PAID]);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.result, 'FAIL');
  assert.equal(run.rows['consume-exact-drop'], 'FAIL');
});
