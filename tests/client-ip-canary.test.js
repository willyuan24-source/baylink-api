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

/**
 * The fixture API behind a stand-in for Cloudflare and Render: Cloudflare
 * overwrites CF-Connecting-IP and appends the visitor to X-Forwarded-For,
 * then Render appends the Cloudflare edge, which rotates on every request.
 */
async function behindCloudflare(t, config = {}) {
  let calls = 0;
  const app = createApplication({ models: createMemoryModels(), config: { NODE_ENV: 'test', JWT_SECRET: SECRET, OPENAI_API_KEY: 'test-key-never-print', TRUST_PROXY_HOPS: 1, ...config },
    plannerNow: () => NOW, clientIpLog: () => {}, ai: { baybay: async () => { calls++; return final('已参考站内资料，这是测试回答。'); } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  let requests = 0;
  const front = http.createServer((req, res) => {
    const edge = EDGES[requests++ % EDGES.length];
    const forwarded = req.headers['x-forwarded-for'];
    const headers = { ...req.headers, 'cf-connecting-ip': VISITOR, 'x-forwarded-for': `${forwarded ? `${forwarded}, ` : ''}${VISITOR}, ${edge}` };
    const upstream = http.request({ host: '127.0.0.1', port: app.server.address().port, method: req.method, path: req.url, headers }, response => {
      res.writeHead(response.statusCode, response.headers);
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

test('canary without the diagnostic window: two paid asks prove the default key', async t => {
  const api = await behindCloudflare(t);
  const run = await canary(['--base', api.base, '--reads', '5', '--consume', '2', '--i-approve-spend']);
  assert.equal(run.code, 0, run.stdout);
  assert.equal(run.result, 'PASS');
  assert.deepEqual(run.rows, {
    'diag-window': 'SKIP',
    'usage-reads-stable': 'INCONCLUSIVE', 'usage-forged-reads': 'INCONCLUSIVE',
    'consume-monotonic': 'PASS', 'consume-exact-drop': 'PASS',
    'after-ask-reads-stable': 'PASS', 'after-ask-forged-reads': 'PASS',
  });
  assert.match(run.stdout, /r15 r15 ask\(200\) r14 r14 ask\(200\) r13 r13/);
  assert.match(run.stdout, /after-ask-reads-stable\s+remaining 13 13 13 13 13 \/ limit 15/);
  assert.match(run.stdout, /after-ask-forged-reads\s+remaining 13 13 13 13 13 vs plain 13/);
  assert.equal(api.calls(), 2, 'exactly the two approved asks reached the provider');
});

test('canary read-only run is INCONCLUSIVE, never PASS, and makes no ask', async t => {
  const api = await behindCloudflare(t);
  const run = await canary(['--base', api.base, '--reads', '5']);
  assert.equal(run.code, 3, run.stdout);
  assert.equal(run.result, 'INCONCLUSIVE');
  assert.ok(!Object.values(run.rows).includes('PASS'), run.stdout);
  assert.equal(run.rows['after-ask-reads-stable'], 'INCONCLUSIVE');
  assert.equal(api.calls(), 0);
});

test('canary fails when the key rotates with the Cloudflare edge (CLIENT_IP_SOURCE=off)', async t => {
  const api = await behindCloudflare(t, { CLIENT_IP_SOURCE: 'off' });
  const run = await canary(['--base', api.base, '--reads', '5', '--consume', '2', '--i-approve-spend']);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.result, 'FAIL');
  assert.equal(run.rows['consume-exact-drop'], 'FAIL');
});

test('canary fails when a forged header can pick the key', async t => {
  // Trusting four hops lets the leftmost forged XFF entry become req.ip, while
  // plain reads (two entries) stay on the visitor: only the forged reads move.
  const api = await behindCloudflare(t, { CLIENT_IP_SOURCE: 'off', TRUST_PROXY_HOPS: 4 });
  const run = await canary(['--base', api.base, '--reads', '5', '--consume', '2', '--i-approve-spend']);
  assert.equal(run.code, 1, run.stdout);
  assert.equal(run.rows['consume-exact-drop'], 'PASS');
  assert.equal(run.rows['after-ask-reads-stable'], 'PASS');
  assert.equal(run.rows['after-ask-forged-reads'], 'FAIL');
  assert.match(run.stdout, /after-ask-forged-reads\s+remaining 15 15 15 15 15 vs plain 13/);
});

test('canary refuses paid asks without approval and keeps reads within the usage-read limit', async () => {
  for (const args of [['--consume', '2'], ['--reads', '21'], ['--reads', '4'], ['--consume', '5', '--i-approve-spend']]) {
    const run = await canary(['--base', 'http://127.0.0.1:9/api', ...args]);
    assert.equal(run.code, 2, args.join(' '));
    assert.equal(run.stdout, '', 'nothing is requested before the arguments are valid');
  }
});
