#!/usr/bin/env node
// Canary for the client-IP counting key (docs/client-ip-rollout.md).
// Free by default: it only reads GET /ai/usage and, while
// CLIENT_IP_DIAGNOSTIC_UNTIL is open, GET /_diag/client-ip. --consume K makes
// K real guest BayBay asks (paid, about $0.23 each) and runs only together
// with --i-approve-spend. It never logs in and never sends credentials.
//
// Reads alone cannot prove the key: an unused or idle bucket reads the same
// under any key. RESULT: PASS therefore needs at least one ask that reached the
// model, dropped remaining by exactly 1, and was followed by --reads identical
// plain reads and forged-header reads of the now-used bucket, at least one of
// which reached the API. That proof does not need the diagnostic window. A run
// without it is INCONCLUSIVE at best.
//
// Forged headers go one variant per request. Cloudflare answers some of them
// itself (on 2026-10-08 a client-sent CF-Connecting-IP got "403 error code:
// 1000" with no Render headers). Such a request never reached the API, so it
// cannot choose a key: it is listed in a forged-edge-rejected INFO row, not
// failed. A run that cannot finish (DNS, network, timeout, unexpected status)
// is ERROR, which says nothing about the key either way.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';

const USAGE = `Usage: node scripts/canary-ai-usage.mjs --base <https://host/api> [--reads 10] [--family 4|6]
       [--probe <8-24 lowercase letters/digits>] [--consume <1-4> --i-approve-spend]
Exit code: 0 PASS, 1 FAIL, 2 bad arguments, 3 INCONCLUSIVE (nothing proves the key yet),
           4 ERROR (the run could not finish; rerun, not a rollback signal).`;
const ASK_COST_USD = 0.23;
const MAX_CONSUME = 4;
// GET /ai/usage allows 120 reads per key per minute. A run makes at most
// 4 * reads + 2 * consume + 3 of them, so 20 keeps even a fast run under that.
const MAX_READS = 20;
const EXIT = { PASS: 0, FAIL: 1, INCONCLUSIVE: 3, ERROR: 4 };
const ASKS = [
  '周末在湾区带孩子去哪里玩比较好？请简单推荐两个地方。',
  '湾区有什么适合老人散步的公园？请推荐两个。',
  '雨天在湾区可以去哪些室内地方？请简单说两个。',
  '推荐两个适合拍照的湾区海边步道。',
];

// Documentation ranges (RFC 2544 / RFC 3849): never a real visitor.
const forgedIp = () => `198.18.${crypto.randomInt(256)}.${crypto.randomInt(1, 255)}`;
const forgedIpv6 = () => `2001:db8:${crypto.randomInt(65536).toString(16)}::1`;
// One variant per forged request, so a header the edge rejects cannot hide the
// others. The combined variant leaves out CF-Connecting-IP for that reason.
// --reads is at least 5, so every variant is sent at least once per phase.
const FORGED = [
  ['x-forwarded-for', () => ({ 'X-Forwarded-For': `${forgedIp()}, ${forgedIp()}` })],
  ['cf-connecting-ip', () => ({ 'CF-Connecting-IP': forgedIp() })],
  ['true-client-ip', () => ({ 'True-Client-IP': forgedIp() })],
  ['x-real-ip', () => ({ 'X-Real-IP': forgedIpv6() })],
  ['xff+true-client-ip+x-real-ip', () => ({ 'X-Forwarded-For': `${forgedIp()}, ${forgedIp()}`, 'True-Client-IP': forgedIp(), 'X-Real-IP': forgedIp() })],
];
// Every response that passed through Render carries these.
const ORIGIN_HEADERS = ['rndr-id', 'x-render-origin-server'];

function parseArgs(argv) {
  const options = { reads: 10, family: 4, consume: 0, approveSpend: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i], value = argv[i + 1];
    if (flag === '--i-approve-spend') { options.approveSpend = true; continue; }
    if (!['--base', '--reads', '--family', '--probe', '--consume'].includes(flag) || value === undefined) throw new Error(`Unknown or incomplete argument: ${flag}`);
    i++;
    if (flag === '--base') options.base = value.replace(/\/+$/, '');
    else if (flag === '--probe') options.probe = value;
    else options[flag.slice(2)] = Number(value);
  }
  if (!options.base || !/^https?:\/\/[^/]+\/api$/.test(options.base)) throw new Error('--base is required and must end in /api, e.g. https://example.onrender.com/api');
  if (!Number.isInteger(options.reads) || options.reads < FORGED.length || options.reads > MAX_READS) throw new Error(`--reads must be an integer from ${FORGED.length} to ${MAX_READS}`);
  if (![4, 6].includes(options.family)) throw new Error('--family must be 4 or 6');
  if (!Number.isInteger(options.consume) || options.consume < 0 || options.consume > MAX_CONSUME) throw new Error(`--consume must be an integer from 0 to ${MAX_CONSUME}`);
  if (options.consume && !options.approveSpend) throw new Error(`--consume ${options.consume} makes paid BayBay asks (about $${(options.consume * ASK_COST_USD).toFixed(2)}). Add --i-approve-spend only with the owner's approval.`);
  options.probe ??= Array.from(crypto.randomBytes(12), byte => 'abcdefghijklmnopqrstuvwxyz0123456789'[byte % 36]).join('');
  if (!/^[a-z0-9]{8,24}$/.test(options.probe)) throw new Error('--probe must be 8-24 lowercase letters or digits');
  return options;
}

function call(options, path, { method = 'GET', headers = {}, body } = {}) {
  const url = new URL(`${options.base}${path}`);
  const client = url.protocol === 'https:' ? https : http;
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = client.request(url, { method, family: options.family, timeout: 120000, headers: { Accept: 'application/json', 'User-Agent': 'baylink-client-ip-canary/1',
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}), ...headers } }, response => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { text += chunk; });
      response.on('end', () => {
        let data = null;
        try { data = JSON.parse(text); } catch { /* Non-JSON bodies (e.g. the default 404 page) are reported by status. */ }
        resolve({ status: response.statusCode, headers: response.headers, text, data });
      });
    });
    request.on('timeout', () => request.destroy(new Error(`timeout: ${method} ${url.pathname}`)));
    request.on('error', error => reject(error.code === 'ENOTFOUND' && options.family === 6
      ? new Error(`${url.hostname} has no IPv6 (AAAA) address (ENOTFOUND with --family 6); use --family 4`) : error));
    if (payload) request.write(payload);
    request.end();
  });
}

const rows = [];
const report = (check, result, detail) => rows.push({ check, result, detail });
const snippet = response => response.text.replace(/\s+/g, ' ').trim().slice(0, 60);

/**
 * A 4xx that Cloudflare produced itself: Server says cloudflare and none of
 * Render's headers are present, so the request never reached the API. A 5xx
 * is not one: Cloudflare answers 52x when the origin fails.
 */
const edgeRejected = response => response.status >= 400 && response.status < 500
  && /cloudflare/i.test(String(response.headers.server || '')) && !ORIGIN_HEADERS.some(name => response.headers[name] !== undefined);

const edgeRejections = new Map();
function noteEdgeRejection(variant, response) {
  const seen = edgeRejections.get(variant) || { count: 0, detail: `${response.status} "${snippet(response)}"` };
  seen.count++;
  edgeRejections.set(variant, seen);
}

function usageFrom(response, what) {
  if (response.status === 200 && Number.isInteger(response.data?.remaining)) return response.data;
  const edge = edgeRejected(response) ? ' from Cloudflare, before the API' : '';
  throw new Error(`${what} GET /ai/usage returned ${response.status}${edge} "${snippet(response)}"`);
}

const usagePath = options => `/ai/usage?probe=${options.probe}`;
const readUsage = async options => usageFrom(await call(options, usagePath(options)), 'plain');

/** Forged read number i: one header variant, either answered by the API or rejected at the edge. */
async function forgedCall(options, path, i) {
  const [variant, headers] = FORGED[i % FORGED.length];
  const response = await call(options, path, { headers: headers() });
  if (edgeRejected(response)) { noteEdgeRejection(variant, response); return { variant, edge: response.status }; }
  return { variant, response };
}

async function forgedUsage(options, i) {
  const read = await forgedCall(options, usagePath(options), i);
  return read.edge ? read : { variant: read.variant, remaining: usageFrom(read.response, `forged ${read.variant}`).remaining };
}

/** "x-forwarded-for 13 13, cf-connecting-ip edge-403 edge-403, ..." in variant order. */
const describeForged = reads => FORGED.map(([variant]) => {
  const values = reads.filter(read => read.variant === variant).map(read => (read.edge ? `edge-${read.edge}` : read.remaining));
  return values.length ? `${variant} ${values.join(' ')}` : null;
}).filter(Boolean).join(', ');

async function diagnostics(options) {
  const first = await call(options, '/_diag/client-ip');
  if (first.status === 404) return report('diag-window', 'SKIP', 'GET /_diag/client-ip is 404: CLIENT_IP_DIAGNOSTIC_UNTIL is not open');
  if (first.status !== 200 || !first.data?.fingerprints) return report('diag-window', 'FAIL', `unexpected ${first.status}`);
  const plain = [first.data];
  for (let i = 1; i < 6; i++) plain.push((await call(options, '/_diag/client-ip')).data);
  const forged = [];
  for (let i = 0; i < 6; i++) {
    const read = await forgedCall(options, '/_diag/client-ip', i);
    if (!read.edge) forged.push(read.response.data);
  }
  if ([...plain, ...forged].some(row => !row?.fingerprints)) return report('diag-window', 'FAIL', 'a diagnostic read was rate limited or malformed; wait a minute and retry');
  const { mode, reqIp, reqIpFrom, xffLength, cfConnectingIp, cfConnectingIpEqualsXffMinus2, cloudflareMode, cfColo } = first.data;
  report('diag-window', 'PASS', `mode=${mode} reqIp=${reqIpFrom}:${reqIp.class} xffLength=${xffLength} cf-connecting-ip=${cfConnectingIp ? cfConnectingIp.class : 'absent'} cf==xff[-2]=${cfConnectingIpEqualsXffMinus2} cloudflareKeyFrom=${cloudflareMode.keyFrom}${cloudflareMode.edgeFrom === undefined ? '' : ` cloudflareEdgeFrom=${cloudflareMode.edgeFrom ?? 'none'}`} colo=${cfColo}`);
  const distinct = (list, field) => new Set(list.map(row => row.fingerprints[field])).size;
  const plainKeys = distinct(plain, 'cloudflare');
  const sources = [...new Set(plain.map(row => row.cloudflareMode.keyFrom))];
  // edge-* sources mean cloudflare mode would fall back to today's edge key (see the decision table).
  const visitorKey = sources.every(source => ['cf-connecting-ip', 'xff-left-of-edge'].includes(source));
  report('diag-cloudflare-key-stable', plainKeys === 1 && visitorKey ? 'PASS' : 'FAIL', `${plain.length} reads -> ${plainKeys} cloudflare-mode key(s), from ${sources.join('/')}`);
  const forgedKeys = new Set([...plain, ...forged].map(row => row.fingerprints.cloudflare)).size;
  report('diag-cloudflare-key-forged', !forged.length ? 'INCONCLUSIVE' : forgedKeys === 1 ? 'PASS' : 'FAIL',
    `${forged.length} forged-header read(s) reached the API -> ${forgedKeys} key(s) overall`);
  const currentKeys = distinct([...plain, ...forged], 'current');
  report('diag-current-key', mode === 'cloudflare' ? currentKeys === 1 ? 'PASS' : 'FAIL' : 'INFO',
    `${plain.length + forged.length} reads -> ${currentKeys} key(s) under the live mode (${mode}); more than one means the live key rotates`);
}

/**
 * --reads plain reads, then --reads forged-header reads, one variant each.
 * Any difference among the reads that reached the API is a FAIL. Equal series
 * prove the key only when the bucket is known to be in use, i.e. after an ask
 * that reached the model, and only if a forged read reached the API at all;
 * otherwise they are INCONCLUSIVE.
 */
async function stableReads(options, phase, proven) {
  const plain = [];
  for (let i = 0; i < options.reads; i++) plain.push(await readUsage(options));
  const forged = [];
  for (let i = 0; i < options.reads; i++) forged.push(await forgedUsage(options, i));
  const series = plain.map(row => row.remaining);
  const reached = forged.filter(read => !read.edge);
  const idle = proven ? '' : ' (reads alone cannot tell keys apart: an unused or idle bucket reads the same under any key)';
  report(`${phase}-reads-stable`, new Set(series).size !== 1 ? 'FAIL' : proven ? 'PASS' : 'INCONCLUSIVE', `remaining ${series.join(' ')} / limit ${plain[0].limit}${idle}`);
  const forgedResult = reached.some(read => read.remaining !== series[0]) ? 'FAIL' : proven && reached.length ? 'PASS' : 'INCONCLUSIVE';
  report(`${phase}-forged-reads`, forgedResult, `plain ${series[0]} vs forged ${describeForged(forged)}${
    reached.length ? idle : ' (every forged request was rejected by Cloudflare before the API, so none was tested)'}`);
  return series;
}

const usageReads = options => stableReads(options, 'usage', false);

/** Paid asks, each between two reads. Returns { exact, wrong, last }. */
async function consume(options) {
  if (!options.consume) {
    report('consume', 'SKIP', 'no paid asks (pass --consume K --i-approve-spend with owner approval)');
    return { exact: 0, wrong: 0 };
  }
  const reads = [], steps = [];
  const read = async () => { const value = (await readUsage(options)).remaining; reads.push(value); steps.push(`r${value}`); return value; };
  let exact = 0, inconclusive = 0, wrong = 0;
  await read(); await read();
  for (let i = 0; i < options.consume; i++) {
    const before = reads.at(-1);
    const response = await call(options, '/ai/guide-chat', { method: 'POST', body: { assistantVersion: 2, searchMode: 'site', locale: 'zh-Hans', message: ASKS[i % ASKS.length] } });
    const research = response.data?.research || {};
    // Only an ask that reached the model reserved quota. Capacity, safety or
    // deterministic answers do not, and say nothing about the key.
    const billed = response.status === 200 && response.data?.degraded !== true && Array.isArray(research.modelResponses) && research.modelResponses.length > 0
      && !(research.warnings || []).includes('model_unavailable_or_capacity');
    steps.push(`ask(${response.status}${billed ? '' : ' not-billed'})`);
    const after = await read();
    await read();
    if (!billed) inconclusive++;
    else if (after === before - 1) exact++;
    else wrong++;
  }
  while (reads.length < 5) await read();
  const increases = reads.slice(1).filter((value, i) => value > reads[i]).length;
  report('consume-monotonic', increases ? 'FAIL' : 'PASS', `${steps.join(' ')}${increases ? ` (${increases} increase(s): the key rotated)` : ''}`);
  report('consume-exact-drop', wrong ? 'FAIL' : exact ? 'PASS' : 'INCONCLUSIVE',
    `${exact} ask(s) dropped remaining by exactly 1, ${wrong} did not, ${inconclusive} did not reach the model`);
  return { exact, wrong, last: reads.at(-1) };
}

/**
 * After an exact drop the bucket is in use, so every read under the same key
 * shows the same remaining, below the limit. A rotating key or a forged header
 * that selects a key would show another bucket's value (often the limit).
 */
async function afterAskReads(options, { exact, wrong, last }) {
  if (wrong || !exact) {
    for (const check of ['after-ask-reads-stable', 'after-ask-forged-reads']) {
      report(check, wrong ? 'SKIP' : 'INCONCLUSIVE', wrong ? 'skipped: consume-exact-drop already failed' : 'no ask reached the model, so no bucket is known to be in use');
    }
    return;
  }
  const plain = await stableReads(options, 'after-ask', true);
  if (plain[0] !== last) report('after-ask-matches-consume', 'FAIL', `remaining ${plain[0]} after the asks vs ${last} at the end of consume`);
}

const PROOF = ['consume-monotonic', 'consume-exact-drop', 'after-ask-reads-stable', 'after-ask-forged-reads'];

/** FAIL on any failed row; then ERROR if the run stopped; PASS only with the paid proof; otherwise INCONCLUSIVE. */
function overall() {
  if (rows.some(row => row.result === 'FAIL')) return 'FAIL';
  if (rows.some(row => row.result === 'ERROR')) return 'ERROR';
  const passed = check => rows.some(row => row.check === check && row.result === 'PASS');
  return PROOF.every(passed) ? 'PASS' : 'INCONCLUSIVE';
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { console.error(`${error.message}\n${USAGE}`); process.exitCode = 2; return; }
  console.log(`client-ip canary: base=${options.base} family=IPv${options.family} probe=${options.probe} reads=${options.reads} consume=${options.consume}${options.consume ? ` (about $${(options.consume * ASK_COST_USD).toFixed(2)})` : ''}`);
  try {
    await diagnostics(options);
    await usageReads(options);
    await afterAskReads(options, await consume(options));
  } catch (error) {
    report('run', 'ERROR', error.message);
  }
  if (edgeRejections.size) {
    report('forged-edge-rejected', 'INFO', `${[...edgeRejections].map(([variant, { count, detail }]) => `${variant} x${count}: ${detail}`).join('; ')}`
      + ' (answered by Cloudflare, never reached the API, so it cannot choose a key)');
  }
  const width = Math.max(...rows.map(row => row.check.length));
  for (const row of rows) console.log(`${row.result.padEnd(12)} ${row.check.padEnd(width)}  ${row.detail}`);
  const result = overall();
  console.log({
    PASS: 'RESULT: PASS (an ask that reached the model dropped remaining by exactly 1, and plain and forged reads then agreed)',
    FAIL: 'RESULT: FAIL',
    ERROR: 'RESULT: ERROR (the run could not finish: DNS, network, timeout or an unexpected HTTP status. This says nothing about the key and is not a rollback signal: rerun, and send the output to the engineer if it repeats)',
    INCONCLUSIVE: options.consume
      ? 'RESULT: INCONCLUSIVE (no failures, but nothing proves the key: no ask reached the model, or no forged read reached the API; see the INCONCLUSIVE rows and rerun later)'
      : 'RESULT: INCONCLUSIVE (read-only run: no failures, but reads alone cannot prove the key; with owner approval run --consume 2 --i-approve-spend)',
  }[result]);
  process.exitCode = EXIT[result];
}

await main();
