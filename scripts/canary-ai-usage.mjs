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
// plain reads and --reads identical forged-header reads of the now-used bucket.
// That proof does not need the diagnostic window. A run without it is
// INCONCLUSIVE at best.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';

const USAGE = `Usage: node scripts/canary-ai-usage.mjs --base <https://host/api> [--reads 10] [--family 4|6]
       [--probe <8-24 lowercase letters/digits>] [--consume <1-4> --i-approve-spend]
Exit code: 0 PASS, 1 FAIL, 2 bad arguments, 3 INCONCLUSIVE (no ask reached the model).`;
const ASK_COST_USD = 0.23;
const MAX_CONSUME = 4;
// GET /ai/usage allows 120 reads per key per minute. A run makes at most
// 4 * reads + 2 * consume + 3 of them, so 20 keeps even a fast run under that.
const MAX_READS = 20;
const EXIT = { PASS: 0, FAIL: 1, INCONCLUSIVE: 3 };
const ASKS = [
  '周末在湾区带孩子去哪里玩比较好？请简单推荐两个地方。',
  '湾区有什么适合老人散步的公园？请推荐两个。',
  '雨天在湾区可以去哪些室内地方？请简单说两个。',
  '推荐两个适合拍照的湾区海边步道。',
];

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
  if (!Number.isInteger(options.reads) || options.reads < 5 || options.reads > MAX_READS) throw new Error(`--reads must be an integer from 5 to ${MAX_READS}`);
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
        resolve({ status: response.statusCode, data });
      });
    });
    request.on('timeout', () => request.destroy(new Error(`timeout: ${method} ${url.pathname}`)));
    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

// Documentation ranges (RFC 5737 / RFC 2544 / RFC 3849): never a real visitor.
const forgedHeaders = () => {
  const ip = () => `198.18.${crypto.randomInt(256)}.${crypto.randomInt(1, 255)}`;
  return { 'X-Forwarded-For': `${ip()}, ${ip()}`, 'CF-Connecting-IP': ip(), 'True-Client-IP': ip(), 'X-Real-IP': `2001:db8:${crypto.randomInt(65536).toString(16)}::1` };
};

const rows = [];
const report = (check, result, detail) => rows.push({ check, result, detail });

async function readUsage(options, headers = {}) {
  const response = await call(options, `/ai/usage?probe=${options.probe}`, { headers });
  if (response.status !== 200 || !Number.isInteger(response.data?.remaining)) throw new Error(`GET /ai/usage returned ${response.status} ${JSON.stringify(response.data)}`);
  return response.data;
}

async function diagnostics(options) {
  const first = await call(options, '/_diag/client-ip');
  if (first.status === 404) return report('diag-window', 'SKIP', 'GET /_diag/client-ip is 404: CLIENT_IP_DIAGNOSTIC_UNTIL is not open');
  if (first.status !== 200 || !first.data?.fingerprints) return report('diag-window', 'FAIL', `unexpected ${first.status}`);
  const plain = [first.data];
  for (let i = 1; i < 6; i++) plain.push((await call(options, '/_diag/client-ip')).data);
  const forged = [];
  for (let i = 0; i < 6; i++) forged.push((await call(options, '/_diag/client-ip', { headers: forgedHeaders() })).data);
  if ([...plain, ...forged].some(row => !row?.fingerprints)) return report('diag-window', 'FAIL', 'a diagnostic read was rate limited or malformed; wait a minute and retry');
  const { mode, reqIp, reqIpFrom, xffLength, cfConnectingIp, cfConnectingIpEqualsXffMinus2, cloudflareMode, cfColo } = first.data;
  report('diag-window', 'PASS', `mode=${mode} reqIp=${reqIpFrom}:${reqIp.class} xffLength=${xffLength} cf-connecting-ip=${cfConnectingIp ? cfConnectingIp.class : 'absent'} cf==xff[-2]=${cfConnectingIpEqualsXffMinus2} cloudflareKeyFrom=${cloudflareMode.keyFrom} colo=${cfColo}`);
  const distinct = (list, field) => new Set(list.map(row => row.fingerprints[field])).size;
  const plainKeys = distinct(plain, 'cloudflare');
  const sources = [...new Set(plain.map(row => row.cloudflareMode.keyFrom))];
  // edge-* sources mean cloudflare mode would fall back to today's edge key (see the decision table).
  const visitorKey = sources.every(source => ['cf-connecting-ip', 'xff-left-of-edge'].includes(source));
  report('diag-cloudflare-key-stable', plainKeys === 1 && visitorKey ? 'PASS' : 'FAIL', `${plain.length} reads -> ${plainKeys} cloudflare-mode key(s), from ${sources.join('/')}`);
  const forgedKeys = new Set([...plain, ...forged].map(row => row.fingerprints.cloudflare)).size;
  report('diag-cloudflare-key-forged', forgedKeys === 1 ? 'PASS' : 'FAIL', `${forged.length} reads with forged XFF/CF-Connecting-IP/True-Client-IP/X-Real-IP -> ${forgedKeys} key(s) overall`);
  const currentKeys = distinct([...plain, ...forged], 'current');
  report('diag-current-key', mode === 'cloudflare' ? currentKeys === 1 ? 'PASS' : 'FAIL' : 'INFO',
    `${plain.length + forged.length} reads -> ${currentKeys} key(s) under the live mode (${mode}); more than one means the live key rotates`);
}

/**
 * --reads plain reads, then --reads reads with forged XFF/CF-Connecting-IP/
 * True-Client-IP/X-Real-IP. Any difference is a FAIL. Equal series prove the
 * key only when the bucket is known to be in use, i.e. after an ask that
 * reached the model; before that they are INCONCLUSIVE.
 */
async function stableReads(options, phase, proven) {
  const plain = [];
  for (let i = 0; i < options.reads; i++) plain.push(await readUsage(options));
  const forged = [];
  for (let i = 0; i < options.reads; i++) forged.push((await readUsage(options, forgedHeaders())).remaining);
  const series = plain.map(row => row.remaining);
  const verdict = ok => (!ok ? 'FAIL' : proven ? 'PASS' : 'INCONCLUSIVE');
  const note = proven ? '' : ' (reads alone cannot tell keys apart: an unused or idle bucket reads the same under any key)';
  report(`${phase}-reads-stable`, verdict(new Set(series).size === 1), `remaining ${series.join(' ')} / limit ${plain[0].limit}${note}`);
  report(`${phase}-forged-reads`, verdict(forged.every(value => value === series[0])), `remaining ${forged.join(' ')} vs plain ${series[0]}${note}`);
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

/** PASS only with the paid proof; FAIL on any failed row; otherwise INCONCLUSIVE. */
function overall() {
  if (rows.some(row => row.result === 'FAIL')) return 'FAIL';
  const passed = check => rows.some(row => row.check === check && row.result === 'PASS');
  return ['consume-monotonic', 'consume-exact-drop', 'after-ask-reads-stable', 'after-ask-forged-reads'].every(passed) ? 'PASS' : 'INCONCLUSIVE';
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
    report('run', 'FAIL', error.message);
  }
  const width = Math.max(...rows.map(row => row.check.length));
  for (const row of rows) console.log(`${row.result.padEnd(12)} ${row.check.padEnd(width)}  ${row.detail}`);
  const result = overall();
  console.log({
    PASS: 'RESULT: PASS (an ask that reached the model dropped remaining by exactly 1, and plain and forged reads then agreed)',
    FAIL: 'RESULT: FAIL',
    INCONCLUSIVE: 'RESULT: INCONCLUSIVE (no failures, but no ask reached the model, so nothing proves the key; run --consume 2 --i-approve-spend with owner approval)',
  }[result]);
  process.exitCode = EXIT[result];
}

await main();
