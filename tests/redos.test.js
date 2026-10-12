// Request-path regular expressions must run in linear time (CODE-API-01). Each
// classifier gets pathological input (long runs of spaces, tabs, NBSP or U+3000
// between the words a pattern looks for) and must finish well inside 50 ms. The
// timing runs in a child process with a hard timeout, so a regression fails here in
// seconds instead of pinning the test runner for minutes.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { isBookingRequest, asksForPlan, CLASSIFIER_INPUT_CHARS } = require('../lib/baybayRouter');

const ROOT = path.join(__dirname, '..');
const BUDGET_MS = 50;

// Runs `body` (which must print one JSON line of {name, ms}) in a fresh node with a
// 10 s ceiling and returns the timings.
function timeInChild(body) {
  const script = `const ROOT = ${JSON.stringify(ROOT)};
const time = fn => { const t = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t) / 1e6; };
const out = [];
${body}
process.stdout.write(JSON.stringify(out));`;
  const child = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(child.error?.code, undefined, `the classifiers did not finish within 10 s (catastrophic backtracking): ${child.error?.message}`);
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout);
}

test('the booking and plan classifiers finish 499-character whitespace payloads in under 50 ms (CODE-API-01)', () => {
  const timings = timeInChild(`
const { isBookingRequest, asksForPlan } = require(require('path').join(ROOT, 'lib/baybayRouter'));
isBookingRequest('warm up'); asksForPlan('warm up');
const payloads = {};
for (const [label, ws] of [['space', ' '], ['tab', '\\t'], ['nbsp', '\\u00a0'], ['ideographic', '\\u3000']]) {
  payloads['请+' + label] = '请' + ws.repeat(497) + 'x';
  payloads['a+' + label] = 'a' + ws.repeat(497) + 'x';
  payloads['帮我+' + label] = '帮我' + ws.repeat(496) + 'x';
  payloads['请你能+' + label] = '请' + ws.repeat(165) + '你' + ws.repeat(165) + '能' + ws.repeat(165) + 'x';
  payloads['please+' + label] = 'please' + ws.repeat(492) + 'x';
}
for (const [name, message] of Object.entries(payloads)) {
  out.push({ name: 'booking ' + name, ms: time(() => isBookingRequest(message)) });
  out.push({ name: 'plan ' + name, ms: time(() => asksForPlan(message)) });
}`);
  assert.equal(timings.length, 40);
  for (const { name, ms } of timings) assert.ok(ms < BUDGET_MS, `${name}: ${ms.toFixed(1)} ms`);
});

test('the booking patterns are linear on their own, without the input cap (4,000-character runs)', () => {
  const timings = timeInChild(`
const { bookingPatterns } = require(require('path').join(ROOT, 'lib/baybayRouter'));
for (const re of Object.values(bookingPatterns)) re.test('warm up');
for (const [label, ws] of [['space', ' '], ['tab', '\\t'], ['nbsp', '\\u00a0'], ['ideographic', '\\u3000']]) {
  for (const [shape, message] of [['请', '请' + ws.repeat(4000) + 'x'], ['帮我', '帮我' + ws.repeat(4000) + 'x'], ['a', 'a' + ws.repeat(4000) + 'x'],
    ['请你能', '请' + ws.repeat(4000) + '你' + ws.repeat(4000) + '能' + ws.repeat(4000) + 'x'], ['please', 'please' + ws.repeat(4000) + 'x']]) {
    for (const [lang, re] of Object.entries(bookingPatterns)) out.push({ name: lang + ' ' + shape + '+' + label, ms: time(() => re.test(message)) });
  }
}`);
  assert.equal(timings.length, 40);
  for (const { name, ms } of timings) assert.ok(ms < BUDGET_MS, `${name}: ${ms.toFixed(1)} ms`);
});

test('the rewritten booking classifier keeps its meaning with any whitespace between the words', () => {
  for (const text of ['请  你能不能   帮我   订一张机票', '请　你帮我订酒店', '麻烦 baybay 帮我 直接 买两张票', '你 可以 帮我订个餐厅吗', 'BayBay，  帮我订个餐厅',
    '我想让你帮我订机票', 'Can you book a table for two', 'please\treserve a table']) assert.equal(isBookingRequest(text), true, text);
  for (const text of ['老公说要给我买包，  湾区哪里有奥特莱斯', '帮我订个  周六在 Berkeley 的行程', '妈妈帮我订了机票，  到机场怎么走', 'Can you buy tickets   at the door?']) {
    assert.equal(isBookingRequest(text), false, text);
  }
  assert.equal(asksForPlan('帮我排   一下'), false, 'the plan ask still needs 排一下 together');
  assert.equal(asksForPlan('周六带孩子去 Berkeley，  帮我排一下'), true);
});

test('the classifiers read at most the guide-chat message cap', () => {
  assert.equal(CLASSIFIER_INPUT_CHARS, 500);
  const filler = '天气不错'.repeat(130); // 520 characters, no request in it
  assert.equal(isBookingRequest(`${filler}，帮我订机票`), false, 'text past the cap is not read');
  assert.equal(isBookingRequest(`${filler.slice(0, 480)}，帮我订机票`), true);
});
