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
// Best of three, so a garbage collection or a busy machine does not fail a linear case.
const time = fn => Math.min(...[0, 1, 2].map(() => { const t = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t) / 1e6; }));
const out = [];
${body}
process.stdout.write(JSON.stringify(out));`;
  const child = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(child.error?.code, undefined, `the timed calls did not finish within 10 s (catastrophic backtracking): ${child.error?.message}`);
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

// The CODE-API-01 sweep: every request-path pattern a backtracking probe found
// super-linear, fed its worst input at the size it can reach in production (a
// 500-character message, a 1,200-character history turn, a 6,000-character model
// answer, a 12,000-character web answer, a page's 300 KB head). Before the fixes the
// plan-edit lead-in was exponential (那就 x 30 took ~40 s) and the planner budget
// pattern O(n^4) (a 500-character message took ~60 s); both ran on every BayBay turn.
test('request-path patterns found by the sweep stay under 50 ms at their input bounds', () => {
  const timings = timeInChild(`
const lib = name => require(require('path').join(ROOT, 'lib', name));
const { preparePlanEdit } = lib('baybayPlanEdits');
const { inferFilters } = lib('planner');
const { resolveConversationRequest } = lib('guideConversation');
const { renderCitations, stripLoginPitch, parseDraft } = lib('baybayAgent');
const { stripCodeFence, parseFastDraft, readerProse } = lib('baybayFastPath');
const { citedNameFallback } = lib('plannerWebExtraction');
const { assertSearchScope } = lib('bayAreaSearchScope');
const { unverifiedTransitTiming } = lib('guideTransit');
const { fallbackExcerpt } = lib('baybayExcerpt');
const { factText } = lib('sourceTriage');
const { mediaCandidates } = lib('sourceMonitor');
const { currentEmergencyTopic, emergencyResponse } = lib('safetyRouting');
const { regularHoursQuote } = lib('plannerWebFacts');
const { sanitizeDraft } = lib('baybayProgress');
const { knownLinks } = lib('baybayAnswerQuality');
const { snippet } = lib('baybayEvidence');
const fill = (head, pump, size, tail = 'x') => head + pump.repeat(Math.ceil((size - head.length - tail.length) / pump.length)).slice(0, size - head.length - tail.length) + tail;
const store = { sources: new Map(), aliases: new Map() };
const raw = text => ({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] }] });
const cases = {
  'plan edit 那就 x 249 (500)': () => preparePlanEdit({ message: fill('', '那就', 500), catalog: { events: [], places: [] } }),
  'plan edit 那就 then 只去 (500)': () => preparePlanEdit({ message: fill('', '那就', 498, '只去'), catalog: { events: [], places: [] } }),
  'planner budget + spaces (500)': () => inferFilters(fill('budget', ' ', 500), '2026-10-12'),
  'planner 预算： + U+3000 (500)': () => inferFilters(fill('预算：', '\\u3000', 500), '2026-10-12'),
  'planner party count digits (800)': () => inferFilters(fill('two', '50', 800), '2026-10-12'),
  'planner party count + spaces (800)': () => inferFilters(fill('3', ' ', 800), '2026-10-12'),
  'history budget phrase (500)': () => resolveConversationRequest('预算再低一点', [{ role: 'user', content: fill('月租', ' ', 500) }, { role: 'assistant', content: '好的' }]),
  'citations [ x 12000': () => renderCitations('['.repeat(12000), store),
  'citations [[ + spaces (12000)': () => renderCitations(fill('[[', ' ', 12000), store),
  'login pitch 登录 x 3000 (6000)': () => stripLoginPitch('登录'.repeat(3000)),
  'login pitch spaces + newline (6000)': () => stripLoginPitch(fill('a', ' ', 6000, 'x')),
  'fence + 30000 spaces': () => stripCodeFence(fill('{}', ' ', 30000, 'y')),
  'parseDraft fence + spaces': () => parseDraft(raw(fill('{"answer":"a"}', ' ', 30000, 'y'))),
  'parseFastDraft fence + spaces': () => parseFastDraft(raw(fill('{"lead":"a"}', '\\u3000', 30000, 'y'))),
  'web subject spaces (12000)': () => citedNameFallback({ answer: fill('Foo', ' ', 12000), sources: [] }),
  'web subject indented lines (12000)': () => citedNameFallback({ answer: fill('', '\\n' + ' '.repeat(40), 12000), sources: [] }),
  'weekday check 今天 + spaces (6000)': () => { try { assertSearchScope({ answer: fill('今天', ' ', 6000) }, { query: '周六去哪' }); } catch {} },
  'transit timing digits (6000)': () => unverifiedTransitTiming(fill('', '0', 6000)),
  'transit timing spaces (6000)': () => unverifiedTransitTiming(fill('1', ' ', 6000)),
  'excerpt label lines (9000)': () => fallbackExcerpt(fill('', '\\u3000:', 9000)),
  'counter digits (10000)': () => factText(fill('', '50', 10000)),
  'counter groups (10000)': () => factText(fill('', '5,', 10000)),
  'meta attribute run (100000)': () => mediaCandidates('<head><meta ' + 'Az'.repeat(50000) + '></head>', 'https://example.org/'),
  'emergency number run (5000)': () => currentEmergencyTopic(fill('一直', '几一', 5000)),
  'emergency response number run (5000)': () => emergencyResponse(fill('我爸', '三五', 5000, '年前')),
  'opening hours spaces (12000)': () => regularHoursQuote(fill('Thu', ' ', 12000, '\\n')),
  'region code context (6000)': () => readerProse(fill('region', '\\u3000', 6000, ' peninsula'), 'en'),
  'draft citations [ x 6000': () => sanitizeDraft('['.repeat(6000), 'zh-Hans'),
  'answer links [ x 12000': () => knownLinks('['.repeat(12000), new Map()),
  'snippet whitespace (12000)': () => snippet(fill('a', '\\u3000', 12000), { base: new Set(['a']), expanded: new Set() }),
};
for (const fn of Object.values(cases)) fn(); // warm up (regex compilation, catalog load)
for (const [name, fn] of Object.entries(cases)) out.push({ name, ms: time(fn) });`);
  assert.equal(timings.length, 30);
  for (const { name, ms } of timings) assert.ok(ms < BUDGET_MS, `${name}: ${ms.toFixed(1)} ms`);
});

test('the sweep rewrites keep their matches', () => {
  const { inferFilters } = require('../lib/planner');
  const { preparePlanEdit } = require('../lib/baybayPlanEdits');
  const { stripLoginPitch, renderCitations } = require('../lib/baybayAgent');
  const { stripCodeFence } = require('../lib/baybayFastPath');
  const { unverifiedTransitTiming } = require('../lib/guideTransit');
  const { fallbackExcerpt } = require('../lib/baybayExcerpt');
  const today = '2026-10-12';
  assert.equal(inferFilters('预算 不超过 $80，两个大人一个孩子', today).budget, 80);
  assert.equal(inferFilters('budget: up to USD 120 for the day', today).budget, 120);
  assert.equal(inferFilters('我们 2 位大人和 12 个孩子', today).partySize, 14);
  const edit = preparePlanEdit({ message: '那就只去第一个', previousState: { selectedCandidateIds: ['a', 'b'] }, catalog: { events: [], places: [] } }).edit;
  assert.deepEqual([edit.kind, edit.only, edit.requestedIds], ['remove', true, ['a']]);
  assert.equal(stripLoginPitch('周六可以去金门公园。登录后可以联网查最新开放时间。门票免费。'), '周六可以去金门公园。门票免费。');
  assert.equal(stripLoginPitch('Free on Sundays. Sign in to use web search for live hours. Bring water.'), 'Free on Sundays. Bring water.');
  assert.equal(stripCodeFence('```json\n{"a":1}\n```'), '{"a":1}');
  const store = { sources: new Map([['s1', { title: 'T', url: 'https://t.example' }]]), aliases: new Map() };
  assert.deepEqual(renderCitations('见 [官网](https://t.example) [[s1]]', store), { answer: '见 官网 [1]', sources: [{ title: 'T', url: 'https://t.example' }] });
  assert.equal(unverifiedTransitTiming('坐 BART 大约 35 - 40 分钟'), true);
  assert.equal(unverifiedTransitTiming('about 20 to 25  minutes by bus'), true);
  assert.equal(fallbackExcerpt('开放时间：\n周二至周日开放。'), '周二至周日开放。');
});
