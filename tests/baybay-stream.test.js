// API-BB-STREAM: Anthropic streaming, the fast path's lead-first drafts and the SSE
// `draft` event (web contract WEB-BB-STREAMPREP #25, RC-21). Offline ($0): the
// provider is the recorded-format fixtures in tests/fixtures/anthropic-stream/ or a
// stub that streams a message in byte chunks (tests/support/anthropic-sse.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { createSseParser, createMessageAccumulator, readMessageStream, estimatedUsage, createJsonFieldStream, fastDraftField } = require('../lib/anthropicStream');
const { createDraftWriter, draftCorrected, sanitizeDraft, stablePrefix, createBayBayProgressStream, DRAFT_MAX_CHARS } = require('../lib/baybayProgress');
const { createAnthropicBaybay, normalizedResponse } = require('../lib/anthropicBaybay');
const { fetchAiStream } = require('../lib/aiRequest');
const { createAiGovernance } = require('../lib/aiGovernance');
const { createAiRuntimeMetrics } = require('../lib/aiRuntimeMetrics');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { systemBlocks, FAST_FORMAT } = require('../lib/baybayFastPath');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const { createMemoryModels } = require('./support/memory-models');
const { sseFor, byteChunks, sseResponse } = require('./support/anthropic-sse');

const FIXTURES = path.join(__dirname, 'fixtures', 'anthropic-stream');
const fixture = name => fs.readFileSync(path.join(FIXTURES, name), 'utf8').replace(/\r\n/g, '\n');
const expected = name => JSON.parse(fixture(name));
async function* iterate(chunks) { for (const chunk of chunks) yield chunk; }

// ---------------------------------------------------------------- SSE and message rebuild

test('SSE framing: LF, CR and CRLF line ends (CRLF split across chunks), comments, multi-line data; an unterminated last event is dropped', () => {
  const seen = [];
  const parser = createSseParser(event => seen.push(event));
  for (const chunk of ['event: a\r', '\ndata: 1\r\n\r\n: keepalive\n', 'event: b\rdata: x\rdata: y\r\r', 'data:no-space\n\nevent: c\ndata: lost']) parser.push(chunk);
  parser.end();
  assert.deepEqual(seen, [{ event: 'a', data: '1' }, { event: 'b', data: 'x\ny' }, { event: 'message', data: 'no-space' }]);
});

test('recorded fast-path stream rebuilds the exact non-streamed message at every byte split, LF or CRLF, keeping the signature verbatim', async () => {
  const sse = fixture('fast-path.sse'), message = expected('fast-path.message.json');
  for (const size of [1, 2, 3, 5, 7, 13, 64, 1 << 20]) for (const lineEnd of ['\n', '\r\n']) {
    const texts = [];
    const accumulator = createMessageAccumulator({ onDelta: delta => { if (delta.type === 'text') texts.push(delta.text); } });
    const rebuilt = await readMessageStream(iterate(byteChunks(sse.replace(/\n/g, lineEnd), size)), accumulator);
    assert.deepEqual(rebuilt, message, `split ${size} ${JSON.stringify(lineEnd)}`);
    assert.equal(texts.join(''), message.content[1].text);
  }
  // Usage: message_start's input and cache counts survive; message_delta sets the final output.
  const rebuilt = await readMessageStream(iterate([fixture('fast-path.sse')]));
  assert.deepEqual(rebuilt.usage, { input_tokens: 2210, cache_creation_input_tokens: 0, cache_read_input_tokens: 3104, output_tokens: 214, service_tier: 'standard' });
  // A fetch Response body (WHATWG stream) works the same way.
  assert.deepEqual(await readMessageStream(sseResponse(sse, { size: 3 }).body), message);
});

test('a live recorded Sonnet 5.5 fast-path stream (eval stream-1009, C03): padded JSON, lead first, drafts equal the lead and carry no markers', async () => {
  // Recorded with --save-sse from the real API: data lines carry whitespace padding,
  // message_delta repeats input usage and adds stop_details/container, ping has a space.
  const sse = fixture('live-sonnet-fast-path.sse');
  const reference = await readMessageStream(iterate([sse]));
  for (const size of [1, 3, 17, 4096]) assert.deepEqual(await readMessageStream(iterate(byteChunks(sse, size))), reference);
  assert.deepEqual(reference.content.map(block => block.type), ['text']);
  assert.equal(reference.stop_reason, 'end_turn');
  assert.deepEqual([reference.usage.cache_read_input_tokens, reference.usage.output_tokens], [3106, 479]);
  const answer = JSON.parse(reference.content[0].text);
  assert.match(reference.content[0].text, /^\{"lead":/, 'structured output streams the lead first');
  const events = [];
  const writer = createDraftWriter({ emit: event => events.push(event), ...fakeTimers() });
  const fields = createJsonFieldStream({ match: fastDraftField, onText: (target, text) => writer.text(target.field, target.index, text), onDone: target => writer.done(target.field, target.index) });
  await readMessageStream(iterate(byteChunks(sse, 7)), createMessageAccumulator({ onDelta: delta => { if (delta.type === 'text') fields.push(delta.text); } }));
  writer.end({ complete: true });
  assert.equal(events[0].field, 'lead');
  assert.equal(joined(events, 'lead'), sanitizeDraft(answer.lead, 'zh-Hans'));
  answer.points.slice(0, 5).forEach((point, index) => assert.equal(joined(events, 'point', index), sanitizeDraft(point.text, 'zh-Hans').trimStart()));
  for (const event of events) assert.doesNotMatch(event.text, /\[\[|\[\d+\]|https?:|20\d\d-\d\d-\d\d/);
});

test('recorded tool round: summarized thinking + signature verbatim and a tool input split into JSON fragments', async () => {
  const message = expected('tool-round.message.json');
  for (const size of [1, 4, 9, 4096]) assert.deepEqual(await readMessageStream(iterate(byteChunks(fixture('tool-round.sse'), size))), message);
  const normalized = normalizedResponse(message);
  assert.equal(normalized.status, 'completed');
  assert.deepEqual(normalized.output, [{ type: 'function_call', call_id: 'toolu_fixture_01', name: 'search_site', arguments: JSON.stringify({ query: '伯克利 周六 亲子 博物馆 "免费"' }) }]);
});

test('stream errors, truncation, fallback blocks, citations and unknown events', async () => {
  const start = 'event: message_start\ndata: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":[],"usage":{"input_tokens":1000,"cache_read_input_tokens":500,"output_tokens":1}}}\n\n';
  const text = 'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\nevent: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"蓝天使周六下午飞过 Marina Green"}}\n\n';
  // An error event mid-stream (e.g. overloaded) is a provider failure, never a partial answer.
  await assert.rejects(readMessageStream(iterate([start, text, 'event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}\n\n'])),
    { code: 'AI_PROVIDER_STREAM_ERROR', providerErrorType: 'overloaded_error' });
  // A stream that ends before message_stop is not a message, but its usage can be estimated.
  const accumulator = createMessageAccumulator();
  await assert.rejects(readMessageStream(iterate([start, text]), accumulator), /before message_stop/);
  const usage = estimatedUsage(accumulator.partial());
  assert.equal(usage.input_tokens, 1000); assert.equal(usage.cache_read_input_tokens, 500);
  assert.ok(usage.output_tokens >= 10, 'output estimated from the received text');
  // Fallback marker blocks (server-side fallback), citations, unknown events and delta types.
  const message = await readMessageStream(iterate([start,
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"fallback","from":{"model":"claude-sonnet-5-5"},"to":{"model":"claude-opus-5-5"}}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\nevent: some_future_event\ndata: {"type":"some_future_event"}\n\n',
    'event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":"","citations":null}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"x"}}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"future_delta","value":1}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"ok"}}\n\nevent: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n',
    'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":9,"cache_read_input_tokens":null}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\nevent: ignored_after_stop\ndata: {}\n\n']));
  assert.deepEqual(message.content.map(block => block.type), ['fallback', 'text']);
  assert.deepEqual(message.content[1], { type: 'text', text: 'ok', citations: [{ type: 'char_location', cited_text: 'x' }] });
  assert.deepEqual(message.usage, { input_tokens: 1000, cache_read_input_tokens: 500, output_tokens: 9 });
  // A tool input that does not parse is never executable.
  const broken = await readMessageStream(iterate([start,
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"search_site","input":{}}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"query\\": \\"cut"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\nevent: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n']));
  assert.equal(broken.content[0].input, null);
  assert.equal(normalizedResponse(broken).status, 'failed');
  await assert.rejects(readMessageStream(iterate(['event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'])), /before message_start/);
  await assert.rejects(readMessageStream(iterate([start, 'event: content_block_delta\ndata: {"type":"content_block_delta","index":3,"delta":{"type":"text_delta","text":"x"}}\n\n'])), /unknown content block/);
});

// ---------------------------------------------------------------- incremental JSON fields

test('lead and points[i].text stream out of the JSON as written: escapes and \\u pairs split anywhere; other strings ignored', () => {
  const answer = { lead: '可以，"引号"\n与 \\ 反斜杠 😀 [[e1]]', points: [{ text: '第一点 2026-10-17', cardIds: ['e1'] }, { text: 'second / point', cardIds: [] }],
    candidateIds: ['e1'], followups: ['那下雨天呢？'], coverage: [{ id: 'cost', status: 'answered', summary: 'lead-like summary', sourceIds: [] }], gap: '', extra: { lead: 'nested lead is not the lead' } };
  // JSON.stringify keeps 😀 raw; also check the \u-escaped form models may emit.
  for (const json of [JSON.stringify(answer), JSON.stringify(answer).replace(/😀/g, '\\ud83d\\ude00').replace(/可/, '\\u53ef')]) {
    for (const size of [1, 2, 3, 6, 11, json.length]) {
      const texts = {}, done = [];
      const stream = createJsonFieldStream({ match: fastDraftField, onText: (target, text) => { const key = target.field === 'lead' ? 'lead' : `p${target.index}`; texts[key] = (texts[key] || '') + text; }, onDone: target => done.push(target.field === 'lead' ? 'lead' : `p${target.index}`) });
      for (let index = 0; index < json.length; index += size) stream.push(json.slice(index, index + size));
      assert.deepEqual(texts, { lead: answer.lead, p0: answer.points[0].text, p1: answer.points[1].text }, `split ${size}`);
      assert.deepEqual(done, ['lead', 'p0', 'p1']);
    }
  }
  // Garbage never throws.
  const stream = createJsonFieldStream({ match: fastDraftField, onText: () => { throw new Error('listener'); } });
  stream.push('```json\n{"lead":"x\\u00zz"}'); stream.push(null);
});

// ---------------------------------------------------------------- sanitiser, batching, budget

test('draft sanitiser: no [[ref]], [n], links or URLs; ISO dates and region codes become reader prose; held-back text never changes', () => {
  const clean = sanitizeDraft('主表演 2026-10-11 下午[[e1]]，见 [官网](https://fleetweek.us/a) 或 https://x.y/b 在 south-bay [2]。', 'zh-Hans');
  assert.doesNotMatch(clean, /\[\[|\[\d\]|https?:|\]\(|2026-10-11|south-bay/);
  assert.match(clean, /10月11日（周日）/); assert.match(clean, /南湾/); assert.match(clean, /官网/);
  assert.equal(sanitizeDraft('Sat at 2026-10-10 in east-bay [[e2]].', 'en'), 'Sat at Sat, Oct 10 in East Bay.');
  // A stable prefix never ends inside a word, an unclosed [[ref or a Markdown link.
  assert.equal(stablePrefix('蓝天使周六飞[[e'), '蓝天使周六飞');
  assert.equal(stablePrefix('see [the page](https://x'), 'see');
  assert.equal(stablePrefix('Fleet Week is on Sat'), 'Fleet Week is on');
  assert.equal(stablePrefix('日期 2026-10-1'), '日期');
  assert.equal(stablePrefix('好[[e1]]'), '好', 'a closed ]] may still become ](…)');
  assert.equal(stablePrefix('好[[e1]]。'), '好[[e1]]。');
});

function fakeTimers() {
  const pending = new Set();
  return { setTimer: fn => { const timer = { fn }; pending.add(timer); return timer; }, clearTimer: timer => pending.delete(timer),
    fire() { for (const timer of [...pending]) { pending.delete(timer); timer.fn(); } }, size: () => pending.size };
}

test('draft writer: batches by 40 characters or the 120 ms timer, flushes a finished field at once, numbers events and keeps field order', () => {
  const timers = fakeTimers(), events = [];
  const writer = createDraftWriter({ emit: event => events.push(event), locale: 'zh-Hans', ...timers });
  writer.text('lead', undefined, '蓝天使本周');
  assert.equal(events.length, 0); assert.equal(timers.size(), 1, 'short text waits for the timer');
  timers.fire();
  assert.deepEqual(events, [{ seq: 1, field: 'lead', text: '蓝天使本周' }]);
  writer.text('lead', undefined, '末飞，周六周日下午都有表演[[e');
  timers.fire();
  assert.equal(events.at(-1).text, '末飞，周六周日下午都有表演', 'an unclosed [[ marker is held back');
  writer.text('lead', undefined, '1]]。'); writer.done('lead');
  assert.equal(events.at(-1).text, '。', 'the marker is dropped and the finished field is sent at once');
  writer.text('point', 0, 'x'.repeat(39)); assert.equal(events.length, 3);
  writer.text('point', 0, ' and more'); // 48 characters: flushed without waiting
  assert.equal(events.length, 4); assert.deepEqual({ ...events[3], text: undefined }, { seq: 4, field: 'point', index: 0, text: undefined });
  writer.text('point', 5, 'a sixth point is never drafted'); writer.done('point', 5);
  writer.text('point', 0, ' tail'); writer.done('point', 0); writer.end({ complete: true });
  writer.text('point', 1, 'after the call ended');
  assert.deepEqual(events.map(event => event.seq), [1, 2, 3, 4, 5]);
  assert.ok(!events.some(event => event.index === 5 || /after the call/.test(event.text)));
  assert.deepEqual(writer.sent(), { lead: '蓝天使本周末飞，周六周日下午都有表演。', points: [`${'x'.repeat(39)} and more tail`], chars: 19 + 53, events: 5 });
  // A failed call drops held-back text.
  const dropped = [], failed = createDraftWriter({ emit: event => dropped.push(event), ...fakeTimers() });
  failed.text('lead', undefined, '一半的'); failed.end({ complete: false });
  assert.deepEqual(dropped, []);
});

test('drafts stop at exactly 4,000 characters; a field whose sanitised text stops extending what was sent is frozen', () => {
  const events = [], writer = createDraftWriter({ emit: event => events.push(event), ...fakeTimers() });
  writer.text('lead', undefined, '长'.repeat(3990)); writer.done('lead');
  writer.text('point', 0, '😀'.repeat(20)); writer.done('point', 0);
  writer.text('point', 1, 'more'); writer.done('point', 1);
  const total = events.reduce((sum, event) => sum + event.text.length, 0);
  assert.equal(total, DRAFT_MAX_CHARS, 'the budget fills to exactly 4,000 UTF-16 units');
  assert.ok(!events.some(event => event.index === 1));
  assert.ok(!/[\ud800-\udbff]$/.test(events.at(-1).text), 'never a lone high surrogate at the edge');
  // "( peninsula" was sent as a word; once ")" arrives the code becomes a name, so the field freezes.
  const frozen = [], en = createDraftWriter({ emit: event => frozen.push(event), locale: 'en', ...fakeTimers() });
  en.text('lead', undefined, 'Try the ( peninsula '); en.text('point', 0, 'x'.repeat(41));
  en.text('lead', undefined, ') today'); en.done('lead');
  assert.deepEqual(frozen.filter(event => event.field === 'lead').map(event => event.text), ['Try the ( peninsula']);
  assert.equal(draftCorrected(en.sent(), { lead: 'Try the ( the Peninsula ) today' }), true);
});

test('corrected: true only when the result does not continue what the reader saw', () => {
  const sent = { lead: '蓝天使周六飞。', points: [, '第二点'] };
  assert.equal(draftCorrected(sent, { lead: '蓝天使周六飞[1]。', points: [{ text: '第一点' }, { text: '第二点 [2] 还有' }] }), false);
  assert.equal(draftCorrected({ lead: '蓝天使周', points: [] }, { lead: '蓝天使周六飞。' }), false, 'a draft cut by the budget is a prefix');
  assert.equal(draftCorrected(sent, { lead: '站内已收录「舰队周」。' }), true, 'guard template');
  assert.equal(draftCorrected(sent, {}), true, 'the result has no lead (a rewritten answer)');
  assert.equal(draftCorrected(sent, { lead: '蓝天使周六飞。', points: [{ text: '第一点' }, { text: '换了' }] }), true);
});

// ---------------------------------------------------------------- transport

function sseResponseFixture() {
  const response = new EventEmitter();
  response.output = ''; response.writableEnded = false;
  response.status = () => response; response.set = () => response; response.flushHeaders = () => {};
  response.write = value => { response.output += value; };
  response.end = () => { response.writableEnded = true; response.emit('close'); };
  return response;
}
const frames = output => output.trim().split('\n\n').filter(Boolean).map(block => { const [event, data] = block.split('\n'); return { event: event.slice(7), data: JSON.parse(data.slice(6)) }; });

test('the SSE draft event re-checks shape, order, index and the 4,000-character total', () => {
  const marks = [], res = sseResponseFixture();
  const stream = createBayBayProgressStream(res, { mark: stage => marks.push(stage), response() {} });
  for (const value of [{ seq: 1, field: 'lead', text: '开头' }, { seq: 1, field: 'lead', text: 'dup' }, { seq: 2, field: 'point', text: 'no index' }, { seq: 3, field: 'point', index: 5, text: 'x' },
    { seq: 4, field: 'other', text: 'x' }, { seq: 5, field: 'point', index: 0, text: '' }, { seq: 6, field: 'point', index: 4, text: '第五点', extra: 'dropped' },
    { seq: 7, field: 'lead', text: 'x'.repeat(DRAFT_MAX_CHARS) }]) stream.draft(value);
  stream.result({ ok: true });
  assert.deepEqual(frames(res.output), [{ event: 'draft', data: { seq: 1, field: 'lead', text: '开头' } }, { event: 'draft', data: { seq: 6, field: 'point', index: 4, text: '第五点' } }, { event: 'result', data: { ok: true } }]);
  assert.deepEqual(marks, ['firstDraft', 'firstDraft']);
});

// ---------------------------------------------------------------- adapter

test('adapter: a streamed tool round replays thinking and signature verbatim; call 2 equals the non-streamed run except stream:true', async () => {
  const toolRound = expected('tool-round.message.json');
  const final = { type: 'message', id: 'm2', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"lead":"好","points":[],"candidateIds":[],"followups":[],"coverage":[],"gap":""}' }], usage: { input_tokens: 9, output_tokens: 9 } };
  const tool = { type: 'function', name: 'search_site', description: 'Search', strict: true, parameters: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'], additionalProperties: false } };
  async function runTwoCalls(stream) {
    const bodies = [], texts = [];
    const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture-only' }, route: 'baybay_agent', fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body); bodies.push(body);
      const message = bodies.length === 1 ? toolRound : final;
      if (!body.stream) return { ok: true, status: 200, json: async () => message };
      return sseResponse(bodies.length === 1 ? fixture('tool-round.sse') : sseFor(message), { size: 5 });
    } });
    const payload = input => ({ system: systemBlocks(), cacheControl: { type: 'ephemeral' }, input, tools: [tool], text: { format: FAST_FORMAT }, max_output_tokens: 6000, tool_choice: 'auto', ...(stream ? { stream: true } : {}) });
    const input = [{ role: 'user', content: '{"message":"Berkeley"}' }];
    const first = await request(payload(input), { onText: text => texts.push(text) });
    input.push(...first.output, { type: 'function_call_output', call_id: first.output[0].call_id, output: '{"items":[]}' });
    const second = await request(payload(input), { onText: text => texts.push(text) });
    return { bodies, second, texts };
  }
  const streamed = await runTwoCalls(true), plain = await runTwoCalls(false);
  assert.deepEqual(streamed.bodies[1].messages[1], { role: 'assistant', content: toolRound.content }, 'thinking + signature + tool_use replayed verbatim');
  assert.deepEqual(streamed.bodies.map(({ stream, ...body }) => { assert.equal(stream, true); return body; }), plain.bodies);
  assert.deepEqual(streamed.second, plain.second);
  assert.equal(streamed.texts.join(''), final.content[0].text, 'only answer text is reported, never thinking or tool input');
  assert.equal(plain.texts.length, 0, 'a non-streamed call reports no text');
});

test('adapter: a Haiku refusal retried on Sonnet reports no text from the retry; v1 payloads never stream', async () => {
  const refusal = { type: 'message', id: 'r', model: 'claude-haiku-5-5', role: 'assistant', stop_reason: 'refusal', content: [{ type: 'text', text: '{"lead":"部分' }], usage: { input_tokens: 5, output_tokens: 3 } };
  const ok = { type: 'message', id: 'o', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"lead":"重试的答案"}' }], usage: { input_tokens: 5, output_tokens: 3 } };
  const texts = [], bodies = [];
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture-only', BAYBAY_MODEL_FAST: 'claude-haiku-5-5' }, route: 'baybay_fast', log: () => {}, fetchImpl: async (_url, init) => {
    const body = JSON.parse(init.body); bodies.push(body); return sseResponse(sseFor(bodies.length === 1 ? refusal : ok));
  } });
  const response = await request({ system: systemBlocks(), input: [{ role: 'user', content: '{}' }], tools: [], text: { format: FAST_FORMAT }, max_output_tokens: 4000, stream: true }, { onText: text => texts.push(text) });
  assert.deepEqual(bodies.map(body => [body.model, body.stream]), [['claude-haiku-5-5', true], ['claude-sonnet-5-5', true]]);
  assert.equal(texts.join(''), '{"lead":"部分');
  assert.equal(response.output[0].content[0].text, '{"lead":"重试的答案"}');
  // v1 (an instructions string): `stream` in the payload is ignored and the body is unchanged.
  const v1 = [];
  const legacy = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture-only' }, fetchImpl: async (_url, init) => { v1.push(JSON.parse(init.body)); return { ok: true, status: 200, json: async () => ok }; } });
  await legacy({ model: 'claude-sonnet-5-5', instructions: 'v1', input: [{ role: 'user', content: 'q' }], tools: [], text: { format: FAST_FORMAT }, max_output_tokens: 4000, stream: true }, { onText: text => texts.push(text) });
  assert.equal(v1[0].stream, undefined);
});

// ---------------------------------------------------------------- abort / timeout accounting

const NOW = Date.parse('2026-10-08T20:00:00Z');
function governed() {
  const models = createMemoryModels();
  const metrics = createAiRuntimeMetrics({ Model: models.AiRuntimeMetric, now: () => NOW });
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'stream-test-secret-0123456789' }, now: () => NOW, metrics });
  const inRequest = fn => new Promise((resolve, reject) => {
    const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.ip = 'private-ip';
    const res = new EventEmitter(); res.statusCode = 200; res.writableEnded = false;
    res.status = value => { res.statusCode = value; return res; };
    res.json = () => { res.writableEnded = true; res.emit('finish'); res.emit('close'); return res; };
    governance.middleware(async () => 'private-account')(req, res, () => Promise.resolve(fn(req, res)).then(resolve, reject)).catch(reject);
  });
  return { models, metrics, inRequest };
}

test('a stream cut by the timeout records estimated usage and spend; a completed stream records TTFT and its real usage', async () => {
  const { models, metrics, inRequest } = governed();
  const message = { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"lead":"蓝天使周六下午在 Marina Green 飞过，免费观看。"}' }], usage: { input_tokens: 1000, cache_read_input_tokens: 3000, output_tokens: 120 } };
  const cut = sseFor(message).split('event: content_block_stop')[0];
  const body = JSON.stringify({ model: 'claude-sonnet-5-5', stream: true });
  await inRequest(async (_req, res) => {
    const deltas = [];
    await assert.rejects(fetchAiStream('https://never-fetched.invalid', { body }, { timeoutMs: 300, onDelta: delta => deltas.push(delta),
      fetchImpl: async (_url, init) => sseResponse(cut, { size: 11, hold: true, signal: init.signal }) }), { code: 'AI_PROVIDER_TIMEOUT' });
    assert.ok(deltas.length > 0, 'deltas arrived before the stall');
    const done = await fetchAiStream('https://never-fetched.invalid', { body }, { timeoutMs: 5000, fetchImpl: async () => sseResponse(sseFor(message), { size: 9 }) });
    assert.deepEqual(done, { ...message, stop_sequence: null });
    res.json({ ok: true });
  });
  await metrics.flush();
  const day = models.AiGovernance.rows.find(row => row.id === 'ai:2026-10-08');
  assert.equal(day.failures, 1); assert.equal(day.calls, 1);
  assert.ok(day.inputTokens >= 2 * 4000, 'both calls counted their input (the cut one from message_start)');
  assert.ok(day.outputTokens > 120, 'the cut call adds an output estimate');
  const spend = models.AiGovernance.rows.find(row => row.id === 'ai-usd:2026-10-08');
  assert.equal(spend.pricedCalls, 2); assert.ok(spend.microUsd > 0);
  const runtime = models.AiRuntimeMetric.rows.find(row => row.model === 'claude-sonnet-5-5');
  assert.equal(runtime.providerTimeout, 1); assert.equal(runtime.providerCompleted, 1);
  assert.equal(Object.values(runtime.providerTtft).reduce((sum, value) => sum + value, 0), 1, 'TTFT kept for the completed call only');
  assert.ok(runtime.cacheReadTokens >= 6000);
});

test('an upstream abort mid-stream is a cancellation with an estimate, and is rethrown as cancelled', async () => {
  const { models, inRequest } = governed();
  const message = { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"lead":"一半"}' }], usage: { input_tokens: 500, output_tokens: 10 } };
  const controller = new AbortController();
  await inRequest(async (_req, res) => {
    await assert.rejects(fetchAiStream('https://never-fetched.invalid', { body: JSON.stringify({ model: 'claude-sonnet-5-5', stream: true }), signal: controller.signal }, { timeoutMs: 5000,
      onDelta: () => controller.abort(), fetchImpl: async (_url, init) => sseResponse(sseFor(message).split('event: message_delta')[0], { size: 4, hold: true, signal: init.signal }) }), { code: 'REQUEST_CANCELLED' });
    res.json({ ok: true });
  });
  const day = models.AiGovernance.rows.find(row => row.id === 'ai:2026-10-08');
  assert.equal(day.failures, 1); assert.ok(day.inputTokens >= 500);
});

// ---------------------------------------------------------------- the assistant (BAYBAY_ENGINE=v2)

const TODAY = '2026-10-08';
const guides = require('../data/guide-catalog.json');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' };
const quota = () => ({ updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) });
const claude = (answer, extra = {}) => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn',
  content: [{ type: 'thinking', thinking: '', signature: 'sig-fixture' }, { type: 'text', text: JSON.stringify({ lead: 'L', points: [], candidateIds: [], followups: [], coverage: [], gap: '', ...answer }) }], usage: { input_tokens: 40, output_tokens: 60 }, ...extra });
function assistantWith({ config = {}, answers }) {
  const sent = [];
  const assistant = createBayBayAssistant({ config: { ...base, BAYBAY_ENGINE: 'v2', ...config }, guideCatalog: guides, catalog, now: () => Date.parse('2026-10-08T17:00:00Z'), isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body); sent.push(body);
      const message = typeof answers === 'function' ? answers(body, sent.length) : claude(answers[Math.min(sent.length, answers.length) - 1]);
      return body.stream ? sseResponse(sseFor(message, { piece: 3 }), { size: 5 }) : { ok: true, status: 200, json: async () => message };
    } });
  return { assistant, sent };
}
const ask = async (assistant, message, { currentPath = '/', locale = 'zh-Hans', searchMode = 'site', drafts = true } = {}) => {
  const events = [];
  const result = await assistant.run({ message, locale, currentPath, pageContext: publicContext.resolve({ context: { currentPath }, currentPath, today: TODAY, locale }),
    searchMode, webAccess: { allowed: false }, ...(drafts ? { onDraft: event => events.push(event) } : {}) });
  return { result, events };
};
const joined = (events, field, index) => events.filter(event => event.field === field && (field === 'lead' || event.index === index)).map(event => event.text).join('');

test('v2 fast path with a capable client: one streamed call, lead drafts first, sanitised, ending in the validated result (corrected:false)', async () => {
  const answer = { lead: '会飞，蓝天使周六和周日下午都有表演[[e1]]。', points: [{ text: '主表演 2026-10-11 下午在 Marina Green，免费观看[[e1]]。', cardIds: ['e1'] }, { text: '人多，建议坐 Muni 到 Fort Mason 附近再步行。', cardIds: [] }] };
  const { assistant, sent } = assistantWith({ answers: [answer] });
  const { result, events } = await ask(assistant, '蓝天使这周末飞吗');
  assert.equal(sent.length, 1); assert.equal(sent[0].stream, true);
  assert.equal(result.route.reason, 'site_answer');
  assert.ok(events.length >= 2); assert.equal(events[0].field, 'lead');
  assert.deepEqual(events.map(event => event.seq), events.map((_, index) => index + 1));
  for (const event of events) assert.doesNotMatch(event.text, /\[\[|\[\d+\]|https?:|2026-10-11/);
  assert.equal(joined(events, 'lead'), '会飞，蓝天使周六和周日下午都有表演。');
  assert.equal(joined(events, 'point', 0), '主表演 10月11日（周日） 下午在 Marina Green，免费观看。');
  assert.equal(result.lead.replace(/\[\d+\]/g, ''), joined(events, 'lead'));
  assert.equal(result.corrected, false);
  assert.deepEqual(result.research.drafts, { events: events.length, chars: events.reduce((sum, event) => sum + event.text.length, 0) });
  assert.ok(!result.research.warnings.includes('draft_corrected'));
});

test('no drafts and no streamed call for old tabs, v1, professional topics, plans, thin evidence or BAYBAY_STREAM=off', async () => {
  const answer = { lead: '一句话回答。', points: [{ text: '一点。', cardIds: [] }] };
  const cases = [
    ['old tab (no onDraft)', {}, '蓝天使这周末飞吗', { drafts: false }],
    ['professional topic (RC-21)', {}, 'Medicare A 部分和 B 部分有什么区别？我该选哪个？'],
    ['agent route (day plan)', {}, '周六带孩子在 Berkeley 安排一天行程，不开车'],
    ['thin evidence (<2 records)', {}, 'xyzzy'],
    ['streaming switched off', { BAYBAY_STREAM: 'off' }, '蓝天使这周末飞吗'],
    ['engine v1', { BAYBAY_ENGINE: 'v1' }, '蓝天使这周末飞吗'],
  ];
  for (const [label, config, message, options] of cases) {
    const { assistant, sent } = assistantWith({ config, answers: () => claude(answer) });
    const { result, events } = await ask(assistant, message, options);
    assert.deepEqual(events, [], label);
    assert.ok(sent.every(body => body.stream === undefined), `${label}: the provider call is not streamed`);
    assert.equal(result.corrected, undefined, label);
  }
});

test('engine v1 with a capable client sends the byte-identical request and result it sends without one', async () => {
  const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const strip = result => ({ ...result, assistantSessionToken: undefined, research: { ...result.research, elapsedMs: undefined, timings: undefined, modelResponses: result.research.modelResponses.map(row => ({ ...row, elapsedMs: undefined })) } });
  const runs = [];
  for (const drafts of [false, true]) {
    const { assistant, sent } = assistantWith({ config: { BAYBAY_ENGINE: '' }, answers: () => ({ type: 'message', id: 'v1', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ answer: '蓝天使周六下午飞。', candidateIds: [], followups: [], coverage: [] }) }], usage: { input_tokens: 4, output_tokens: 4 } }) });
    const { result, events } = await ask(assistant, '蓝天使这周末飞吗', { drafts });
    assert.deepEqual(events, []);
    runs.push({ sent: digest(sent), result: digest(strip(result)) });
  }
  assert.deepEqual(runs[1], runs[0]);
});

test('a guard rewrite after streamed drafts sets corrected:true; the retry is not streamed and adds no draft', async () => {
  // Call 1 claims the site has no record of the named Fleet Week entry (false negative);
  // the one retry answers properly. The reader saw call 1's lead, so the result is a correction.
  const { assistant, sent } = assistantWith({ answers: [{ lead: '站内没有收录蓝天使的活动记录。', points: [] }, { lead: '会飞，舰队周蓝天使周六周日下午表演[[e1]]。', points: [{ text: '免费观看[[e1]]。', cardIds: [] }] }] });
  const { result, events } = await ask(assistant, '蓝天使这周末飞吗');
  assert.deepEqual(sent.map(body => body.stream), [true, undefined]);
  assert.equal(joined(events, 'lead'), '站内没有收录蓝天使的活动记录。');
  assert.ok(!events.some(event => /舰队周蓝天使/.test(event.text)), 'retry text never becomes a draft');
  assert.match(result.lead, /^会飞/);
  assert.equal(result.corrected, true);
  assert.ok(result.research.warnings.includes('draft_corrected'));
  assert.ok(result.research.warnings.includes('fast_retry_false_negative'));
});

test('a provider error mid-stream drops the held-back draft text; the retry answers and the draft it continues is not a correction', async () => {
  const lead = `${'甲'.repeat(45)}${'乙'.repeat(10)}。`;
  const full = claude({ lead, points: [] });
  const message = { ...full, content: [full.content[1]] };
  // The first (streamed) call errors after 55 lead characters: 45 were flushed (>= 40),
  // the last 10 were still waiting for the batch timer. The retry is not streamed.
  const delta = text => `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } })}\n\n`;
  const cut = sseFor(message).split('event: content_block_start')[0] + 'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
    + delta('{"lead":"') + delta('甲'.repeat(45)) + delta('乙'.repeat(10)) + 'event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"x"}}\n\n';
  const events = [];
  const failing = createBayBayAssistant({ config: { ...base, BAYBAY_ENGINE: 'v2' }, guideCatalog: guides, catalog, now: () => Date.parse('2026-10-08T17:00:00Z'), isTest: false, Quota: quota(),
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body);
      if (!body.stream) return { ok: true, status: 200, json: async () => message };
      return sseResponse(cut, { size: 6 });
    } });
  const result = await failing.run({ message: '蓝天使这周末飞吗', locale: 'zh-Hans', currentPath: '/', pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale: 'zh-Hans' }), searchMode: 'site', webAccess: { allowed: false }, onDraft: event => events.push(event) });
  assert.ok(result.research.warnings.includes('model_unavailable'));
  assert.equal(joined(events, 'lead'), '甲'.repeat(45), 'the 10 held-back characters are dropped with the failed call');
  assert.ok(result.research.warnings.includes('fast_retry_call_failed'));
  assert.equal(result.lead, lead);
  assert.equal(result.corrected, false, 'the retry answer continues the drafted prefix');
});

// ---------------------------------------------------------------- server.js: the streamVersion gate

test('guide-chat streams draft events only to clients that send streamVersion >= 3 (integer); old tabs and JSON clients are unchanged', async t => {
  const { createApplication } = require('../server');
  const answer = { lead: '可以，蓝天使周六周日下午都有表演[[e1]]。', points: [{ text: '在 Marina Green 免费观看[[e1]]。', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' };
  const providerCalls = [];
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'stream-fixture-session-secret', BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2' },
    models: createMemoryModels(), plannerNow: () => Date.parse('2026-10-08T17:00:00Z'),
    ai: { baybay: async (payload, options) => {
      providerCalls.push({ stream: payload.stream, onText: typeof options?.onText === 'function' });
      const text = JSON.stringify(answer);
      if (options?.onText) for (let index = 0; index < text.length; index += 4) options.onText(text.slice(index, index + 4));
      return { model: 'claude-sonnet-5-5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] }] };
    } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const post = body => fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: '蓝天使这周末飞吗', assistantVersion: 2, searchMode: 'site', ...body }) });
  const read = async response => (await response.text()).split('\n\n').filter(frame => frame.startsWith('event:')).map(frame => { const [event, data] = frame.split('\n'); return { event: event.slice(7), data: JSON.parse(data.slice(6)) }; });

  const capable = await read(await post({ stream: true, streamVersion: 3 }));
  const drafts = capable.filter(frame => frame.event === 'draft');
  assert.ok(drafts.length >= 2);
  assert.ok(capable.findIndex(frame => frame.event === 'draft') < capable.findIndex(frame => frame.event === 'delta'), 'drafts precede the validated text');
  assert.equal(capable.at(-1).event, 'result');
  assert.equal(capable.at(-1).data.corrected, false);
  assert.equal(drafts.filter(frame => frame.data.field === 'lead').map(frame => frame.data.text).join(''), '可以，蓝天使周六周日下午都有表演。');
  for (const frame of drafts) assert.deepEqual(Object.keys(frame.data).sort(), frame.data.field === 'point' ? ['field', 'index', 'seq', 'text'] : ['field', 'seq', 'text']);

  for (const body of [{ stream: true }, { stream: true, streamVersion: 2 }, { stream: true, streamVersion: '3' }, { stream: true, streamVersion: 3.5 }]) {
    const frames_ = await read(await post(body));
    assert.ok(!frames_.some(frame => frame.event === 'draft'), JSON.stringify(body));
    assert.equal(frames_.at(-1).event, 'result'); assert.equal(frames_.at(-1).data.corrected, undefined);
  }
  const json = await (await post({ streamVersion: 3 })).json();
  assert.equal(json.corrected, undefined); assert.ok(json.lead);
  assert.deepEqual(providerCalls.map(call => call.onText), [true, false, false, false, false, false]);
  assert.deepEqual(providerCalls.map(call => call.stream), [true, undefined, undefined, undefined, undefined, undefined]);
});
