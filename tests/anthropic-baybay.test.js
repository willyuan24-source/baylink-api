const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createAnthropicBaybay, anthropicSchema, normalizedResponse, baybayProvider, baybayModel, anthropicAvailable } = require('../lib/anthropicBaybay');
const { parseDraft } = require('../lib/baybayAgent');
const { createAiGovernance } = require('../lib/aiGovernance');
const { createMemoryModels } = require('./support/memory-models');

const tool = { type: 'function', name: 'search_site', description: 'Search site', strict: true, parameters: { type: 'object', properties: { query: { type: 'string', maxLength: 300 } }, required: ['query'], additionalProperties: false } };
const schema = { type: 'object', properties: { answer: { type: 'string' }, candidateIds: { type: 'array', items: { type: 'string' }, maxItems: 6 } }, required: ['answer', 'candidateIds'], additionalProperties: false };
const payload = () => ({ model: 'claude-opus-5-5', instructions: 'Use verified site evidence.', input: [{ role: 'user', content: 'Question' }], tools: [tool], text: { format: { type: 'json_schema', name: 'answer', strict: true, schema } }, max_output_tokens: 6000, temperature: 0.2, reasoning: { effort: 'low' }, include: ['reasoning.encrypted_content'], store: false });
const textReply = (answer = 'Supported answer.') => ({ type: 'message', id: 'msg-answer', model: 'claude-opus-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }], usage: { input_tokens: 11, output_tokens: 25 } });
const reply = value => ({ ok: true, json: async () => value });

test('provider defaults stay OpenAI; Claude config uses the verified model and bounded effort', async () => {
  assert.equal(baybayProvider({}), 'openai');
  assert.equal(baybayModel({}), 'gpt-6.1-sol');
  assert.equal(baybayProvider({ BAYBAY_AI_PROVIDER: ' ANTHROPIC ' }), 'anthropic');
  assert.equal(baybayModel({ BAYBAY_AI_PROVIDER: 'anthropic' }), 'claude-opus-5-5');
  assert.equal(baybayModel({ BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_BAYBAY_MODEL: 'fixture-claude' }), 'fixture-claude');
  for (const [effort, expected] of [[undefined, 'medium'], ['low', 'low'], ['high', 'medium']]) {
    const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'test-key-only', ANTHROPIC_BAYBAY_EFFORT: effort }, fetchImpl: async (url, init) => {
      assert.equal(url, 'https://api.anthropic.com/v1/messages');
      assert.equal(init.headers.Authorization, 'Bearer test-key-only');
      assert.equal(init.headers['anthropic-version'], '2023-06-01');
      const body = JSON.parse(init.body);
      assert.equal(body.system, 'Use verified site evidence.'); assert.equal(body.max_tokens, 6000);
      assert.deepEqual(body.tool_choice, { type: 'auto' });
      assert.equal(body.output_config.effort, expected);
      assert.deepEqual(body.tools[0], { name: 'search_site', description: 'Search site', strict: true, input_schema: { ...tool.parameters, properties: { query: { type: 'string' } } } });
      assert.equal(body.output_config.format.schema.properties.candidateIds.maxItems, undefined);
      for (const field of ['temperature', 'top_p', 'top_k', 'thinking', 'reasoning', 'include', 'store', 'instructions', 'input']) assert.equal(body[field], undefined);
      return reply(textReply());
    } });
    assert.equal(parseDraft(await request(payload())).answer, 'Supported answer.');
  }
});

test('schema adaptation removes unsupported constraints without dropping similarly named properties or changing source', () => {
  const original = { type: 'object', properties: { maximum: { type: 'number', minimum: 1, maximum: 6 }, rows: { type: 'array', minItems: 1, maxItems: 3, items: { type: 'string', maxLength: 10 } } }, additionalProperties: false };
  const clean = anthropicSchema(original);
  assert.deepEqual(clean.properties.maximum, { type: 'number' });
  assert.deepEqual(clean.properties.rows, { type: 'array', items: { type: 'string' } });
  assert.equal(original.properties.rows.maxItems, 3);
});

test('multiple tool rounds replay raw signed content and the exact earlier prefix; final tool_choice can change', async () => {
  const snapshots = [];
  const contents = [
    [{ type: 'thinking', thinking: '', signature: 'signed-first' }, { type: 'tool_use', id: 'call-a', name: 'search_site', input: { query: 'same' } }, { type: 'tool_use', id: 'call-b', name: 'search_site', input: { query: 'same' } }],
    [{ type: 'thinking', thinking: 'private-summary-never-shown', signature: 'signed-second' }, { type: 'redacted_thinking', data: 'opaque' }, { type: 'tool_use', id: 'call-c', name: 'search_site', input: { query: 'third' } }],
  ];
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture' }, fetchImpl: async (_url, init) => {
    snapshots.push(JSON.parse(init.body));
    return reply(snapshots.length <= 2 ? { ...textReply(), stop_reason: 'tool_use', content: contents[snapshots.length - 1] } : textReply());
  } });
  const input = payload();
  const first = await request(input);
  assert.equal(first.output.length, 2); assert.doesNotMatch(JSON.stringify(first), /signed|thinking|private-summary/);
  input.input.push(...first.output, { type: 'function_call_output', call_id: 'call-a', output: '{"sources":[]}' }, { type: 'function_call_output', call_id: 'call-b', output: '{"error":"Tool budget reached."}' });
  const second = await request(input);
  input.input.push(...second.output, { type: 'function_call_output', call_id: 'call-c', output: '{"sources":[]}' }, { role: 'user', content: 'Fresh evidence' }, { role: 'user', content: 'Research is complete. Return final JSON.' });
  input.tool_choice = 'none';
  const final = await request(input);
  assert.equal(parseDraft(final).answer, 'Supported answer.');
  assert.deepEqual(snapshots[1].messages[1], { role: 'assistant', content: contents[0] });
  assert.deepEqual(snapshots[1].messages[2].content.map(block => block.tool_use_id), ['call-a', 'call-b']);
  assert.equal(snapshots[1].messages[2].content[1].is_error, true);
  assert.deepEqual(snapshots[2].messages.slice(0, snapshots[1].messages.length), snapshots[1].messages);
  assert.deepEqual(snapshots[2].messages[3], { role: 'assistant', content: contents[1] });
  assert.equal(snapshots[2].messages[4].content[0].tool_use_id, 'call-c');
  assert.deepEqual(snapshots[2].tools, snapshots[0].tools); assert.equal(snapshots[2].system, snapshots[0].system);
  assert.deepEqual(snapshots[2].tool_choice, { type: 'none' });
});

test('failed transport does not advance transcript or duplicate tool results on retry', async () => {
  const sent = []; let attempts = 0;
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture' }, fetchImpl: async (_url, init) => {
    sent.push(JSON.parse(init.body));
    if (!attempts++) throw new Error('fixture network failure');
    return reply(textReply());
  } });
  await assert.rejects(request(payload()), /fixture network failure/);
  await request(payload());
  assert.deepEqual(sent[0], sent[1]);
});

test('edits to a successful conversation prefix, system or tools fail before transport', async () => {
  for (const mutate of [p => { p.instructions = 'changed'; }, p => { p.tools = []; }, p => { p.input[0].content = 'changed'; }, p => { p.model = 'other-model'; }]) {
    let calls = 0;
    const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture' }, fetchImpl: async () => { calls++; return reply(textReply()); } });
    const input = payload(); const first = await request(input);
    input.input.push(...first.output, { role: 'user', content: 'Continue' }); mutate(input);
    await assert.rejects(request(input), /append-only|unchanged/); assert.equal(calls, 1);
  }
});

test('refusal, truncation, provider errors and malformed stops never expose partial answer or execute tools', () => {
  for (const reason of ['refusal', 'max_tokens', 'model_context_window_exceeded', 'pause_turn', null]) {
    const result = normalizedResponse({ ...textReply('Do not accept this even though JSON is complete'), stop_reason: reason });
    assert.deepEqual(result.output, []); assert.equal(parseDraft(result), null);
    assert.notEqual(result.status, 'completed');
  }
  for (const raw of [{ ...textReply(), type: 'error', error: { message: 'private provider details' } }, { ...textReply(), stop_reason: 'tool_use' }, { ...textReply(), stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'missing-args', name: 'search_site' }] }]) {
    assert.deepEqual(normalizedResponse(raw).output, []);
    assert.equal(normalizedResponse(raw).status, 'failed');
  }
});

test('usage retains billable output including hidden thinking and counts cached input', () => {
  const result = normalizedResponse({ ...textReply(), usage: { input_tokens: 10, cache_creation_input_tokens: 20, cache_read_input_tokens: 30, output_tokens: 100, output_tokens_details: { thinking_tokens: 70 } }, content: [{ type: 'thinking', thinking: 'private', signature: 'signature' }, ...textReply().content] });
  assert.equal(result.usage.input_tokens, 60); assert.equal(result.usage.input_tokens_details.cached_tokens, 30);
  assert.equal(result.usage.output_tokens, 100); assert.equal(result.usage.output_tokens_details.reasoning_tokens, 70);
  assert.doesNotMatch(JSON.stringify(result), /private|signature/);
});

test('workspace-scoped requests send the configured workspace header', async () => {
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_WORKSPACE_ID: 'wrkspc_fixture' }, fetchImpl: async (_url, init) => {
    assert.equal(init.headers['anthropic-workspace-id'], 'wrkspc_fixture');
    return reply(textReply());
  } });
  await request(payload());
});

test('usage window accepts a future ISO deadline and fails closed on expiry or invalid values before fetching', async () => {
  const config = { ANTHROPIC_API_KEY: 'fixture', ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' };
  const boundary = Date.parse(config.ANTHROPIC_USE_UNTIL);
  assert.equal(anthropicAvailable(config, boundary - 1), true);
  assert.equal(anthropicAvailable(config, boundary), false);
  assert.equal(anthropicAvailable({ ANTHROPIC_API_KEY: 'fixture' }, boundary), true);
  assert.equal(anthropicAvailable({ ANTHROPIC_API_KEY: ' ' }, boundary), false);
  for (const until of ['2000-01-01T00:00:00Z', 'not-a-date', '2026-02-30T00:00:00Z', '1', ' ']) {
    let calls = 0;
    const request = createAnthropicBaybay({ config: { ...config, ANTHROPIC_USE_UNTIL: until }, fetchImpl: async () => { calls++; return reply(textReply()); } });
    await assert.rejects(request(payload()), /unavailable|usage window/); assert.equal(calls, 0);
  }
});

test('Claude expiry reached during quota reservation blocks actual transport without refund or retry', async t => {
  const expiry = Date.parse('2099-10-30T00:00:00Z');
  let clock = expiry - 1, calls = 0;
  t.mock.method(Date, 'now', () => clock);
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'isolated-adapter-expiry-test' }, now: () => clock });
  const req = new EventEmitter(); req.path = '/api/ai/guide-chat'; req.ip = 'fixture';
  const res = new EventEmitter(); res.writableEnded = false;
  const request = createAnthropicBaybay({ config: { ANTHROPIC_API_KEY: 'synthetic-key', ANTHROPIC_USE_UNTIL: new Date(expiry).toISOString() },
    fetchImpl: async () => { calls++; return reply(textReply()); } });
  await new Promise((resolve, reject) => {
    governance.middleware(async () => { await Promise.resolve(); clock = expiry; return 'fixture-user'; })(req, res, async () => {
      try {
        await assert.rejects(request(payload()), /unavailable|usage window/);
        assert.equal(calls, 0);
        assert.equal(models.AiGovernance.rows[0].count, 1);
        assert.equal(models.AiGovernance.rows[0].calls || 0, 0);
        assert.equal(models.AiGovernance.rows[0].failures, 1);
        res.writableEnded = true; res.emit('finish'); resolve();
      } catch (error) { reject(error); }
    }).catch(reject);
  });
});
