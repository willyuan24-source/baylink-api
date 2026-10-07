const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const member = require('./support/member-session');

const ANSWER = 'Use the BAYLINK guides to review local information and confirm changing conditions with the listed official sources.';
const ASK = { message: 'Please explain how to use BAYLINK and its guides.', locale: 'en', searchMode: 'site' };
const completed = (extra = {}) => ({
  type: 'message', model: 'claude-opus-5-5', stop_reason: 'end_turn',
  content: [{ type: 'text', text: JSON.stringify({ answer: ANSWER, safetyNote: '' }) }],
  usage: { input_tokens: 80, output_tokens: 60 }, ...extra,
});

async function fixture(t, { config = {}, response = completed(), providerFetch, ai, authenticated = false } = {}) {
  const calls = [];
  const application = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-claude-guide-chat-tests', BAYBAY_AI_PROVIDER: 'anthropic',
      ANTHROPIC_API_KEY: 'synthetic-claude-key', OPENAI_API_KEY: 'synthetic-openai-key', ...config },
    models: createMemoryModels({ User: [member.user] }), plannerNow: () => Date.parse('2026-10-07T19:00:00Z'), ai,
    guideChatFetch: async (url, options) => {
      calls.push({ url, ...options, body: JSON.parse(options.body) });
      return providerFetch ? providerFetch(url, options) : { ok: true, json: async () => response };
    },
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return {
    calls,
    ask: async (body = {}) => {
      const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(authenticated ? member.headers('isolated-claude-guide-chat-tests') : {}) }, body: JSON.stringify({ ...ASK, ...body }),
      });
      assert.equal(response.status, 200);
      const data = await response.json();
      assert.doesNotMatch(JSON.stringify(data), /synthetic-(?:claude|openai)-key|HIDDEN-THINKING|PRIVATE-SIGNATURE/);
      return data;
    },
  };
}

test('legacy guide chat sends native Claude JSON output requests and reads text after thinking', async t => {
  const json = JSON.stringify({ answer: ANSWER, safetyNote: '' });
  const f = await fixture(t, { response: completed({ content: [
    { type: 'thinking', thinking: 'HIDDEN-THINKING', signature: 'PRIVATE-SIGNATURE' },
    { type: 'text', text: json.slice(0, 28) }, { type: 'text', text: json.slice(28) },
  ] }) });
  const history = [{ role: 'user', content: 'I am new to BAYLINK.' }, { role: 'assistant', content: 'You can read the local guides.' }];
  const result = await f.ask({ history });
  assert.equal(result.responseMode, 'ai');
  assert.equal(result.degraded, false);
  assert.equal(result.answer, ANSWER);
  assert.equal(result.retrieval.configuredModel, 'claude-opus-5-5');
  assert.equal(result.retrieval.model, 'claude-opus-5-5');
  assert.equal(f.calls.length, 1);
  const request = f.calls[0];
  assert.equal(request.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(request.method, 'POST');
  assert.equal(request.headers.Authorization, 'Bearer synthetic-claude-key');
  assert.equal(request.headers['anthropic-version'], '2023-06-01');
  assert.ok(request.signal instanceof AbortSignal);
  assert.equal(request.body.model, 'claude-opus-5-5');
  assert.equal(request.body.max_tokens, 4096);
  assert.equal(request.body.output_config.effort, 'medium');
  assert.equal(request.body.output_config.format.type, 'json_schema');
  assert.deepEqual(request.body.output_config.format.schema.required, ['answer', 'safetyNote']);
  assert.equal(request.body.output_config.format.schema.additionalProperties, false);
  assert.match(request.body.system, /BAYLINK/);
  assert.deepEqual(request.body.messages.slice(0, 2), history);
  assert.equal(request.body.messages.at(-1).role, 'user');
  assert.match(request.body.messages.at(-1).content, /2026-10-07/);
  for (const field of ['temperature', 'top_p', 'top_k', 'thinking', 'store', 'response_format', 'max_completion_tokens']) {
    assert.equal(request.body[field], undefined, field);
  }
});

test('legacy Claude guide metadata distinguishes configured model from served model and forwards workspace', async t => {
  const f = await fixture(t, { config: { ANTHROPIC_BAYBAY_MODEL: 'claude-opus-custom', ANTHROPIC_WORKSPACE_ID: 'wrkspc_fixture' },
    response: completed({ model: 'claude-opus-served' }) });
  const result = await f.ask();
  assert.equal(f.calls[0].body.model, 'claude-opus-custom');
  assert.equal(f.calls[0].headers['anthropic-workspace-id'], 'wrkspc_fixture');
  assert.equal(result.retrieval.configuredModel, 'claude-opus-custom');
  assert.equal(result.retrieval.model, 'claude-opus-served');
});

test('missing Claude credentials never use an available OpenAI key', async t => {
  const f = await fixture(t, { config: { ANTHROPIC_API_KEY: '' } });
  const result = await f.ask();
  assert.equal(result.responseMode, 'fallback');
  assert.equal(result.degraded, true);
  assert.equal(result.retrieval.configuredModel, 'claude-opus-5-5');
  assert.equal(result.retrieval.model, undefined);
  assert.equal(f.calls.length, 0);
});

test('unknown guide providers fail locally without invoking either provider or injected AI', async t => {
  for (const injected of [false, true]) {
    await t.test(injected ? 'injected provider' : 'native provider', async t => {
      const f = await fixture(t, { config: { BAYBAY_AI_PROVIDER: 'anthropi' },
        ...(injected ? { ai: { guideChat: async () => assert.fail('unknown provider must not invoke AI') } } : {}) });
      const result = await f.ask();
      assert.equal(result.responseMode, 'fallback');
      assert.equal(result.degraded, true);
      assert.equal(result.retrieval.model, undefined);
      assert.equal(f.calls.length, 0);
    });
  }
});

test('expired or invalid Claude use windows prohibit new calls without falling back to OpenAI', async t => {
  for (const until of ['2000-01-01T00:00:00Z', 'invalid-expiry']) {
    await t.test(until, async t => {
      const f = await fixture(t, { config: { ANTHROPIC_USE_UNTIL: until } });
      const result = await f.ask();
      assert.equal(result.responseMode, 'fallback');
      assert.equal(result.degraded, true);
      assert.equal(result.retrieval.configuredModel, 'claude-opus-5-5');
      assert.equal(f.calls.length, 0);
    });
  }
});

test('legacy Claude chat rejects refusal and incomplete output even when it contains valid JSON', async t => {
  for (const stopReason of ['refusal', 'max_tokens', 'model_context_window_exceeded', 'tool_use', 'stop_sequence', null]) {
    await t.test(String(stopReason), async t => {
      const f = await fixture(t, { response: completed({ stop_reason: stopReason }) });
      const result = await f.ask();
      assert.equal(result.responseMode, 'fallback');
      assert.equal(result.degraded, true);
      assert.notEqual(result.answer, ANSWER);
      assert.equal(result.retrieval.model, undefined);
      assert.equal(f.calls.length, 1);
      assert.equal(f.calls[0].url, 'https://api.anthropic.com/v1/messages');
    });
  }
});

test('malformed or thinking-only Claude output cannot become a successful guide answer', async t => {
  for (const content of [undefined, [{ type: 'text', text: 'not JSON' }], [{ type: 'thinking', thinking: JSON.stringify({ answer: ANSWER }) }]]) {
    await t.test(JSON.stringify(content), async t => {
      const f = await fixture(t, { response: completed({ content }) });
      const result = await f.ask();
      assert.equal(result.responseMode, 'fallback');
      assert.equal(result.degraded, true);
      assert.notEqual(result.answer, ANSWER);
      assert.equal(f.calls.length, 1);
    });
  }
});

test('Claude provider HTTP errors fall back locally without calling OpenAI', async t => {
  const f = await fixture(t, { providerFetch: async () => ({ ok: false, status: 429 }) });
  const result = await f.ask();
  assert.equal(result.responseMode, 'fallback');
  assert.equal(result.degraded, true);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, 'https://api.anthropic.com/v1/messages');
});

test('legacy web failure metadata names the selected Claude model', async t => {
  let searchCalls = 0;
  const f = await fixture(t, { authenticated: true, config: { ANTHROPIC_BAYBAY_MODEL: 'claude-opus-custom' },
    ai: { plannerWebSearch: async () => { searchCalls++; throw new Error('Fixture search unavailable'); } },
  });
  const result = await f.ask({ message: 'Oakland museum hours', searchMode: 'smart' });
  assert.equal(result.responseMode, 'ai');
  assert.equal(result.retrieval.webStatus, 'unavailable');
  assert.equal(result.retrieval.webConfiguredModel, 'claude-opus-custom');
  assert.equal(searchCalls, 1);
});

test('default legacy provider keeps the OpenAI request and model contract', async t => {
  const f = await fixture(t, { config: { BAYBAY_AI_PROVIDER: undefined, OPENAI_MODEL: 'gpt-4o-mini' },
    response: { model: 'openai-fixture-model', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ answer: ANSWER }) } }] } });
  const result = await f.ask();
  assert.equal(result.responseMode, 'ai');
  assert.equal(result.answer, ANSWER);
  assert.equal(result.retrieval.configuredModel, 'gpt-4o-mini');
  assert.equal(result.retrieval.model, 'openai-fixture-model');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(f.calls[0].headers.Authorization, 'Bearer synthetic-openai-key');
  assert.equal(f.calls[0].body.messages[0].role, 'system');
  assert.equal(f.calls[0].body.response_format.type, 'json_object');
  assert.equal(f.calls[0].body.max_completion_tokens, 2000);
});

test('existing guideChat injection remains usable without either provider credential', async t => {
  let injectedCalls = 0;
  const f = await fixture(t, { config: { ANTHROPIC_API_KEY: '', OPENAI_API_KEY: '' }, ai: {
    guideChat: async () => {
      injectedCalls++;
      return { model: 'injected-fixture-model', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ answer: ANSWER }) } }] };
    },
  } });
  const result = await f.ask();
  assert.equal(result.responseMode, 'ai');
  assert.equal(result.answer, ANSWER);
  assert.equal(result.retrieval.model, 'injected-fixture-model');
  assert.equal(injectedCalls, 1);
  assert.equal(f.calls.length, 0);
});
