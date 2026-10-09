const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createAiGovernance } = require('../lib/aiGovernance');
const { requestAnthropicJson, selectedAiAvailable } = require('../lib/anthropicJson');
const { extractEvent, conversationAssist, validateImage, registerLocalAi } = require('../lib/localAi');

const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-claude-only', ANTHROPIC_WORKSPACE_ID: 'wrkspc_fixture', OPENAI_API_KEY: 'fixture-openai-must-not-be-used' };
const image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+yP1sAAAAASUVORK5CYII=';
const event = { title: 'Library workshop', date: '2026-10-03', startTime: '14:00', endTime: '16:00', city: 'Fremont', venue: 'Main library', address: '', price: '', sourceUrl: '', description: 'Children’s workshop' };
const extracted = { draft: event, dateText: 'October 3, 2026' };
const messages = [{ role: 'system', content: 'Translate the provided text.' }, { role: 'user', content: 'A fictional sample message.' }];
// requestAnthropicJson requires an output schema on every call.
const schema = { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false };
const raw = value => ({ type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'thinking', thinking: '', signature: 'opaque-test-signature' }, { type: 'text', text: JSON.stringify(value) }], usage: { input_tokens: 12, output_tokens: 45 } });
const response = value => ({ ok: true, json: async () => value });

function delayedReservation(work) {
  let release, ready;
  const pending = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { ready = resolve; });
  const Model = { updateOne: async () => ({}), findOneAndUpdate: async () => { ready(); return pending; } };
  const governance = createAiGovernance({ Model, config: { JWT_SECRET: 'fixture-quota-signing-key' } });
  const req = Object.assign(new EventEmitter(), { ip: '127.0.0.1', path: '/api/ai/event-extract' });
  const res = Object.assign(new EventEmitter(), { writableEnded: false });
  const finish = () => { res.writableEnded = true; res.emit('finish'); };
  const result = new Promise((resolve, reject) => {
    governance.middleware(async () => undefined)(req, res, () => {
      Promise.resolve().then(work).then(value => { finish(); resolve(value); }, error => { finish(); reject(error); });
    }).catch(reject);
  });
  return { result, started, release: () => release({ count: 1 }) };
}

test('selected provider availability honors explicit config, expiry, and a supplied preflight clock', () => {
  assert.equal(selectedAiAvailable({}), false);
  assert.equal(selectedAiAvailable({ OPENAI_API_KEY: 'fixture' }), true);
  assert.equal(selectedAiAvailable({ ...config, BAYBAY_AI_PROVIDER: 'unknown' }), false);
  assert.equal(selectedAiAvailable({ ...config, ANTHROPIC_API_KEY: '' }), false);
  const until = '2026-10-30T00:00:00Z', boundary = Date.parse(until);
  assert.equal(selectedAiAvailable({ ...config, ANTHROPIC_USE_UNTIL: until }, boundary - 1), true);
  assert.equal(selectedAiAvailable({ ...config, ANTHROPIC_USE_UNTIL: until }, boundary), false);
  assert.equal(selectedAiAvailable({ ...config, ANTHROPIC_USE_UNTIL: 'bad' }, boundary), false);
});

test('shared JSON helper sends a native bounded Claude request and parses only visible text', async () => {
  let sent;
  const result = await requestAnthropicJson(messages, { config, maxTokens: 50000,
    schema: { type: 'object', properties: { text: { type: 'string', maxLength: 300 } }, required: ['text'], additionalProperties: false },
    fetchImpl: async (url, init) => {
      assert.equal(url, 'https://api.anthropic.com/v1/messages');
      assert.equal(init.headers.Authorization, 'Bearer fixture-claude-only');
      assert.equal(init.headers['anthropic-version'], '2023-06-01');
      assert.equal(init.headers['anthropic-workspace-id'], 'wrkspc_fixture');
      sent = JSON.parse(init.body);
      return response(raw({ text: 'Translated sample.' }));
    },
  });
  assert.deepEqual(result, { text: 'Translated sample.' });
  assert.equal(sent.model, 'claude-opus-5-5'); assert.equal(sent.max_tokens, 9000);
  assert.equal(sent.output_config.effort, 'medium');
  // The schema replaces the old "return exactly one JSON object" system line.
  assert.equal(sent.system, 'Translate the provided text.'); assert.equal(sent.output_config.format.type, 'json_schema');
  assert.deepEqual(sent.messages, [{ role: 'user', content: [{ type: 'text', text: messages[1].content }] }]);
  assert.equal(sent.output_config.format.schema.properties.text.maxLength, undefined);
  for (const field of ['temperature', 'top_p', 'top_k', 'thinking', 'response_format', 'max_completion_tokens', 'tools', 'tool_choice']) assert.equal(sent[field], undefined);
  assert.doesNotMatch(JSON.stringify(result), /opaque-test-signature/);
});

test('shared JSON helper preserves text conversation roles and allows only low or medium effort', async () => {
  for (const effort of ['low', 'high']) {
    const history = [...messages, { role: 'assistant', content: '{"text":"Earlier sample"}' }, { role: 'user', content: 'Revise the sample.' }];
    await requestAnthropicJson(history, { config: { ...config, ANTHROPIC_BAYBAY_EFFORT: effort, ANTHROPIC_BAYBAY_MODEL: 'fixture-claude-model' }, schema, fetchImpl: async (_url, init) => {
      const sent = JSON.parse(init.body);
      assert.equal(sent.model, 'fixture-claude-model');
      assert.equal(sent.output_config.effort, effort === 'low' ? 'low' : 'medium');
      assert.deepEqual(sent.messages.map(message => message.role), ['user', 'assistant', 'user']);
      return response(raw({ text: 'Revised sample.' }));
    } });
  }
});

test('event extraction uses Claude vision with base64 data and retains year and field validation', async () => {
  let sent;
  const result = await extractEvent({ image, locale: 'en' }, { config, fetchImpl: async (url, init) => {
    assert.equal(url, 'https://api.anthropic.com/v1/messages'); sent = JSON.parse(init.body);
    return response(raw(extracted));
  } });
  assert.deepEqual(result.draft, event);
  assert.deepEqual(sent.messages[0].content, [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: image.split(',')[1] } }]);
  assert.match(sent.system, /NEVER use the current year/); assert.equal(sent.max_tokens, 6000);
  const missingYear = await extractEvent({ image, locale: 'en' }, { config, fetchImpl: async () => response(raw({ ...extracted, dateText: 'October 3' })) });
  assert.equal(missingYear.draft.date, '');
  await assert.rejects(extractEvent({ image, locale: 'en' }, { config, fetchImpl: async () => response(raw({ ...extracted, draft: { ...event, date: '2026-02-30' } })) }), { status: 502 });
});

test('shared vision conversion accepts supported MIME signatures and rejects remote or malformed images without transport', async () => {
  const imageMessage = uri => [{ role: 'user', content: [{ type: 'text', text: 'Read this fixture image.' }, { type: 'image_url', image_url: { url: uri, detail: 'high' } }] }];
  const samples = [image, 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', `data:image/jpeg;base64,${Buffer.from([255, 216, 255, 224]).toString('base64')}`, `data:image/webp;base64,${Buffer.from('RIFF0000WEBP', 'ascii').toString('base64')}`];
  for (const uri of samples) await requestAnthropicJson(imageMessage(uri), { config, schema, fetchImpl: async (_url, init) => {
    const block = JSON.parse(init.body).messages[0].content[1];
    assert.equal(block.type, 'image'); assert.equal(block.source.data, uri.split(',')[1]);
    return response(raw({ text: 'Image sample.' }));
  } });
  for (const uri of ['https://example.com/image.png', 'data:image/svg+xml;base64,AAAA', image.replace('png', 'jpeg'), image.slice(0, -1), image.replace('iVB', 'i_B'), 'data:image/png;base64,AAAA', `data:image/png;base64,${'A'.repeat(4 * 1024 * 1024 + 4)}`]) {
    let calls = 0;
    await assert.rejects(requestAnthropicJson(imageMessage(uri), { config, schema, fetchImpl: async () => { calls++; return response(raw({})); } }), { status: 400, code: 'AI_IMAGE_INVALID' });
    assert.equal(calls, 0);
  }
  assert.throws(() => validateImage(image.slice(0, -1)), { status: 400 });
  assert.throws(() => validateImage(samples[1]), { status: 400 }, 'event extraction keeps its existing PNG/JPEG/WebP policy');
});

test('JSON helpers refuse truncation, refusals, tool calls, malformed JSON and non-object results', async () => {
  for (const candidate of [
    { ...raw({ text: 'Valid-looking partial' }), stop_reason: 'max_tokens' },
    { ...raw({ text: 'Filtered' }), stop_reason: 'refusal' },
    { ...raw({ text: 'Pause' }), stop_reason: 'pause_turn' },
    { ...raw({ text: 'Ignore' }), content: [{ type: 'tool_use', id: 'call', name: 'unused', input: {} }, ...raw({ text: 'Ignore' }).content] },
    { ...raw({}), content: [{ type: 'text', text: '```json\n{}\n```' }] },
    raw([]), raw(null), raw('string'),
  ]) {
    let calls = 0;
    await assert.rejects(requestAnthropicJson(messages, { config, schema, fetchImpl: async url => {
      assert.equal(url, 'https://api.anthropic.com/v1/messages'); calls++; return response(candidate);
    } }), { status: 502 });
    assert.equal(calls, 1);
  }
});

test('conversation translation and editable drafting use Claude but retain text bounds and failure behavior', async () => {
  for (const mode of ['translate', 'draft']) {
    const input = { mode, targetLocale: 'en', message: 'A fictional selected message.', ...(mode === 'draft' ? { intent: 'Ask about the time' } : {}) };
    const text = await conversationAssist(input, { config, fetchImpl: async (url, init) => {
      assert.equal(url, 'https://api.anthropic.com/v1/messages');
      const sent = JSON.parse(init.body); const content = JSON.parse(sent.messages[0].content[0].text);
      assert.equal(content.message, input.message);
      assert.equal(content.intent, input.intent); assert.match(sent.system, /untrusted/);
      return response(raw({ text: 'Editable sample response.' }));
    } });
    assert.equal(text, 'Editable sample response.');
    for (const value of [{ text: '' }, { text: ['wrong'] }, { text: '```json' }, { text: 'a'.repeat(mode === 'draft' ? 2001 : 6001) }]) {
      await assert.rejects(conversationAssist(input, { config, fetchImpl: async () => response(raw(value)) }), { status: 503 });
    }
    await assert.rejects(conversationAssist(input, { config, fetchImpl: async () => response({ ...raw({ text: 'Truncated sample' }), stop_reason: 'max_tokens' }) }), { status: 503 });
  }
});

test('missing, expired and unknown selected providers fail closed before native or injected local calls', async () => {
  for (const override of [{ ANTHROPIC_API_KEY: '' }, { ANTHROPIC_USE_UNTIL: '2000-01-01T00:00:00Z' }, { ANTHROPIC_USE_UNTIL: 'invalid' }, { BAYBAY_AI_PROVIDER: 'unknown' }]) {
    let calls = 0;
    const options = { config: { ...config, ...override }, fetchImpl: async () => { calls++; return response(raw(extracted)); } };
    await assert.rejects(extractEvent({ image, locale: 'en' }, options), { status: 503 });
    await assert.rejects(conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Sample' }, options), { status: 503 });
    await assert.rejects(requestAnthropicJson(messages, options), { status: 503 });
    await assert.rejects(extractEvent({ image, locale: 'en' }, { ...options, ai: async () => { calls++; return extracted; } }), { status: 503 });
    assert.equal(calls, 0);
  }
  const injected = await extractEvent({ image, locale: 'en' }, { config: {}, isTest: true, ai: async () => extracted });
  assert.deepEqual(injected.draft, event, 'keyless default OpenAI test injection remains compatible');
});

test('production Claude inner and outer local deadlines both use 28 seconds', async t => {
  const delays = [], original = global.setTimeout;
  t.mock.method(global, 'setTimeout', (callback, delay, ...args) => { delays.push(delay); return original(callback, delay, ...args); });
  await conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Sample' }, { config, fetchImpl: async () => response(raw({ text: 'Sample' })) });
  assert.deepEqual(delays, [28000, 28000]);
});

test('shared helper preserves explicit short deadlines and caller cancellation', async () => {
  let upstream;
  await assert.rejects(requestAnthropicJson(messages, { config, schema, timeoutMs: 10, fetchImpl: async (_url, init) => {
    upstream = init.signal; return new Promise(() => {});
  } }), { code: 'AI_PROVIDER_TIMEOUT' });
  assert.equal(upstream.aborted, true);
  const controller = new AbortController();
  await assert.rejects(requestAnthropicJson(messages, { config, schema, signal: controller.signal, fetchImpl: async (_url, init) => {
    upstream = init.signal; queueMicrotask(() => controller.abort()); return new Promise(() => {});
  } }), { code: 'REQUEST_CANCELLED' });
  assert.equal(upstream.aborted, true);
});

test('native HTTP failures never try an OpenAI endpoint', async () => {
  for (const status of [401, 429, 500, 529]) {
    const urls = [];
    await assert.rejects(conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Sample' }, { config, fetchImpl: async url => { urls.push(url); return { ok: false, status }; } }));
    // 429/529 get their one Claude retry; nothing ever goes to OpenAI.
    assert.deepEqual(urls, Array([429, 529].includes(status) ? 2 : 1).fill('https://api.anthropic.com/v1/messages'));
  }
});

test('registered routes reject expired or unknown providers before claiming quota or invoking callbacks', async () => {
  for (const override of [{ ANTHROPIC_USE_UNTIL: '2000-01-01T00:00:00Z' }, { BAYBAY_AI_PROVIDER: 'unknown' }]) {
    const routes = new Map(); let calls = 0;
    registerLocalAi({ post: (path, ...handlers) => routes.set(path, handlers.at(-1)) }, {
      config: { ...config, ...override }, ai: { eventExtract: async () => { calls++; return extracted; } },
      Quota: { updateOne: async () => { calls++; } }, checkRateLimit: () => true,
    });
    let status, body;
    await routes.get('/api/ai/event-extract')({ body: { image, locale: 'en' } }, { set: () => {}, status(value) { status = value; return this; }, json(value) { body = value; } });
    assert.equal(status, 503); assert.equal(body.ok, false); assert.equal(calls, 0);
  }
});

test('local timeout aborts Claude and OpenAI before a delayed quota reservation can start transport', async () => {
  for (const provider of ['anthropic', 'openai']) {
    for (const operation of ['conversation', 'image']) {
      let calls = 0;
      const options = { config: { ...config, BAYBAY_AI_PROVIDER: provider }, timeoutMs: 10, fetchImpl: async () => { calls++; return response(raw({ text: 'Must never run' })); } };
      const pending = delayedReservation(() => operation === 'image' ? extractEvent({ image, locale: 'en' }, options)
        : conversationAssist({ mode: 'translate', targetLocale: 'en', message: 'Fictional sample' }, options));
      const rejected = assert.rejects(pending.result, { status: 503 });
      await pending.started;
      await rejected;
      pending.release();
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(calls, 0, `${provider} ${operation} must not start transport after its outer deadline`);
    }
  }
});

test('shared Claude helper rechecks the real usage deadline after delayed governance reservation', async t => {
  const before = Date.parse('2026-10-29T23:59:59Z'); let time = before, calls = 0;
  t.mock.method(Date, 'now', () => time);
  const pending = delayedReservation(() => requestAnthropicJson(messages, {
    config: { ...config, ANTHROPIC_USE_UNTIL: '2026-10-30T00:00:00Z' }, schema,
    fetchImpl: async () => { calls++; return response(raw({ text: 'Must not spend after expiry' })); },
  }));
  const rejected = assert.rejects(pending.result, { status: 503, code: 'AI_PROVIDER_UNAVAILABLE' });
  await pending.started;
  time = before + 1000;
  pending.release();
  await rejected;
  assert.equal(calls, 0);
});
