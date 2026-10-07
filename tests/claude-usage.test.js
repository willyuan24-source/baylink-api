const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizedUsage } = require('../lib/aiRequest');

test('Claude totals include cache writes/reads and count hidden thinking only once', () => {
  const raw = { type: 'message', usage: { input_tokens: 100, cache_creation_input_tokens: 30, cache_read_input_tokens: 200,
    output_tokens: 400, output_tokens_details: { thinking_tokens: 350 } } };
  assert.equal(normalizedUsage(raw).input_tokens, 330);
  assert.equal(normalizedUsage(raw).output_tokens, 400);
  assert.equal(raw.usage.input_tokens, 100, 'accounting does not mutate the provider response');
});

test('malformed cache fields do not corrupt usage and OpenAI cached input stays inclusive', () => {
  assert.equal(normalizedUsage({ type: 'message', usage: { input_tokens: 10, cache_creation_input_tokens: -1, cache_read_input_tokens: '20' } }).input_tokens, 10);
  const usage = { input_tokens: 100, input_tokens_details: { cached_tokens: 80 }, output_tokens: 4 };
  assert.deepEqual(normalizedUsage({ usage }), usage);
  assert.deepEqual(normalizedUsage({ type: 'message' }), {});
});
