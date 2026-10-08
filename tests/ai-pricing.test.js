const test = require('node:test');
const assert = require('node:assert/strict');
const { PRICE_TABLE, HAIKU_LONG_PROMPT_THRESHOLD, claudeUsage, claudeCost, priceEntry, pricedModel, microUsdToUsd } = require('../lib/aiPricing');

const cost = (model, usage, day = '2026-10-08') => claudeCost({ model, usage, day });

test('dated table carries the 2026-10-08 Claude 5.5 prices in integer nano-USD per token', () => {
  const entry = PRICE_TABLE[0];
  assert.equal(entry.effectiveFrom, '2026-10-08');
  assert.match(entry.source, /model-migration\.md/);
  assert.deepEqual(entry.models['claude-opus-5-5'].standard, { input: 4000, output: 20000, cacheRead: 200, cacheWrite5m: 5000, cacheWrite1h: 8000 });
  assert.deepEqual(entry.models['claude-sonnet-5-5'].standard, { input: 2000, output: 10000, cacheRead: 200, cacheWrite5m: 2500, cacheWrite1h: 4000 });
  assert.deepEqual(entry.models['claude-haiku-5-5'].standard, { input: 100, output: 500, cacheRead: 10, cacheWrite5m: 125, cacheWrite1h: 200 });
  assert.deepEqual(entry.models['claude-haiku-5-5'].longPrompt, { input: 500, output: 2500, cacheRead: 50, cacheWrite5m: 625, cacheWrite1h: 1000 });
  assert.equal(entry.webSearchNanoUsd, 10_000_000);
  for (const model of Object.values(entry.models)) for (const card of [model.standard, model.longPrompt].filter(Boolean)) {
    for (const rate of Object.values(card)) assert.ok(Number.isSafeInteger(rate) && rate > 0);
  }
  assert.ok(Object.isFrozen(PRICE_TABLE) && Object.isFrozen(entry.models['claude-opus-5-5'].standard));
});

test('Opus, Sonnet and Haiku per-question arithmetic matches the plan examples exactly', () => {
  // Opus 5.5: 14,000 in x $4/M + 500 out x $20/M = $0.056 + $0.010.
  assert.deepEqual([cost('claude-opus-5-5', { input_tokens: 14000, output_tokens: 500 }).microUsd, cost('claude-opus-5-5', { input_tokens: 14000, output_tokens: 500 }).card], [66000, 'standard']);
  // Sonnet 5.5: $0.028 + $0.005.
  assert.equal(cost('claude-sonnet-5-5', { input_tokens: 14000, output_tokens: 500 }).microUsd, 33000);
  // Haiku 5.5: $0.0014 + $0.00025 = $0.00165.
  assert.equal(cost('claude-haiku-5-5', { input_tokens: 14000, output_tokens: 500 }).microUsd, 1650);
  // BBLIVE 10-07 measured Opus total: 1,326,899 in + 25,074 out, no cache = $5.81.
  assert.equal(microUsdToUsd(cost('claude-opus-5-5', { input_tokens: 1326899, output_tokens: 25074 }).microUsd).toFixed(2), '5.81');
});

test('cache reads and both cache-write TTLs are priced separately from uncached input', () => {
  const usage = { input_tokens: 1000, cache_read_input_tokens: 10000, cache_creation_input_tokens: 3000,
    cache_creation: { ephemeral_5m_input_tokens: 2000, ephemeral_1h_input_tokens: 1000 }, output_tokens: 100 };
  const opus = cost('claude-opus-5-5', usage);
  // 1000x4000 + 10000x200 + 2000x5000 + 1000x8000 + 100x20000 nano-USD.
  assert.equal(opus.nanoUsd, 4_000_000 + 2_000_000 + 10_000_000 + 8_000_000 + 2_000_000);
  assert.equal(opus.microUsd, 26000);
  assert.deepEqual(opus.usage, { inputTokens: 1000, cacheReadTokens: 10000, cacheWrite5mTokens: 2000, cacheWrite1hTokens: 1000,
    cacheWriteTokens: 3000, outputTokens: 100, webSearchRequests: 0, promptTokens: 14000 });
  assert.equal(cost('claude-sonnet-5-5', usage).nanoUsd, 2_000_000 + 2_000_000 + 5_000_000 + 4_000_000 + 1_000_000);
  // Without a TTL split every write is the 5-minute TTL; a split never loses tokens.
  assert.deepEqual(claudeUsage({ cache_creation_input_tokens: 700 }).cacheWrite5mTokens, 700);
  assert.deepEqual(claudeUsage({ cache_creation_input_tokens: 700, cache_creation: { ephemeral_1h_input_tokens: 200 } }), {
    inputTokens: 0, cacheReadTokens: 0, cacheWrite5mTokens: 500, cacheWrite1hTokens: 200, cacheWriteTokens: 700, outputTokens: 0, webSearchRequests: 0, promptTokens: 700 });
  assert.equal(claudeUsage({ cache_creation: { ephemeral_5m_input_tokens: 40, ephemeral_1h_input_tokens: 2 } }).cacheWriteTokens, 42);
  for (const malformed of [{ input_tokens: -5, cache_read_input_tokens: '20', output_tokens: 1.5 }, null, 'usage']) {
    assert.deepEqual(claudeUsage(malformed), { inputTokens: 0, cacheReadTokens: 0, cacheWrite5mTokens: 0, cacheWrite1hTokens: 0, cacheWriteTokens: 0, outputTokens: 0, webSearchRequests: 0, promptTokens: 0 });
  }
});

test('Haiku 100K prompt cliff switches every token to the long-prompt card at 100,001 prompt tokens', () => {
  assert.equal(HAIKU_LONG_PROMPT_THRESHOLD, 100000);
  const atLimit = cost('claude-haiku-5-5', { input_tokens: 90000, cache_read_input_tokens: 10000, output_tokens: 1000 });
  assert.equal(atLimit.card, 'standard');
  assert.equal(atLimit.nanoUsd, 90000 * 100 + 10000 * 10 + 1000 * 500);
  const above = cost('claude-haiku-5-5', { input_tokens: 90001, cache_read_input_tokens: 10000, output_tokens: 1000 });
  assert.equal(above.card, 'long-prompt');
  assert.equal(above.nanoUsd, 90001 * 500 + 10000 * 50 + 1000 * 2500);
  assert.equal(above.microUsd, 48001);
  assert.ok(above.microUsd > 4.9 * atLimit.microUsd, 'one extra prompt token costs about 5x');
  // Cache writes count toward the prompt length that selects the card.
  assert.equal(cost('claude-haiku-5-5', { input_tokens: 50000, cache_creation_input_tokens: 50001 }).card, 'long-prompt');
  assert.equal(cost('claude-haiku-5-5', { input_tokens: 50000, cache_creation_input_tokens: 50000 }).card, 'standard');
  // Output length never selects the card, and Opus/Sonnet have one card at any length.
  assert.equal(cost('claude-haiku-5-5', { input_tokens: 1000, output_tokens: 120000 }).card, 'standard');
  assert.equal(cost('claude-opus-5-5', { input_tokens: 900000 }).card, 'standard');
});

test('web search requests add $0.01 each; dated model ids price as their family; unknown models are never guessed', () => {
  assert.equal(cost('claude-opus-5-5', { input_tokens: 0, output_tokens: 0, server_tool_use: { web_search_requests: 2 } }).microUsd, 20000);
  assert.equal(cost('claude-haiku-5-5-20261001', { input_tokens: 1000 }).microUsd, 100);
  assert.equal(pricedModel('claude-sonnet-5-5-2026-10-01'), 'claude-sonnet-5-5');
  for (const model of ['claude-opus-5-5-custom', 'fixture-claude', 'gpt-6.1-sol', undefined, { model: 'claude-opus-5-5' }]) {
    const result = cost(model, { input_tokens: 10, output_tokens: 10 });
    assert.equal(result.priced, false); assert.equal(result.microUsd, undefined);
  }
});

test('the price entry in force is chosen by Pacific date; earlier dates use the earliest known entry', () => {
  assert.equal(priceEntry('2026-10-08').effectiveFrom, '2026-10-08');
  assert.equal(priceEntry('2027-01-01').effectiveFrom, '2026-10-08');
  assert.equal(priceEntry('2026-01-01').effectiveFrom, '2026-10-08');
  assert.equal(priceEntry('not a date').effectiveFrom, '2026-10-08');
  assert.equal(cost('claude-opus-5-5', { input_tokens: 1 }, '2026-12-31').priceDate, '2026-10-08');
});

test('server-side fallback iterations are priced per attempt at each attempt model', () => {
  const usage = { input_tokens: 500, output_tokens: 200, iterations: [
    { type: 'message', model: 'claude-opus-5-5', input_tokens: 1000, output_tokens: 0 },
    { type: 'fallback_message', model: 'claude-sonnet-5-5', input_tokens: 500, output_tokens: 200 },
  ] };
  const result = cost('claude-sonnet-5-5', usage);
  assert.equal(result.nanoUsd, 1000 * 4000 + 500 * 2000 + 200 * 10000);
  // Entries without a model are priced at the response model; non-numeric entries fall back to top-level usage.
  assert.equal(cost('claude-sonnet-5-5', { input_tokens: 1, iterations: [{ input_tokens: 10 }] }).nanoUsd, 10 * 2000);
  assert.equal(cost('claude-sonnet-5-5', { input_tokens: 1, iterations: [{ type: 'message' }] }).nanoUsd, 2000);
  assert.equal(cost('claude-sonnet-5-5', { input_tokens: 1, iterations: [{ model: 'gpt-6.1-sol', input_tokens: 10 }] }).priced, false);
});

test('stored micro-USD stays within 1% of usage x list price over randomized usage', () => {
  const list = { 'claude-opus-5-5': [4, 20, 0.2, 5, 8], 'claude-sonnet-5-5': [2, 10, 0.2, 2.5, 4], 'claude-haiku-5-5': [0.1, 0.5, 0.01, 0.125, 0.2] };
  let seed = 7;
  const random = maximum => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % maximum; };
  for (let index = 0; index < 600; index++) {
    const model = Object.keys(list)[index % 3];
    const usage = { input_tokens: random(90000) + 500, cache_read_input_tokens: random(20000), cache_creation_input_tokens: random(8000), output_tokens: random(4000) + 50 };
    const [input, output, read, write5m] = list[model];
    const prompt = usage.input_tokens + usage.cache_read_input_tokens + usage.cache_creation_input_tokens;
    const factor = model === 'claude-haiku-5-5' && prompt > 100000 ? 5 : 1;
    const expected = factor * (usage.input_tokens * input + usage.cache_read_input_tokens * read + usage.cache_creation_input_tokens * write5m + usage.output_tokens * output);
    const actual = cost(model, usage).microUsd;
    assert.ok(Math.abs(actual - expected) <= Math.max(1, expected * 0.01), `${model} ${JSON.stringify(usage)} ${actual} vs ${expected}`);
  }
});
