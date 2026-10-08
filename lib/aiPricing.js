// Dated Claude price table and exact integer cost arithmetic.
//
// Prices are stored in nano-USD per token (USD per million tokens x 1000), so
// every rate is an integer and a request's cost is exact before it is rounded
// once to micro-USD for storage. Source: claude-api skill, shared/model-migration.md
// (Claude Opus 5.5, Claude Sonnet 5.5 and Claude Haiku 5.5 sections), read 2026-10-08.
// Add a new dated entry instead of editing an old one; costs are priced with the
// entry in force on the call's Pacific date.

const MILLION_TOKENS_USD_TO_NANO = 1000;
const nano = usdPerMillion => Math.round(usdPerMillion * MILLION_TOKENS_USD_TO_NANO);
const card = ({ input, output, cacheRead }) => Object.freeze({
  input: nano(input), output: nano(output), cacheRead: nano(cacheRead),
  // Cache writes are priced from the input rate: 5-minute TTL 1.25x, 1-hour TTL 2x.
  cacheWrite5m: nano(input * 1.25), cacheWrite1h: nano(input * 2),
});

const HAIKU_LONG_PROMPT_THRESHOLD = 100000;
const WEB_SEARCH_NANO_USD = 10_000_000; // $0.01 per web_search request ($10 per 1,000).

const PRICE_TABLE = Object.freeze([
  Object.freeze({
    effectiveFrom: '2026-10-08',
    source: 'claude-api skill shared/model-migration.md, Claude Opus 5.5 / Sonnet 5.5 / Haiku 5.5 sections',
    webSearchNanoUsd: WEB_SEARCH_NANO_USD,
    models: Object.freeze({
      // Opus 5.5: $4 / $20; cache read $0.20 (0.05x); 5-minute write $5; 1-hour write $8.
      'claude-opus-5-5': Object.freeze({ standard: card({ input: 4, output: 20, cacheRead: 0.2 }) }),
      // Sonnet 5.5: $2 / $10; cache read $0.20; 5-minute write $2.50; 1-hour write $4.
      'claude-sonnet-5-5': Object.freeze({ standard: card({ input: 2, output: 10, cacheRead: 0.2 }) }),
      // Haiku 5.5 has two rate cards chosen by total prompt length: $0.10 / $0.50 up to
      // 100K prompt tokens, $0.50 / $2.50 above. Cache reads are 0.1x the card's input rate.
      'claude-haiku-5-5': Object.freeze({
        standard: card({ input: 0.1, output: 0.5, cacheRead: 0.01 }),
        longPrompt: card({ input: 0.5, output: 2.5, cacheRead: 0.05 }),
        longPromptAbove: HAIKU_LONG_PROMPT_THRESHOLD,
      }),
    }),
  }),
]);

const tokens = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const pricedModel = value => typeof value === 'string' ? value.trim().replace(/-\d{8}$/, '').replace(/-\d{4}-\d{2}-\d{2}$/, '') : '';

function priceEntry(day) {
  const date = typeof day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : null;
  const eligible = date ? PRICE_TABLE.filter(entry => entry.effectiveFrom <= date) : PRICE_TABLE;
  // Before the first dated entry the earliest known prices are the best estimate.
  return (eligible.length ? eligible : PRICE_TABLE).reduce((latest, entry) => entry.effectiveFrom > latest.effectiveFrom ? entry : latest);
}

/** Raw Claude usage split into billable buckets. `inputTokens` is the uncached
 * remainder only; the prompt is input + cache reads + cache writes. */
function claudeUsage(usage = {}) {
  const raw = usage && typeof usage === 'object' ? usage : {};
  const split = raw.cache_creation && typeof raw.cache_creation === 'object' ? raw.cache_creation : null;
  // Without a TTL split every cache write is the default 5-minute TTL. With one,
  // 1-hour writes are itemized and the rest of the (larger) total is 5-minute.
  const cacheWrite1h = tokens(split?.ephemeral_1h_input_tokens);
  const cacheWriteTotal = Math.max(tokens(raw.cache_creation_input_tokens), cacheWrite1h + tokens(split?.ephemeral_5m_input_tokens));
  const cacheWrite5m = cacheWriteTotal - cacheWrite1h;
  const inputTokens = tokens(raw.input_tokens), cacheReadTokens = tokens(raw.cache_read_input_tokens);
  return {
    inputTokens, cacheReadTokens, cacheWrite5mTokens: cacheWrite5m, cacheWrite1hTokens: cacheWrite1h,
    cacheWriteTokens: cacheWrite5m + cacheWrite1h, outputTokens: tokens(raw.output_tokens),
    webSearchRequests: tokens(raw.server_tool_use?.web_search_requests),
    promptTokens: inputTokens + cacheReadTokens + cacheWrite5m + cacheWrite1h,
  };
}

function priceUsage(model, usage, entry) {
  const prices = entry.models[pricedModel(model)];
  if (!prices) return null;
  const parts = claudeUsage(usage);
  const long = prices.longPrompt && parts.promptTokens > prices.longPromptAbove;
  const rates = long ? prices.longPrompt : prices.standard;
  const nanoUsd = parts.inputTokens * rates.input + parts.cacheReadTokens * rates.cacheRead
    + parts.cacheWrite5mTokens * rates.cacheWrite5m + parts.cacheWrite1hTokens * rates.cacheWrite1h
    + parts.outputTokens * rates.output + parts.webSearchRequests * entry.webSearchNanoUsd;
  return { nanoUsd, card: long ? 'long-prompt' : 'standard', usage: parts };
}

/**
 * Cost of one Claude Messages response. `model` is the model that served it
 * (falls back to the requested model). When `usage.iterations` itemizes several
 * attempts (server-side fallback), each attempt is priced at its own model.
 * Unknown models return `{ priced: false }` instead of a guess.
 */
function claudeCost({ model, usage, day } = {}) {
  const entry = priceEntry(day);
  const iterations = Array.isArray(usage?.iterations) ? usage.iterations.filter(item => item && typeof item === 'object') : [];
  const attempts = iterations.length && iterations.every(item => Number.isSafeInteger(item.input_tokens) || Number.isSafeInteger(item.output_tokens))
    ? iterations.map(item => ({ model: typeof item.model === 'string' ? item.model : model, usage: item }))
    : [{ model, usage }];
  let nanoUsd = 0, longPrompt = false;
  for (const attempt of attempts) {
    const priced = priceUsage(attempt.model, attempt.usage, entry);
    if (!priced) return { priced: false, model: pricedModel(model) || null, priceDate: entry.effectiveFrom };
    nanoUsd += priced.nanoUsd; longPrompt ||= priced.card === 'long-prompt';
  }
  // Integer nano-USD -> micro-USD, rounded once per response (max error $0.0000005).
  return { priced: true, model: pricedModel(model), nanoUsd, microUsd: Math.round(nanoUsd / 1000),
    card: longPrompt ? 'long-prompt' : 'standard', priceDate: entry.effectiveFrom, usage: claudeUsage(usage) };
}

const microUsdToUsd = microUsd => tokens(microUsd) / 1e6;

module.exports = { PRICE_TABLE, HAIKU_LONG_PROMPT_THRESHOLD, WEB_SEARCH_NANO_USD, claudeUsage, claudeCost, priceEntry, pricedModel, microUsdToUsd };
