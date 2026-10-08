// Dated Claude price table for the local BayBay eval (USD per million tokens).
// Source: claude-api skill model table cached 2026-10-06 (the same table the
// 10-07 audit used). Check the official pricing page before quoting these
// numbers to anyone; the eval only needs them to compare arms consistently.
export const PRICING_DATE = '2026-10-06';

const TABLE = {
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2, cacheWrite: 5 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5 },
  // Haiku 5.5 has two rate cards chosen by prompt length. Cache reads are
  // 0.1x and 5-minute cache writes 1.25x of whichever input rate applies.
  'claude-haiku-5-5': { input: 0.1, output: 0.5, cacheRead: 0.01, cacheWrite: 0.125,
    longPromptTokens: 100000, long: { input: 0.5, output: 2.5, cacheRead: 0.05, cacheWrite: 0.625 } },
};
export const WEB_SEARCH_USD = 0.01;

const count = value => Number.isSafeInteger(value) && value > 0 ? value : 0;

/** Raw Messages API usage, kept apart: uncached input, cache write, cache read. */
export function rawUsage(usage = {}) {
  return {
    inputTokens: count(usage.input_tokens),
    cacheWriteTokens: count(usage.cache_creation_input_tokens),
    cacheReadTokens: count(usage.cache_read_input_tokens),
    outputTokens: count(usage.output_tokens),
    webSearches: count(usage.server_tool_use?.web_search_requests),
  };
}

/** Price one provider call. Unknown models throw: an unpriced call must never
 * look free in a budget check. */
export function callCostUsd(model, usage) {
  const key = Object.keys(TABLE).find(id => typeof model === 'string' && (model === id || model.startsWith(`${id}-`)));
  if (!key) throw new Error(`No eval price for model ${JSON.stringify(model)}`);
  let rates = TABLE[key];
  const promptTokens = usage.inputTokens + usage.cacheWriteTokens + usage.cacheReadTokens;
  if (rates.long && promptTokens > rates.longPromptTokens) rates = rates.long;
  return (usage.inputTokens * rates.input + usage.cacheWriteTokens * rates.cacheWrite
    + usage.cacheReadTokens * rates.cacheRead + usage.outputTokens * rates.output) / 1e6
    + usage.webSearches * WEB_SEARCH_USD;
}

export function pricedModels() { return Object.keys(TABLE); }
