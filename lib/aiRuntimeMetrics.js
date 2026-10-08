const { performance } = require('node:perf_hooks');
const { bayAreaDate } = require('./eventEngagement');

const RETENTION_DAYS = 30;
const LATENCY_BUCKETS_MS = Object.freeze([250, 500, 1000, 2000, 3000, 5000, 8000, 15000, 30000, 60000, 100000, 180000]);
const BUCKET_KEYS = Object.freeze([...LATENCY_BUCKETS_MS.map(value => `le${value}`), 'overflow']);
const FEATURES = Object.freeze(['guide_chat', 'planner_recommend', 'planner_web_search', 'post_assist', 'outing_draft', 'event_extract', 'conversation_assist', 'post_translation', 'other']);
// Unknown names collapse into one bucket. Neither request strings nor arbitrary
// provider-returned model names may create identifiers or unbounded cardinality.
const MODELS = Object.freeze(['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'gpt-6.1-sol', 'gpt-6-sol', 'gpt-6-astra', 'gpt-6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-4.1-nano', 'gpt-4o', 'gpt-4o-mini', 'other', 'none', 'mixed']);
const COUNTERS = Object.freeze(['requestCompleted', 'requestRejected', 'requestError', 'requestCancelled', 'requestDegraded',
  'providerCompleted', 'providerError', 'providerTimeout', 'providerCancelled', 'providerIncomplete',
  'inputTokens', 'outputTokens', 'inputUsageMissing', 'outputUsageMissing',
  // Claude billing view (lib/aiPricing): raw cache reads/writes, classifier or
  // model refusals, integer micro-USD cost, and provider calls without a price.
  'cacheReadTokens', 'cacheWriteTokens', 'providerRefusal', 'costMicroUsd', 'costUnpriced']);
// providerTtft: provider response headers after request start (see docs/ai-runtime-metrics.md).
const HISTOGRAMS = Object.freeze(['providerLatency', 'providerTtft', 'firstQuickCard', 'firstValidatedText', 'completeResult', 'requestEnd']);
const PROVIDER_HISTOGRAMS = Object.freeze(['providerLatency', 'providerTtft']);
const calendarDay = (day, offset) => new Date(Date.parse(`${day}T12:00:00Z`) + offset * 86400000).toISOString().slice(0, 10);
const count = value => Number.isSafeInteger(value) && value >= 0;
const tokenCount = value => count(value) && value <= 1000000000;

function metricModel(value) {
  if (typeof value !== 'string' || value.length > 80) return 'other';
  const base = value.replace(/-\d{4}-\d{2}-\d{2}$/, '');
  return MODELS.includes(base) && !['none', 'mixed'].includes(base) ? base : 'other';
}
function metricFeature(path) {
  const paths = { '/api/ai/guide-chat': 'guide_chat', '/api/planner/recommend': 'planner_recommend', '/api/planner/web-search': 'planner_web_search',
    '/api/ai/post-assist': 'post_assist', '/api/ai/outing-draft': 'outing_draft', '/api/ai/event-extract': 'event_extract' };
  if (paths[path]) return paths[path];
  if (/^\/api\/conversations\/[^/]+\/ai$/.test(path)) return 'conversation_assist';
  if (/^\/api\/posts\/[^/]+\/translation$/.test(path)) return 'post_translation';
  return 'other';
}
function latencyBucket(duration) {
  if (!Number.isFinite(duration) || duration < 0) return null;
  const index = LATENCY_BUCKETS_MS.findIndex(value => duration <= value);
  return index < 0 ? 'overflow' : BUCKET_KEYS[index];
}
function createAiRuntimeMetricModel(mongoose, injected = {}) {
  if (injected.AiRuntimeMetric) return injected.AiRuntimeMetric;
  const numeric = () => ({ type: Number, min: 0 });
  const schema = new mongoose.Schema({
    _id: { type: String, required: true },
    day: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    feature: { type: String, required: true, enum: FEATURES }, model: { type: String, required: true, enum: MODELS },
    ...Object.fromEntries(COUNTERS.map(key => [key, numeric()])),
    ...Object.fromEntries(HISTOGRAMS.map(key => [key, Object.fromEntries(BUCKET_KEYS.map(bucket => [bucket, numeric()]))])),
    expiresAt: { type: Date, required: true },
  }, { strict: 'throw', versionKey: false });
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  schema.index({ day: 1 });
  return mongoose.models.AiRuntimeMetric || mongoose.model('AiRuntimeMetric', schema);
}

function createAiRuntimeMetrics({ Model, now = Date.now, clock = () => performance.now(), enabled = true, maxPending = 256 }) {
  const pending = new Set();
  let failedWrites = 0, droppedWrites = 0;
  const health = () => ({ pendingWrites: pending.size, failedWrites, droppedWrites });
  function write(day, feature, model, values) {
    if (!enabled) return;
    if (pending.size >= maxPending) { droppedWrites++; return; }
    const increment = Object.fromEntries(Object.entries(values).filter(([key, value]) => {
      const [histogram, bucket, extra] = key.split('.');
      return count(value) && (COUNTERS.includes(key) || (!extra && HISTOGRAMS.includes(histogram) && BUCKET_KEYS.includes(bucket)));
    }));
    if (!Object.keys(increment).length) return;
    const _id = `${day}:${feature}:${model}`;
    const update = { $inc: increment, $setOnInsert: { _id, day, feature, model, expiresAt: new Date(`${calendarDay(day, RETENTION_DAYS)}T00:00:00Z`) } };
    // A single $inc is atomic across instances. Retry ONLY a definitely rejected
    // insertion race, never an uncertain write that may already have succeeded.
    const operation = (async () => {
      try {
        await Model.updateOne({ _id }, update, { upsert: true, setDefaultsOnInsert: false, runValidators: true, maxTimeMS: 2000 });
      } catch (error) {
        if (error.code !== 11000) throw error;
        const recovered = await Model.updateOne({ _id }, { $inc: increment }, { runValidators: true, maxTimeMS: 2000 });
        if (recovered.matchedCount === 0) throw new Error('Missing metric bucket');
      }
    })().catch(() => { failedWrites++; });
    pending.add(operation);
    void operation.finally(() => pending.delete(operation));
  }
  function startRequest(feature) {
    if (!FEATURES.includes(feature)) feature = 'other';
    const day = bayAreaDate(now()), start = clock(), providers = [], stages = {};
    let ended = false, responseFailed = false, degraded = false;
    const elapsed = () => Math.max(0, clock() - start);
    const mark = stage => { if (!ended && HISTOGRAMS.includes(stage) && ![...PROVIDER_HISTOGRAMS, 'requestEnd'].includes(stage) && stages[stage] === undefined) stages[stage] = elapsed(); };
    return {
      mark,
      response({ ok, degraded: fallback } = {}, status = 200) {
        if (ended) return;
        responseFailed = ok === false || status >= 400;
        degraded = fallback === true;
        if (!responseFailed) mark('completeResult');
      },
      providerStarted(requestedModel) {
        const slot = { model: metricModel(requestedModel) }; providers.push(slot);
        let recorded = false;
        return ({ outcome, durationMs, usage, model, ttftMs, billing, refusal } = {}) => {
          if (recorded) return; recorded = true;
          if (model !== undefined) slot.model = metricModel(model);
          const counter = { completed: 'providerCompleted', error: 'providerError', timeout: 'providerTimeout', cancelled: 'providerCancelled', incomplete: 'providerIncomplete' }[outcome];
          if (!counter) return;
          const values = { [counter]: 1 };
          const bucket = latencyBucket(durationMs);
          if (bucket) values[`providerLatency.${bucket}`] = 1;
          const input = usage?.input_tokens ?? usage?.prompt_tokens, output = usage?.output_tokens ?? usage?.completion_tokens;
          if (tokenCount(input)) values.inputTokens = input; else values.inputUsageMissing = 1;
          if (tokenCount(output)) values.outputTokens = output; else values.outputUsageMissing = 1;
          // Header timing is kept only for answered calls; error responses would skew it.
          const ttftBucket = ['completed', 'incomplete'].includes(outcome) ? latencyBucket(ttftMs) : null;
          if (ttftBucket) values[`providerTtft.${ttftBucket}`] = 1;
          if (refusal === true) values.providerRefusal = 1;
          if (billing?.priced === true) {
            if (count(billing.microUsd)) values.costMicroUsd = billing.microUsd;
            if (tokenCount(billing.cacheReadTokens)) values.cacheReadTokens = billing.cacheReadTokens;
            if (tokenCount(billing.cacheWriteTokens)) values.cacheWriteTokens = billing.cacheWriteTokens;
          } else if (billing) values.costUnpriced = 1;
          write(day, feature, slot.model, values);
        };
      },
      end({ cancelled = false, status = 200 } = {}) {
        if (ended) return; ended = true;
        const models = [...new Set(providers.map(provider => provider.model))];
        const model = models.length > 1 ? 'mixed' : models[0] || 'none';
        const outcome = cancelled || status === 499 ? 'requestCancelled' : status >= 500 ? 'requestError' : status >= 400 ? 'requestRejected' : responseFailed ? 'requestError' : 'requestCompleted';
        const values = { [outcome]: 1, [`requestEnd.${latencyBucket(elapsed())}`]: 1 };
        if (outcome === 'requestCompleted' && degraded) values.requestDegraded = 1;
        for (const [stage, duration] of Object.entries(stages)) {
          if (stage === 'completeResult' && outcome !== 'requestCompleted') continue;
          const bucket = latencyBucket(duration); if (bucket) values[`${stage}.${bucket}`] = 1;
        }
        write(day, feature, model, values);
      },
    };
  }
  async function report() {
    const timestamp = now(), through = bayAreaDate(timestamp), from = calendarDay(through, -29);
    const rows = await Model.find({ day: { $gte: from, $lte: through }, expiresAt: { $gt: new Date(timestamp).toISOString() } })
      .select(['day', 'feature', 'model', ...COUNTERS, ...HISTOGRAMS].join(' ')).sort({ day: 1, feature: 1, model: 1 }).limit(30 * FEATURES.length * MODELS.length).lean();
    // Reconstruct only the permitted fields, even for imported/legacy documents.
    const daily = rows.filter(row => /^\d{4}-\d{2}-\d{2}$/.test(row.day) && FEATURES.includes(row.feature) && MODELS.includes(row.model)).map(row => ({
      day: row.day, feature: row.feature, model: row.model,
      ...Object.fromEntries(COUNTERS.filter(key => count(row[key])).map(key => [key, row[key]])),
      ...Object.fromEntries(HISTOGRAMS.filter(key => row[key]).map(key => [key, Object.fromEntries(BUCKET_KEYS.filter(bucket => count(row[key][bucket])).map(bucket => [bucket, row[key][bucket]]))])),
    }));
    return { retentionDays: RETENTION_DAYS, from, through, latencyBucketUpperBoundsMs: [...LATENCY_BUCKETS_MS, null], histogramMode: 'exclusive',
      timingBasis: 'server-observed; validated text is not provider first-token time', writeHealth: health(), daily };
  }
  return { startRequest, report, health, flush: async () => { while (pending.size) await Promise.all([...pending]); } };
}

module.exports = { RETENTION_DAYS, LATENCY_BUCKETS_MS, FEATURES, MODELS, COUNTERS, HISTOGRAMS, PROVIDER_HISTOGRAMS, metricModel, metricFeature, latencyBucket, createAiRuntimeMetricModel, createAiRuntimeMetrics };
