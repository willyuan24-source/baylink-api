// Per-route Claude configuration: model, effort, output budget and deadlines.
//
// Routes without their own default reproduce the requests the backend sent
// before this module existed (2026-10-08): ANTHROPIC_BAYBAY_MODEL (default
// Claude Opus 5.5) and ANTHROPIC_BAYBAY_EFFORT ('low', otherwise 'medium'),
// with the caller's existing max_tokens and timeouts.
//
// R0 (2026-10-09, overhaul API-BB-R0): baybay_agent and baybay_professional
// have their own default, Claude Sonnet 5.5 at effort low. The legacy
// all-route variables no longer move these two routes; their per-route
// variables do. BAYBAY_MODEL_AGENT=claude-opus-5-5 (and
// BAYBAY_MODEL_PROFESSIONAL=claude-opus-5-5) is the rollback: a route whose
// model comes from a variable takes its effort from BAYBAY_EFFORT_<ROUTE>, else
// from the legacy ANTHROPIC_BAYBAY_EFFORT rule, exactly as before R0.
//
// Per-route environment overrides change one route without touching the others:
//
//   BAYBAY_MODEL_<ROUTE>         claude-opus-5-5 | claude-sonnet-5-5 | claude-haiku-5-5
//   BAYBAY_EFFORT_<ROUTE>        low | medium | high
//   BAYBAY_MAX_TOKENS_<ROUTE>    256..32000 (Haiku is always raised to >= 4000)
//   BAYBAY_FIRST_BYTE_MS_<ROUTE> 500..120000 (unset = no separate first-byte deadline)
//   BAYBAY_TOTAL_MS_<ROUTE>      1000..180000 (caps the provider call; caller deadlines still apply)
//   BAYBAY_FALLBACKS[_<ROUTE>]   default | off (server-side refusal fallback; Opus/Sonnet only)
//   BAYBAY_THINKING_<ROUTE>      adaptive | disabled (disabled is sent to Haiku 5.5 only; eval arm, RC-18)
//
// <ROUTE> is the route name without its "baybay_" prefix, upper-cased
// (baybay_agent -> AGENT, helper_translate -> HELPER_TRANSLATE). Helper routes
// also accept BAYBAY_MODEL_HELPERS / BAYBAY_EFFORT_HELPERS for all helpers.

const DEFAULT_MODEL = 'claude-opus-5-5';
const REFUSAL_RETRY_MODEL = 'claude-sonnet-5-5';
// R0 default for the BayBay agent loop and guarded professional answers.
const R0_MODEL = 'claude-sonnet-5-5';
const R0_EFFORT = 'low';
const KNOWN_MODELS = Object.freeze(['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5']);
const EFFORTS = Object.freeze(['low', 'medium', 'high']);
const HAIKU_MIN_MAX_TOKENS = 4000;
const HAIKU_MAX_PROMPT_TOKENS = 60000;
const CALLER_MAX_TOKENS_CEILING = 9000;
const SERVER_FALLBACK_BETA = 'server-side-fallback-2026-07-01';
const LIMITS = Object.freeze({ maxTokens: [256, 32000], firstByteMs: [500, 120000], totalMs: [1000, 180000] });

// Helper callers have always been capped at 9,000 output tokens; the agent and the
// other BayBay routes keep the caller's value (they size it for thinking).
// `model`/`effort`: the route's own default; null = the legacy all-route variables.
const route = (env, fields) => {
  const helper = env.startsWith('HELPER_');
  return Object.freeze({ env, group: helper ? 'helpers' : 'baybay', model: null, effort: null, allowHaiku: true, firstByteMs: null, callerMaxTokensCeiling: helper ? CALLER_MAX_TOKENS_CEILING : null, ...fields });
};
const ROUTES = Object.freeze({
  // Not wired yet: the single-call fast path arrives with API-BB-ENGINE.
  baybay_fast: route('FAST', { maxTokens: HAIKU_MIN_MAX_TOKENS, totalMs: 28000 }),
  // Agent research/synthesis loop. The caller sends 6,000 (research) or 9,000 (final) and 25 s / 28 s deadlines.
  // R0 default: Sonnet 5.5 at effort low (eval r0-check, 2026-10-08).
  baybay_agent: route('AGENT', { model: R0_MODEL, effort: R0_EFFORT, maxTokens: 9000, totalMs: 28000 }),
  // Guarded professional-topic answers (baybayAgent runs with baybayRoute({ safetyTopic })).
  // RC-20: never Haiku 5.5. R0 default: Sonnet 5.5 at effort low; Opus by override.
  baybay_professional: route('PROFESSIONAL', { model: R0_MODEL, effort: R0_EFFORT, maxTokens: 9000, totalMs: 28000, allowHaiku: false }),
  // Native web search. Haiku 5.5 is refused here until a test call proves web_search works on it.
  baybay_web: route('WEB', { maxTokens: 4096, totalMs: 35000, allowHaiku: false }),
  // Legacy guide chat (server.js). Not wired yet: server.js still reads the legacy variables.
  baybay_legacy: route('LEGACY', { maxTokens: 4096, totalMs: 28000 }),
  helper_translate: route('HELPER_TRANSLATE', { maxTokens: 6000, totalMs: 28000 }),
  helper_post_assist: route('HELPER_POST_ASSIST', { maxTokens: 6000, totalMs: 28000 }),
  helper_outing: route('HELPER_OUTING', { maxTokens: 6000, totalMs: 28000 }),
  helper_planner: route('HELPER_PLANNER', { maxTokens: 4000, totalMs: 28000 }),
  helper_event_extract: route('HELPER_EVENT_EXTRACT', { maxTokens: 6000, totalMs: 28000 }),
  helper_conversation: route('HELPER_CONVERSATION', { maxTokens: 6000, totalMs: 28000 }),
  helper_other: route('HELPER_OTHER', { maxTokens: 6000, totalMs: 28000 }),
  // Not wired yet: source-change triage arrives with API-FRESH-TRIAGE.
  triage: route('TRIAGE', { maxTokens: HAIKU_MIN_MAX_TOKENS, totalMs: 28000 }),
});
const ROUTE_NAMES = Object.freeze(Object.keys(ROUTES));

// Governed request feature (lib/aiRuntimeMetrics metricFeature) -> helper route,
// used when a helper call does not name its route explicitly.
const FEATURE_ROUTES = Object.freeze({ post_translation: 'helper_translate', post_assist: 'helper_post_assist', outing_draft: 'helper_outing',
  planner_recommend: 'helper_planner', event_extract: 'helper_event_extract', conversation_assist: 'helper_conversation' });
const routeForFeature = feature => FEATURE_ROUTES[feature] || 'helper_other';

const text = value => typeof value === 'string' ? value.trim() : '';
function modelFamily(model) {
  const match = /^claude-(opus|sonnet|haiku)-/.exec(text(model));
  return match ? match[1] : null;
}
// Server-side fallbacks exist for the Opus and Sonnet lines only. Claude Haiku 5.5
// has none: "default" stays declined and a model list is a 400.
const serverFallbacksAllowed = model => ['opus', 'sonnet'].includes(modelFamily(model));
const legacyEffort = config => config.ANTHROPIC_BAYBAY_EFFORT === 'low' ? 'low' : 'medium';
const legacyModel = config => config.ANTHROPIC_BAYBAY_MODEL || DEFAULT_MODEL;

function boundedInteger(value, [minimum, maximum]) {
  const raw = text(value);
  if (!/^\d+$/.test(raw)) return null;
  const number = Number(raw);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : null;
}

/** Resolve one route from config (process.env shape). Pure and cheap: callers resolve per request. */
function aiRoute(name, config = {}) {
  if (!Object.hasOwn(ROUTES, name)) throw new Error(`Unknown AI route: ${String(name).slice(0, 40)}`);
  const key = name, spec = ROUTES[key], ignored = [];
  const setting = (prefix, groupAllowed = true) => {
    const own = `${prefix}_${spec.env}`, group = `${prefix}_HELPERS`;
    if (text(config[own])) return { name: own, value: text(config[own]) };
    if (groupAllowed && spec.group === 'helpers' && text(config[group])) return { name: group, value: text(config[group]) };
    return null;
  };

  // A route with its own default (R0: agent, professional) ignores the legacy
  // all-route variable; the others keep reading it.
  let model = spec.model || legacyModel(config);
  let modelSource = spec.model ? 'route' : config.ANTHROPIC_BAYBAY_MODEL ? 'ANTHROPIC_BAYBAY_MODEL' : 'default';
  const modelOverride = setting('BAYBAY_MODEL');
  if (modelOverride && !KNOWN_MODELS.includes(modelOverride.value)) ignored.push({ name: modelOverride.name, reason: 'unknown_model' });
  else if (modelOverride && !spec.allowHaiku && modelFamily(modelOverride.value) === 'haiku') ignored.push({ name: modelOverride.name, reason: 'haiku_not_verified_for_route' });
  else if (modelOverride) { model = modelOverride.value; modelSource = modelOverride.name; }
  if (!spec.allowHaiku && modelFamily(model) === 'haiku') {
    // The legacy variable once drove every route at once; never let it move web search
    // or professional answers to Haiku.
    ignored.push({ name: modelSource, reason: 'haiku_not_verified_for_route' });
    model = spec.model || DEFAULT_MODEL; modelSource = spec.model ? 'route' : 'default';
  }

  // The route's own effort belongs to its own model. When a variable chooses the
  // model (the R0 rollback BAYBAY_MODEL_AGENT=claude-opus-5-5), effort follows the
  // legacy rule again unless BAYBAY_EFFORT_<ROUTE> says otherwise.
  let effort = legacyEffort(config), effortSource = config.ANTHROPIC_BAYBAY_EFFORT ? 'ANTHROPIC_BAYBAY_EFFORT' : 'default';
  if (spec.effort && modelSource === 'route') { effort = spec.effort; effortSource = 'route'; }
  const effortOverride = setting('BAYBAY_EFFORT');
  if (effortOverride && EFFORTS.includes(effortOverride.value)) { effort = effortOverride.value; effortSource = effortOverride.name; }
  else if (effortOverride) ignored.push({ name: effortOverride.name, reason: 'unsupported_effort' });

  const numeric = (prefix, field) => {
    const override = setting(prefix, false);
    if (!override) return { value: spec[field], overridden: false };
    const value = boundedInteger(override.value, LIMITS[field]);
    if (value === null) { ignored.push({ name: override.name, reason: 'out_of_range' }); return { value: spec[field], overridden: false }; }
    return { value, overridden: true };
  };
  const maxTokens = numeric('BAYBAY_MAX_TOKENS', 'maxTokens');
  const firstByteMs = numeric('BAYBAY_FIRST_BYTE_MS', 'firstByteMs');
  const totalMs = numeric('BAYBAY_TOTAL_MS', 'totalMs');

  const fallbackSetting = text(config[`BAYBAY_FALLBACKS_${spec.env}`]) ? { name: `BAYBAY_FALLBACKS_${spec.env}`, value: text(config[`BAYBAY_FALLBACKS_${spec.env}`]) }
    : text(config.BAYBAY_FALLBACKS) ? { name: 'BAYBAY_FALLBACKS', value: text(config.BAYBAY_FALLBACKS) } : null;
  if (fallbackSetting && !['default', 'off'].includes(fallbackSetting.value)) ignored.push({ name: fallbackSetting.name, reason: 'unsupported_fallbacks' });
  const thinkingSetting = setting('BAYBAY_THINKING', false);
  if (thinkingSetting && !['adaptive', 'disabled'].includes(thinkingSetting.value)) ignored.push({ name: thinkingSetting.name, reason: 'unsupported_thinking' });

  return Object.freeze({
    route: key, model, modelSource, effort, effortSource,
    maxTokens: maxTokens.value, maxTokensOverridden: maxTokens.overridden, callerMaxTokensCeiling: spec.callerMaxTokensCeiling,
    firstByteMs: firstByteMs.value, totalMs: totalMs.value,
    fallbacks: fallbackSetting?.value === 'default' ? 'default' : 'off',
    thinking: thinkingSetting?.value === 'disabled' ? 'disabled' : 'adaptive',
    maxPromptTokens: modelFamily(model) === 'haiku' ? HAIKU_MAX_PROMPT_TOKENS : null,
    ignored: Object.freeze(ignored),
  });
}

/** max_tokens for a request: an env override wins, then the caller's value (helper
 * routes cap it at 9,000 as before; BayBay routes pass it through unchanged), then
 * the route default. Claude Haiku 5.5 counts thinking toward max_tokens, so Haiku
 * requests never go below 4,000. */
function maxTokensFor(config, requested, model = config.model) {
  const caller = Number(requested), ceiling = config.callerMaxTokensCeiling;
  let value = config.maxTokensOverridden ? config.maxTokens
    : Number.isSafeInteger(caller) && caller > 0 ? (ceiling ? Math.min(caller, ceiling) : caller) : config.maxTokens;
  if (modelFamily(model) === 'haiku') value = Math.max(value, HAIKU_MIN_MAX_TOKENS);
  return value;
}

/** Total provider deadline: the caller's (stage-aware) deadline capped by the route. */
function timeoutFor(config, requested) {
  const caller = Number(requested);
  const valid = Number.isFinite(caller) && caller > 0;
  if (!config.totalMs) return valid ? caller : undefined;
  return valid ? Math.min(caller, config.totalMs) : config.totalMs;
}

/** First-byte deadline, only when configured and shorter than the total deadline. */
const firstByteFor = (config, totalMs) => config.firstByteMs && (!totalMs || config.firstByteMs < totalMs) ? config.firstByteMs : undefined;

/**
 * Request controls shared by every Claude adapter. Sampling parameters
 * (temperature/top_p/top_k) are never produced: Claude Haiku 5.5 rejects
 * non-default values and no route needs them. Effort is always explicit
 * (Sonnet 5.5 would otherwise default to high).
 */
function requestControls(config, model, requestedMaxTokens) {
  const fallbacks = config.fallbacks === 'default' && serverFallbacksAllowed(model);
  // Thinking is adaptive (field omitted) unless a route opts into disabled thinking,
  // which only Haiku 5.5 accepts (at low/medium/high). Opus 5.5 and Sonnet 5.5 return
  // a 400 for it, so the Sonnet refusal retry never carries it.
  const thinkingOff = config.thinking === 'disabled' && modelFamily(model) === 'haiku' && EFFORTS.includes(config.effort);
  return {
    model, effort: config.effort, maxTokens: maxTokensFor(config, requestedMaxTokens, model),
    ...(thinkingOff ? { thinking: { type: 'disabled' } } : {}),
    ...(fallbacks ? { fallbacks: 'default' } : {}), betas: fallbacks ? [SERVER_FALLBACK_BETA] : [],
  };
}

function anthropicHeaders(config, betas = []) {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${config.ANTHROPIC_API_KEY}`, 'anthropic-version': '2023-06-01',
    ...(config.ANTHROPIC_WORKSPACE_ID ? { 'anthropic-workspace-id': config.ANTHROPIC_WORKSPACE_ID } : {}),
    ...(betas.length ? { 'anthropic-beta': betas.join(',') } : {}) };
}

// Conservative prompt-size estimate without a tokenizer: UTF-8 bytes / 3 (one
// token per CJK character, generous for ASCII JSON). Images count as a fixed
// 2,000 tokens instead of their base64 length.
const IMAGE_TOKEN_ESTIMATE = 2000;
function estimatePromptTokens({ system, messages, tools } = {}) {
  let images = 0;
  const textOnly = JSON.stringify({ system, tools, messages }, (key, value) => {
    if (value && typeof value === 'object' && value.type === 'image') { images++; return null; }
    return value;
  });
  return Math.ceil(Buffer.byteLength(textOnly || '', 'utf8') / 3) + images * IMAGE_TOKEN_ESTIMATE;
}

/** Prompt-size check for one request. Only Haiku requests are capped (60K), which
 * keeps them clear of the 100K price cliff. Returns `{ estimate, cap }` when the
 * estimated prompt is over the cap, else null. Callers escalate an over-cap request
 * to Claude Sonnet 5.5 (the refusal-retry model, no cap) instead of failing it. */
function promptOverCap(body) {
  const cap = modelFamily(body?.model) === 'haiku' ? HAIKU_MAX_PROMPT_TOKENS : null;
  if (!cap) return null;
  const estimate = estimatePromptTokens(body);
  return estimate > cap ? { estimate, cap } : null;
}

/** One sanitized line per prompt-cap escalation: route, models and sizes only. */
function logPromptCap({ route: name, from, to, estimate, cap }, log = console.warn) {
  try { log(`[ai-prompt-cap] ${JSON.stringify({ route: name, from, to, estimate, cap })}`); } catch { /* Logging never changes the request outcome. */ }
}

// Invalid per-route settings are ignored (the route keeps its default). Say so once
// per process, naming the variable and the reason only, never its value, so a typo
// such as BAYBAY_MODEL_AGENT=claude-haiku-5.5 does not pass silently.
const reportedIgnored = new Set();
function warnIgnoredSettings(resolved, log = console.warn) {
  for (const item of resolved?.ignored || []) {
    const key = `${resolved.route}:${item.name}:${item.reason}`;
    if (reportedIgnored.has(key)) continue;
    reportedIgnored.add(key);
    try { log(`[ai-models] ignored ${JSON.stringify({ route: resolved.route, name: item.name, reason: item.reason })}`); } catch { /* Never fatal. */ }
  }
}

const REFUSAL_CATEGORY = /^[a-z][a-z0-9_]{0,39}$/;
/** Log a Haiku refusal that is being retried on Sonnet. Never logs prompt or answer text. */
function logRefusalRetry({ route: name, from, to, response }, log = console.warn) {
  const category = response?.stop_details?.category;
  try {
    const safeCategory = category == null ? null : typeof category === 'string' && REFUSAL_CATEGORY.test(category) ? category : 'unrecognized';
    log(`[ai-refusal] ${JSON.stringify({ route: name, from, to, category: safeCategory })}`);
  } catch { /* Logging never changes the request outcome. */ }
}

/** Public, secret-free description of every route (for capabilities or admin views). */
function describeAiModels(config = {}) {
  return ROUTE_NAMES.map(name => {
    const resolved = aiRoute(name, config);
    return { route: name, model: resolved.model, effort: resolved.effort, maxTokens: resolved.maxTokens, firstByteMs: resolved.firstByteMs,
      totalMs: resolved.totalMs, fallbacks: resolved.fallbacks, thinking: resolved.thinking, maxPromptTokens: resolved.maxPromptTokens,
      ignored: resolved.ignored.map(item => ({ ...item })) };
  });
}

module.exports = {
  DEFAULT_MODEL, REFUSAL_RETRY_MODEL, R0_MODEL, R0_EFFORT, KNOWN_MODELS, EFFORTS, HAIKU_MIN_MAX_TOKENS, HAIKU_MAX_PROMPT_TOKENS, CALLER_MAX_TOKENS_CEILING,
  SERVER_FALLBACK_BETA, ROUTES, ROUTE_NAMES, FEATURE_ROUTES,
  aiRoute, routeForFeature, modelFamily, serverFallbacksAllowed, maxTokensFor, timeoutFor, firstByteFor, requestControls,
  anthropicHeaders, estimatePromptTokens, promptOverCap, logPromptCap, warnIgnoredSettings, logRefusalRetry, describeAiModels,
};
