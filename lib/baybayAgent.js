// BayBay assistant (POST /api/ai/guide-chat). createBayBayAssistant() holds what every turn
// shares (catalogs, providers, quota claims, the source-monitor index, the $ caps and pause
// state, capabilities); run() answers one turn by calling the engine stages in
// lib/baybayEngine/ in order (H40: v1 and v2 were one 870-line run()):
//   emergency card and pause checks (here) → router.resolveTurn (task state)
//   → capacity claim (here) → evidence.gatherEvidence → research.createResearch (tools)
//   → router.routeTurn (v2 path) → stream.fastAnswer (v2 fast path) or research.research
//   (agent path, v1 and v2) → answer.finish.
// Engine v1 (BAYBAY_ENGINE=v1, the rollback) keeps its prompt and input in lib/baybayEngine/v1.js.
const crypto = require('node:crypto');
const { baybayProvider, baybayModel, anthropicAvailable } = require('./anthropicBaybay');
const { loadPlannerCatalog } = require('./planner');
const { bayAreaDate, safeModel } = require('./bayAreaSearchScope');
const { resolveTaskSecret } = require('./baybayState');
const { primeSiteEvidence } = require('./baybayEvidence');
const { baybayEngine } = require('./baybayRouter');
const { requestChecklist } = require('./baybayAnswerQuality');
const { loadDiscoveryCatalog } = require('./publicContext');
const { assertActive, aiExecution } = require('./aiGovernance');
const { emergencyResponse, possibleEmergencyTopic, professionalResponse } = require('./safetyRouting');
const { canonical } = require('./baybayTools');
const { createStageTimer, boundedOperation } = require('./baybayTiming');
const { foodEvidenceGap, foodRequest } = require('./foodEvidence');
const { budgetNotice, noticeBanners, pacificResetAt, aiUntilOf, scheduledPause } = require('./aiBudget');
const { copy } = require('./baybayEngine/util');
const { TOOLS, v2Rules } = require('./baybayEngine/prompt');
const { parseDraft, v1Instructions } = require('./baybayEngine/v1');
const { resolveTurn, routeTurn } = require('./baybayEngine/router');
const { sourceContextText, gatherEvidence, refRegions } = require('./baybayEngine/evidence');
const { UNAVAILABLE_HELP } = require('./baybayEngine/fallback');
const { renderCitations, stripLoginPitch, finish } = require('./baybayEngine/answer');
const { fastAnswer } = require('./baybayEngine/stream');
const { createResearch, research } = require('./baybayEngine/research');

// H03: source-monitor refresh interval, retry after a failed read, and the longest a cold
// instance (no index yet) waits for its first read on the request path.
const MONITOR_REFRESH_MS = 60000, MONITOR_RETRY_MS = 10000, MONITOR_COLD_WAIT_MS = 250;

// `budget` (API-BB-CUTOVER; server.js passes aiGovernance.spendLevel) resolves to today's
// spend state `{level: 'ok'|'soft'|'hard', caps: {enforced}, day}`. Without it (the eval
// harness, unit tests) no $ cap applies.
function createBayBayAssistant({ config = {}, catalog: supplied, guideCatalog = [], englishGuideCatalog, ai, isTest = false, webSearch, sourceFetch, fetchImpl, routeCompute, Quota, now = Date.now, monitorStatus, discoveryCatalog, discoveryCatalogEn, budget }) {
  const provider = baybayProvider(config), anthropic = provider === 'anthropic';
  const catalog = loadPlannerCatalog(supplied);
  // v2 indexes offers and openings (ENGINE-10); loaded on the first v2 request only.
  let discoveries;
  const discoveriesFor = () => discoveries ||= { ...loadDiscoveryCatalog(discoveryCatalog), english: loadDiscoveryCatalog(discoveryCatalogEn, true) };
  if (!isTest) { primeSiteEvidence({ guideCatalog, catalog }); if (englishGuideCatalog) primeSiteEvidence({ guideCatalog: englishGuideCatalog, catalog }); }
  // The OpenAI path skips a preferred model that returned HTTP 400/403/404 for ten minutes.
  const providerState = { unavailableModelUntil: 0 };
  // H03 (audit 10-13, BB-1013-01): the source monitor's review status is refreshed in the
  // background, at boot and then at most once a minute when a question finds it stale
  // (stale-while-revalidate), and indexed by canonical URL once per refresh. A question
  // never waits for the 1,400-row list (monitorMs was 0.6-2.5 s on 5 of 10 live turns);
  // only a cold instance with no index yet waits up to MONITOR_COLD_WAIT_MS for the first.
  let statusCache = { status: null, loadedAt: 0 }, monitorPending = null;
  const refreshMonitor = () => {
    if (!monitorStatus || isTest || monitorPending) return monitorPending;
    monitorPending = Promise.resolve().then(() => boundedOperation(monitorStatus, 15000, 'monitor_timeout')).then(rows => {
      // The first row for a URL decides (BBENG-01).
      const status = new Map();
      for (const row of Array.isArray(rows) ? rows : []) { const key = canonical(row?.url); if (key && !status.has(key)) status.set(key, row.reviewStatus); }
      statusCache = { status, loadedAt: Date.now() };
    }).catch(() => { statusCache = { ...statusCache, loadedAt: Date.now() - MONITOR_REFRESH_MS + MONITOR_RETRY_MS }; })
      .finally(() => { monitorPending = null; });
    return monitorPending;
  };
  // H03: a quota row that exists today is not upserted again (one round trip per claim, not two).
  const ensuredQuotaRows = new Set();
  const claim = async (kind, maximum) => {
    if (isTest && !Quota) return true;
    if (!Quota || maximum === 0) return false;
    const id = `${kind}:${bayAreaDate(now)}`;
    const reserve = async () => !!await Quota.findOneAndUpdate({ id, count: { $lt: maximum } }, { $inc: { count: 1 } }, { new: true });
    if (ensuredQuotaRows.has(id)) { if (await reserve()) return true; ensuredQuotaRows.delete(id); }
    try { await Quota.updateOne({ id }, { $setOnInsert: { id, count: 0, expiresAt: new Date(now() + 3 * 86400000) } }, { upsert: true }); } catch (e) { if (e.code !== 11000) throw e; }
    if (ensuredQuotaRows.size >= 200) ensuredQuotaRows.clear();
    ensuredQuotaRows.add(id);
    return reserve();
  };
  // CODE-API-02: one member's or one visitor's daily share of BayBay model runs. The
  // defaults (80 / 30) sit above the per-person AI counts (AI_USER_DAILY_LIMIT 40,
  // AI_GUEST_DAILY_LIMIT 15) and far below the site-wide 1,000. The quota row is keyed
  // by an HMAC of the user id or client IP, never the raw value.
  const shareLimit = (value, fallback) => { const limit = Number(value); return Number.isSafeInteger(limit) && limit > 0 ? limit : fallback; };
  const runShareSecret = resolveTaskSecret(config) || 'baybay-run-share';
  const runShare = ({ userId, ip }) => {
    const member = typeof userId === 'string' && userId.length > 0;
    const scope = member ? 'member' : 'visitor';
    const key = crypto.createHmac('sha256', runShareSecret).update(`${scope}:${member ? userId : String(ip || 'unknown')}`).digest('hex').slice(0, 24);
    return { scope, kind: `baybay-run:${scope}:${key}`, limit: member ? shareLimit(config.BAYBAY_MEMBER_RUN_LIMIT, 80) : shareLimit(config.BAYBAY_VISITOR_RUN_LIMIT, 30) };
  };
  const engine = anthropic && baybayEngine(config) === 'v2' ? 'v2' : 'v1';
  // H03: warm what the first question would otherwise build (the cold first question after a
  // deploy took 16.4 s to its lead): the offers/openings index and the monitor index.
  if (!isTest) { refreshMonitor(); if (engine === 'v2') discoveriesFor(); }
  const capabilities = () => ({ version: 2, enabled: config.BAYBAY_AGENT_ENABLED !== 'false', tools: ['site', 'web', 'sources', 'weather', 'plans'], taskMemory: !!resolveTaskSecret(config), routeEstimates: config.PLANNER_TRAVEL_ENABLED === 'true' && !!config.GOOGLE_ROUTES_API_KEY, configuredProvider: provider, configuredModel: safeModel(baybayModel(config)), modelAccessVerified: false, engine });
  // H40: what every turn of this assistant shares; the engine modules read it from the turn.
  const deps = { config, provider, anthropic, catalog, guideCatalog, englishGuideCatalog, ai, isTest, webSearch, sourceFetch, fetchImpl, routeCompute, now, discoveriesFor, claim, capabilities, providerState };
  // ---- API-BB-CUTOVER: $ caps and pause mode -----------------------------------
  /** Today's enforced cap level: 'ok' | 'soft' | 'hard'. Never throws; unknown → 'ok'. */
  const readBudget = async () => {
    if (typeof budget !== 'function') return { level: 'ok' };
    const state = await boundedOperation(budget, 2000, 'budget_timeout').catch(() => null);
    return { level: state?.caps?.enforced !== false && ['soft', 'hard'].includes(state?.level) ? state.level : 'ok', day: state?.day };
  };
  // Mirrors run()'s capacity check: an injected OpenAI-shaped provider (tests) needs no key;
  // Claude always needs a usable key inside ANTHROPIC_USE_UNTIL.
  const providerReady = () => ['openai', 'anthropic'].includes(provider) && (anthropic ? anthropicAvailable(config) : !!config.OPENAI_API_KEY || !!ai);
  /** Why BayBay cannot call a model right now (never for the emergency card), or null. */
  const pauseReason = level => config.BAYBAY_AGENT_ENABLED === 'false' ? 'disabled' : String(config.BAYBAY_PAUSED || '').trim().toLowerCase() === 'true' ? 'paused'
    : !providerReady() ? 'provider_unavailable' : level === 'hard' ? 'daily_budget' : null;
  /**
   * GET /api/ai/baybay-capabilities: capabilities() plus the pause state, for the banner
   * (WEB-BB-UI). While paused, `enabled` is false and `pause` carries the reason, the
   * banner text in every locale and the 911 / 211 actions to show first. Past the soft
   * cap, `reduced` says answers are site-only fast answers and web tools are not offered.
   * A guest (webAccess.allowed false) is offered site and plan tools only, as before.
   * BAYBAY_AGENT_ENABLED=false is not a pause: `enabled` is false as before and guide-chat
   * answers on its legacy model path, which only the hard $ cap stops.
   */
  async function status({ webAccess } = {}) {
    // BBENG-05: the Claude cutoff (ANTHROPIC_USE_UNTIL) as aiUntil, and in its last 7 days
    // pauseScheduled {kind, at, banner} so the web can warn before BayBay pauses.
    const until = anthropic ? aiUntilOf(config) : null, scheduled = anthropic ? scheduledPause(config, now()) : null;
    const base = { ...capabilities(), ...(until ? { aiUntil: until } : {}), ...(scheduled ? { pauseScheduled: scheduled } : {}) }, spend = await readBudget();
    const reason = base.enabled ? pauseReason(spend.level) : spend.level === 'hard' ? 'daily_budget' : null;
    const resumes = spend.day ? { resumesAt: pacificResetAt(spend.day) } : {};
    if (reason) {
      const kind = reason === 'daily_budget' ? 'ai_daily_budget' : 'ai_paused';
      return { ...base, enabled: false, tools: ['site'], routeEstimates: false,
        pause: { reason, kind, banner: noticeBanners(kind), ...(reason === 'daily_budget' ? resumes : {}), actions: UNAVAILABLE_HELP.actions }, reduced: null };
    }
    const reduced = spend.level === 'soft' ? { reason: 'daily_budget_soft', kind: 'ai_budget_reduced', banner: noticeBanners('ai_budget_reduced'), ...resumes } : null;
    const siteOnly = reduced || webAccess?.allowed === false ? { tools: ['site', 'plans'], routeEstimates: false } : {};
    return { ...base, ...siteOnly, pause: null, reduced };
  }
  // onDraft (API-BB-STREAM): the caller can show streamed answer drafts (guide-chat
  // passes it only for a client that sent streamVersion >= 3, RC-21). It receives
  // ready SSE `draft` values {seq, field, index?, text} from lib/baybayProgress.js.
  async function run({ message, history = [], searchContext = {}, sessionToken, searchMode = 'smart', locale = 'zh-Hans', preferences, currentPath, ip = 'unknown', userId, onProgress, onQuickCard, onDraft, webAccess, pageContext, signal }) {
    assertActive(signal);
    // A current emergency returns the fixed 911 card before retrieval, quota
    // or any model, including when the model is unavailable (degraded).
    const emergency = emergencyResponse(message, locale);
    if (emergency) return emergency;
    // SAFETY-2: a possible emergency below the card's bar. If no model answer comes
    // (paused, over the limit, provider down, or a template replaces it), the answer
    // is the 911-first floor with no site cards.
    const floorTopic = possibleEmergencyTopic(message, history);
    // A professional topic becomes a guarded model answer with a resource card.
    // The deterministic template remains its floor when no model answer exists.
    const professional = professionalResponse(message, locale, { guideCatalog, englishGuideCatalog });
    const guard = professional?.safety || null;
    // BBL-02: tell a streaming client at once that BayBay is working; the budget read
    // and the task state come before retrieval and used to delay the first frame.
    if (anthropic && baybayEngine(config) === 'v2') { try { const pending = onProgress?.({ phase: 'site', status: 'running' }); pending?.catch?.(() => {}); } catch { /* optional */ } }
    // API-BB-CUTOVER $ caps and pause mode (after the emergency card, which never
    // depends on them). Paused or past the hard cap: no model call; the answer comes
    // from site records with an honest `notice`. Past the soft cap: site evidence only
    // (the standard guest scope, no web search) and, on v2, the fast path only.
    const spend = await readBudget();
    const paused = pauseReason(spend.level);
    const resumes = spend.day ? { resumesAt: pacificResetAt(spend.day) } : {};
    let notice = paused ? budgetNotice(paused === 'daily_budget' ? 'ai_daily_budget' : 'ai_paused', locale, paused === 'daily_budget' ? resumes : {}) : null;
    const reducedBudget = !paused && spend.level === 'soft';
    if (reducedBudget && webAccess?.allowed !== false) {
      if (searchMode !== 'site') notice = budgetNotice('ai_budget_reduced', locale, resumes);
      webAccess = { ...(webAccess || {}), allowed: false, reason: 'daily_budget' };
    }
    if (webAccess?.allowed === false) searchMode = 'site';
    // BAYBAY_ENGINE=v2 (Claude only): deterministic router, single-call fast path,
    // v2 retrieval and the frozen-system cache layout. v1 is unchanged.
    const v2 = anthropic && baybayEngine(config) === 'v2';
    const checklist = requestChecklist(message, locale);
    const started = Date.now(), deadline = started + 75000, today = bayAreaDate(now);
    const timing = createStageTimer(started);
    const progress = (phase, status) => { try { const pending = onProgress?.({ phase, status }); pending?.catch?.(() => {}); } catch { /* progress is optional and cannot affect an answer */ } };
    const stage = async (key, phase, work) => { assertActive(signal); progress(phase, 'running'); try { return await timing.measure(key, work); } finally { progress(phase, 'completed'); } };
    // H40: the turn, read and written by the engine modules. Fields that change during the
    // turn (plan, model, webStatus, webCheckedAt, cached, notice, routing, draftWriter,
    // instructions) are always read from it, never copied. The arrays (rules, steps,
    // warnings, …) are created here once and only ever filled in place.
    const turn = { ...deps, message, history, searchContext, sessionToken, searchMode, locale, preferences, currentPath, ip, userId, onProgress, onQuickCard, onDraft, webAccess, pageContext, signal,
      floorTopic, professional, guard, paused, resumes, reducedBudget, v2, checklist, started, deadline, today, timing, progress, stage,
      rules: [], steps: [], warnings: [], travelEstimates: [], webResearch: [], modelResponses: [],
      notice, routing: null, draftWriter: null, plan: null, model: undefined, webStatus: 'not_requested', webCheckedAt: undefined, cached: false, instructions: undefined };
    resolveTurn(turn);
    const { resolved, warnings, steps } = turn;
    timing.record('stateMs', started);
    // H03 (audit 10-13, BB-1013-01): BayBay's run-share claim and the visible AI share
    // (the governed request's reservation) start here, beside retrieval, instead of after
    // it; their Mongo round trips (quotaMs up to 1.7 s live) no longer add to the lead.
    // A clarifying turn makes no model call and claims nothing, as before.
    const providerAvailable = anthropic ? anthropicAvailable(config) : !!config.OPENAI_API_KEY;
    // BAYBAY_DAILY_RUN_LIMIT defaults to 1,000 model runs a day (API-BB-CUTOVER; was 200):
    // at about a cent a question the $ caps bound the spend, and the count only stops abuse.
    const claims = !paused && ['openai', 'anthropic'].includes(provider) && !(anthropic && !providerAvailable) && !(!ai && (isTest || !providerAvailable));
    // CODE-API-02: each member and each visitor first claims a run from their own daily
    // share (BAYBAY_MEMBER_RUN_LIMIT / BAYBAY_VISITOR_RUN_LIMIT), and only then one from
    // the site-wide BAYBAY_DAILY_RUN_LIMIT, so one client that keeps asking cannot use up
    // the day for everyone. The share is keyed by an HMAC of the user id or client IP.
    const own = runShare({ userId, ip });
    let ownShareSpent = false;
    const capacityClaim = claims && !resolved.clarification ? (async () => {
      const quota = (kind, maximum) => boundedOperation(() => claim(kind, maximum), 3000, 'quota_timeout');
      try {
        if (!await quota(own.kind, own.limit)) { ownShareSpent = true; return false; }
        return await quota('baybay-agent', Number(config.BAYBAY_DAILY_RUN_LIMIT ?? 1000));
      } catch { warnings.push('quota_unavailable'); return false; }
    })() : null;
    // The governed reservation is memoized per request; the model call awaits the same one.
    // Not for a food ask, which can end in a templated evidence gap with no model call, and
    // only once the run share is claimed: a refused share (or quota_unavailable) ends with no
    // model call, so it must not spend the visitor's AI share. It still overlaps retrieval.
    if (capacityClaim && !foodRequest(message)) {
      const governed = aiExecution();
      capacityClaim.then(ok => { if (ok) governed?.reserve?.()?.catch?.(() => {}); }).catch(() => { /* claimed again at the model call */ });
    }
    gatherEvidence(turn);
    const { site, store } = turn;
    // v1 only: its SYSTEM text patched for this turn (v2 sends frozen blocks and v2Rules).
    if (!v2) turn.instructions = v1Instructions(turn);
    steps.push({ tool: 'search_site', status: 'completed', label: copy(locale, '已检索站内攻略与候选地点', 'Searched site guides and candidates') });
    if (monitorStatus && !isTest) {
      try {
        // BBENG-01: the review status by canonical URL is built once per refresh, not by
        // scanning every monitored row for every source of every question. H03: the refresh
        // runs in the background (refreshMonitor); a stale index is used while it runs.
        if (Date.now() - statusCache.loadedAt > MONITOR_REFRESH_MS) refreshMonitor();
        if (!statusCache.status && monitorPending) {
          await timing.measure('monitorMs', () => Promise.race([monitorPending, new Promise(resolve => { const timer = setTimeout(resolve, MONITOR_COLD_WAIT_MS); timer.unref?.(); })]));
        }
        if (statusCache.status) for (const source of store.sources.values()) if (statusCache.status.get(canonical(source.url)) === 'pending') source.needsReview = true;
      } catch { /* optional freshness never blocks retrieval */ }
    }
    Object.assign(turn, createResearch(turn));
    if (resolved.clarification) return finish(turn, null);
    if (searchMode === 'site' && site.foodEvidence?.status === 'needs-confirmation' && !guard) {
      // A bounded evidence gap is a complete, intentional site-only response,
      // not a provider failure. Keep the normal response envelope/page context.
      warnings.push('food_evidence_unconfirmed');
      return finish(turn, { answer: foodEvidenceGap(site.foodEvidence, locale), candidateIds: [], followups: [] });
    }
    routeTurn(turn);
    if (v2) turn.rules.push(...v2Rules(turn));
    // ---- v2 user turn and ref regions (computed for both engines, as before) ----
    turn.nowClock = new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Los_Angeles', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(now()));
    turn.refRegion = refRegions(turn);
    // quotaMs is now only the wait left after retrieval (the claim started beside it).
    const capacity = !!capacityClaim && await timing.measure('quotaMs', () => capacityClaim);
    if (!capacity) {
      warnings.push('model_unavailable_or_capacity');
      if (paused) warnings.push(paused === 'daily_budget' ? 'ai_daily_budget' : 'ai_paused');
      // The daily run limit is a daily AI limit too: the reader gets the same notice.
      else if (claims && !warnings.includes('quota_unavailable')) { warnings.push(ownShareSpent ? `baybay_${own.scope}_run_limit` : 'baybay_run_limit'); turn.notice = budgetNotice('ai_daily_budget', locale, resumes); }
      return finish(turn, null);
    }
    if (turn.routing?.path === 'fast') return finish(turn, await fastAnswer(turn));
    return research(turn);
  }
  return { run, capabilities, status };
}
module.exports = { createBayBayAssistant, parseDraft, renderCitations, stripLoginPitch, sourceContextText, TOOLS };
