// BayBay engine: what this turn asks for and which path answers it (H40 split of
// lib/baybayAgent.js). resolveTurn() reads the signed task token (or replays the history),
// resolves the task state and the plan edit, and sets the clarifications, stop limits and
// research deadline. routeTurn() decides the v2 path (deterministic router, budget fast-only)
// and the facts both engines use for research (timely, live check).
const { normalizeGuideQuery } = require('../guideLocale');
const { isSearchReset } = require('../guideWebSearch');
const { resolveTaskState, resolveTaskSecret, decodeTaskToken } = require('../baybayState');
const { routeBayBay, isBookingRequest, asksForPlan } = require('../baybayRouter');
const { needsExtendedSynthesis } = require('../baybayAnswerQuality');
const { preparePlanEdit, requestedStopLimit } = require('../baybayPlanEdits');
const { nearbyClarifier } = require('../baybayQuality');
const { arr, copy } = require('./util');

// A member asking to open or re-check an official page needs the research tools.
const LIVE_CHECK = /官网|官網|官方(?:页面|頁面|网页|網頁|网站|網站)|核对|核對|核实|核實|联网|聯網|\b(?:official (?:page|site|website)|check online|look (?:it )?up)\b|\bofficial(?:\s+[\w'’&.-]+){1,4}?\s+(?:page|site|website|calendar|schedule)\b|\b(?:open|re-?check|double-check|verify)\b[^.?!]{0,60}\bofficial\b/i;

/** The task state of this turn, its plan edit and limits; sets them on the turn. May throw INVALID_ASSISTANT_SESSION. */
function resolveTurn(turn) {
  const { message, config, sessionToken, now, searchMode, history, today, catalog, searchContext, pageContext, preferences, v2, locale, checklist, deadline } = turn;
  const normalized = normalizeGuideQuery(message);
  const reset = isSearchReset(message);
  const taskSecret = resolveTaskSecret(config);
  const previous = !reset && sessionToken ? decodeTaskToken(sessionToken, { secret: taskSecret, now }) : null;
  if (!reset && sessionToken && !previous) throw Object.assign(new Error('会话条件已过期，请开启新对话后重试。'), { status: 400, code: 'INVALID_ASSISTANT_SESSION' });
  if (searchMode === 'site' && previous?.lastPlan?.selectedRefs?.length) {
    const externalIds = new Set(previous.lastPlan.selectedRefs.map(ref => ref.id));
    previous.lastPlan = { ...previous.lastPlan, selectedRefs: [],
      candidateIds: (previous.lastPlan.candidateIds || []).filter(id => !externalIds.has(id)),
      selectedIds: (previous.lastPlan.selectedIds || []).filter(id => !externalIds.has(id)) };
    previous.state.selectedCandidateIds = (previous.state.selectedCandidateIds || []).filter(id => !externalIds.has(id));
  }
  let inherited = previous?.state;
  // v2 also carries follow-up constraints (API-BB-QUALITY); v1 resolves exactly as before.
  if (!inherited && !reset) for (const entry of history.filter(h => h.role === 'user')) inherited = resolveTaskState({ message: entry.content, previous: inherited, today, catalog, ...(v2 ? { carry: true } : {}) }).state;
  const resolved = resolveTaskState({ message, previous: inherited, searchContext, today, catalog, preferences: pageContext?.contextUsed?.preferences || preferences, ...(v2 ? { carry: true } : {}) });
  const planningPaused = resolved.planningPaused === true;
  const comparingInformation = resolved.informationAlternatives === true;
  const planningNotRequested = planningPaused || comparingInformation;
  // v2: "帮我订一张去北京的机票" asks BayBay to do what it cannot (book or pay). Say so
  // and give the next step, instead of asking which Bay Area city is meant.
  const booking = v2 && isBookingRequest(message);
  if (booking && /^BayBay 当前提供旧金山湾区/.test(resolved.clarification || '')) resolved.clarification = undefined;
  const { state, edit } = preparePlanEdit({ message, previousState: previous?.state, state: resolved.state, lastPlan: previous?.lastPlan, catalog });
  // C11: "附近有什么好吃的" with no city, area, origin or page is one short question, no cards.
  const nearbyAsk = v2 && !resolved.clarification ? nearbyClarifier(message, { state, hasPage: !!pageContext?.contextReferences?.length, locale }) : null;
  if (nearbyAsk) resolved.clarification = nearbyAsk;
  const indexedEdit = ['replace', 'remove'].includes(edit?.kind);
  const explicitCandidateIds = !indexedEdit ? arr(resolved.explicitCandidateIds, 6) : [];
  const requestedMaxStops = requestedStopLimit(message);
  const maxStops = requestedMaxStops || state.maxStops;
  if (explicitCandidateIds.length) state.selectedCandidateIds = [...explicitCandidateIds];
  const extendedSynthesis = needsExtendedSynthesis(checklist, state);
  const researchDeadline = deadline - (extendedSynthesis ? 32000 : 24000);
  if (edit?.kind === 'invalid') resolved.clarification = copy(locale, '请指定上一份行程里的一站，例如“换掉第二站”。目前没有修改其余站点。', 'Choose one existing numbered stop, for example “replace the second stop”. The other stops have not been changed.');
  if (maxStops && Math.max(explicitCandidateIds.length, edit?.named && edit.only ? edit.keepNames.length : 0) > maxStops) resolved.clarification = copy(locale,
    `你明确指定的地点超过了最多 ${maxStops} 站的限制。请说明保留哪些地点，或放宽站数；我还没有替你删除指定地点。`,
    `Your named destinations exceed the ${maxStops}-stop limit. Choose which destinations to keep, or increase the limit; none of your named destinations has been dropped.`);
  Object.assign(turn, { normalized, taskSecret, previous, resolved, planningPaused, comparingInformation, planningNotRequested, booking, state, edit, nearbyAsk, indexedEdit, explicitCandidateIds,
    requestedMaxStops, maxStops, extendedSynthesis, researchDeadline });
}

/** timely and liveCheck (both engines), and the v2 route of this turn on turn.routing. */
function routeTurn(turn) {
  const { state, normalized, v2, guard, edit, explicitCandidateIds, samePlanScope, previous, planningNotRequested, message, searchMode, reducedBudget, indexedEdit, warnings } = turn;
  const timely = ['day-plan', 'discover', 'transit'].includes(state.goal) || /今天|明天|最新|核实|营业|门票|优惠|freebie|\b(?:today|tomorrow|latest|hours|tickets?|price|verify|current)\b/i.test(normalized);
  // A member who asks to open or re-check an official page needs the tools the fast path lacks.
  const liveCheck = LIVE_CHECK.test(normalized);
  if (v2) turn.routing = routeBayBay({ professional: guard, state, edit, explicitCandidateIds, planFollowup: !!(samePlanScope && previous?.lastPlan),
    planRequest: !planningNotRequested && asksForPlan(message), searchMode, timely: timely || liveCheck });
  // Soft $ cap: one fast call for everything (a day plan is still built from the
  // answer's choices by create_plan in finish(), without a research loop). A replace or
  // remove edit of the plan in scope (换掉第二站) keeps the agent path, the one that gets
  // the previous plan and the edit; its tools are site-only, as searchMode is 'site' here.
  if (v2 && reducedBudget && turn.routing?.path === 'agent' && !(indexedEdit && samePlanScope && previous?.lastPlan)) {
    warnings.push('budget_fast_only');
    turn.routing = { path: 'fast', route: guard ? 'baybay_professional' : 'baybay_fast', reason: 'budget_fast_only' };
  }
  Object.assign(turn, { timely, liveCheck });
}

module.exports = { LIVE_CHECK, resolveTurn, routeTurn };
