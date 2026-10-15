// BayBay engine: tools and the research loop (H40 split of lib/baybayAgent.js).
// createResearch() builds one turn's tool executor (search_site, search_web, read_source,
// verify_candidate, get_route, get_weather, create_plan) with its budgets, and makePlan(),
// which runs a selection through the user-selection and feasibility guards. research() is
// the agent path: v2 sends the v2 user turn and rules with the frozen system blocks and
// streams the answering round's lead; v1 sends its SYSTEM instructions and contextInput
// (./v1.js), on Claude or the OpenAI Responses API. Both end in finish().
const { fetchAiJson } = require('../aiRequest');
const { createAnthropicBaybay, baybayModel, baybayRoute } = require('../anthropicBaybay');
const { safeModel } = require('../bayAreaSearchScope');
const { buildSiteEvidence } = require('../baybayEvidence');
const { systemBlocks, FAST_FORMAT, parseFastDraft } = require('../baybayFastPath');
const { assertActive } = require('../aiGovernance');
const { buildItinerary } = require('../baybayPlan');
const { resolvePlanSelection } = require('../baybayPlanEdits');
const { enrichPlanRoutes } = require('../baybayRoutePlan');
const { createResearchTools, verifiedCandidate, normalizeResearchError } = require('../baybayTools');
const { coverageFor, checklistAnswer, directSiteAnswer, planInteractionOnly } = require('../baybayAnswerQuality');
const { boundedOperation } = require('../baybayTiming');
const { createJsonFieldStream } = require('../anthropicStream');
const { createDraftWriter } = require('../baybayProgress');
const { failureReason } = require('../baybayQuality');
const { str, obj, arr, positive, copy } = require('./util');
const { TOOLS, SITE_TOOL_NAMES, SITE_TOOLS, v2Tool, V2_AGENT_RULES, V2_AGENT_WEB_RULES, pushRule, responseDiagnostic, cacheUsage } = require('./prompt');
const v1 = require('./v1');
const { modelPlan, modelSources, compactCandidates, newEvidence, readableSource, webSeen, v2UserContent, currentPageFor } = require('./evidence');
const { renderCitations, finish, resolveDraft } = require('./answer');
const { streamDrafts, premiseMismatch, leadDraftField } = require('./stream');
const { FINAL_FORMAT, parseDraft, withPageAlias } = v1;

/** One turn's tools: the executor with its budgets, and makePlan(). Stored on the turn. */
function createResearch(turn) {
  const { searchMode, timing, explicitCandidateIds, retainedCandidateIds, edit, store, now, locale, state, maxStops, travelEstimates, message, requestedAlternativeChoices, reviseChoices,
    today, webSearch, ip, config, isTest, sourceFetch, fetchImpl, routeCompute, claim, researchDeadline, planningNotRequested, signal, progress, stage, site, englishGuideCatalog,
    guideCatalog, catalog, v2, steps, warnings, webResearch, scopeGuides } = turn;
  const availableTools = searchMode === 'site' ? SITE_TOOLS : TOOLS;
  const makePlan = candidateIds => timing.sync('planMs', () => {
    // Explicit destinations belong to the user. A model may not add a third
    // stop, replace them, or clear a retained plan by returning an empty list.
    const proposedIds = explicitCandidateIds.length ? explicitCandidateIds : retainedCandidateIds.length ? retainedCandidateIds : candidateIds?.length ? candidateIds : state.selectedCandidateIds?.length ? state.selectedCandidateIds : candidateIds;
    const selection = resolvePlanSelection({ edit, candidateIds: proposedIds, candidates: store.candidates, now: now(), locale });
    const rows = selection.explicitSelection && !selection.selectedIds.length ? [] : [...store.candidates.values()].filter(c => !c.isOrigin);
    const result = buildItinerary({ state: { ...state, ...(maxStops ? { maxStops } : {}) }, candidates: rows, selectedIds: selection.selectedIds, travelEstimates, now, locale });
    const noAdditionalStops = explicitCandidateIds.length > 0 && String(message).split(/[，,。.!！？?；;\n]/).some(clause =>
      /^(?:\s|请|請|也)*(?:不要|不需要|无需|無需|不用|别|別|不)(?:再)?(?:添加|增加|加入|加|安排|推荐|推薦|补|補)(?:任何|其他|其它|别的|別的|新的|额外|額外|一个|一個|更多|替代)*(?:景点|景點|地点|地點|地方|站)/.test(clause)
      || /^\s*(?:please\s+)?(?:do not|don['’]t|no|without|avoid)\s+(?:(?:add|adding|include|including|recommend|recommending|suggest|suggesting)\s+)?(?:any\s+)?(?:additional|extra|other|new|more)\s+(?:stops?|places?|attractions?|destinations?)\b/i.test(clause));
    const removalOnly = edit?.kind === 'remove' && !/备选|備選|替代|换|換|\b(?:alternative|instead|replace|swap)\b/i.test(message);
    if (selection.suppressAlternatives || noAdditionalStops || removalOnly) result.alternatives = [];
    else if ((explicitCandidateIds.length && !requestedAlternativeChoices) || (retainedCandidateIds.length && !reviseChoices)) {
      // Named destinations constrain every card from the first request, not
      // just later follow-ups. Timing-only alternatives may stay; replacing
      // a user-selected stop requires an explicit request to compare choices.
      const keptIds = result.stops.map(stop => stop.entityId || stop.id);
      result.alternatives = result.alternatives.filter(other => other.stops.length === keptIds.length
        && other.stops.every((stop, index) => (stop.entityId || stop.id) === keptIds[index]));
    }
    if (selection.notice) { result.unknowns = [...new Set([...(result.unknowns || []), selection.notice])]; if (result.status === 'ready') result.status = 'needs_verification'; }
    return result;
  });
  const tools = createResearchTools({ store, state, today, locale, searchMode, webSearch: input => webSearch(input, ip), config, isTest, sourceFetch, fetchImpl, routeCompute, claimRoute: () => boundedOperation(() => claim('planner-travel', Number(config.PLANNER_TRAVEL_DAILY_LIMIT ?? 100)), 3000, 'quota_timeout').catch(() => false), now, deadline: researchDeadline });
  const attempts = { read_source: 0, search_web: 0 }, exhausted = new Set(), failedCalls = new Map();
  const offeredTools = () => availableTools.filter(item => !exhausted.has(item.name) && !(planningNotRequested && item.name === 'create_plan'));
  const execute = async (name, args) => {
    assertActive(signal);
    if (planningNotRequested && name === 'create_plan') return { error: 'The user requested information, not a new itinerary. Answer their question using the evidence. No itinerary was changed.', code: 'plan_not_requested', retryable: false };
    // Hiding a tool is guidance, not authority: reject a model that emits an
    // undeclared external call while retaining the research tools' own guards.
    if (searchMode === 'site' && TOOLS.some(item => item.name === name) && !SITE_TOOL_NAMES.has(name)) {
      steps.push({ tool: name, status: 'unavailable', label: name, code: 'site_only' });
      return { error: `The user chose site-only mode; answer from site snapshots or suggest ${copy(locale, locale === 'zh-Hant' ? '智能檢索 / 聯網查' : '智能检索 / 联网查', 'Smart / Web')} for current official verification.`, code: 'site_only', retryable: false };
    }
    if (name !== 'create_plan' && Date.now() > researchDeadline - 1500) return { error: 'Research time budget reached.', code: 'research_deadline' };
    const key = JSON.stringify([name, args]);
    if (failedCalls.has(key)) return failedCalls.get(key);
    if (exhausted.has(name)) return { error: 'This tool budget is exhausted. Use the collected evidence and finish the answer.', code: 'tool_budget_exhausted', retryable: false };
    if (Object.hasOwn(attempts, name)) { attempts[name]++; if (attempts[name] >= (name === 'read_source' ? 3 : 2)) exhausted.add(name); }
    try {
      let result;
      if (name === 'search_site') {
        progress('site', 'running');
        result = timing.sync('siteMs', () => buildSiteEvidence({ query: str(args.query, 500), ...(site.foodEvidence ? { originalQuery: message } : {}), state, guideCatalog: locale === 'en' && englishGuideCatalog ? englishGuideCatalog : guideCatalog, catalog, today, ...(v2 ? { v2: true } : {}) }));
        progress('site', 'completed');
        for (const s of result.sources || []) store.addSource(s);
        for (const g of result.guides || []) store.addSource({ ...g, kind: 'guide', verification: 'catalog' });
        scopeGuides.push(...(result.guides || []));
        for (const c of result.candidates || []) store.addCandidate(c);
        // v2 sends only what the model has not seen yet (no evidence is repeated).
        result = v2 ? newEvidence(turn) : { sources: modelSources(turn), candidates: [...store.candidates.values()].slice(0, 16) };
      } else if (name === 'search_web') { result = await stage('searchMs', 'research', () => tools.searchWeb(str(args.query, 390))); if (!result.error) { turn.webStatus = 'completed'; turn.webCheckedAt = result.checkedAt; turn.cached = result.cached; webResearch.push({ answer: str(result.answer, 4000), sourceIds: result.sources?.map(s => s.id) || [], checkedAt: result.checkedAt, notice: result.notice }); } else if (searchMode !== 'site' && turn.webStatus !== 'completed') turn.webStatus = 'unavailable'; else if (searchMode !== 'site') warnings.push('additional_web_lookup_unavailable'); }
      else if (name === 'read_source') {
        result = await stage('readMs', 'sources', () => tools.readSource(v2 ? readableSource(turn, args.sourceId) : args.sourceId));
        if (!result?.error && result.verification === 'page-read') { turn.webStatus = 'completed'; turn.webCheckedAt = result.checkedAt || turn.webCheckedAt; }
      }
      else if (name === 'verify_candidate') { result = verifiedCandidate({ candidate: store.candidates.get(args.candidateId), source: store.sources.get(args.sourceId), kind: args.kind, proofs: args.proofs, state, today }); if (!result.error) store.addCandidate(result); }
      else if (name === 'get_route') { result = await stage('routeMs', 'routes', () => tools.route(args)); if (result.ok) travelEstimates.push(result); }
      else if (name === 'get_weather') result = await stage('weatherMs', 'research', () => tools.weather(args.candidateId));
      else if (name === 'create_plan') {
        turn.plan = makePlan(arr(args.candidateIds, 6));
        if (searchMode !== 'site') turn.plan = await enrichPlanRoutes({ plan: turn.plan, makePlan, route: routeArgs => execute('get_route', routeArgs), state, deadline: researchDeadline });
        result = turn.plan;
      }
      else return { error: 'Unknown tool.' };
      if (result?.error && result.retryable === false) failedCalls.set(key, result);
      if (['source_tool_limit', 'source_reader_unavailable', 'research_deadline', 'web_tool_limit', 'web_daily_limit', 'web_rate_limit', 'route_tool_limit', 'route_daily_limit', 'route_not_configured', 'weather_tool_limit'].includes(result?.code)) exhausted.add(name);
      steps.push({ tool: name, status: result?.error ? 'unavailable' : 'completed', label: name, ...(result?.error && /^[a-z][a-z0-9_]{0,79}$/.test(result.code || '') ? { code: result.code } : {}) });
      return result;
    } catch (error) {
      if (name === 'search_web') { if (turn.webStatus !== 'completed') turn.webStatus = 'unavailable'; else warnings.push('additional_web_lookup_unavailable'); }
      const failure = normalizeResearchError(error, name);
      if (failure.retryable === false) failedCalls.set(key, failure);
      steps.push({ tool: name, status: 'unavailable', label: name, code: failure.code });
      return failure;
    }
  };
  return { availableTools, makePlan, attempts, exhausted, offeredTools, execute };
}

/** The agent path: research rounds with tools, then the final answer. */
async function research(turn) {
  const { v2, searchMode, rules, state, explicitCandidateIds, timely, execute, normalized, config, history, now, contextReferences, locale, today, store, anthropic, fetchImpl, guard,
    availableTools, offeredTools, ai, providerState, deadline, researchDeadline, signal, checklist, site, onDraft, stage, extendedSynthesis, modelResponses, warnings, message, attempts, samePlanScope, previous, edit } = turn;
  const addRule = value => pushRule(rules, value);
  if (v2) addRule(V2_AGENT_RULES + (searchMode !== 'site' ? `\n${V2_AGENT_WEB_RULES}` : ''));
  // Named venue plans already have official source links and exact catalog
  // destinations. Broad events search adds latency and unrelated candidates.
  const namedPlan = state.goal === 'day-plan' && explicitCandidateIds.length > 0;
  if (searchMode !== 'site' && !namedPlan && (searchMode === 'web' || timely)) {
    const publicQuery = `${state.city || 'Bay Area'} ${state.date || ''} ${state.goal === 'day-plan' ? 'things to do official events opening hours' : str(normalized.replace(/[^\s]+@[^\s]+|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, ''), 230)} ${state.freeOnly ? 'free admission conditions' : ''}`;
    await execute('search_web', { query: publicQuery });
  }
  if (namedPlan) await execute('create_plan', { candidateIds: explicitCandidateIds });
  const maxRounds = positive(config.BAYBAY_MAX_MODEL_ROUNDS, 4, 4), maxTools = 8;
  let toolCount = 0;
  const recentConversation = history.filter(entry => ['user', 'assistant'].includes(entry.role)).slice(-8).map(entry => ({ role: entry.role, content: str(entry.content, 1400) }));
  const nowBayArea = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Los_Angeles', dateStyle: 'short', timeStyle: 'short' }).format(new Date(now()));
  const currentPage = currentPageFor(contextReferences[0], locale, today);
  const contextInput = () => v1.contextInput(turn, { recentConversation, nowBayArea, currentPage });
  const web = v2 ? webSeen(turn) : undefined;
  if (web?.results) addRule('webResearch holds this run\'s web search. Its summaries are leads, not exact page quotes: use them for what is current, prefer an official page read for dates, hours and eligibility, and cite a web source by its id ([[s-…]]).');
  else if (web) addRule('The web search for this question did not complete. Answer from the site records and say briefly that current official details could not be checked just now.');
  const input = v2 ? [{ role: 'user', content: v2UserContent(turn, { candidates: compactCandidates(turn), previousPlan: samePlanScope ? previous?.lastPlan || null : null, planEdit: edit, currentPlan: modelPlan(turn.plan), web }) },
    ...(rules.length ? [{ role: 'system', content: rules.join('\n\n') }] : [])] : contextInput();
  // Guarded professional answers run on their own route (RC-20: never Haiku); the
  // adapter then sends that route's model and effort for every call of the run.
  const anthropicRequest = anthropic ? createAnthropicBaybay({ config, fetchImpl, route: baybayRoute({ safetyTopic: guard?.topic }) }) : null;
  // Claude signatures bind to the initial tools and system. Tool budgets are
  // still enforced by execute(); only tool_choice changes during synthesis.
  // v2: one fixed, name-sorted tool list per mode (site / member) so the cached
  // prefix never varies; execute() still enforces budgets and exclusions.
  const anthropicTools = anthropic ? v2 ? availableTools.map(v2Tool).sort((a, b) => a.name.localeCompare(b.name)) : offeredTools() : null;
  const anthropicInstructions = turn.instructions;
  let citationRepair = '';
  let chosen = anthropic ? baybayModel(config, baybayRoute({ safetyTopic: guard?.topic })) : baybayModel(config);
  if (!anthropic && providerState.unavailableModelUntil > Date.now()) chosen = config.OPENAI_BAYBAY_FALLBACK_MODEL || 'gpt-4.1-mini';
  let recoverFinal = false, recoveryUsed = false;
  // API-BB-5 (live 10-15, L07; 10-13: 8.8 s): a new day plan in site mode waited for two model rounds before any
  // text (the model asked create_plan, then wrote). The plan engine builds the plan from the site's candidates
  // first, so one streamed call writes the answer around it; the 10-15 recovery path did exactly this live. Plan
  // edits, follow-ups on a plan, member web research and BAYBAY_DAY_PLAN_FAST=off keep the agent rounds.
  const sitePlan = v2 && searchMode === 'site' && state.goal === 'day-plan' && !turn.edit && !turn.samePlanScope && (site.candidates || []).length >= 2
    && String(config.BAYBAY_DAY_PLAN_FAST || '').trim().toLowerCase() !== 'off';
  if (sitePlan && !namedPlan) warnings.push('day_plan_single_call');
  let forceFinal = searchMode === 'site' && (namedPlan || sitePlan || directSiteAnswer({ message, checklist, state, site }));
  // One extra call can recover unusable final output, including a plan answer
  // without its evidence. Never extend research or replay unsupported prose.
  for (let round = 0; round < maxRounds + 1 && Date.now() < deadline - 2000; round++) {
    assertActive(signal);
    if (round >= maxRounds && !recoverFinal) break;
    const finalRound = forceFinal || recoverFinal || toolCount >= maxTools || round >= maxRounds - 1 || Date.now() >= researchDeadline - 8000 || state.goal !== 'day-plan' && attempts.read_source >= 3;
    if (finalRound && state.goal === 'day-plan' && !(recoverFinal && turn.plan)) await execute('create_plan', { candidateIds: turn.plan?.stops.map(stop => stop.entityId || stop.id) || state.selectedCandidateIds });
    const finalInstruction = '\nResearch is complete. Return the final JSON now using only the attached current evidence and calculated plan. No tools are available. Give every requested conclusion supported by the collected facts and identify each remaining gap. Preserve the requestChecklist coverage; do not spend output on research narration.';
    // v2 final round sends only the delta: what changed since the model last saw it.
    const finalFrom = input.length;
    if (v2 && finalRound) input.push({ role: 'user', content: JSON.stringify({ researchComplete: true, ...(turn.plan ? { currentPlan: modelPlan(turn.plan) } : {}), ...newEvidence(turn) }) }, { role: 'system', content: (finalInstruction + citationRepair).trim(), reminder: true });
    else if (anthropic && finalRound) input.push(...contextInput(), { role: 'user', content: finalInstruction + citationRepair });
    const currentInput = anthropic ? input : finalRound ? contextInput() : input;
    const payload = v2 ? { model: chosen, system: systemBlocks(), cacheControl: { type: 'ephemeral' }, input: currentInput, tools: anthropicTools, text: { format: FAST_FORMAT }, max_output_tokens: finalRound ? 9000 : 6000, tool_choice: finalRound ? 'none' : 'auto' }
      : { model: chosen, store: false, instructions: anthropic ? anthropicInstructions : turn.instructions + (finalRound ? finalInstruction : ''), input: /^gpt-[56]/.test(chosen) || anthropic ? currentInput : currentInput.filter(item => item.type !== 'reasoning'), include: ['reasoning.encrypted_content'], tools: anthropic ? anthropicTools : finalRound ? [] : offeredTools(), text: { format: FINAL_FORMAT }, max_output_tokens: anthropic ? (finalRound ? 9000 : 6000) : /^gpt-[56]/.test(chosen) ? (finalRound ? 5000 : 3000) : checklist.complex ? 3200 : 1800,
      ...(anthropic ? { tool_choice: finalRound ? 'none' : 'auto' } : /^gpt-[56]/.test(chosen) ? { reasoning: { effort: 'low' } } : { temperature: 0.2 }) };
    let callFinal = finalRound;
    // H03 (audit 10-13, BBENG-07): the agent's answering round streams its lead to a capable
    // client (day plans and plan edits spun 7-13 s with no text). Any round may be the one
    // that answers (the model answers once its tools are done), so each round streams until
    // one has sent draft text; a round that calls tools sends none. A recovery round answers
    // in the result only. Lead only, since a plan answer is re-laid out around the card.
    // The Batch-5 brief supersedes RC-21 here too; a premise mismatch still sends no draft.
    let finalFields = null;
    if (v2 && anthropic && !recoverFinal && !turn.draftWriter?.sent().events && streamDrafts(turn) && !checklist.complex && !premiseMismatch(site)) {
      turn.draftWriter = createDraftWriter({ emit: event => { const pending = onDraft(event); pending?.catch?.(() => {}); }, locale });
      finalFields = createJsonFieldStream({ match: leadDraftField, onText: (target, text) => turn.draftWriter.text(target.field, target.index, text), onDone: target => turn.draftWriter.done(target.field, target.index) });
      payload.stream = true;
    }
    const onFinalText = finalFields ? text => finalFields.push(text) : null;
    let response, lastCallElapsedMs = 0;
    try {
      const call = async () => {
        const began = Date.now();
        const providerTimeout = anthropic ? (callFinal ? 28000 : 25000) : callFinal && extendedSynthesis ? 28000 : 18000;
        const timeoutMs = Math.max(1000, Math.min(providerTimeout, (callFinal ? deadline : researchDeadline) - Date.now() - 1000));
        try {
          return await stage(callFinal ? 'finalMs' : 'modelMs', callFinal ? 'answer' : 'research', () => ai ? boundedOperation(() => onFinalText ? ai(payload, { onText: onFinalText }) : ai(payload), timeoutMs, 'AI request timed out') : anthropic ? anthropicRequest(payload, { timeoutMs, signal, ...(onFinalText ? { onText: onFinalText } : {}) }) : fetchAiJson('https://api.openai.com/v1/responses', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.OPENAI_API_KEY}` }, body: JSON.stringify(payload) }, { timeoutMs, ...(fetchImpl ? { fetchImpl } : {}) }));
        } catch (error) {
          modelResponses.push({ ...responseDiagnostic({ status: 'failed' }, round + 1, callFinal ? 'final' : 'research', chosen), elapsedMs: Math.max(0, Date.now() - began), ...(v2 ? { failure: failureReason(error) } : {}) });
          throw error;
        } finally { lastCallElapsedMs = Math.max(0, Date.now() - began); }
      };
      try { response = await call(); }
      catch (error) {
        const unavailable = /HTTP (?:400|403|404)/.test(error.message), timedOut = /timed out/i.test(error.message);
        if (!anthropic && !ai && (unavailable || timedOut && deadline - Date.now() > 8000) && chosen !== (config.OPENAI_BAYBAY_FALLBACK_MODEL || 'gpt-4.1-mini')) {
          if (unavailable) providerState.unavailableModelUntil = Date.now() + 10 * 60000;
          chosen = config.OPENAI_BAYBAY_FALLBACK_MODEL || 'gpt-4.1-mini'; payload.model = chosen;
          if (Date.now() >= researchDeadline - 8000) {
            callFinal = true; payload.tools = []; payload.instructions += '\nResearch time is complete. Return the final JSON from the current evidence and plan, with a conclusion or precise gap for each requestChecklist item.';
            if (state.goal === 'day-plan') await execute('create_plan', { candidateIds: turn.plan?.stops.map(stop => stop.entityId || stop.id) || state.selectedCandidateIds });
            payload.input = contextInput();
          } else payload.input = currentInput.filter(item => item.type !== 'reasoning');
          delete payload.reasoning; payload.temperature = 0.2; payload.max_output_tokens = checklist.complex ? 3200 : 1800;
          warnings.push(unavailable ? 'preferred_model_unavailable' : 'preferred_model_timeout'); response = await call();
        }
        else throw error;
      }
    } catch {
      if (finalFields) turn.draftWriter.end({ complete: false });
      warnings.push('model_unavailable');
      // A research failure must not consume the reserved synthesis stage.
      // Try it once with current evidence; never extend the research loop.
      if (!callFinal && !recoveryUsed && Date.now() < deadline - 4500) { recoverFinal = true; recoveryUsed = true; if (!anthropic) chosen = config.OPENAI_BAYBAY_FALLBACK_MODEL || 'gpt-4.1-mini'; continue; }
      // API-BB-5: a single-call day plan's only call failed (429/529/connection): one recovery call with the same
      // plan and evidence, as the fast path retries once. Its final turn is sent once, not twice.
      if (v2 && callFinal && sitePlan && !namedPlan && !recoveryUsed && Date.now() < deadline - 4500) { input.length = finalFrom; recoverFinal = true; recoveryUsed = true; continue; }
      break;
    }
    if (finalFields) turn.draftWriter.end({ complete: true });
    turn.model = safeModel(response.model || chosen);
    const diagnostic = { ...responseDiagnostic(response, round + 1, recoverFinal ? 'recovery' : callFinal ? 'final' : 'research', chosen), elapsedMs: lastCallElapsedMs, ...(v2 ? { route: turn.routing?.route, ...cacheUsage(response) } : {}) };
    modelResponses.push(diagnostic);
    if (diagnostic.status === 'incomplete') warnings.push(`model_response_incomplete_${diagnostic.incompleteReason}`);
    if (anthropic) input.push(...(response.output || []).filter(x => ['function_call', 'reasoning', 'message'].includes(x.type)));
    const calls = (response.output || []).filter(x => x.type === 'function_call');
    if (!calls.length) {
      const draft = v2 ? resolveDraft(turn, parseFastDraft(response)) : withPageAlias(turn, parseDraft(response));
      if (draft?.answer) {
        const previewCoverage = coverageFor({ checklist, draft, sources: store.sources, locale });
        const preview = renderCitations(Array.isArray(draft.coverage) ? checklistAnswer(draft.answer, previewCoverage, checklist, locale) : draft.answer, store);
        const planRefs = new Set((turn.plan?.stops || []).flatMap(stop => [...(stop.sourceIds || []), ...(stop.admissionFacts?.sourceIds || [])]));
        const planUrls = new Set([...planRefs].map(id => store.sources.get(id)?.url).filter(Boolean));
        if (turn.plan?.stops.length && planUrls.size && !planInteractionOnly(message)
          && !preview.sources.some(source => planUrls.has(source.url)) && !recoveryUsed
          && !modelResponses.some(item => item.status === 'failed') && Date.now() < deadline - 5000) {
          warnings.push('answer_plan_citation_retry');
          citationRepair = '\nThe previous final answer did not cite the current itinerary evidence and cannot be shown. Rebuild a concise answer to the actual question from the attached currentPlan and evidence, keeping confirmed user choices and asking at most two missing details. Include the exact [[source-id]] next to each place-specific fact, using currentPlan.stops sourceIds or admissionFacts.sourceIds found in evidence. Do not attach a source to a claim it does not support, invent route times, or replace the practical answer with a price dump. No additional research is allowed.';
          if (!anthropic) turn.instructions += citationRepair;
          recoverFinal = true; recoveryUsed = true; continue;
        }
        if (recoverFinal) warnings.push('final_synthesis_recovered');
        return finish(turn, draft);
      }
      warnings.push('invalid_model_response', diagnostic.outputTextChars ? 'model_response_invalid_json' : 'model_response_no_text');
      if (!recoveryUsed && diagnostic.incompleteReason !== 'content_filter' && Date.now() < deadline - 3000) {
        recoverFinal = true; recoveryUsed = true; if (!anthropic) chosen = config.OPENAI_BAYBAY_FALLBACK_MODEL || 'gpt-4.1-mini'; continue;
      }
      break;
    }
    if (callFinal) { warnings.push('model_ignored_final_instruction'); break; }
    if (!anthropic) input.push(...response.output.filter(x => ['function_call', 'reasoning', 'message'].includes(x.type)));
    for (const call of calls) {
      let result;
      try { const args = JSON.parse(call.arguments); if (!obj(args)) throw new Error('Invalid arguments'); result = ++toolCount > maxTools ? { error: 'Tool budget reached.' } : await execute(call.name, args); }
      catch { result = { error: 'Invalid tool arguments.' }; }
      const compact = call.name === 'create_plan' && result?.stops ? { id: result.id, date: result.date, status: result.status, stops: result.stops.map(s => ({ ...s, notes: s.notes?.slice(0, 3) })), budget: modelPlan(result).budget, checks: result.checks, unknowns: result.unknowns, summary: result.summary, alternatives: result.alternatives?.map(p => ({ id: p.id, status: p.status, stops: p.stops?.map(s => ({ id: s.id, title: s.title, city: s.city })), summary: p.summary })) } : result;
      input.push({ type: 'function_call_output', call_id: call.call_id, output: JSON.stringify(compact) });
    }
    if (searchMode === 'site' && state.goal !== 'day-plan' && calls.some(call => call.name === 'search_site')) forceFinal = true;
  }
  return finish(turn, null);
}

module.exports = { createResearch, research };
