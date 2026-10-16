// BayBay engine v2: the fast path's single model call and the streamed drafts (H40 split of
// lib/baybayAgent.js). fastAnswer() sends the frozen system blocks, the v2 user turn and the
// turn's rules, streams the lead (and points) as `draft` events to a capable client (RC-21,
// API-BB-STREAM), retries once on Claude Sonnet 5.5 low (RC-18) and returns the resolved
// draft, or null when no usable answer came (finish() then uses a floor).
const { createAnthropicBaybay } = require('../anthropicBaybay');
const { safeModel } = require('../bayAreaSearchScope');
const { systemBlocks, FAST_FORMAT, parseFastDraft, fastProblems, RETRY_NOTES } = require('../baybayFastPath');
const { REFUSAL_RETRY_MODEL, modelFamily, aiRoute } = require('../aiModels');
const { boundedOperation } = require('../baybayTiming');
const { createJsonFieldStream, fastDraftField } = require('../anthropicStream');
const { createDraftWriter } = require('../baybayProgress');
const { budgetNotice } = require('../aiBudget');
const { failureReason } = require('../baybayQuality');
const { responseDiagnostic, cacheUsage } = require('./prompt');
const { v2UserContent } = require('./evidence');
const { resolveDraft } = require('./answer');

// Streamed drafts need at least this many usable records (the viewed page counts as
// one); below it the answer is likely a gap or a guard rewrite (RC-21 low evidence).
const DRAFT_MIN_RECORDS = 2;
// A near miss, a mismatched record or an unconfirmed food type: the answer corrects a premise
// or names a gap, the lead a guard most often rewrites, so no draft is streamed (RC-21).
const premiseMismatch = site => !!site?.nearMiss?.length || (site?.items || []).some(item => item.mismatch) || site?.foodEvidence?.status === 'needs-confirmation';
const leadDraftField = path => path.length === 1 && path[0] === 'lead' ? { field: 'lead' } : null;

// Drafts only for a client that reads them, with streaming on, and never beside a possible emergency.
function streamDrafts({ onDraft, config, floorTopic }) {
  return typeof onDraft === 'function' && String(config.BAYBAY_STREAM || '').trim().toLowerCase() !== 'off' && !floorTopic;
}

/** The v2 fast path: one model call (plus at most one retry) for the routed answer. */
async function fastAnswer(turn) {
  const { site, contextReferences, guard, checklist, locale, onDraft, rules, ai, config, fetchImpl, deadline, signal, stage, modelResponses, warnings, resumes } = turn;
  const routeName = turn.routing.route, user = v2UserContent(turn), rulesText = rules.join('\n\n');
  // Drafts (API-BB-STREAM, RC-21): only for a capable client, only on an ordinary
  // site answer (never a professional/safety topic, a multi-part checklist whose
  // answer is re-laid out, or thin evidence), only from the first call. Only then
  // is the call streamed; every other fast call is the ENGINE request unchanged.
  const named = (site.items || []).filter(item => item.named);
  const records = (site.items || []).filter(item => !item.mismatch).length + (contextReferences.length ? 1 : 0);
  const lowEvidence = records < DRAFT_MIN_RECORDS || premiseMismatch(site);
  // H03 (audit 10-13, BBENG-07): a professional answer streams its lead only (the guarded
  // points and the resource card come with the result); never beside a possible emergency.
  // The Batch-5 brief supersedes RC-21 here; its premise half still holds (a near miss, a
  // mismatched record or an unconfirmed food type sends no draft), while the record count
  // does not, since a professional answer rests on its guard's official resources.
  const leadOnly = routeName === 'baybay_professional' && !!guard;
  const drafting = streamDrafts(turn) && ((turn.routing.reason === 'site_answer' && routeName === 'baybay_fast' && !guard && !checklist.complex && !lowEvidence)
    || (leadOnly && !checklist.complex && !premiseMismatch(site)));
  if (drafting) turn.draftWriter = createDraftWriter({ emit: event => { const pending = onDraft(event); pending?.catch?.(() => {}); }, locale });
  const fields = drafting ? createJsonFieldStream({ match: leadOnly ? leadDraftField : fastDraftField, onText: (target, text) => turn.draftWriter.text(target.field, target.index, text), onDone: target => turn.draftWriter.done(target.field, target.index) }) : null;
  const payloadFor = (note, stream) => ({ system: systemBlocks(), input: [{ role: 'user', content: user }, ...(rulesText || note ? [{ role: 'system', content: [rulesText, note].filter(Boolean).join('\n\n') }] : [])],
    tools: [], text: { format: FAST_FORMAT }, max_output_tokens: 4000, ...(stream ? { stream: true } : {}) });
  const call = async (callConfig, note, phase, round, onText) => {
    const requested = aiRoute(routeName, callConfig).model, began = Date.now();
    const timeoutMs = Math.max(1000, Math.min(28000, deadline - Date.now() - 1000));
    const payload = payloadFor(note, !!onText);
    try {
      // An injected provider (tests) may report its text through the same hook.
      const response = await stage('finalMs', 'answer', () => ai ? boundedOperation(() => onText ? ai(payload, { onText }) : ai(payload), timeoutMs, 'AI request timed out')
        : createAnthropicBaybay({ config: callConfig, fetchImpl, route: routeName })(payload, { timeoutMs, signal, ...(onText ? { onText } : {}) }));
      turn.model = safeModel(response.model || requested);
      const diagnostic = { ...responseDiagnostic(response, round, phase, requested), elapsedMs: Math.max(0, Date.now() - began), route: routeName, ...cacheUsage(response) };
      modelResponses.push(diagnostic);
      if (diagnostic.status === 'incomplete') warnings.push(`model_response_incomplete_${diagnostic.incompleteReason}`);
      return response;
    } catch (error) {
      // (f) why it failed, in a fixed vocabulary (BBENG-06): kind, HTTP status, governance code.
      modelResponses.push({ ...responseDiagnostic({ status: 'failed' }, round, phase, requested), elapsedMs: Math.max(0, Date.now() - began), route: routeName, failure: failureReason(error) });
      throw error;
    }
  };
  let response, raw = null, problems = ['call_failed'], failure = null;
  try { response = await call(config, '', 'final', 1, fields ? text => fields.push(text) : null); raw = parseFastDraft(response); problems = fastProblems(raw, { named, page: contextReferences[0] }); }
  catch (error) { warnings.push('model_unavailable'); failure = failureReason(error); }
  // The draft ends with the first call: a retry's answer arrives only in `result`. The answer's points settle a
  // count the streamed lead was held at (API-BB-5, leadDraftText).
  finally { turn.draftWriter?.end({ complete: !!raw, points: raw?.points }); }
  // Today's AI quota or $ cap refused the call (BBENG-04, captain item a): not a provider
  // failure. No retry, and the reader gets the daily notice instead of an unexplained gap.
  if (failure?.kind === 'quota') {
    const unreadable = failure.code === 'AI_QUOTA_UNAVAILABLE';
    warnings.push(unreadable ? 'quota_unavailable' : 'ai_daily_limit');
    turn.notice ||= budgetNotice(unreadable ? 'ai_paused' : 'ai_daily_budget', locale, unreadable ? {} : resumes);
    return null;
  }
  // One retry on Claude Sonnet 5.5 low (RC-18). A Haiku refusal was already retried
  // on Sonnet inside the adapter; a Sonnet refusal is not asked again.
  const refusedOnSonnet = response?.incomplete_details?.reason === 'content_filter' && modelFamily(turn.model) === 'sonnet';
  if (problems.length && !refusedOnSonnet && Date.now() < deadline - 6000) {
    warnings.push(`fast_retry_${problems[0]}`);
    const retryConfig = routeName === 'baybay_professional' ? { ...config, BAYBAY_MODEL_PROFESSIONAL: REFUSAL_RETRY_MODEL, BAYBAY_EFFORT_PROFESSIONAL: 'low' }
      : { ...config, BAYBAY_MODEL_FAST: REFUSAL_RETRY_MODEL, BAYBAY_EFFORT_FAST: 'low', BAYBAY_THINKING_FAST: 'adaptive' };
    // An overloaded or rate-limited provider gets a short jittered pause before the retry.
    if (failure?.status === 429 || failure?.status >= 500) await new Promise(resolve => setTimeout(resolve, Math.min(600 + Math.floor(Math.random() * 600), Math.max(0, deadline - Date.now() - 7000))));
    // BBL-02: a first call the provider refused with an HTTP status (429, 529, 5xx) before
    // any draft leaves the reader with nothing; the retry answers the same request, so it
    // may stream its lead instead. A broken stream is retried without streaming, as before.
    const restream = drafting && problems[0] === 'call_failed' && failure?.kind === 'http' && !turn.draftWriter?.sent().events;
    if (restream) turn.draftWriter = createDraftWriter({ emit: event => { const pending = onDraft(event); pending?.catch?.(() => {}); }, locale });
    const retryFields = restream ? createJsonFieldStream({ match: leadOnly ? leadDraftField : fastDraftField, onText: (target, text) => turn.draftWriter.text(target.field, target.index, text), onDone: target => turn.draftWriter.done(target.field, target.index) }) : null;
    let retried = null;
    try {
      retried = parseFastDraft(await call(retryConfig, RETRY_NOTES[problems[0]] || '', 'recovery', 2, retryFields ? text => retryFields.push(text) : null));
      if (retried && (!raw || fastProblems(retried, { named, page: contextReferences[0] }).length < problems.length)) { raw = retried; warnings.push('final_synthesis_recovered'); }
    } catch { warnings.push('model_unavailable'); }
    finally { if (restream) turn.draftWriter.end({ complete: !!retried && raw === retried, points: retried?.points }); }
  }
  if (!raw) { warnings.push('invalid_model_response'); return null; }
  return resolveDraft(turn, raw);
}

module.exports = { DRAFT_MIN_RECORDS, premiseMismatch, leadDraftField, streamDrafts, fastAnswer };
