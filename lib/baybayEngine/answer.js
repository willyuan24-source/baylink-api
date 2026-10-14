// BayBay engine: the answer the reader gets (H40 split of lib/baybayAgent.js). finish() turns a
// model draft (or none) into the response: the final plan, the floors and guards that may
// replace the text (emergency floor, professional template, false negatives, school
// authority, admission conflicts, plan assurances, scope), citations, the final cards, the
// v2 lead/points shape and the signed task token. resolveDraft() maps a v2 draft's refs to
// evidence ids and applies the lead, area and newcomer repairs.
const { assertActive, aiRefusal } = require('../aiGovernance');
const { budgetNotice } = require('../aiBudget');
const { emergencyFloor } = require('../safetyRouting');
const { coverageFor, checklistAnswer, checklistFallback, admissionConflict, admissionCorrection, planInteractionOnly, sourcedPlanSummary } = require('../baybayAnswerQuality');
const { evidenceScopes, repairBenefitCoverage } = require('../baybayBenefitScope');
const { guardCommunityAbsence } = require('../baybayCommunityAbsence');
const { eventStatusLabel } = require('../eventStatus');
const { readerRange } = require('../baybayEvidence');
const { isSchoolRequest } = require('../guideConversation');
const { assertSearchScope, searchScope, mentionedCities } = require('../bayAreaSearchScope');
const { canonical } = require('../baybayTools');
const { assembleAnswer, leadUnits, readerDraft, readerProse } = require('../baybayFastPath');
const { draftCorrected } = require('../baybayProgress');
const { encodeTaskToken } = require('../baybayState');
const { leadConsistency, dropOffArea, ensureNewcomerSsn } = require('../baybayQuality');
const { str, copy, localeIndex } = require('./util');
const { fallbackAnswer, unavailableHelp, healthWorry, UNAVAILABLE_HELP, professionalFloor } = require('./fallback');
const { quickRef, asQuickCards, citeRefs, refSource, entityOf, candidateOf } = require('./evidence');

function renderCitations(answer, store) {
  const used = [];
  let result = str(answer, 12000).replace(/\[\d+\]/g, '').replace(/\[([^\]]{1,200})\]\(https?:[^)]{0,2000}\)/g, '$1').replace(/https?:\/\/[^\s<>]+/g, '');
  result = result.replace(/\[\[([^\]]{1,100})\]\]/g, (_, cited) => {
    // [[page]] is the fixed citation for the page the user is viewing.
    const id = store.sources.has(cited) ? cited : store.aliases?.get(cited);
    const source = id && store.sources.get(id); if (!source) return '';
    let at = used.findIndex(s => s.id === id); if (at < 0) { at = used.length; used.push(source); }
    return `[${at + 1}]`;
  });
  return { answer: result, sources: used.map(({ title, url }) => ({ title, url })) };
}

// v2: render lead, points and gap with one shared citation numbering, so the
// parts read exactly like the legacy answer they were assembled into.
const PART_BREAK = '\n\u241E\n';
function renderCitationParts(parts, store) {
  const rendered = renderCitations(parts.join(PART_BREAK), store);
  const out = rendered.answer.split(PART_BREAK.trim()).map(part => part.trim());
  return out.length === parts.length ? { parts: out, sources: rendered.sources } : null;
}

// Guests get site answers; a sentence selling sign-up for live web lookup is
// removed from the answer text (the interface shows access notices itself).
// Sentences about logging in to an official service account are kept.
// Linear time (CODE-API-01 sweep): each clause is matched once, then tested for a
// sign-in word within 40 characters of a web word. One pattern that scanned a whole
// clause before looking for the pair backtracked quadratically (6,000 characters of
// 登录 took seconds).
const PITCH_CHAR = String.raw`(?:(?!\.\s)[^。！？!?\n；;])`;
const PITCH_SIGN_IN = String.raw`(?:登录|登錄|登入|注册|註冊|\bsign(?:ing)?[- ]in\b|\blog(?:ging)?[- ]in\b|\bcreat(?:e|ing) an account\b)`;
const PITCH_WEB = String.raw`(?:联网|聯網|live web|web lookup|web search)`;
const PITCH_SENTENCE = new RegExp(String.raw`${PITCH_CHAR}+(?:[。！？!?；;]|\.(?=\s|$))?`, 'g');
const LOGIN_PITCH = new RegExp(String.raw`${PITCH_SIGN_IN}${PITCH_CHAR}{0,40}${PITCH_WEB}|${PITCH_WEB}${PITCH_CHAR}{0,40}${PITCH_SIGN_IN}`, 'i');
function stripLoginPitch(answer) {
  const stripped = String(answer).replace(PITCH_SENTENCE, clause => LOGIN_PITCH.test(clause) ? '' : clause)
    .replace(/(?<![ \t])[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  return stripped || answer;
}

/** The response for this turn from a model draft, or from none (clarification, floor, fallback). */
async function finish(turn, draft) {
  const { signal, store, state, resolved, explicitCandidateIds, edit, v2, locale, resumes, warnings, guard, floorTopic, checklist, message, pageSourceId, scopeGuides, contextReferences, site,
    today, normalized, booking, now, webAccess, entityCards, localMatches, recommendationReferences, nearbyAsk, resourceSourceIds, taskSecret, samePlanScope, previous, pageContext, steps,
    modelResponses, started, timing, searchMode, capabilities } = turn;
  assertActive(signal);
  const finalIds = draft?.candidateIds?.filter(id => id !== 'origin' && store.candidates.has(id) && !state.excludedCandidateIds?.includes(id));
  if (state.goal === 'day-plan' && !resolved.clarification && !turn.plan) await turn.execute('create_plan', { candidateIds: finalIds });
  // The final selection may refine a researched draft. Run it through the
  // same user-selection and feasibility guards as create_plan, then use that
  // one result for the card, handoff and signed published plan.
  else if (turn.plan) turn.plan = turn.makePlan(finalIds?.length ? finalIds : turn.plan.stops.map(stop => stop.entityId || stop.id));
  if (turn.plan && !explicitCandidateIds.length && !(edit?.named && edit.only)) state.selectedCandidateIds = turn.plan.stops.map(stop => stop.entityId || stop.id);
  let degraded = !draft && !resolved.clarification;
  // v2: a provider call refused by today's quota or $ cap (agent path too) explains itself.
  if (v2 && !draft && !turn.notice && aiRefusal()) { turn.notice = budgetNotice('ai_daily_budget', locale, resumes); warnings.push('ai_daily_limit'); }
  // Without a usable model answer, a professional topic falls back to its
  // curated template plus the cited official contacts and pillar guide.
  const floor = floorTopic ? emergencyFloor(floorTopic, locale) : null;
  const fallback = () => floor?.answer || (guard && professionalFloor(turn)) || (!turn.plan && checklistFallback({ checklist, sources: store.sources, locale })) || fallbackAnswer({ locale, state, store, plan: turn.plan, webStatus: turn.webStatus, message, pageSourceId });
  let answerCoverage = coverageFor({ checklist, draft, sources: store.sources, locale, fallback: !draft || !!resolved.clarification });
  const scopeRepair = repairBenefitCoverage(answerCoverage, evidenceScopes(scopeGuides, store), locale, store.sources);
  if (scopeRepair.changed) { answerCoverage = scopeRepair.coverage; degraded = true; warnings.push('answer_benefit_scope_corrected'); }
  // Without a model answer, a possible emergency gets the floor even over a clarifying question.
  let answer = floor && !draft?.answer ? floor.answer
    : resolved.clarification || (draft?.answer ? Array.isArray(draft.coverage) ? checklistAnswer(draft.answer, answerCoverage, checklist, locale) : draft.answer : fallback());
  // search_site only searches guides and planner candidates; it never
  // establishes absence from the public community-post/outing collections.
  const communityAbsence = guardCommunityAbsence({ answer, locale });
  if (communityAbsence.changed) { answer = communityAbsence.answer; warnings.push(communityAbsence.warning); degraded = true; }
  // v2 also catches the Traditional wording (站內沒有…), so a zh-Hant answer gets its template.
  if ((v2 ? /站[内內](?:没有|沒有|未|暂无|暫無).{0,15}(?:收录|收錄|找到|活动|活動|记录|記錄)|no (?:site|published|matching) (?:record|event)|not (?:listed|recorded)/i
    : /站内(?:没有|未|暂无|暫無).{0,15}(?:收录|收錄|找到|活动|活動|记录|記錄)|no (?:site|published|matching) (?:record|event)|not (?:listed|recorded)/i).test(answer) && (contextReferences.length || site.nearMiss?.length)) {
    const ref = contextReferences[0] || site.nearMiss[0], source = [...store.sources.values()].find(row => row.title === ref.title);
    // API-STATUS: a sold-out, postponed or cancelled record is named with its status; a postponed or cancelled one gets
    // no date and never reads as "ended" once its original day has passed.
    const status = ref.eventStatus || (['sold_out', 'postponed', 'cancelled'].includes(ref.reason) ? ref.reason : null);
    const undated = status === 'postponed' || status === 'cancelled';
    const ended = !undated && (ref.temporalStatus === 'past' || ref.reason === 'past' || (ref.endDate && ref.endDate < today));
    const label = !ended && status ? eventStatusLabel(status, locale) : '';
    const dates = v2 && !undated ? readerRange(ref.startDate, ref.endDate, locale) : '';
    if (v2) answer = [`站内已收录「${ref.title}」${dates ? `（${dates}）` : ''}${ended ? '，这一场已经结束' : label ? `，${label}` : ''}。${ended || label ? '' : '这不代表所问日期或所有条件都匹配；'}请以项目页的日期、场次、费用和资格为准。`,
      `站內已收錄「${ref.title}」${dates ? `（${dates}）` : ''}${ended ? '，這一場已經結束' : label ? `，${label}` : ''}。${ended || label ? '' : '這不代表所問日期或所有條件都符合；'}請以項目頁的日期、場次、費用和資格為準。`,
      `The site has a record for ${ref.title}${dates ? ` (${dates})` : ''}${ended ? '; it has already ended' : label ? `; ${label}` : ''}.${ended || label ? '' : ' That does not establish a match for the requested date or every requirement;'} Check the published dates, sessions, prices and eligibility.`][localeIndex(locale)] + (source ? ` [[${source.id}]]` : '');
    else answer = copy(locale, `站内已收录「${ref.title}」${label ? `（${label}）` : ''}。${ref.startDate && !undated ? `已发布日期为 ${ref.startDate}${ref.endDate && ref.endDate !== ref.startDate ? ' 至 ' + ref.endDate : ''}。` : ''}这不代表所问日期或所有条件都匹配；请按项目页的资格、费用及场次核对。`, `The site has a record for ${ref.title}${label ? ` (${label})` : ''}.${ref.startDate && !undated ? ` Published dates: ${ref.startDate}${ref.endDate && ref.endDate !== ref.startDate ? ' through ' + ref.endDate : ''}.` : ''} This does not establish a match for the requested date or every requirement; check the published conditions and occurrence dates.`) + (source ? ` [[${source.id}]]` : '');
    warnings.push('false_negative_corrected'); degraded = true;
  }
  // Retain the legacy school guard when public enrollment moves to v2.
  // Editorial regions are not school-district authorities.
  if (isSchoolRequest(message) && /\b(?:Peninsula|East\s+Bay|South\s+Bay|North\s+Bay|Bay\s+Area)\s+School\s+District\b/i.test(answer)) {
    const schoolGuide = [...store.sources.values()].find(source => source.kind === 'guide' && /school-(?:district|enrollment)/.test(source.url));
    answer = copy(locale, '城市不等于学区。请按目标年级和学年，使用对应学区官方招生及地址查询入口核对；本次无法确认具体学校分配。', 'A city is not a school district. Check the official district enrollment and address locator for the requested grade and academic year; this answer cannot confirm an assigned school.') + (schoolGuide ? ` [[${schoolGuide.id}]]` : '');
    warnings.push('answer_school_authority_rejected'); degraded = true;
  }
  if (admissionConflict(answer, turn.plan)) { answer = admissionCorrection(turn.plan, locale); warnings.push('answer_admission_conflict'); degraded = true; }
  if (turn.plan?.status !== 'ready' && turn.plan && /(?:保证|保證|确保|確保|肯定|guarantee).{0,35}(?:回来|回來|到家|赶上|趕上|到达|到達|return|arrive)|(?:全程总价|全程總價|总共只需|總共只需|all[- ]in total|entire trip costs)\s*[:：]?\s*\$?\d|(?:完全符合|肯定不会超|肯定不會超|guaranteed within).{0,8}(?:预算|預算|budget)/i.test(answer)) { answer = fallback(); warnings.push('unsupported_plan_assurance'); degraded = true; }
  const allowedAnswerCities = ['information', 'newcomer'].includes(state.goal) ? mentionedCities(normalized).filter(city => !state.excludedCities?.includes(city)) : [];
  try { assertSearchScope({ answer }, { query: normalized, locale, allowedAnswerCities, ...(booking ? { foreignMentionsAllowed: true } : {}) }, searchScope({ query: normalized, ...(state.city ? { city: state.city } : {}), ...(state.date ? { date: state.date } : {}) }, now)); } catch { answer = fallback(); warnings.push('answer_scope_rejected'); degraded = true; }
  if (degraded && (!scopeRepair.changed || warnings.includes('answer_admission_conflict') || warnings.includes('answer_scope_rejected') || warnings.includes('unsupported_plan_assurance'))) answerCoverage = coverageFor({ checklist, sources: store.sources, locale, fallback: true });
  // The resource card's phone numbers (and the primary official entry)
  // always reach the reader, even when the model omitted them.
  if (guard && !resolved.clarification) {
    const digits = value => String(value).replace(/\D/g, '');
    const missing = guard.resources.map((row, index) => ({ row, id: resourceSourceIds[index], index })).filter(({ row, id, index }) => id
      && (row.phone ? !digits(answer).includes(digits(row.phone).slice(-10)) : index === 0 && !answer.includes(`[[${id}]]`)));
    if (missing.length) answer += `\n\n${['官方联系：', '官方聯絡：', 'Official contact: '][localeIndex(locale)]}${missing.map(({ row, id }) => `${row.title}${row.phone ? ` ${row.phone}` : ''} [[${id}]]`).join(locale === 'en' ? '; ' : '；')}`;
  }
  if (webAccess?.allowed === false) {
    const pitchFree = stripLoginPitch(answer);
    if (pitchFree !== answer) { answer = pitchFree; warnings.push('guest_login_pitch_removed'); }
  }
  // The floor stays exactly as written: no contact line, excerpt or card after it,
  // and no listing or page card beside it (a relevance floor for emergencies).
  const floorShown = !!floor && answer.startsWith(floor.answer);
  if (floorShown) { answer = floor.answer; degraded = true; warnings.push('emergency_floor'); }
  const unavailable = !floorShown && answer.startsWith(unavailableHelp(locale));
  // H72 (audit 10-13): without a model answer, a health worry or a professional topic
  // shows no event, offer or opening card (a Medi-Cal question got a play day and an iPad
  // class); the page being read stays.
  const noEntityCards = !draft?.answer && !resolved.clarification && (unavailable || !!guard || healthWorry(message));
  let rendered = renderCitations(answer, store), citationsRepaired = false;
  const planSourceIds = new Set((turn.plan?.stops || []).flatMap(stop => [...(stop.sourceIds || []), ...(stop.admissionFacts?.sourceIds || [])]));
  const planSourceUrls = new Set([...planSourceIds].map(id => store.sources.get(id)?.url).filter(Boolean));
  if (turn.plan?.stops.length && !resolved.clarification && !planInteractionOnly(message) && !rendered.sources.some(source => planSourceUrls.has(source.url))) {
    // Do not attach evidence to unsupported model prose. The replacement
    // contains only the card's sourced records, with explicit limitations.
    const replacement = sourcedPlanSummary(turn.plan, store.sources, locale);
    rendered = renderCitations(replacement.answer, store); citationsRepaired = true;
    answerCoverage = coverageFor({ checklist, sources: store.sources, locale, draft: { coverage: checklist.items.map(item => ({ id: item.id, status: 'unknown', summary: replacement.sections[item.id] || '', sourceIds: item.id === 'transport' ? [] : replacement.sourceIds.slice(0, 4) })) } });
    degraded = true;
    warnings.push(rendered.sources.length ? 'answer_plan_citations_repaired' : 'answer_plan_sources_missing');
  }
  const visibleUrls = new Set(rendered.sources.map(s => s.url));
  // Retrieval previews are not the final recommendation. Once synthesis
  // has chosen records or cited evidence, drop unrelated initial cards.
  // Keep fallback/clarification records and all page context separately.
  const sourceKey = value => { if (typeof value !== 'string' || !value) return null; try { const url = new URL(value, 'https://www.baylink.us'); url.hash = ''; return canonical(url.href); } catch { return null; } };
  const citedKeys = new Set(rendered.sources.map(source => sourceKey(source.url)).filter(Boolean));
  const finalSelectedIds = new Set(turn.plan ? turn.plan.stops.map(stop => stop.entityId || stop.id) : finalIds || []);
  const candidates = [...store.candidates.values()].filter(candidate => !candidate.isOrigin);
  const candidateCardUrl = candidate => candidate.kind === 'event' ? `/events/${candidate.id}` : candidate.guideSlug ? `/guides/${candidate.guideSlug}` : '/explore';
  // v2 (no plan): the cards are the records the model chose, best first, then the
  // records it cited; offers and openings included; up to five.
  const v2Cards = () => {
    const cards = new Map(entityCards); for (const ref of contextReferences) if (ref.kind !== 'guide') cards.set(`${ref.kind}:${ref.id}`, ref);
    const chosen = (draft.entities || []).map(entity => cards.get(`${entity.kind}:${entity.id}`)).filter(Boolean);
    const cited = [...cards.values()].filter(card => citedKeys.has(sourceKey(card.url)));
    return [...new Map([...chosen, ...cited].map(card => [`${card.kind}:${card.id}`, card])).values()].slice(0, 5);
  };
  const finalMatches = floorShown ? [] : noEntityCards ? localMatches.filter(ref => contextReferences.some(page => page.kind === ref.kind && page.id === ref.id)) : v2 && draft?.answer && !turn.plan && !resolved.clarification ? v2Cards() : draft?.answer && !resolved.clarification ? localMatches.filter(ref => {
    const candidate = candidates.find(row => row.kind === ref.kind && row.id === ref.id);
    if (candidate && finalSelectedIds.has(candidate.id)) return true;
    // A plan's final stop list is authoritative; a cited rejected stop
    // must not reappear as a recommendation beside that plan.
    if (turn.plan && candidate) return false;
    const key = sourceKey(ref.url);
    if (key && citedKeys.has(key) && (!candidate || candidates.filter(row => sourceKey(candidateCardUrl(row)) === key).length === 1)) return true;
    // Several events can share an institution page or guide. A shared
    // citation cannot establish which event the answer recommends.
    return candidate && candidate.sourceIds?.some(id => {
      const cited = sourceKey(store.sources.get(id)?.url);
      return cited && citedKeys.has(cited) && candidates.filter(row => row.sourceIds?.includes(id)).length === 1;
    });
  }) : localMatches;
  const finalReferenceKeys = new Set(finalMatches.map(ref => `${ref.kind}:${ref.id}`));
  const siteGuides = [...new Map((site.guides || []).map(g => [g.url, { title: g.title, url: g.url, slug: g.slug }])).values()];
  const citedGuides = siteGuides.filter(g => visibleUrls.has(g.url));
  const planRefs = planSourceIds;
  const coverageRefs = new Set(answerCoverage.items.flatMap(item => item.sourceIds));
  // Coverage exposes at most 8 × 4 source IDs. Put them first so every ID
  // has a matching public evidence record even when discovery found more.
  const evidencePriority = source => coverageRefs.has(source.id) ? 0 : visibleUrls.has(source.url) || planRefs.has(source.id) ? 1 : 2;
  const evidence = [...store.sources.values()].sort((a, b) => evidencePriority(a) - evidencePriority(b)).slice(0, 40).map(({ id, title, url, kind, checkedAt, verification, needsReview }) => ({ id, title, url, kind: kind || 'web', checkedAt, verification, needsReview }));
  const finalCards = asQuickCards(finalMatches);
  // v2 answer fields (WEB-BB-UI contract): lead, points[{text, cardIds}], pageEntity.
  // Only when the reader's answer is still the model's own (a guard that rewrote it
  // leaves the legacy answer alone); a guard's appended contact line becomes a point.
  let shape = null;
  if (v2 && draft?.points && !resolved.clarification && !citationsRepaired && !checklist.complex) {
    const base = assembleAnswer(draft);
    if (answer.startsWith(base)) {
      const extra = answer.slice(base.length).trim();
      const gapShown = draft.gap && !draft.points.some(point => point.text.includes(draft.gap)) && !draft.lead.includes(draft.gap) ? draft.gap : '';
      const parts = renderCitationParts([draft.lead, ...draft.points.map(point => point.text), gapShown, extra], store);
      // cardIds are keys of the returned localMatches: a place becomes its guide card
      // (as asQuickCards shows it), and a record without a card is left out.
      const knownCards = new Map([...(entityCards?.values() || []), ...contextReferences, ...finalMatches].map(ref => [`${ref.kind}:${ref.id}`, ref]));
      const shownKeys = new Set(finalCards.map(ref => `${ref.kind}:${ref.id}`));
      const cardKeys = ids => [...new Set(ids.map(key => { const card = knownCards.get(key); const quick = card && quickRef(card); return quick ? `${quick.kind}:${quick.id}` : null; })
        .filter(key => key && shownKeys.has(key)))];
      if (parts && parts.sources.length === rendered.sources.length) shape = { lead: parts.parts[0],
        points: [...draft.points.map((point, index) => ({ text: parts.parts[index + 1], cardIds: cardKeys(point.cardIds) })), ...(extra ? [{ text: parts.parts.at(-1), cardIds: [] }] : [])].filter(point => point.text),
        ...(parts.parts[draft.points.length + 1] ? { gap: parts.parts[draft.points.length + 1] } : {}) };
      // The lead limit (zh 40 characters, en 20 words) is a prompt rule; record a long one.
      if (shape && leadUnits(shape.lead, locale) > (locale === 'en' ? 20 : 40)) warnings.push('answer_lead_long');
    }
  }
  // Streamed drafts: `corrected` tells the client that the result does not continue
  // the draft it showed (a guard rewrite, a retry or a template), RC-21.
  const drafted = turn.draftWriter?.sent();
  const corrected = drafted?.events ? draftCorrected(drafted, shape || {}) : undefined;
  if (corrected) warnings.push('draft_corrected');
  const assistantSessionToken = encodeTaskToken({ state, lastPlan: turn.plan ? { candidateIds: [...store.candidates.keys()].slice(0, 30), selectedIds: turn.plan.stops.map(s => s.entityId || s.id), selectedRefs: turn.plan.stops.map(s => store.candidates.get(s.entityId || s.id)).filter(c => c?.origin === 'web').map(c => ({ id: c.id, title: c.title, city: c.city, sourceUrl: store.sources.get(c.sourceIds?.[0])?.url, previousKind: c.kind })), title: turn.plan.title, date: state.date } : samePlanScope ? previous?.lastPlan : undefined }, { secret: taskSecret, now });
  if (!assistantSessionToken) warnings.push('task_memory_unavailable');
  return { ok: true, ...rendered, responseMode: 'assistant', degraded, taskState: state, ...(turn.plan ? { assistantPlan: turn.plan } : {}), assistantSessionToken,
    evidence, answerCoverage, suggestedGuides: floorShown ? [] : [...(guard?.guides || []), ...citedGuides].filter((guide, index, rows) => rows.findIndex(row => row.url === guide.url) === index).slice(0, 4), suggestedActions: floorShown ? [] : communityAbsence.suggestedActions, matchingPosts: [], interactiveCards: [], followups: floorShown ? [] : draft?.followups || [],
    ...(guard ? { safetyRoute: 'professional', safetyTopic: guard.topic, safety: guard } : {}),
    ...(floorShown ? { fallbackHelp: { actions: floor.actions }, emergencyFloor: floor.topic } : unavailable ? { fallbackHelp: UNAVAILABLE_HELP } : {}),
    contextReferences: floorShown ? [] : contextReferences, contextUsed: pageContext?.contextUsed || { references: [], notices: [] },
    // API-BB-CUTOVER: pause / daily-limit / reduced-mode banner {kind, text, resumesAt?}.
    ...(turn.notice ? { notice: turn.notice } : {}),
    ...(v2 ? { engine: 'v2', route: turn.routing ? { path: turn.routing.path, reason: turn.routing.reason } : { path: resolved.clarification ? 'clarification' : 'deterministic' },
      ...(shape || {}), pageEntity: contextReferences[0] && !floorShown ? { kind: contextReferences[0].kind, id: contextReferences[0].id, title: contextReferences[0].title } : null,
      ...(corrected !== undefined ? { corrected } : {}) } : {}),
    localMatches: nearbyAsk ? [] : finalCards,
    nextSteps: recommendationReferences.filter(ref => finalReferenceKeys.has(`${ref.kind}:${ref.id}`) && ref.kind === 'event' && !['past', 'inactive'].includes(ref.temporalStatus) && !ref.eventStatus).map(ref => ({ kind: 'plan', label: copy(locale, '带着这个活动安排一天', 'Plan around this event'), references: [{ kind: 'event', id: ref.id, ...(ref.date ? { date: ref.date } : {}) }] })).slice(0, 1),
    research: { steps, model: turn.model, warnings: [...new Set(warnings)], modelResponses, ...(drafted?.events ? { drafts: { events: drafted.events, chars: drafted.chars } } : {}), usage: { inputTokens: modelResponses.reduce((sum, row) => sum + (row.inputTokens || 0), 0), outputTokens: modelResponses.reduce((sum, row) => sum + (row.outputTokens || 0), 0) }, elapsedMs: Date.now() - started, timings: timing.snapshot() },
    retrieval: { requestedMode: searchMode, scope: turn.webStatus === 'completed' ? 'site+web' : evidence.length ? 'site' : 'none', webStatus: turn.webStatus, requestedDate: state.date, city: state.city, area: 'San Francisco Bay Area, California, United States', checkedAt: turn.webCheckedAt, cached: turn.cached, model: turn.model, configuredModel: capabilities().configuredModel, sourceCount: rendered.sources.length },
  };
}

/** A v2 structured answer with refs resolved to evidence ids and reader prose; `answer` is the legacy text. */
function resolveDraft(turn, raw) {
  const { warnings, comparingInformation, state, refRegion, message, locale } = turn;
  if (!raw) return null;
  // The lead must not contradict its points (a count, or a choice the points call undecidable).
  const consistent = leadConsistency(raw, { locale });
  for (const repair of consistent.repairs) warnings.push(`answer_${repair}_repaired`);
  // Padding with records from another region (an SF museum for an Oakland weekend) is dropped.
  const area = comparingInformation ? { draft: consistent.draft, dropped: 0 } : dropOffArea(consistent.draft, { region: state.region, areaOf: ref => refRegion.get(ref) || null });
  if (area.dropped) warnings.push('answer_off_area_dropped');
  // B8: a newcomer setup answer always names the SSN step (appended last when missing).
  const ssn = ensureNewcomerSsn(area.draft, { message, state, locale });
  if (ssn.added) warnings.push('answer_newcomer_ssn_added');
  const draft = readerDraft(ssn.draft, locale);
  const resolved = { lead: citeRefs(turn, draft.lead), gap: citeRefs(turn, draft.gap), followups: draft.followups.map(value => readerProse(value, locale)),
    points: draft.points.map(point => ({ text: citeRefs(turn, point.text), cardIds: [...new Set(point.cardIds.map(ref => entityOf(turn, ref)).filter(Boolean).map(entity => `${entity.kind}:${entity.id}`))] })),
    coverage: draft.coverage.map(item => item && typeof item === 'object' ? { ...item, summary: citeRefs(turn, item.summary), sourceIds: (Array.isArray(item.sourceIds) ? item.sourceIds : []).map(ref => refSource(turn, ref) || ref) } : item),
    entities: [...new Map([...draft.candidateIds, ...draft.points.flatMap(point => point.cardIds)].map(ref => entityOf(turn, ref)).filter(Boolean).map(entity => [`${entity.kind}:${entity.id}`, entity])).values()],
    candidateIds: [...new Set(draft.candidateIds.map(ref => candidateOf(turn, ref)).filter(Boolean))] };
  return { ...resolved, answer: assembleAnswer(resolved) };
}

module.exports = { renderCitations, renderCitationParts, stripLoginPitch, finish, resolveDraft };
