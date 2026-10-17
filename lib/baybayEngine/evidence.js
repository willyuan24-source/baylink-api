// BayBay engine: the evidence of one turn (H40 split of lib/baybayAgent.js).
// gatherEvidence() runs site retrieval (v2: buildFastEvidence with offers and openings;
// v1: buildSiteEvidence), fills the evidence store, registers the viewed page and the v2
// refs (e1…, r1…, page), builds the preview cards and sends them to onQuickCard, and sets
// the plan scope carried from the previous turn. The other functions are the model's view
// of that evidence (what each request carries) and the v2 ref resolution.
const { buildSiteEvidence, buildFastEvidence, readerRange, snippet } = require('../baybayEvidence');
const { createEvidenceStore, canonical } = require('../baybayTools');
const { matchesFoodEvidence } = require('../foodEvidence');
const { cardInLocale } = require('../baybayQuality');
const { eventStatusLabel, eventStatusNote } = require('../eventStatus');
const { withAdmissionFacts } = require('../baybayFacts');
const { evidenceScopes } = require('../baybayBenefitScope');
const { fastUserContent, recentTurns } = require('../baybayFastPath');
const { str, arr, localeIndex } = require('./util');
const { healthWorry } = require('./fallback');

/** The days a task asks about, from today on: its date, or its date range (at most 14 days). */
function askedDaysOf(state, today) {
  const range = state?.date ? { start: state.date, end: state.date } : state?.dateRange;
  if (!range || !/^\d{4}-\d{2}-\d{2}$/.test(range.start || '') || !/^\d{4}-\d{2}-\d{2}$/.test(range.end || '')) return [];
  const days = [];
  for (let day = new Date(`${range.start > today ? range.start : today}T12:00:00Z`); days.length < 14; day.setUTCDate(day.getUTCDate() + 1)) {
    const value = day.toISOString().slice(0, 10);
    if (value > range.end) break;
    days.push(value);
  }
  return days;
}

// Match the plan card's pending-cost display in the model's input. The engine
// retains its arithmetic subtotal, but an unpriced trip has no displayed $0 fee.
function modelPlan(plan) {
  if (!plan) return plan;
  const pending = plan.budget?.knownTotalUsd === 0 && (plan.budget.unknownItems?.length || !plan.stops?.length || plan.stops.some(stop => stop.admissionUsd == null));
  return { ...plan, budget: pending ? { ...plan.budget, knownTotalUsd: null, knownPerPersonUsd: null, calculationStatus: 'pending' } : plan.budget,
    ...(plan.alternatives ? { alternatives: plan.alternatives.map(modelPlan) } : {}) };
}

/**
 * API-BB-6 (live 10-15, L07): the one-call site day plan's view of the calculated plan. The model writes the answer
 * around it, so it gets each stop once with the evidence refs to cite (e1…, or a store source id when the stop's record
 * is not an evidence item), the stop's admission facts without their source plumbing, what is still unknown once (the
 * plan's checks repeat its unknowns), failed checks, and alternatives by stop title. modelPlan() sent ≈14,000 characters
 * for a three-stop plan (alternatives in full, admission facts twice, every check); this sends ≈2,500.
 */
function planView(turn, plan) {
  if (!plan) return null;
  const { itemRefs, store } = turn;
  const refOf = new Map([...itemRefs].map(([ref, row]) => [row.sourceId, ref]));
  const planSources = new Map();
  const cite = id => refOf.get(id) || (store.sources.has(id) ? (planSources.set(id, store.sources.get(id)), id) : null);
  const admission = facts => !facts ? undefined : { status: facts.status, ...(facts.knownPerPersonUsd != null ? { perPersonUsd: facts.knownPerPersonUsd } : {}),
    ...(facts.knownTotalUsd != null ? { totalUsd: facts.knownTotalUsd } : {}), ...(facts.breakdown?.length ? { breakdown: facts.breakdown.slice(0, 4) } : {}),
    ...(facts.applicability?.dateStatus && facts.applicability.dateStatus !== 'confirmed' ? { dateStatus: facts.applicability.dateStatus } : {}) };
  const minutes = stop => stop.durationMinutes || stop.suggestedDurationMinutes;
  // A stop's unconfirmed checks (opening_hours, reservation, travel_time, …) go on the stop by code; the plan's
  // unknowns repeat their messages, so open keeps only the rest (origin, start time, what the subtotal leaves out).
  const stopChecks = (plan.checks || []).filter(check => check.stopId && check.status !== 'pass');
  const stopKeyed = new Set([...stopChecks.map(check => check.message), ...(plan.stops || []).flatMap(stop => stop.notes || [])]);
  // API-BB-8 (live 10-17, L07): a stop without a timed session carries its recorded opening window that day (the Ferry
  // Plaza market's 08:00–14:00), so its point can give it.
  const hours = stop => (stop.openingWindows || []).filter(w => /^\d{2}:\d{2}$/.test(w?.open || '') && /^\d{2}:\d{2}$/.test(w?.close || '')).slice(0, 3).map(w => `${w.open}–${w.close}`).join(', ');
  const stops = (plan.stops || []).map(stop => ({ id: stop.entityId || stop.id, kind: stop.kind, title: str(stop.title, 200), ...(stop.city ? { city: stop.city } : {}),
    ...(stop.venue ? { venue: str(stop.venue, 160) } : {}), ...(stop.startTime ? { time: stop.endTime ? `${stop.startTime}–${stop.endTime}` : stop.startTime } : hours(stop) ? { hours: hours(stop) } : {}), timeStatus: stop.timeStatus,
    ...(minutes(stop) ? { minutes: minutes(stop) } : {}), ...(admission(stop.admissionFacts) ? { admission: admission(stop.admissionFacts) } : stop.admissionUsd != null ? { admission: { perPersonUsd: stop.admissionUsd } } : {}),
    ...(stop.notes?.length ? { notes: stop.notes.slice(0, 2).map(note => str(note, 160)) } : {}),
    ...(stopChecks.some(check => check.stopId === stop.id) ? { unconfirmed: [...new Set(stopChecks.filter(check => check.stopId === stop.id).map(check => check.code))] } : {}),
    refs: [...new Set([...(stop.sourceIds || []), ...(stop.admissionFacts?.sourceIds || [])].map(cite).filter(Boolean))].slice(0, 3) }));
  const budget = modelPlan(plan).budget;
  return { title: plan.title, date: plan.date, status: plan.status, summary: plan.summary, stops,
    ...(budget ? { budget: { knownTotalUsd: budget.knownTotalUsd ?? null, knownPerPersonUsd: budget.knownPerPersonUsd ?? null, ...(budget.calculationStatus ? { calculationStatus: budget.calculationStatus } : {}), ...(budget.scope ? { scope: budget.scope } : {}) } } : {}),
    open: [...new Set(plan.unknowns || [])].filter(value => !stopKeyed.has(value)).slice(0, 6).map(value => str(value, 200)),
    ...((plan.checks || []).some(check => check.status === 'fail') ? { failed: plan.checks.filter(check => check.status === 'fail').slice(0, 6).map(check => str(check.message, 200)) } : {}),
    ...(plan.travelLegs?.length ? { travelLegs: plan.travelLegs.slice(0, 6) } : {}),
    ...(plan.alternatives?.length ? { alternatives: plan.alternatives.slice(0, 2).map(other => ({ status: other.status, stops: (other.stops || []).map(stop => str(stop.title, 120)) })) } : {}),
    ...(planSources.size ? { sources: [...planSources.values()].map(source => ({ id: source.id, title: str(source.title, 160), url: source.url })) } : {}) };
}

/** Compact a read page using whole relevant paragraphs, not a prefix that can
 * cut off "not included" or other eligibility conditions mid-sentence. */
function sourceContextText(value, query, limit = 1800) {
  const content = typeof value === 'string' ? value.trim() : '';
  if (content.length <= limit) return content;
  const terms = [...new Set((String(query).toLowerCase().match(/[a-z][a-z0-9'-]{2,}|[\u3400-\u9fff]{2,}/g) || [])
    .filter(term => !/^(?:the|and|for|from|with|can|are|how|this|that|please|what|would|could|have|today)$/.test(term)))];
  // Most official sources are English while users ask in Chinese. Rank the
  // actual subject, not just a shared brand/member name across unrelated deals.
  const concepts = [
    [/儿童|兒童|孩子|小孩|\b(?:kids?|children|child)\b/i, /\b(?:kids?|children|child|aged)\b/i],
    [/成人|大人|\badults?\b/i, /\badults?\b/i],
    [/门票|門票|票价|票價|预算|預算|费用|費用|多少钱|多少錢|\b(?:admission|tickets?|prices?|budget|costs?|fees?)\b/i, /\b(?:admission|tickets?|prices?|fees?|costs?)\b|(?:\$|USD)\s*\d/i],
    [/餐|吃饭|吃飯|\b(?:food|meal|restaurant|entree|entrée|dining)\b/i, /\b(?:restaurant|meals?|entrées?|entrees?|dine[- ]in|dining)\b/i],
    [/年龄|年齡|岁|歲|\b(?:age|aged|under|older|younger)\b/i, /\b(?:aged?|under|older|younger|years? old|age limit)\b/i],
    [/停车|停車|车位|車位|\bparking\b/i, /\b(?:parking|vehicles?|garage|parking spaces?)\b/i],
    [/公交|巴士|接驳|接駁|班次|班距|\b(?:bus|transit|shuttle|timetable|frequency)\b/i, /\b(?:bus|transit|shuttle|timetable|schedule|frequency|route|hourly)\b/i],
    [/营业|營業|开馆|開館|开放|開放|闭馆|閉館|\b(?:hours|opening|closed)\b/i, /\b(?:hours|opening|closed|open|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b/i],
    [/特别展|特別展|特展|\b(?:special exhibition|ticketed exhibition)\b/i, /\b(?:special|ticketed) exhibitions?\b/i],
    [/借记卡|借記卡|银行卡|銀行卡|持卡|\b(?:bank|cardholder|debit)\b/i, /\b(?:cardholders?|debit|credit card|bank)\b/i],
    [/打印|列印|\bprint/i, /\bprint(?:ing|ers?)?\b|打印|列印/i],
    [/\bkanopy\b/i, /\bkanopy\b/i],
    [/居住|居民|年龄|年齡|卡种|卡種|ecard|residen|card type/i, /residen|age|ecard|card type|eligib|居住|居民|年龄|年齡|卡种|卡種/i],
    [/discover\s*(?:&|and)\s*go|借.{0,5}票|馆票|館票|museum passes/i, /discover\s*(?:&|and)\s*go|museum pass|借.{0,5}票|馆票|館票/i],
  ].filter(([question]) => question.test(query)).map(([, source]) => source);
  const lines = content.split(/\n+/).map((text, index) => ({ text: text.trim(), index })).filter(row => row.text);
  const paragraphs = [];
  for (let i = 0; i < lines.length; i++) {
    const row = lines[i], next = lines[i + 1];
    // HTML admission tables often put the ticket tier and amount on separate
    // lines. Keep these adjacent source facts together; an orphan price cannot
    // establish which traveler pays it. Never infer amounts from other rows.
    const ticketLabel = row.text.length <= 120 && /\b(?:adults?|seniors?|youth|children|child|students?|educators?|members?|tickets?|EBT|card holders?)\b|成人|儿童|兒童|长者|長者|学生|學生|会员|會員/i.test(row.text);
    const price = next && /^(?:(?:\$|USD)\s*\d+(?:\.\d{1,2})?|free|免费|免費)\s*\*?$/i.test(next.text);
    if (ticketLabel && price) { paragraphs.push({ text: `${row.text}\n${next.text}`, index: row.index }); i++; }
    else paragraphs.push(row);
  }
  const relevant = paragraphs.map(row => ({ ...row, score: terms.reduce((sum, term) => sum + Number(row.text.toLowerCase().includes(term)), 0)
    + concepts.reduce((sum, concept) => sum + (concept.test(row.text) ? 8 : 0), 0)
    + (/eligib|cardholders?|terms|admission|not included|must be|closed|opening|hours|资格|資格|条款|條款|仅限|僅限|不包含|闭馆|閉館/i.test(row.text) ? 5 : 0) }))
    .sort((a, b) => b.score - a.score || a.index - b.index);
  const selected = new Map(); let length = 0;
  const add = row => {
    if (!row || selected.has(row.index) || length + row.text.length + 2 > limit) return;
    selected.set(row.index, row.text); length += row.text.length + 2;
  };
  if (paragraphs[0]?.text.length <= 250) add(paragraphs[0]);
  for (const row of relevant) if (row.score) add(row);
  for (const row of paragraphs) add(row);
  return [...selected].sort((a, b) => a[0] - b[0]).map(([, text]) => text).join('\n\n')
    || 'This source has no complete paragraph within the context budget; its rules remain unresolved.';
}

const TEMPORAL_LABELS = { past: ['已结束', '已結束', 'ended'], inactive: ['已暂停或下架', '已暫停或下架', 'paused or withdrawn'], upcoming: ['尚未开始', '尚未開始', 'not started yet'], current: ['进行中', '進行中', 'ongoing'] };
const temporalLabel = (status, locale) => TEMPORAL_LABELS[status]?.[localeIndex(locale)];

/** The page the user is viewing, as the first field of the model input. "这个"
 * resolves to it; [[page]] cites it. Dates carry their weekday and the
 * editorial temporal status so "还有吗" can be answered from the record. */
function currentPageFor(ref, locale, today) {
  if (!ref) return null;
  // API-STATUS: a sold-out, postponed or cancelled event page is named with its status, never recommended; a postponed or
  // cancelled one carries no date of its own and its status label replaces the generic "paused or withdrawn".
  const halted = ref.eventStatus === 'postponed' || ref.eventStatus === 'cancelled';
  const stateLabel = halted ? eventStatusLabel(ref.eventStatus, locale) : temporalLabel(ref.temporalStatus, locale);
  return { id: 'page', kind: ref.kind, title: ref.title, url: `https://www.baylink.us${ref.url}`,
    ...(ref.dateText && !halted ? { dates: ref.dateText } : {}), ...(ref.dateLabel ? { scheduleLabel: str(ref.dateLabel, 200) } : {}),
    ...(ref.city ? { city: ref.city } : {}), ...(ref.venue ? { venue: str(ref.venue, 200) } : {}), ...(ref.costLabel ? { cost: str(ref.costLabel, 200) } : {}),
    temporalStatus: ref.temporalStatus, ...(stateLabel ? { temporalLabel: stateLabel } : {}), today,
    ...(ref.eventStatus ? { eventStatus: ref.eventStatus, eventStatusLabel: eventStatusLabel(ref.eventStatus, locale), note: eventStatusNote(ref.eventStatus) } : {}),
    summary: str(ref.summary, 400), details: (ref.details || []).slice(0, 8).map(detail => str(detail, 300)),
    ...(ref.sourceUrl ? { officialUrl: ref.sourceUrl } : {}), ...(ref.verifiedAt ? { verifiedAt: ref.verifiedAt } : {}) };
}
function pageRecordText(ref, locale, today) {
  const page = currentPageFor(ref, locale, today);
  return ['BAYLINK published page record (editorial snapshot; not a live official-page read).', `${page.title}\nPage: ${ref.url} (${ref.kind} ${ref.id})`,
    [page.dates, page.scheduleLabel].filter(Boolean).join(' · '), [page.city, page.venue].filter(Boolean).join(' · '), page.cost,
    page.temporalLabel && `${page.temporalStatus}: ${page.temporalLabel}`, page.eventStatus && `Event status: ${page.eventStatusLabel}. ${page.note}`, str(ref.summary, 1600), ...page.details,
    // The date the record's official page was last read (by an editor or an agent): never "editor verified" (API-BB-4B).
    page.officialUrl && `Official source: ${page.officialUrl}`, page.verifiedAt && `Official page last read: ${page.verifiedAt}`].filter(Boolean).join('\n\n');
}

// A place card shows as its BAYLINK guide; a place without a guide page has no card.
// API-BB-8 (live 10-17, L06 Coyote Hills / L07 Chinatown cards read 办事指南): a place's guide is a leisure guide, in the
// web's guide category `city` (城市指南; all 29 place guides are), never a how-to guide. The card says so: guideType
// 'leisure', guideCategory 'city' and, in the reader's locale, typeLabel. A guide card the page context brings (the
// guide being read) carries none: the web reads its own guide category for it.
const quickRef = ref => ref.kind !== 'place' ? ref : /^\/guides\/([A-Za-z0-9_-]+)$/.test(ref.url) ? { ...ref, kind: 'guide', id: ref.url.split('/').pop(), guideType: 'leisure', guideCategory: 'city' } : null;
const GUIDE_TYPE_LABELS = { city: ['城市指南', '城市指南', 'City guide'] };
const asQuickCards = (refs, locale = 'zh-Hans') => refs.map(quickRef).filter(Boolean).map(ref => ({ ...ref, title: String(ref.title || '').slice(0, 300), summary: String(ref.summary || '').slice(0, 1600),
  ...(ref.kind === 'guide' && GUIDE_TYPE_LABELS[ref.guideCategory] ? { typeLabel: GUIDE_TYPE_LABELS[ref.guideCategory][localeIndex(locale)] } : {}) }));

/** Site retrieval, the evidence store, page and v2 refs, preview cards and plan scope for one turn. */
function gatherEvidence(turn) {
  const { progress, timing, v2, normalized, message, state, locale, englishGuideCatalog, guideCatalog, catalog, today, currentPath, pageContext, guard, discoveriesFor,
    nearbyAsk, floorTopic, onQuickCard, previous, planningPaused, indexedEdit, requestedMaxStops, explicitCandidateIds, searchMode } = turn;
  progress('site', 'running');
  const pageRefs = pageContext?.contextReferences || [];
  const site = timing.sync('siteMs', () => (v2 ? buildFastEvidence : buildSiteEvidence)({ query: normalized, originalQuery: message, state, guideCatalog: locale === 'en' && englishGuideCatalog ? englishGuideCatalog : guideCatalog, catalog, today, currentPath,
    selectedGuideUrls: pageContext?.contextReferences.filter(ref => ref.kind === 'guide').map(ref => ref.url),
    // A professional answer always sees its pillar guide's matching paragraphs.
    boostGuideUrls: guard ? guard.guides.map(guide => guide.url) : [],
    ...(v2 ? { discoveries: discoveriesFor(), locale, pageKeys: pageRefs.map(ref => `${ref.kind}:${ref.id}`), pageTitles: pageRefs.filter(ref => ref.kind !== 'guide').map(ref => ref.title), audience: true } : {}) }));
  progress('site', 'completed');
  const store = createEvidenceStore(site);
  const contextReferences = pageContext?.contextReferences || [];
  // A selected article remains context and evidence, but is not a food
  // recommendation unless its retrieved paragraph or candidate matches.
  // Filter before onQuickCard so streaming cannot flash an unrelated card.
  const recommendationReferences = site.foodEvidence ? contextReferences.filter(ref => ref.kind === 'guide'
    ? (site.guides || []).some(row => (row.slug === ref.id || row.url === ref.url) && matchesFoodEvidence(row, site.foodEvidence))
    : (site.candidates || []).some(row => row.kind === ref.kind && row.id === ref.id)) : contextReferences;
  // v2 cards come from the evidence items (offers and openings included); the
  // model's chosen records reorder them in finish().
  // In the reader's locale (I18N-SEO-01): English titles and summaries for en, an event's Traditional title for zh-Hant.
  // H39 (audit 10-13, BB-1013-09): an event card carries the asked day it occurs on
  // (`date`, the web's model.day), so a market held on Tuesdays and Saturdays shows
  // "周六 10/17" inside a Saturday answer, not today. The first asked day it occurs on.
  const askedDays = askedDaysOf(state, today);
  const cardDay = row => row && askedDays.find(day => row.startDate <= day && day <= row.endDate
    && (!Array.isArray(row.occurrenceDates) || row.occurrenceDates.includes(day)) && (!Array.isArray(row.sessions) || !row.sessions.length || row.sessions.some(session => session?.date === day)));
  const itemCard = item => cardInLocale({ kind: item.kind, id: item.id, title: item.title, url: item.page.replace(/^https:\/\/www\.baylink\.us/, ''), summary: item.row?.summary || item.text,
    ...(item.row?.startDate ? { startDate: item.row.startDate } : {}), ...(item.row?.endDate ? { endDate: item.row.endDate } : {}),
    ...(item.kind === 'event' && cardDay(item.row) ? { date: cardDay(item.row) } : {}), temporalStatus: item.temporalStatus || 'current' }, { locale, row: item.row, kind: item.catalogKind || item.kind });
  const entityCards = v2 ? new Map((site.items || []).filter(item => item.kind !== 'guide' && !item.mismatch && /^https:\/\/www\.baylink\.us\//.test(item.page || '') && !['past', 'inactive'].includes(item.temporalStatus)).map(item => [`${item.kind}:${item.id}`, itemCard(item)])) : null;
  // API-BB-4B (live check 10-13, L01): on an ask with a city or area, the preview and fallback
  // cards are that area's records first, then records with no stated place, then other areas.
  // An offer with no place in its record (Randall Museum's free admission, San Francisco) no
  // longer leads a San Mateo ask. The model's choices still order the final cards.
  const itemRows = new Map((site.items || []).map(item => [`${item.kind}:${item.id}`, item.row]));
  const area = row => !row ? 0 : state.city ? (row.city === state.city ? 0 : row.region && row.region === state.region ? 1 : !row.city && !row.region ? 2 : 3)
    : state.region && state.region !== 'all' ? (row.region === state.region ? 0 : !row.city && !row.region ? 2 : 3) : 0;
  const nearFirst = v2 ? [...entityCards.values()].map((card, index) => ({ card, index, rank: area(itemRows.get(`${card.kind}:${card.id}`)) })).sort((a, b) => a.rank - b.rank || a.index - b.index).map(entry => entry.card) : [];
  const localMatches = v2 ? [...new Map([...recommendationReferences, ...nearFirst].map(row => [`${row.kind}:${row.id}`, row])).values()].slice(0, 3)
    : [...new Map([...recommendationReferences, ...(site.candidates || []).map(row => ({ kind: row.kind, id: row.id, title: row.title, url: row.kind === 'event' ? `/events/${row.id}` : row.guideSlug ? `/guides/${row.guideSlug}` : '/explore', summary: row.summary, ...(row.startDate ? { startDate: row.startDate } : {}), ...(row.endDate ? { endDate: row.endDate } : {}), ...(row.kind === 'event' && cardDay(row) ? { date: cardDay(row) } : {}), temporalStatus: row.startDate > today ? 'upcoming' : 'current' }))].map(row => [`${row.kind}:${row.id}`, row])).values()].slice(0, 3);
  const quickCards = nearbyAsk ? [] : asQuickCards(localMatches, locale);
  // No early site card beside a possible emergency (SAFETY-2): a preview listing would
  // read as the answer if no model answer follows. Nor beside a health worry or a
  // professional topic (H72): the preview is the retrieval's events, not their answer.
  if (!floorTopic && !guard && !healthWorry(message)) try { const pending = onQuickCard?.(quickCards); pending?.catch?.(() => {}); } catch { /* transport cannot alter retrieval */ }
  // The page the user is viewing is the top-priority evidence with the fixed
  // citation id "page"; other selected items stay ordinary page records.
  const pageSourceIds = contextReferences.map(ref => store.addSource({ kind: 'guide', title: ref.title, url: `https://www.baylink.us${ref.url}`, verification: 'site-record', recordedAt: ref.verifiedAt, text: pageRecordText(ref, locale, today) })?.id).filter(Boolean);
  const pageSourceId = pageSourceIds[0];
  store.aliases = new Map(pageSourceId ? [['page', pageSourceId]] : []);
  for (const ref of site.nearMiss || []) store.addSource({ kind: 'guide', title: ref.title, url: `https://www.baylink.us/events/${ref.id}`, verification: 'site-record', text: JSON.stringify({ ...ref, note: eventStatusNote(ref.reason) || 'Named reference only. Does NOT satisfy requested dates/constraints; correct the premise, never recommend as a matching option.' }) });
  // v2: every evidence item is a citable store source under its ref (e1…, r1… for
  // a professional topic's official contacts); event/place items stay plan candidates.
  const itemRefs = new Map(), sentSourceIds = new Set(pageSourceIds);
  // v2 read_source: a ref opens its record's official page (registered on first read).
  const officialRefs = new Map(contextReferences[0]?.sourceUrl ? [['page', { url: contextReferences[0].sourceUrl, title: contextReferences[0].title }]] : []);
  if (v2) for (const item of site.items || []) {
    if (item.official && item.official !== item.page) officialRefs.set(item.ref, { url: item.official, title: item.title });
    const source = item.kind === 'guide' ? store.addSource({ kind: 'guide', title: item.title, url: item.guideUrl, verification: 'site-record', text: item.text, recordedAt: item.guide?.updatedAt })
      : store.addSource({ kind: item.kind === 'event' ? 'event' : 'place', title: item.title, titleOrigin: 'source', url: item.page, verification: 'site-record', text: item.text, recordedAt: item.row?.verifiedAt });
    if (!source) continue;
    const candidateId = ['event', 'place'].includes(item.catalogKind) && store.candidates.has(item.catalogId) ? item.catalogId : null;
    if (candidateId) { const candidate = store.candidates.get(candidateId); candidate.sourceIds = [...new Set([source.id, ...(candidate.sourceIds || [])])]; }
    itemRefs.set(item.ref, { sourceId: source.id, kind: item.kind, id: item.id, candidateId });
    store.aliases.set(item.ref, source.id); sentSourceIds.add(source.id);
  }
  // Official contacts are citable evidence, so the card and the answer agree.
  const resourceSourceIds = guard ? guard.resources.map(row => store.addSource({ url: row.url, title: row.title, kind: 'web', verification: 'catalog' })?.id) : [];
  const resourceItems = [];
  if (v2 && guard) {
    guard.resources.forEach((row, index) => {
      const id = resourceSourceIds[index]; if (!id) return;
      const ref = `r${index + 1}`; itemRefs.set(ref, { sourceId: id, kind: 'official' }); store.aliases.set(ref, id); sentSourceIds.add(id);
      resourceItems.push({ ref, kind: 'official', title: row.title, page: row.url, text: [row.title, row.phone].filter(Boolean).join(' ') });
    });
  }
  const scopeGuides = [...(site.guides || [])];
  if (site.originCandidate) store.addCandidate({ ...site.originCandidate, id: 'origin', isOrigin: true });
  const samePlanScope = previous?.state && ['city', 'date'].every(key => previous.state[key] === state[key])
    && (previous.state.goal === state.goal || planningPaused);
  const changeRequest = normalized.split(/[。！？!?；;，,\n]/).filter(clause => !/(?:不要|不需要|无需|無需|不用|别|別|不改|保持|保留|\b(?:do not|don['’]t|keep|preserve|without)\b).{0,30}(?:改|换|換|替|加|增|重排|顺序|順序|行程|change|replace|swap|add|rearrange|replan)/i.test(clause)).join(' ');
  const reviseChoices = /换|換|替换|替換|备选|備選|替代|重排|重新安排|改去|增[加添]|加一|删|刪|移除|不要.{0,20}(?:站|地方|景点|景點)|\b(?:replace|swap|replan|rearrange|add|remove|drop|different|other option|alternative)\b/i.test(changeRequest);
  const requestedAlternativeChoices = normalized.split(/[。！？!?；;，,\n]/).some(clause =>
    !/(?:不要|不需要|无需|無需|不用|别|別|没有|沒有|\b(?:do not|don['’]t|no|without|avoid)\b).{0,30}(?:备选|備選|替代|缩减|縮減|\b(?:alternative|reduced|shorter)\b)/i.test(clause)
    && /备选|備選|替代|(?:比较|比較).{0,12}(?:缩减|縮減)|\b(?:alternative|compare.{0,20}(?:reduced|shorter))\b/i.test(clause));
  const retainedCandidateIds = !indexedEdit && samePlanScope && !reviseChoices && !requestedMaxStops ? arr(state.selectedCandidateIds, 6) : [];
  // Published choices seed ordinary follow-ups; they are not a permanent user
  // constraint. A new city/date is cleared by preparePlanEdit, and an explicit
  // replan may choose new stops even when the old card was already published.
  if (reviseChoices && !indexedEdit && !explicitCandidateIds.length) state.selectedCandidateIds = [];
  if (searchMode !== 'site' && samePlanScope) for (const ref of previous.lastPlan?.selectedRefs || []) {
    if (!state.excludedCandidateIds?.includes(ref.id) && !store.candidates.has(ref.id)) store.addCandidate({ id: ref.id, title: ref.title, city: ref.city, sourceUrls: [ref.sourceUrl], origin: 'web', kind: 'unknown', verification: 'needs-revalidation', previousKind: ref.previousKind });
  }
  Object.assign(turn, { site, store, contextReferences, recommendationReferences, entityCards, localMatches, pageSourceId, itemRefs, sentSourceIds, officialRefs, resourceSourceIds, resourceItems,
    scopeGuides, samePlanScope, reviseChoices, requestedAlternativeChoices, retainedCandidateIds, sentCandidateIds: new Set() });
}

/** The evidence a v1 request (and a v1 search_site result) carries: at most 24 sources, the plan's first. */
function modelSources(turn) {
  const { checklist, contextReferences, message, pageSourceId, store } = turn;
  const selectedRefs = new Set((turn.plan?.stops || []).flatMap(stop => [...(stop.sourceIds || []), ...(stop.admissionFacts?.sourceIds || [])]));
  const candidateRefs = new Set([...store.candidates.values()].flatMap(c => c.sourceIds || []));
  // The current itinerary's evidence must not fall beyond the context cap
  // when retrieval also returns many guides or unrelated source leads.
  // An event/offer/opening page record leads the evidence. On a guide page
  // the guide's own boosted paragraphs lead and its page record follows.
  const priority = s => s.id === pageSourceId && contextReferences[0]?.kind !== 'guide' ? -2 : selectedRefs.has(s.id) ? -1 : s.kind === 'guide' ? 0 : ['search-result', 'page-read', 'api'].includes(s.verification) ? 1 : candidateRefs.has(s.id) ? 2 : 3;
  return [...store.sources.values()].sort((a, b) => priority(a) - priority(b)).slice(0, 24).map(s => ({ ...s, ...(s.id === pageSourceId ? { id: 'page' } : {}),
    text: s.verification === 'page-read' || s.kind === 'guide' ? sourceContextText(s.text, message, checklist.complex ? 2600 : 1800) : str(s.text, 1800),
    ...((s.verification === 'page-read' || s.kind === 'guide') && s.text?.length > (checklist.complex ? 2600 : 1800) ? { textExcerpted: true, excerptNotice: 'Selected complete paragraphs; omitted content is not evidence that a condition is absent.' } : {}) }));
}

function compactCandidate(turn, c) {
  const { state, locale, today } = turn;
  return ({ id: c.id, kind: c.kind, title: str(c.title, 200), ...(c.city ? { city: c.city } : {}), ...(c.startDate ? { when: readerRange(c.startDate, c.endDate, locale) } : {}),
    ...(c.costLabel ? { cost: str(c.costLabel, 120) } : {}), ...(withAdmissionFacts(c, state, { locale, today }).admissionFacts ? { admissionFacts: withAdmissionFacts(c, state, { locale, today }).admissionFacts } : {}), summary: str(c.summary, 200), sourceIds: (c.sourceIds || []).slice(0, 3) });
}
/** v2: candidates the model has not been sent yet, the chosen and planned ones first. */
function compactCandidates(turn, limit = 12) {
  const { sentCandidateIds, state, store } = turn;
  const wanted = new Set([...(state.selectedCandidateIds || []), ...(turn.plan?.stops || []).map(stop => stop.entityId || stop.id), 'origin']);
  return [...store.candidates.values()].filter(c => !sentCandidateIds.has(c.id)).sort((a, b) => Number(wanted.has(b.id)) - Number(wanted.has(a.id))).slice(0, limit)
    .map(c => { sentCandidateIds.add(c.id); return compactCandidate(turn, c); });
}
/** v2: only what the model has not seen yet (no evidence is repeated). */
function newEvidence(turn) {
  const { store, sentSourceIds } = turn;
  const sources = [...store.sources.values()].filter(source => !sentSourceIds.has(source.id) && (source.text || source.kind === 'guide')).slice(0, 10)
    .map(source => { sentSourceIds.add(source.id); return { id: source.id, kind: source.kind || 'web', title: source.title, url: source.url, text: snippet(String(source.text || ''), { base: new Set(), expanded: new Set() }, 400) }; });
  return { sources, candidates: compactCandidates(turn, 8) };
}
// v2: the model knows refs. e1 / page open the record's official page (never the
// BAYLINK page itself), r1 is already the official contact, a store id is read as is.
function readableSource(turn, value) {
  const { store, itemRefs, officialRefs, sentSourceIds } = turn;
  const key = String(value ?? '').trim().replace(/^\[\[\s*|\s*\]\]$/g, '');
  if (store.sources.has(key)) return key;
  if (itemRefs.get(key)?.kind === 'official') return itemRefs.get(key).sourceId;
  const official = officialRefs.get(key), url = official && canonical(official.url);
  if (!url) return key;
  const source = [...store.sources.values()].find(row => row.url === url) || store.addSource({ kind: 'web', title: official.title, url, verification: 'catalog' });
  if (!source) return key;
  sentSourceIds.add(source.id); // the page text arrives in the tool result
  return source.id;
}
// v2 agent: the server's pre-search, so the model starts from it instead of searching again.
function webSeen(turn) {
  const { webResearch, store, sentSourceIds } = turn;
  if (!webResearch.length) return turn.webStatus === 'unavailable' ? { status: 'unavailable' } : undefined;
  const sources = [...store.sources.values()].filter(row => row.verification === 'search-result' && !sentSourceIds.has(row.id)).slice(0, 8)
    .map(row => { sentSourceIds.add(row.id); return { id: row.id, title: str(row.title, 200), url: row.url, ...(row.text ? { text: str(row.text, 300) } : {}) }; });
  return { status: turn.webStatus, ...(turn.webCheckedAt ? { checkedAt: turn.webCheckedAt } : {}), results: webResearch.map(row => ({ summary: str(row.answer, 1500), sourceIds: row.sourceIds })), sources };
}

/** The v2 user turn (fast path, and the first call of the v2 agent). */
function v2UserContent(turn, extra = {}) {
  const { contextReferences, locale, today, message, nowClock, state, maxStops, checklist, history, resourceItems, site, scopeGuides, store } = turn;
  return fastUserContent({ currentPage: currentPageFor(contextReferences[0], locale, today),
    otherPages: contextReferences.slice(1).map(ref => currentPageFor(ref, locale, today)).map(({ id, ...ref }) => ref), message, locale, today, now: nowClock, state, maxStops, checklist,
    recentConversation: recentTurns(history), items: [...resourceItems, ...(site.items || [])], sourceScopes: checklist.complex ? evidenceScopes(scopeGuides, store) : undefined,
    foodRequirement: site.foodEvidence ? { ...site.foodEvidence, unverified: ['current-menu', 'opening-hours', 'availability'] } : undefined, ...extra });
}
function refSource(turn, ref) {
  const { pageSourceId, itemRefs } = turn;
  return ref === 'page' ? pageSourceId : itemRefs.get(ref)?.sourceId;
}
// The catalog region of each event, place, offer or opening ref; named records count as in the area.
function refRegions({ site }) {
  return new Map((site.items || []).filter(item => item.kind !== 'guide' && !item.named).map(item => [item.ref, item.row?.region || null]));
}
// The ref is trimmed after matching; padding inside the pattern (\s*, lazy ref, \s*)
// backtracked quadratically on a long run of spaces in a model-written summary.
function citeRefs(turn, value) {
  return typeof value === 'string' ? value.replace(/\[\[([^\]]{0,100})\]\]/g, (match, ref) => { const id = refSource(turn, ref.trim()); return id ? `[[${id}]]` : match; }) : value;
}
function entityOf(turn, ref) {
  const { contextReferences, itemRefs } = turn;
  if (ref === 'page') return contextReferences[0] && contextReferences[0].kind !== 'guide' ? { kind: contextReferences[0].kind, id: contextReferences[0].id } : null;
  const row = itemRefs.get(ref);
  return row && !['guide', 'official'].includes(row.kind) ? { kind: row.kind, id: row.id } : null;
}
function candidateOf(turn, ref) {
  const { contextReferences, itemRefs, store } = turn;
  return ref === 'page' ? (contextReferences[0] && store.candidates.has(contextReferences[0].id) ? contextReferences[0].id : null)
    : itemRefs.get(ref)?.candidateId || (store.candidates.has(ref) ? ref : null);
}

module.exports = { modelPlan, planView, sourceContextText, currentPageFor, pageRecordText, quickRef, asQuickCards, gatherEvidence, modelSources, compactCandidates, newEvidence, readableSource, webSeen,
  v2UserContent, refSource, refRegions, citeRefs, entityOf, candidateOf };
