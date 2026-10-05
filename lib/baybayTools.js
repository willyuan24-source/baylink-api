const crypto = require('node:crypto');
const { fetchSource } = require('./sourceMonitor');
const { safeUrl, normalizeWebSearchError, WEB_SEARCH_FAILURES } = require('./plannerWebSearch');
const { inferFilters } = require('./planner');
const { computeTravel, travelResult, travelWithDeadline } = require('./plannerTravel');
const { localInstant } = require('./serviceBookings');
const { admissionRuleFromQuote, withAdmissionFacts } = require('./baybayFacts');
const { hasPrivateSearchData } = require('./guideWebSearch');

const flat = s => String(s || '').replace(/\s+/g, ' ').trim();
const canonical = value => { const url = safeUrl(value); if (!url) return null; const u = new URL(url); for (const k of [...u.searchParams.keys()]) if (/^utm_|^fbclid$|^gclid$/i.test(k)) u.searchParams.delete(k); return u.href.replace(/\/$/, ''); };
const idFor = value => crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
const boundedText = (v, max = 500) => flat(v).slice(0, max);
const locationOK = c => c?.precision === 'venue' && Number.isFinite(c?.lat) && Number.isFinite(c?.lng) && c.lat >= 36 && c.lat <= 40 && c.lng >= -124 && c.lng <= -120;
const PRIVATE_QUERY = /\b\d{3}-\d{2}-\d{4}\b|\bsk-[\w-]{12,}|(?:password|api[_ -]?key|access[_ -]?token|密码|密碼)\s*[:=：]\s*\S+|\b\d{1,6}\s+(?:[\w.'-]+\s+){0,5}(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|way|boulevard|blvd)\b|[^\s]+@[^\s]+|\b\d{3}[-.]\d{3}[-.]\d{4}\b/i;
const PRICE_FIELDS = ['admissionUsd', 'admission', 'admissionScope', 'admissionAppliesTo', 'admissionEligibility', 'feesIncluded'];
const identityKey = value => flat(value).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const externalCandidate = candidate => candidate.origin === 'web' || candidate.sourceKind === 'web' || candidate.external === true || /^web-/.test(candidate.id);
function candidateNames(candidate) {
  const title = flat(candidate.title);
  // Only editorial records have a trusted descriptive suffix. A cafe's museum
  // suffix is not an alias for the cafe, and new web entities get no aliases.
  return [...new Set([title, ...(!externalCandidate(candidate) ? [title.split(/\s+·\s+/)[0]] : [])].map(identityKey).filter(Boolean))];
}
const namedIn = (quote, candidate) => candidateNames(candidate).some(name => ` ${identityKey(quote)} `.includes(` ${name} `));
const titleRank = row => row?.titleOrigin === 'candidate' ? 0 : ({ catalog: 1, 'site-record': 1, 'search-result': 2, 'page-read': 3, api: 4 }[row?.verification] ?? 1);
const TOOL_FAILURES = {
  site_only: ['External lookup is disabled in site-only mode.', false],
  web_tool_limit: ['Web lookup budget reached. Use the evidence already retrieved.', false],
  web_private_query: ['Use only a public venue name, city and topic; omit addresses, contact details and secrets.', true],
  research_deadline: ['Not enough research time remains for another lookup. Use the evidence already retrieved.', false],
  web_duplicate_query: ['This query was already searched. Use its evidence or refine the question.', true],
  source_id_invalid: ['Choose an existing public source ID.', true],
  source_attempted: ['This page was already attempted without readable evidence. Use a different official source.', false],
  source_tool_limit: ['Source reading limit reached. Use the evidence already retrieved.', false],
  source_reader_unavailable: ['The source reader is unavailable for this request.', false],
  source_no_readable_text: ['The page did not provide readable source text. Use a different official source.', true],
  source_forbidden: ['The publisher blocked automated reading of this page. Try another official source; do not bypass the restriction.', false],
  source_rate_limit: ['The publisher temporarily limited page access. Use another official source or try later.', false],
  source_not_found: ['The official page was not found. Look for its current official replacement.', false],
  source_timeout: ['The page did not finish loading within the deadline. Its facts remain unverified.', true],
  source_page_too_large: ['This page exceeded the bounded reader size limit. Try a more focused official page.', false],
  source_unsafe_url: ['The source URL failed public-address safety checks and was not read.', false],
  source_unsupported_format: ['The page format could not be read by this source reader. Use an official text page.', false],
  source_manual_required: ['The page requires interactive or manual access. Do not treat it as verified.', false],
  source_redirect_limit: ['The page redirected too many times. Use a different official page without bypassing access restrictions.', false],
  source_unavailable: ['The official page could not be read. Its facts remain unverified.', true],
  research_unavailable: ['This lookup could not be completed. Keep the relevant facts unknown.', true],
};
const toolFailure = code => { const [error, retryable] = TOOL_FAILURES[code] || TOOL_FAILURES.research_unavailable; return { error, code: Object.hasOwn(TOOL_FAILURES, code) ? code : 'research_unavailable', retryable }; };
function normalizeResearchError(error, toolName = 'research') {
  if (Object.hasOwn(TOOL_FAILURES, error?.code)) return toolFailure(error.code);
  if (toolName === 'search_web' || error?.code === 'SEARCH_VERIFICATION_FAILED' || Object.hasOwn(WEB_SEARCH_FAILURES, error?.code)) {
    const safe = normalizeWebSearchError(error);
    return { error: safe.message, code: safe.code, retryable: WEB_SEARCH_FAILURES[safe.code].retryable, ...(safe.reason ? { reason: safe.reason } : {}) };
  }
  if (toolName === 'read_source') {
    const codes = { 'http-403': 'source_forbidden', 'http-429': 'source_rate_limit', 'http-404': 'source_not_found', timeout: 'source_timeout',
      'page-too-large': 'source_page_too_large', 'unsafe-url': 'source_unsafe_url', 'unsafe-address': 'source_unsafe_url',
      'unsupported-content': 'source_unsupported_format', 'unsupported-encoding': 'source_unsupported_format',
      'manual-required': 'source_manual_required', 'redirect-limit': 'source_redirect_limit' };
    return toolFailure(codes[error?.code] || (['AbortError', 'TimeoutError'].includes(error?.name) ? 'source_timeout' : 'source_unavailable'));
  }
  return toolFailure('research_unavailable');
}

function relevantPageLinks(links, sourceUrl) {
  const source = canonical(sourceUrl); if (!source || !source.startsWith('https:')) return [];
  const origin = new URL(source).origin, seen = new Set([source]);
  return (Array.isArray(links) ? links : []).slice(0, 120).flatMap(link => {
    const url = canonical(link?.url);
    if (!url || new URL(url).origin !== origin || seen.has(url)) return [];
    seen.add(url);
    const title = boundedText(link.title || url, 220), label = `${title} ${url}`;
    const priority = /eligib|\bterms\b|conditions?|资格|資格|条款|條款/i.test(label) ? 3
      : /admission|tickets?|discount|门票|門票|优惠|優惠/i.test(label) ? 2
        : /hours|opening|visit|开放|開放|营业|營業/i.test(label) ? 1 : 0;
    return priority ? [{ title, url, priority }] : [];
  }).sort((a, b) => b.priority - a.priority).slice(0, 6).map(({ title, url }) => ({ title, url }));
}

function unqualifiedFreeAdmission(admission, sourceText) {
  if (!/\b(?:free (?:general )?(?:admission|entry)|(?:general )?(?:admission|entry)\s*(?:is|:)?\s*free)\b|免费入场|免費入場|入场免费|入場免費/i.test(admission)) return false;
  // The model may quote only "free admission" from a conditional sentence.
  // Inspect the surrounding source sentence as well as the supplied quotation.
  const text = flat(sourceText), position = text.indexOf(admission);
  const before = text.slice(Math.max(0, position - 180), position).split(/[.!?;。；]/).pop();
  const remainder = text.slice(position + admission.length, position + admission.length + 400);
  const after = /[.!?;。；]$/.test(admission) ? '' : remainder.split(/[.!?;。；]/)[0];
  const context = `${before} ${admission} ${after}`;
  if (/\b(?:members?|card\s*holders?|children|kids|youth|teens?|residents?|students?|military|veterans?|seniors?|disabled|disabilities|caregivers?|ebt|snap|qualif\w*|eligible|eligibility|with|purchase|purchases|spend|spending|buy one|get one|bogo|first|second|third|last|every|only|except|after|before|until|between|through|during|on|at|friday|saturday|sunday|monday|tuesday|wednesday|thursday|january|february|march|april|may|june|july|august|september|october|november|december)\b|\$\s*[1-9]|USD\s*[1-9]|\b\d{1,2}:\d{2}\b|持卡|会员|會員|儿童|兒童|居民|学生|學生|买一|買一|消费|消費|仅限|僅限|每[周週月]|周[一二三四五六日天]|週[一二三四五六日天]|之后|之後|之前|期间|期間/i.test(context)) return false;
  const following = (/[.!?;。；]$/.test(admission) ? remainder : remainder.replace(/^[^.!?;。；]*[.!?;。；]/, '')).split(/[.!?;。；]/)[0].trim();
  const preceding = text.slice(Math.max(0, position - 240), position).trim().replace(/[.!?;。；]+$/, '').split(/[.!?;。；]/).pop().trim();
  // A directly adjacent eligibility sentence can qualify a cropped quotation.
  // Do not let unrelated footer words such as "with" invalidate free entry.
  return ![preceding, following].some(sentence => /^(?:(?:this|the|our)\s+)?(?:offer|admission|entry|tickets?|discount|promotion|benefit|eligibility|only|valid|available|requires?|must|for|applies|limited|excludes?)\b|^(?:优惠|優惠|入场|入場|门票|門票|仅限|僅限|须|須)/i.test(sentence)
    && /\b(?:members?|card\s*holders?|children|kids|residents?|students?|military|veterans?|seniors?|ebt|snap|qualif\w*|eligible|eligibility|only|purchase|spend|bogo|first|last|every|after|before|until|during)\b|持卡|会员|會員|儿童|兒童|居民|学生|學生|消费|消費|仅限|僅限/i.test(sentence));
}

function createEvidenceStore(initial = {}) {
  const sources = new Map(), candidates = new Map();
  const addSource = row => {
    const url = row?.url?.startsWith('/guides/') ? row.url : canonical(row?.url);
    if (!url) return null;
    const id = `s-${idFor(url)}`, previous = sources.get(id);
    const value = { ...previous, ...row, id, url, title: boundedText(row.title || previous?.title || url, 220), titleOrigin: row.title ? row.titleOrigin || 'source' : previous?.titleOrigin, text: String(row.text || previous?.text || '').slice(0, 9000),
      checkedAt: row.checkedAt || row.recordedAt || row.updatedAt || previous?.checkedAt,
      recordedAt: row.recordedAt || row.updatedAt || previous?.recordedAt };
    if (previous && titleRank(previous) >= titleRank(row)) { value.title = previous.title; value.titleOrigin = previous.titleOrigin; }
    if (row.titleOrigin === 'candidate') {
      value.candidateTitles = [...new Set([...(previous?.candidateTitles || []), boundedText(row.title, 220)].filter(Boolean))].slice(0, 8);
      if (value.titleOrigin === 'candidate' && value.candidateTitles.length > 1) {
        // Shared venue pages are not the identity of the last added business.
        const parsed = new URL(url); value.title = boundedText(`${parsed.hostname}${parsed.pathname}`, 220);
      }
    }
    if (row.kind === 'guide' && previous?.text && row.text && !previous.text.includes(row.text)) value.text = `${previous.text}\n\n${row.text}`.slice(0, 9000);
    const rank = { catalog: 0, 'search-result': 1, 'page-read': 2, api: 3 };
    if (previous && (rank[previous.verification] ?? 0) > (rank[row.verification] ?? 0)) Object.assign(value, { kind: previous.kind, verification: previous.verification, checkedAt: previous.checkedAt, text: previous.text });
    // Search retrieval does not establish an exact page excerpt or a current fact.
    if (previous?.verification === 'page-read' && row.verification !== 'page-read') Object.assign(value, { text: previous.text, verification: previous.verification, checkedAt: previous.checkedAt });
    sources.set(id, value);
    // Editorial guides link to official references. Register those public URLs
    // as readable sources, without presenting them as already-fetched pages.
    if (row.kind === 'guide') {
      const references = (Array.isArray(row.sourceUrls) ? row.sourceUrls : []).slice(0, 12).map(reference => {
        const url = typeof reference === 'string' ? reference : reference?.url;
        return url && addSource({ url, title: reference?.title || row.title, kind: 'web', verification: 'catalog', recordedAt: value.recordedAt })?.id;
      }).filter(Boolean);
      value.referenceSourceIds = [...new Set([...(previous?.referenceSourceIds || []), ...references])];
    }
    return value;
  };
  const addCandidate = row => {
    if (!row || typeof row.id !== 'string' || !row.title) return null;
    const sourceIds = [...new Set([...(row.sourceIds || []), ...(row.sourceUrls || []), row.officialUrl].map(value => sources.has(value) ? value : value && addSource({ url: typeof value === 'string' ? value : value.url, title: value.title || row.title, titleOrigin: value.title ? 'source' : 'candidate', kind: row.kind === 'event' ? 'event' : 'place', verification: 'catalog', checkedAt: row.checkedAt || row.recordedAt || row.verifiedAt, recordedAt: row.recordedAt || row.verifiedAt })?.id).filter(Boolean))];
    const existing = candidates.get(row.id);
    const value = { ...existing, ...row, sourceIds: [...new Set([...(existing?.sourceIds || []), ...sourceIds])] };
    if (existing?.verifiedFacts) {
      value.verifiedFacts = { ...existing.verifiedFacts, ...row.verifiedFacts };
      const proofFields = { admission: ['costLabel', 'cost'], date: ['occurrenceDates', 'startDate', 'endDate'], closed: ['availability'], address: ['address'], kind: ['kind'] };
      for (const [proof, fields] of Object.entries(proofFields)) if (existing.verifiedFacts[proof] && !row.verifiedFacts?.[proof]) {
        for (const field of fields) if (existing[field] !== undefined) value[field] = existing[field];
      }
      if (!row.verifiedFacts || !Object.keys(row.verifiedFacts).length) {
        value.verification = existing.verification; value.checkedAt = existing.checkedAt;
      }
      value.planning = { ...existing.planning, ...row.planning };
      if (existing.verifiedFacts.admission && !row.verifiedFacts?.admission) for (const field of PRICE_FIELDS) value.planning[field] = existing.planning?.[field] ?? null;
      if (existing.verifiedFacts.hours && !row.verifiedFacts?.hours) value.planning.schedule = existing.planning?.schedule ?? null;
      if (existing.verification === 'page-verified' && value.verifiedFacts.city && ['event', 'place'].includes(value.kind) && (value.kind !== 'event' || value.verifiedFacts.date)) value.verification = 'page-verified';
    }
    candidates.set(row.id, value); return value;
  };
  for (const s of initial.sources || []) addSource(s);
  for (const g of initial.guides || []) addSource({ ...g, kind: 'guide', verification: 'catalog' });
  for (const c of initial.candidates || []) addCandidate(c);
  return { sources, candidates, addSource, addCandidate };
}

function verifiedCandidate({ candidate, source, proofs = {}, state, today, kind }) {
  if (!candidate || source?.verification !== 'page-read' || !candidate.sourceIds?.includes(source.id)) return { error: 'Read this candidate’s own source before verifying it.' };
  const text = flat(source.text), exact = key => typeof proofs[key] === 'string' && flat(proofs[key]).length >= 3 && flat(proofs[key]).length <= 600 && text.includes(flat(proofs[key])) ? flat(proofs[key]) : null;
  const name = exact('name');
  if (!name || !namedIn(name, candidate)) return { error: 'The page must contain the candidate name in the supplied exact quotation.' };
  const next = { ...candidate, verifiedFacts: { ...candidate.verifiedFacts, name }, checkedAt: source.checkedAt };
  const external = externalCandidate(candidate);
  const proposedKind = external ? (['event', 'place'].includes(kind) ? kind : candidate.verifiedFacts?.kind ? candidate.kind : 'unknown') : candidate.kind;
  const city = exact('city');
  if (city && candidate.city && ` ${identityKey(city)} `.includes(` ${identityKey(candidate.city)} `)) next.verifiedFacts.city = city;
  const date = exact('date');
  if (date && /(?<!\d)20\d{2}(?!\d)/.test(date)) {
    try { const parsed = inferFilters(date, today); if (parsed.date && (!state.date || parsed.date === state.date)) { next.occurrenceDates = [parsed.date]; next.startDate = parsed.date; next.endDate = parsed.date; next.verifiedFacts.date = date; } } catch { /* ambiguous dates are not verified */ }
  }
  if (external) {
    next.kind = 'unknown';
    if (proposedKind === 'event' && next.verifiedFacts.date) { next.kind = 'event'; next.verifiedFacts.kind = next.verifiedFacts.date; }
    if (proposedKind === 'place') {
      const venue = exact('venue');
      const obviousEvent = /\b(?:festival|fair|concert|event|workshop|meetup|webinar|reception|open house|performance|vs\.?)\b|音乐节|音樂節|艺术节|藝術節|演唱会|演唱會|活动|活動|开放日|開放日|市集|比赛|比賽/i.test(candidate.title);
      const permanent = venue && /\b(?:museum|park|library|restaurant|cafe|caf[ée]|store|shopping (?:center|centre|mall)|mall|outlet|garden|zoo|aquarium|beach|trail|plaza|historic site|science cent(?:er|re)|visitor cent(?:er|re)|stadium|arena|theat(?:er|re))\b|博物馆|博物館|公园|公園|图书馆|圖書館|餐厅|餐廳|咖啡|商场|商場|购物中心|購物中心|动物园|動物園|水族馆|水族館|植物园|植物園|海滩|海灘|步道/i.test(venue);
      if (!obviousEvent && permanent && namedIn(venue, candidate)) { next.kind = 'place'; next.verifiedFacts.kind = venue; next.verifiedFacts.venue = venue; }
    }
  }
  const admission = exact('admission');
  if (admission) {
    next.costLabel = admission; next.verifiedFacts.admission = admission;
    // A new quotation supersedes stale numeric/tier prices. Keep the quotation
    // but do not infer a party price from a mixed table or a conditional offer.
    next.planning = { ...candidate.planning, admissionUsd: null, admission: null, admissionScope: null, admissionAppliesTo: null, admissionEligibility: null, feesIncluded: false };
    const unqualifiedFree = unqualifiedFreeAdmission(admission, source.text);
    next.cost = unqualifiedFree ? 'free' : /(?:admission|entry|入场|入場|门票|門票)[^.;。；]{0,25}(?:\$\s*\d|USD\s*\d)|\$\s*\d[^.;。；]{0,20}(?:admission|entry)/i.test(admission) ? 'paid' : 'unknown';
    const rule = admissionRuleFromQuote({ quote: admission, source, candidate: next, unqualifiedFree });
    if (rule) { next.planning.admission = rule; if (rule.adultUsd > 0 || rule.groupUsd > 0) next.cost = 'paid'; }
  }
  for (const key of ['hours', 'address']) { const quote = exact(key); if (quote) { next.verifiedFacts[key] = quote; if (key === 'address') next.address = quote; else next.planning = { ...(next.planning || candidate.planning), schedule: null }; } }
  const closed = exact('closed');
  if (closed && /sold out|event full|cancelled|canceled|permanently closed|已满|已滿|售罄|取消|暂停|暫停/i.test(closed)) { next.availability = 'unavailable'; next.verifiedFacts.closed = closed; }
  next.verification = next.verifiedFacts.city && ['event', 'place'].includes(next.kind) && (next.kind !== 'event' || next.verifiedFacts.date) ? 'page-verified' : 'partial';
  return withAdmissionFacts(next, state, { today });
}

function createResearchTools({ store, state, today, locale, searchMode, webSearch, config = {}, isTest = false, sourceFetch, fetchImpl = fetch, routeCompute, claimRoute, now = Date.now, deadline }) {
  const readIds = new Set(), webQueries = new Set(), routeResults = new Map(); let routes = 0, weatherCalls = 0, blockedSearch = null;
  const searchWeb = async query => {
    if (searchMode === 'site') return toolFailure('site_only');
    if (blockedSearch) return { ...blockedSearch };
    if (webQueries.size >= 2) return toolFailure('web_tool_limit');
    if (PRIVATE_QUERY.test(query) || hasPrivateSearchData(query)) return toolFailure('web_private_query');
    if (deadline - Date.now() < 21000) return toolFailure('research_deadline');
    const q = boundedText(query, 390); if (webQueries.has(q)) return toolFailure('web_duplicate_query');
    webQueries.add(q);
    let result;
    try { result = await webSearch({ query: `${q} — San Francisco Bay Area California USA`, locale, ...(state.date ? { date: state.date } : {}), ...(state.city ? { city: state.city } : {}), ...(state.region ? { region: state.region } : {}) }); }
    catch (error) {
      const failure = normalizeResearchError(error, 'search_web');
      if (!failure.retryable) blockedSearch = failure;
      return { ...failure };
    }
    const sources = result.sources.map(s => store.addSource({ ...s, kind: 'web', checkedAt: result.checkedAt, verification: 'search-result' })).filter(Boolean);
    const found = [];
    for (const c of result.candidates || []) {
      if (state.city && c.city && c.city.toLowerCase() !== state.city.toLowerCase()) continue;
      const ids = sources.filter(s => (c.sourceUrls || []).some(url => canonical(url) === canonical(s.url))).map(s => s.id);
      if (!ids.length || !c.name) continue;
      const matches = [...store.candidates.values()].filter(s => (!s.city || !c.city || identityKey(s.city) === identityKey(c.city)) && candidateNames(s).includes(identityKey(c.name)));
      const matching = matches.length === 1 ? matches[0] : null;
      if (matching) { matching.sourceIds = [...new Set([...matching.sourceIds, ...ids])]; found.push(matching); continue; }
      const id = `web-${idFor(`${c.name}:${c.city || ''}:${sources.find(s => ids.includes(s.id))?.url}`)}`;
      found.push(store.addCandidate({ id, kind: 'unknown', title: c.name, city: c.city || null, summary: c.summary || '', sourceIds: ids, sourceUrls: sources.filter(s => ids.includes(s.id)).map(s => s.url), verification: 'search-result', timeLabel: c.timeSummary, costLabel: c.priceSummary, origin: 'web' }));
    }
    return { answer: result.answer, sources, candidates: found, checkedAt: result.checkedAt, cached: !!result.cached, model: result.model, notice: 'Search summaries are leads, not exact source quotations. Read the page to verify new dated plan stops.' };
  };
  const readSource = async sourceId => {
    const source = store.sources.get(sourceId);
    if (!source || !safeUrl(source.url)) return toolFailure('source_id_invalid');
    if (searchMode === 'site') return toolFailure('site_only');
    if (source.verification === 'page-read') return source;
    if (readIds.has(sourceId)) return toolFailure('source_attempted');
    if (readIds.size >= 3) return toolFailure('source_tool_limit');
    readIds.add(sourceId);
    if (isTest && !sourceFetch) return toolFailure('source_reader_unavailable');
    let page;
    try { page = await (sourceFetch || fetchSource)(source, { timeoutMs: Math.min(6000, Math.max(1, deadline - Date.now())) }); }
    catch (error) { return normalizeResearchError(error, 'read_source'); }
    if (!page?.text || page.text.length < 30) return toolFailure('source_no_readable_text');
    const relatedSources = relevantPageLinks(page.links, source.url).map(link => store.addSource({ ...link, kind: 'web', verification: 'catalog', discoveredFrom: source.id }))
      .map(({ id, title, url }) => ({ id, title, url }));
    return store.addSource({ ...source, text: page.text, verification: 'page-read', checkedAt: new Date(now()).toISOString(),
      ...(relatedSources.length ? { relatedSources, relatedSourceNotice: 'These links were found on this page. Read each linked source before treating its rules as verified.' } : {}) });
  };
  const route = async ({ fromId, toId, time }) => {
    const fail = (code, error) => ({ code, error });
    if (searchMode === 'site') return fail('site_only', 'External route lookup is disabled in site-only mode.');
    // Plan cards expose qualified IDs, while the evidence map uses raw IDs.
    // Only resolve an actual existing row with the matching published kind.
    const resolve = id => {
      if (typeof id !== 'string') return null;
      if (store.candidates.has(id)) return store.candidates.get(id);
      const match = /^(place|event):(.+)$/.exec(id), row = match && store.candidates.get(match[2]);
      return row?.kind === match?.[1] ? row : null;
    };
    const from = resolve(fromId), to = resolve(toId);
    if (!from || !to || from.id === to.id || !locationOK(from.location) || !locationOK(to.location)) return fail('route_coordinates_missing', 'Both route endpoints need verified venue coordinates. Use the candidate id origin for the precise departure point, or a listed candidate id. No travel time is assumed.');
    if (!state.date || !/^\d{2}:\d{2}$/.test(time) || !['drive', 'transit', 'walk'].includes(state.travelMode)) return fail('route_conditions_missing', 'A date, departure time and explicit transport mode are required.');
    let departureAt;
    try { departureAt = localInstant(state.date, time); } catch { return fail('route_time_invalid', 'Choose a valid Bay Area departure date and time.'); }
    if (!Number.isFinite(departureAt) || departureAt < now() || departureAt > now() + 100 * 86400000) return fail('route_time_invalid', 'Route departure must be in the future and within 100 days.');
    const cacheKey = `${from.id}:${to.id}:${departureAt}:${state.travelMode}`;
    if (routeResults.has(cacheKey)) return routeResults.get(cacheKey);
    if (routes >= 3) return fail('route_tool_limit', 'Route lookup budget reached.');
    if (!(isTest && routeCompute) && !(config.PLANNER_TRAVEL_ENABLED === 'true' && config.GOOGLE_ROUTES_API_KEY)) return { available: false, ...fail('route_not_configured', 'Route estimates are not configured; travel duration remains unknown.') };
    routes++; if (claimRoute && !await claimRoute()) return fail('route_daily_limit', 'Route quota reached.');
    const input = { from: { ...from, title: from.title }, to: { ...to, title: to.title }, departureAt: new Date(departureAt).toISOString(), travelMode: state.travelMode, locale };
    try {
      const raw = await travelWithDeadline(signal => routeCompute ? routeCompute(input) : computeTravel(input, { apiKey: config.GOOGLE_ROUTES_API_KEY, fetchImpl, signal }), Math.min(8000, Math.max(1, deadline - Date.now())));
      const result = travelResult(raw, input, now());
      routeResults.set(cacheKey, result);
      return result;
    } catch { return fail('route_provider_unavailable', 'The route provider did not return a usable estimate. Keep this leg unverified.'); }
  };
  const weather = async candidateId => {
    if (searchMode === 'site') return { error: 'External weather lookup is disabled in site-only mode.' };
    if (weatherCalls++ >= 1 || (isTest && fetchImpl === fetch)) return { error: 'Weather lookup unavailable.' };
    const c = store.candidates.get(candidateId);
    if (!locationOK(c?.location)) return { error: 'A candidate with verified coordinates is required.' };
    const read = async url => {
      if (!/^https:\/\/api\.weather\.gov\/(?:points|gridpoints)\//.test(url)) throw new Error('Invalid weather endpoint');
      const r = await fetchImpl(url, { headers: { 'User-Agent': 'BAYLINK/2.0 (https://www.baylink.us)', Accept: 'application/geo+json' }, signal: AbortSignal.timeout(Math.min(5000, Math.max(1, deadline - Date.now()))) });
      if (!r.ok) throw new Error('Weather temporarily unavailable'); return r.json();
    };
    const pointUrl = `https://api.weather.gov/points/${c.location.lat.toFixed(4)},${c.location.lng.toFixed(4)}`;
    const point = await read(pointUrl), forecastUrl = point?.properties?.forecast;
    const forecast = await read(forecastUrl);
    const periods = (forecast?.properties?.periods || []).filter(p => !state.date || String(p.startTime).slice(0, 10) === state.date).slice(0, 2).map(p => ({ name: p.name, startTime: p.startTime, endTime: p.endTime, temperature: p.temperature, temperatureUnit: p.temperatureUnit, windSpeed: p.windSpeed, shortForecast: p.shortForecast, detailedForecast: p.detailedForecast }));
    const source = store.addSource({ title: `National Weather Service — ${c.title}`, url: forecastUrl, kind: 'web', verification: 'api', checkedAt: new Date(now()).toISOString(), text: JSON.stringify(periods) });
    return { sourceId: source.id, periods, notice: periods.length ? 'Forecast, not a guarantee.' : 'The requested date is outside the available forecast.' };
  };
  return { searchWeb, readSource, route, weather };
}
module.exports = { createEvidenceStore, createResearchTools, verifiedCandidate, canonical, normalizeResearchError };
