const crypto = require('node:crypto');
const { fetchSource } = require('./sourceMonitor');
const { safeUrl } = require('./plannerWebSearch');
const { inferFilters } = require('./planner');
const { computeTravel, travelResult, travelWithDeadline } = require('./plannerTravel');
const { localInstant } = require('./serviceBookings');

const flat = s => String(s || '').replace(/\s+/g, ' ').trim();
const canonical = value => { const url = safeUrl(value); if (!url) return null; const u = new URL(url); for (const k of [...u.searchParams.keys()]) if (/^utm_|^fbclid$|^gclid$/i.test(k)) u.searchParams.delete(k); return u.href.replace(/\/$/, ''); };
const idFor = value => crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
const boundedText = (v, max = 500) => flat(v).slice(0, max);
const locationOK = c => c?.precision === 'venue' && Number.isFinite(c?.lat) && Number.isFinite(c?.lng) && c.lat >= 36 && c.lat <= 40 && c.lng >= -124 && c.lng <= -120;
const PRIVATE_QUERY = /\b\d{3}-\d{2}-\d{4}\b|\bsk-[\w-]{12,}|(?:password|api[_ -]?key|access[_ -]?token|密码|密碼)\s*[:=：]\s*\S+|\b\d{1,6}\s+(?:[\w.'-]+\s+){0,5}(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|way|boulevard|blvd)\b|[^\s]+@[^\s]+|\b\d{3}[-.]\d{3}[-.]\d{4}\b/i;
const PRICE_FIELDS = ['admissionUsd', 'admission', 'admissionScope', 'admissionAppliesTo', 'admissionEligibility', 'feesIncluded'];

function createEvidenceStore(initial = {}) {
  const sources = new Map(), candidates = new Map();
  const addSource = row => {
    const url = row?.url?.startsWith('/guides/') ? row.url : canonical(row?.url);
    if (!url) return null;
    const id = `s-${idFor(url)}`, previous = sources.get(id);
    const value = { ...previous, ...row, id, url, title: boundedText(row.title || previous?.title || url, 220), text: String(row.text || previous?.text || '').slice(0, 9000),
      checkedAt: row.checkedAt || row.recordedAt || row.updatedAt || previous?.checkedAt,
      recordedAt: row.recordedAt || row.updatedAt || previous?.recordedAt };
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
    const sourceIds = [...new Set([...(row.sourceIds || []), ...(row.sourceUrls || []), row.officialUrl].map(value => sources.has(value) ? value : value && addSource({ url: typeof value === 'string' ? value : value.url, title: value.title || row.title, kind: row.kind === 'event' ? 'event' : 'place', verification: 'catalog', checkedAt: row.checkedAt || row.recordedAt || row.verifiedAt, recordedAt: row.recordedAt || row.verifiedAt })?.id).filter(Boolean))];
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
  if (!name || !name.toLowerCase().includes(flat(candidate.title).toLowerCase())) return { error: 'The page must contain the candidate name in the supplied exact quotation.' };
  const next = { ...candidate, verifiedFacts: { ...candidate.verifiedFacts }, checkedAt: source.checkedAt };
  const external = candidate.origin === 'web' || candidate.sourceKind === 'web' || candidate.external === true || /^web-/.test(candidate.id);
  const proposedKind = external ? (['event', 'place'].includes(kind) ? kind : candidate.verifiedFacts?.kind ? candidate.kind : 'unknown') : candidate.kind;
  const city = exact('city');
  if (city && candidate.city && city.toLowerCase().includes(candidate.city.toLowerCase())) next.verifiedFacts.city = city;
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
      if (!obviousEvent && permanent && venue.toLowerCase().includes(flat(candidate.title).toLowerCase())) { next.kind = 'place'; next.verifiedFacts.kind = venue; next.verifiedFacts.venue = venue; }
    }
  }
  const admission = exact('admission');
  if (admission) {
    next.costLabel = admission; next.verifiedFacts.admission = admission;
    // A new quotation supersedes stale numeric/tier prices. Keep the quotation
    // but do not infer a party price from a mixed table or a conditional offer.
    next.planning = { ...candidate.planning, admissionUsd: null, admission: null, admissionScope: null, admissionAppliesTo: null, admissionEligibility: null, feesIncluded: false };
    const unqualifiedFree = /\b(?:free (?:general )?(?:admission|entry)|(?:general )?(?:admission|entry)\s*(?:is|:)?\s*free)\b|免费入场|免費入場|入场免费|入場免費/i.test(admission)
      && !/\b(?:for (?:members|children|kids|residents|students)|with[^.;。；]{0,50}\b(?:purchase|purchases|spend|spending)|buy one|get one|bogo)\b|会员|會員|儿童|兒童|居民|学生|學生|买一|買一|消费|消費/i.test(admission);
    next.cost = unqualifiedFree ? 'free' : /(?:admission|entry|入场|入場|门票|門票)[^.;。；]{0,25}(?:\$\s*\d|USD\s*\d)|\$\s*\d[^.;。；]{0,20}(?:admission|entry)/i.test(admission) ? 'paid' : 'unknown';
  }
  for (const key of ['hours', 'address']) { const quote = exact(key); if (quote) { next.verifiedFacts[key] = quote; if (key === 'address') next.address = quote; else next.planning = { ...(next.planning || candidate.planning), schedule: null }; } }
  const closed = exact('closed');
  if (closed && /sold out|event full|cancelled|canceled|permanently closed|已满|已滿|售罄|取消|暂停|暫停/i.test(closed)) { next.availability = 'unavailable'; next.verifiedFacts.closed = closed; }
  next.verification = next.verifiedFacts.city && ['event', 'place'].includes(next.kind) && (next.kind !== 'event' || next.verifiedFacts.date) ? 'page-verified' : 'partial';
  return next;
}

function createResearchTools({ store, state, today, locale, searchMode, webSearch, config = {}, isTest = false, sourceFetch, fetchImpl = fetch, routeCompute, claimRoute, now = Date.now, deadline }) {
  const readIds = new Set(), webQueries = new Set(), routeResults = new Map(); let routes = 0, weatherCalls = 0;
  const searchWeb = async query => {
    if (searchMode === 'site') return { error: 'The user selected site-only. External lookup is disabled.' };
    if (webQueries.size >= 2) return { error: 'Web lookup budget reached. Use the evidence already retrieved.' };
    if (PRIVATE_QUERY.test(query)) return { error: 'Use only a public venue name, city and topic; omit addresses, contact details and secrets.' };
    if (deadline - Date.now() < 21000) return { error: 'Not enough research time remains for another web lookup.' };
    const q = boundedText(query, 390); if (webQueries.has(q)) return { error: 'This query was already searched.' };
    webQueries.add(q);
    const result = await webSearch({ query: `${q} — San Francisco Bay Area California USA`, locale, ...(state.date ? { date: state.date } : {}), ...(state.city ? { city: state.city } : {}), ...(state.region ? { region: state.region } : {}) });
    const sources = result.sources.map(s => store.addSource({ ...s, kind: 'web', checkedAt: result.checkedAt, verification: 'search-result' })).filter(Boolean);
    const found = [];
    for (const c of result.candidates || []) {
      if (state.city && c.city && c.city.toLowerCase() !== state.city.toLowerCase()) continue;
      const ids = sources.filter(s => (c.sourceUrls || []).some(url => canonical(url) === canonical(s.url))).map(s => s.id);
      if (!ids.length || !c.name) continue;
      const matching = [...store.candidates.values()].find(s => (!s.city || !c.city || s.city.toLowerCase() === c.city.toLowerCase()) && (flat(s.title).toLowerCase() === flat(c.name).toLowerCase() || (s.sourceIds?.some(id => ids.includes(id)) && flat(s.title).toLowerCase().includes(flat(c.name).toLowerCase()))));
      if (matching) { matching.sourceIds = [...new Set([...matching.sourceIds, ...ids])]; found.push(matching); continue; }
      const id = `web-${idFor(`${c.name}:${c.city || ''}:${sources.find(s => ids.includes(s.id))?.url}`)}`;
      found.push(store.addCandidate({ id, kind: 'unknown', title: c.name, city: c.city || null, summary: c.summary || '', sourceIds: ids, sourceUrls: sources.filter(s => ids.includes(s.id)).map(s => s.url), verification: 'search-result', timeLabel: c.timeSummary, costLabel: c.priceSummary, origin: 'web' }));
    }
    return { answer: result.answer, sources, candidates: found, checkedAt: result.checkedAt, cached: !!result.cached, model: result.model, notice: 'Search summaries are leads, not exact source quotations. Read the page to verify new dated plan stops.' };
  };
  const readSource = async sourceId => {
    const source = store.sources.get(sourceId);
    if (!source || !safeUrl(source.url)) return { error: 'Choose an existing public source ID.' };
    if (searchMode === 'site') return { error: 'External pages are disabled in site-only mode.' };
    if (source.verification === 'page-read') return source;
    if (readIds.has(sourceId)) return { error: 'This page was already attempted and did not produce readable evidence.' };
    if (readIds.size >= 3) return { error: 'Source reading limit reached.' };
    readIds.add(sourceId);
    if (isTest && !sourceFetch) return { error: 'No source reader injected for this test.' };
    const page = await (sourceFetch || fetchSource)(source, { timeoutMs: Math.min(6000, Math.max(1, deadline - Date.now())) });
    if (!page?.text || page.text.length < 30) return { error: 'The page did not provide readable text.' };
    return store.addSource({ ...source, text: page.text, verification: 'page-read', checkedAt: new Date(now()).toISOString() });
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
module.exports = { createEvidenceStore, createResearchTools, verifiedCandidate, canonical };
