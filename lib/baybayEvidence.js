const crypto = require('node:crypto');
const { loadPlannerCatalog, eventOccursOn, active, priceOf, admissionLowerBound, validDate, REGIONS } = require('./planner');
const { canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate } = require('./bayAreaSearchScope');
const { validateTaskState } = require('./baybayState');
const { withAdmissionFacts } = require('./baybayFacts');
const { isSchoolRequest, isSchoolGuide } = require('./guideConversation');
const { isLibraryServiceQuestion } = require('./publicResearch');

const STOP = new Set('a an and are as at be by for from how i in is it me my of on or our the this to us we what where with you your can do does would please today tomorrow day plan event events san francisco bay area california'.split(' '));
const CJK_STOP = new Set(['什么', '什麼', '怎么', '怎麼', '可以', '今天', '明天', '安排', '推荐', '推薦', '一下', '有没有', '有沒有', '湾区', '灣區']);
const SYNONYMS = [
  ['wheelchair-access', 'limited-walking', 'stroller-access', '少走路', '不想走太多', '无障碍', '無障礙', 'accessible', 'accessibility', 'wheelchair', 'stroller', '平坦'],
  ['with-seniors', '老人', '长辈', '長輩', 'senior', 'elderly', 'benches', '休息'],
  ['transit', '公共交通', '公交', 'no-car', '不开车', '不開車', 'bart', 'muni', 'caltrain', '交通', '转乘', '轉乘'],
  ['family', '亲子', '親子', '孩子', '小孩', '儿童', '兒童', 'kids', 'children', 'playground'],
  ['utilities', '水电', '水電', '开户', '開戶', '搬家', '供水', '电力', '電力', '垃圾', 'internet', 'water', 'electricity', 'waste'],
  ['shopping', '购物', '購物', 'outlet', 'mall', '商场', '商場', '折扣'],
  ['vegetarian', '素食', 'vegan'],
  ['arts', 'museum', 'museums', '博物馆', '博物館', '艺术', '藝術', '展览', '展覽'],
  ['music', 'concert', 'concerts', '音乐', '音樂', '演唱会', '演唱會'],
  ['food', 'restaurant', 'restaurants', 'dining', '美食', '餐厅', '餐廳'],
];
// Balance explicit subjects in a multi-part question. These are retrieval
// concepts, not factual answers or a list of specially favored providers.
const REQUEST_SUBJECTS = [
  ['printing', /打印|列印|\bprint(?:ing|ers?)?\b/i],
  ['films', /看片|影音|电影|電影|\b(?:kanopy|hoopla|streaming|movies?|films?)\b/i],
  ['passes', /馆票|館票|博物馆门票|博物館門票|(?:借|图书|圖書|library).{0,24}(?:门票|門票|passes)|discover\s*(?:&|and)\s*go|museum passes/i],
  ['eligibility', /资格|資格|居住|居民|年龄|年齡|卡种|卡種|实体卡|實體卡|\b(?:eligib\w*|residen\w*|ecard|card type|age)\b/i],
  ['admission', /票价|票價|收费|收費|\b(?:admission|ticket prices?|fees?)\b/i],
  ['hours', /营业|營業|开放|開放|开馆|開館|\b(?:hours|opening|closed)\b/i],
  ['travel', /交通|公交|路线|路線|\b(?:transit|transport|routes?|travel|parking)\b/i],
  ['food', /午餐|餐饮|餐飲|吃饭|吃飯|\b(?:food|lunch|dining|restaurants?)\b/i],
  ['license', /驾照|駕照|driver.?s? licen[sc]e/i],
  ['registration', /车辆登记|車輛登記|车辆注册|車輛註冊|vehicle registration/i],
  ['address', /地址变更|地址變更|地址更新|更新地址|更改地址|change.{0,12}address|address change/i],
  ['deadlines', /期限|时限|時限|\b(?:deadlines?|time limits?|within\s+\d+\s+days?)\b|\d+\s*(?:天|days?\b)/i],
  ['utilities', /水电|水電|供水|电力|電力|\b(?:utilities|water|electricity|internet|waste)\b/i],
];
const safeUrl = value => {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && value.length <= 2048 ? url.href : null; } catch { return null; }
};
const siteUrl = (value, slug) => typeof value === 'string' && /^\/guides\/[a-zA-Z0-9_-]+(?:#[a-zA-Z0-9_-]+)?$/.test(value)
  ? value : typeof slug === 'string' && /^[a-zA-Z0-9_-]+$/.test(slug) ? `/guides/${slug}` : null;
const fingerprint = value => crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
const normalize = value => normalizeCityMentions(String(value || '')).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const textValue = value => typeof value === 'string' ? value : '';
const rowCities = row => String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/).map(canonicalCity).filter(Boolean);
// Production catalogs are immutable snapshots. Weak ownership permits a reload
// to replace either snapshot without retaining obsolete indexes indefinitely.
const GUIDE_INDEXES = new WeakMap();
const GUIDE_SOURCE_INDEXES = new WeakMap();
const DOCUMENT_INDEXES = new WeakMap();
const EMPTY_CATALOG = Object.freeze({});
const REGION_HINTS = [
  ['sf', /旧金山|舊金山|(?<!south\s)\bsan francisco\b(?!\s+bay area)|\bsf\b/i],
  ['east-bay', /东湾|東灣|\beast[- ]bay\b/i],
  ['south-bay', /南湾|南灣|\bsouth[- ]bay\b/i],
  ['peninsula', /半岛|半島|\bpeninsula\b/i],
  ['north-bay', /北湾|北灣|\bnorth[- ]bay\b/i],
];
const mentionedRegions = text => REGION_HINTS.filter(([, pattern]) => pattern.test(text)).map(([region]) => region);

function requestedSchoolRegions(query, state, catalog) {
  if (/全[湾灣]|整[个個][湾灣][区區]|[湾灣][区區](?:各|所有|不同).{0,6}(?:地[区區]|学[区區])|\b(?:across (?:the )?bay area|all (?:bay area )?regions)\b/i.test(query)) return [];
  const regions = new Set(mentionedRegions(query));
  const cities = new Set(mentionedCities(query));
  for (const row of cities.size ? [...(catalog?.events || []), ...(catalog?.places || [])] : []) {
    if (REGIONS.includes(row.region) && rowCities(row).some(city => cities.has(city))) regions.add(row.region);
  }
  // An explicit cross-region comparison overrides a retained single region;
  // short school follow-ups keep the user's already-established region.
  return regions.size ? [...regions] : REGIONS.includes(state.region) ? [state.region] : [];
}

function tokens(text) {
  const value = normalize(text);
  const result = value.match(/[a-z0-9][a-z0-9'-]{1,39}/g)?.filter(word => !STOP.has(word)) || [];
  for (const segment of value.match(/[\u3400-\u9fff]+/g) || []) {
    if (segment.length === 1) continue;
    for (let index = 0; index < segment.length - 1; index++) {
      const term = segment.slice(index, index + 2);
      if (!CJK_STOP.has(term)) result.push(term);
    }
  }
  return result;
}

function queryTokens(query, state) {
  let semanticQuery = normalizeCityMentions(query).replace(/有什么地方去|有什麼地方去|有什么|有什麼|有没有|有沒有|帮我|幫我|请问|請問|怎么样|怎麼樣|怎么办|怎麼辦|怎么|怎麼|不想|太多|安排一天|安排一下|推荐一下|推薦一下/gi, ' ');
  // Geography is an eligibility constraint, not evidence that a utility query
  // is relevant to every fair in the same city.
  for (const city of mentionedCities(semanticQuery)) semanticQuery = semanticQuery.replace(new RegExp(city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), ' ');
  // A broad inferred category (for example arts from one museum-pass clause)
  // must not drown out the other explicit subjects of an information question.
  // Short follow-ups and outing searches still use their retained topic.
  const multipleSubjects = state.goal === 'information' && REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(query)).length >= 2;
  const original = [semanticQuery, !multipleSubjects && state.topic !== 'any' ? state.topic : '', ...state.preferences, ...(state.childAges.length ? ['family'] : []), state.travelMode].filter(Boolean).join(' ');
  const base = new Set(tokens(original));
  const expanded = new Set(base);
  const lower = normalize(original);
  for (const group of SYNONYMS) if (group.some(word => /[a-z]/i.test(word)
    ? new RegExp(`(?:^|[^a-z])${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z])`, 'i').test(lower)
    : lower.includes(word))) for (const word of group) tokens(word).forEach(term => expanded.add(term));
  return { base, expanded };
}

function scorer(documents, query) {
  const frequencies = new Map();
  let totalLength = 0;
  const indexed = documents.map(document => {
    const cacheKey = document._cacheKey || document;
    let entry = DOCUMENT_INDEXES.get(cacheKey);
    if (!entry) {
      const words = tokens(document.text); const counts = new Map();
      words.forEach(word => counts.set(word, (counts.get(word) || 0) + 1));
      entry = { length: words.length, counts, title: new Set(tokens(document.title || '')) };
      DOCUMENT_INDEXES.set(cacheKey, entry);
    }
    // Only query terms need document frequencies. Walking the entire bilingual
    // vocabulary on every request wastes CPU without changing any BM25 score.
    for (const word of query.expanded) if (entry.counts.has(word)) frequencies.set(word, (frequencies.get(word) || 0) + 1);
    totalLength += entry.length;
    return { document, ...entry };
  });
  const averageLength = totalLength / Math.max(documents.length, 1) || 1;
  return indexed.map(({ document, length, counts, title }) => {
    let score = 0; let covered = 0;
    for (const term of query.expanded) {
      const count = counts.get(term) || 0; const inTitle = title.has(term);
      if (!count && !inTitle) continue;
      const weight = query.base.has(term) ? 1 : 0.42;
      const idf = Math.log(1 + (documents.length - (frequencies.get(term) || 0) + 0.5) / ((frequencies.get(term) || 0) + 0.5));
      score += weight * idf * (count * 2.2 / (count + 1.2 * (0.25 + 0.75 * length / averageLength)) + (inTitle ? 1.8 : 0));
      if (query.base.has(term)) covered++;
    }
    score += covered / Math.max(query.base.size, 1) * 2;
    return { ...document, score };
  });
}

function balancedGuideRows(rows, query) {
  const subjects = REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(query)).slice(0, 8);
  const multipart = subjects.length >= 2;
  const entities = [...new Set((String(query).match(/\b[A-Z][A-Za-z0-9]*(?:[ -]+[A-Z][A-Za-z0-9]*){0,5}\b/g) || [])
    .filter(value => (value.includes(' ') || /^[A-Z]{3,12}$/.test(value)) && !canonicalCity(value)))].slice(0, 6).map(value => {
      const words = value.split(/[ -]+/), initials = words.map(word => word[0]).join('');
      return [...new Set([normalize(value), ...(words.length > 1 ? [initials.toLowerCase(), `${words.slice(0, -1).map(word => word[0]).join('').toLowerCase()} ${words.at(-1).toLowerCase()}`] : [])])];
    });
  const facetRows = rows.map(row => {
    const heading = row._contentHeading || '', primary = subjects.filter(([, pattern]) => pattern.test(heading));
    const topics = primary.length ? primary : subjects.filter(([, pattern]) => pattern.test(row.text));
    const named = normalize(heading);
    const entityIds = entities.flatMap((aliases, index) => aliases.some(alias => ` ${named.replace(/[^\p{L}\p{N} ]/gu, ' ')} `.includes(` ${alias} `)) ? [index] : []);
    return { row, primaryTopics: primary.length, facets: multipart ? topics.flatMap(([id]) => [`topic:${id}`, ...(primary.length ? entityIds.map(index => `entity:${index}:${id}`) : [])]) : [] };
  });
  const selected = [], counts = new Map(), contents = new Set(), covered = new Set();
  const cap = multipart ? Math.min(8, 3 + subjects.length) : 3;
  const boost = (rows[0]?.score || 0) * .35;
  while (selected.length < 8) {
    let best = null, bestScore = -1;
    for (const entry of facetRows) {
      const { row, facets } = entry;
      if (contents.has(row._contentKey) || (counts.get(row.slug) || 0) >= cap) continue;
      // Keep explicitly titled subject records useful after the first topic
      // match: a deadline paragraph must not lose to generic application prose
      // merely because another service already covered the deadlines facet.
      const headingBoost = multipart ? boost * .5 * Math.min(entry.primaryTopics, 2) : 0;
      const score = row.score + headingBoost + boost * facets.filter(facet => !covered.has(facet)).length;
      if (score > bestScore) { best = entry; bestScore = score; }
    }
    if (!best) break;
    selected.push(best.row); contents.add(best.row._contentKey);
    counts.set(best.row.slug, (counts.get(best.row.slug) || 0) + 1);
    best.facets.forEach(facet => covered.add(facet));
  }
  return selected;
}

const referenceKey = value => { const url = new URL(value); url.hash = ''; return url.href.replace(/\/$/, ''); };
function guideSourceIndex(guide) {
  let sources = GUIDE_SOURCE_INDEXES.get(guide);
  if (!sources) {
    const seen = new Set();
    sources = (Array.isArray(guide.sources) ? guide.sources : []).flatMap(source => {
      const url = safeUrl(source?.url); if (!url || seen.has(referenceKey(url))) return [];
      seen.add(referenceKey(url));
      const title = String(source.title || '').slice(0, 300);
      let decoded = url; try { decoded = decodeURIComponent(url); } catch { /* malformed URL escapes remain literal */ }
      return [{ title, url, text: `${title} ${decoded.replace(/[./_?#=&%\-]/g, ' ')}`, cities: mentionedCities(title) }];
    });
    GUIDE_SOURCE_INDEXES.set(guide, sources);
  }
  return sources;
}

function selectedGuideSources(row, terms, state, rankings) {
  const all = row._guideSources;
  let ranked = rankings.get(all);
  if (!ranked) {
    ranked = scorer(all.filter(source => (!state.city || !source.cities.length || source.cities.includes(state.city))
      && !(source.cities.length && source.cities.every(city => state.excludedCities.includes(city)))), terms)
      .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url));
    rankings.set(all, ranked);
  }
  const seen = new Set(), selected = [];
  // Inline links support this exact paragraph; the rest are query-relevant
  // references from the whole guide, not verified facts about this venue.
  for (const source of [...row.sourceUrls, ...ranked]) {
    const key = referenceKey(source.url); if (seen.has(key)) continue;
    seen.add(key);
    const published = all.find(reference => referenceKey(reference.url) === key);
    selected.push({ title: published?.title || source.title, url: source.url });
    if (selected.length === 8) break;
  }
  return selected;
}

function guideParagraphs(guide, catalogCities = []) {
  const slug = textValue(guide.slug); const url = siteUrl(guide.url, slug);
  if (!url || !guide.title || typeof guide.content !== 'string') return [];
  const titleCities = [...new Set([...mentionedCities([guide.title, ...(guide.keywords || [])].join(' ')), ...catalogCities])];
  const schoolRegions = isSchoolGuide(guide) ? REGIONS.includes(guide.region) ? [guide.region]
    : mentionedRegions([guide.slug, guide.title, ...(guide.keywords || [])].join(' ')) : [];
  const isOutingGuide = /游玩|遊玩|出游|出遊|城市指南|景点|景點|博物馆|博物館|美术馆|美術館|公园|公園|野餐|散步|一日|半日|一天|周末|週末|免费|免費|活动|活動|亲子|親子|交通|通勤|购物|購物|餐厅|餐廳|美食|\b(?:outings?|attractions?|museums?|parks?|picnic|day trip|weekend|events?|transit|accessible|accessibility|shopping|dining)\b/i.test([guide.title, guide.summary, ...(guide.keywords || [])].join(' '));
  const raw = guide.content.slice(0, 150000).split(/\n\s*\n/).map(part => part.trim()).filter(Boolean);
  const guideSources = guideSourceIndex(guide);
  const result = []; let sectionCities = titleCities.length === 1 ? titleCities : []; let heading = '';
  for (let index = 0; index < raw.length; index++) {
    const paragraph = raw[index];
    // A county-wide library's name is not its namesake municipality. Keep
    // explicit branch-city mentions, and leave utility/city sections untouched.
    const cityText = isLibraryServiceQuestion(paragraph)
      ? paragraph.replace(/\b(?:San Francisco|San Mateo|Santa Clara|Alameda|Contra Costa|Marin|Sonoma|Napa|Solano)\s+County\b/gi, 'county') : paragraph;
    const cities = mentionedCities(cityText);
    const leadingLines = paragraph.split('\n').slice(0, 2).map(line => canonicalCity(line.replace(/^#+\s*/, '').trim()));
    // The production directory uses two leading lines: County, then City.
    // Alameda County in a supplier name is never the section's municipality.
    const headingCity = leadingLines[1] || leadingLines[0];
    // Carry a short city section's scope into the following paragraphs. This
    // prevents an Oakland utility number under a heading being used for Alameda.
    if (headingCity) { sectionCities = [headingCity]; heading = headingCity; }
    else if (paragraph.length < 130 && !/[。.!?]/.test(paragraph) && cities.length) { sectionCities = cities; heading = paragraph; }
    else if (paragraph.length < 80 && !/[。.!?\n]/.test(paragraph)) { sectionCities = titleCities.length === 1 ? titleCities : []; heading = paragraph; }
    const scope = headingCity ? [headingCity] : cities.length ? cities : sectionCities;
    // A short heading alone is not a factual excerpt.
    if (paragraph.length < 36 && index + 1 < raw.length) continue;
    const chunks = paragraph.match(/[\s\S]{1,1600}/g) || [];
    for (let chunkIndex = 0; chunkIndex < Math.min(chunks.length, 6); chunkIndex++) {
      const text = [heading && heading !== paragraph && (!headingCity || chunkIndex > 0) ? heading : '', chunks[chunkIndex].trim()].filter(Boolean).join('\n');
      result.push({ id: slug, slug, evidenceId: `site-guide:${slug}:${fingerprint(text)}`, title: String(guide.title).slice(0, 300), url, text,
        updatedAt: validDate(guide.updatedAt) ? guide.updatedAt : null,
        sourceKind: 'site-guide', verification: 'site-record', verifiedLive: false,
        cities: scope, _guideCities: titleCities, _isOutingGuide: isOutingGuide, _schoolRegions: schoolRegions,
        _contentKey: fingerprint(chunks[chunkIndex].trim()),
        // Inline editorial records carry their own first-line heading. A plain
        // prose paragraph instead belongs to the preceding section heading;
        // incidental mentions of other services are not its primary subject.
        _contentHeading: chunks[chunkIndex].includes('\n') ? chunks[chunkIndex].trim().split('\n')[0] : heading || chunks[chunkIndex].trim(),
        sourceUrls: [...new Set((paragraph.match(/https:\/\/[^\s<>"）)]+/g) || []).map(safeUrl).filter(Boolean))].map(url => ({ title: String(guide.title).slice(0, 300), url })),
        _guideSources: guideSources,
      });
    }
  }
  return result;
}

function indexedGuideDocuments(guideCatalog, catalog) {
  if (!Array.isArray(guideCatalog)) return [];
  let snapshots = GUIDE_INDEXES.get(guideCatalog);
  if (!snapshots) { snapshots = new WeakMap(); GUIDE_INDEXES.set(guideCatalog, snapshots); }
  const catalogKey = catalog || EMPTY_CATALOG;
  let documents = snapshots.get(catalogKey);
  if (!documents) {
    const cityByGuide = new Map();
    for (const row of [...(catalog?.events || []), ...(catalog?.places || [])]) if (row.guideSlug) cityByGuide.set(row.guideSlug, [...new Set([...(cityByGuide.get(row.guideSlug) || []), ...rowCities(row)])]);
    documents = guideCatalog.slice(0, 10000).flatMap(guide => guideParagraphs(guide, cityByGuide.get(guide.slug)));
    snapshots.set(catalogKey, documents);
  }
  return documents;
}

function paragraphFits(row, state, schoolRegions = []) {
  if (['day-plan', 'discover'].includes(state.goal) && !row._isOutingGuide) return false;
  if (schoolRegions.length && row._schoolRegions.length && !row._schoolRegions.some(region => schoolRegions.includes(region))) return false;
  if (state.city && row._guideCities.length === 1 && row._guideCities[0] !== state.city) return false;
  if (row._guideCities.length === 1 && state.excludedCities.includes(row._guideCities[0])) return false;
  if (state.city && row.cities.length && !row.cities.includes(state.city)) return false;
  return !(row.cities.length && row.cities.every(city => state.excludedCities.includes(city)));
}

function sourceSpecificity(url) {
  try {
    const path = new URL(url).pathname.replace(/\/+$/, '').toLowerCase();
    return !path || /^\/(?:events?|calendar|activities|whats-on|things-to-do)(?:\/calendar)?$/.test(path) ? 'directory' : 'direct';
  } catch { return 'unknown'; }
}

function isGenerallyFree(row) {
  return row.cost === 'free' && priceOf(row) === 0
    && !/(?:居民|会员|會員|学生|學生|\d\s*[岁歲]|\b(?:residents?|members?|students?|under\s+\d|children))[^。;；]{0,35}(?:免费|免費|\bfree\b)|\bfree\b[^。.;；]{0,35}\b(?:for|to)\s+(?:(?:eligible|qualifying|local|all)\s+)?(?:residents?|members?|students?|children|kids?|under\s+\d|library card holders?)\b|(?:仅限|僅限|须|須|需要|需先)(?:购买|購買|消费|消費)|\bfree\b[^。.;；]{0,35}\bwith (?:a )?purchase\b/i.test([row.costLabel, ...(row.plan || [])].filter(Boolean).join(' '));
}

function candidateFits(row, kind, state, today) {
  if (!active(row)) return false;
  if (state.goal === 'day-plan' && row.id === state.originCandidateId) return false;
  const cities = rowCities(row);
  if (state.city && !cities.includes(state.city)) return false;
  if (cities.length && cities.every(city => state.excludedCities.includes(city))) return false;
  if (state.region && state.region !== 'all' && !state.city && row.region !== state.region) return false;
  if (state.excludedCandidateIds.includes(row.id) || state.excludedCandidateIds.includes(`${kind}:${row.id}`)) return false;
  if (kind === 'event') {
    if (!validDate(row.startDate) || !validDate(row.endDate) || row.endDate < (state.date || today)) return false;
    if (state.date && !eventOccursOn(row, state.date)) return false;
    if (row.occurrenceDates !== undefined && !row.occurrenceDates.some(date => date >= (state.date || today))) return false;
    if (row.startDate !== row.endDate && row.occurrenceDates === undefined && /每(?:周|週|星期|月)|\bevery\s+(?:week|month|mon|tue|wed|thu|fri|sat|sun)/i.test(`${row.dateLabel || ''} ${row.summary || ''}`)) return false;
  }
  if (state.freeOnly && (!isGenerallyFree(row) || (kind === 'place' && /每(?:周|週|星期|月)|\bevery\s+(?:week|month|mon|tue|wed|thu|fri|sat|sun)/i.test(row.costLabel || '')))) return false;
  if (state.setting && state.setting !== 'any' && row.planning?.setting && row.planning.setting !== state.setting) return false;
  if (state.childAges.some(age => (Number.isFinite(row.planning?.minAge) && age < row.planning.minAge) || (Number.isFinite(row.planning?.maxAge) && age > row.planning.maxAge))) return false;
  if (state.childAges.length && /仅限成人|僅限成人|不适合儿童|不適合兒童|adults?[- ]only|\b(?:18|21)\s*\+/i.test([row.title, row.summary, ...(row.plan || [])].join(' '))) return false;
  const lowerBound = admissionLowerBound(row);
  const maximum = state.budgetScope === 'total' ? state.partySize ? state.budget / state.partySize : null : state.budget;
  if (state.budget !== null && maximum !== null && lowerBound !== null && lowerBound > maximum) return false;
  return true;
}

function normalizeCandidate(row, kind, checkedAt, state) {
  const url = safeUrl(row.officialUrl);
  const evidenceId = `site-${kind}:${row.id}`;
  return {
    ...row, kind, id: row.id, candidateId: `${kind}:${row.id}`, evidenceId,
    officialUrl: url, sourceKind: 'site-catalog', verification: 'site-record', verifiedLive: false,
    recordedAt: validDate(row.verifiedAt) ? row.verifiedAt : checkedAt,
    sourceSpecificity: sourceSpecificity(url),
    catalogDateMatch: kind === 'event' && !!state.date && eventOccursOn(row, state.date),
    // The catalog preserves editorial facts and source links, but does not
    // establish current opening, a reservation, or live ticket availability.
    requiresVerification: ['current-status', ...(kind === 'place' ? ['opening-hours'] : ['session-time']), 'admission-conditions', 'availability'],
  };
}

/** Relevant site paragraphs and strict catalog matches share provenance, while
 * staying explicitly separate from subsequently fetched official-page facts. */
function buildSiteEvidence({ query = '', originalQuery, state: inputState, guideCatalog = [], catalog: suppliedCatalog, today = bayAreaDate() } = {}) {
  const state = validateTaskState(inputState);
  const catalog = loadPlannerCatalog(suppliedCatalog);
  // Locale aliases may translate ordinary words inside an institution's proper
  // name. Retain the original question for named-entity and subject balancing.
  const intentQuery = typeof originalQuery === 'string' ? originalQuery.slice(0, 4000) : String(query).slice(0, 4000);
  const schoolRequest = isSchoolRequest(intentQuery);
  const libraryRequest = ['information', 'newcomer'].includes(state.goal) && isLibraryServiceQuestion(intentQuery);
  const schoolSlugs = schoolRequest ? new Set(guideCatalog.filter(isSchoolGuide).map(guide => guide.slug)) : null;
  const schoolRegions = schoolRequest ? requestedSchoolRegions(intentQuery, state, catalog) : [];
  const retrievalState = schoolRequest && mentionedCities(intentQuery).length > 1 ? { ...state, city: null } : state;
  const terms = queryTokens(String(query).slice(0, 4000), state);
  // Within education guides, the named cities identify the relevant district
  // comparison. Removing both names would rank generic enrollment prose from
  // unrelated regions above the actual boundary-check paragraph.
  if (schoolRequest) for (const term of tokens(mentionedCities(intentQuery).join(' '))) { terms.base.add(term); terms.expanded.add(term); }
  // Eligibility is evaluated on every request; only immutable source parsing
  // and tokenization are cached. No query, filter result or model answer is cached.
  let documents = indexedGuideDocuments(guideCatalog, catalog).filter(row => (!schoolSlugs || schoolSlugs.has(row.slug)) && paragraphFits(row, retrievalState, schoolRegions));
  if (libraryRequest) {
    const libraryDocuments = documents.filter(row => isLibraryServiceQuestion(row.text));
    // Sparse catalogs can have only a general benefits paragraph with a
    // library source link. Do not erase that lead when no topical text exists.
    if (libraryDocuments.length) documents = libraryDocuments;
  }
  const guideScores = scorer(documents, terms).filter(row => row.score > 0).map(row => ({ ...row, score: row.score * (state.city && row.cities.length === 1 && row.cities[0] === state.city ? 1.6 : 1) })).sort((a, b) => b.score - a.score || a.evidenceId.localeCompare(b.evidenceId));
  const sourceRankings = new Map(); const guides = [];
  for (const row of balancedGuideRows(guideScores, intentQuery)) {
    const { score, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, ...guide } = row;
    guides.push({ ...guide, sectionHeading: _contentHeading, requestedTopics: REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(intentQuery) && pattern.test(guide.text)).map(([id]) => id),
      cities: [...guide.cities], sourceUrls: selectedGuideSources(row, terms, retrievalState, sourceRankings), relevance: Number(score.toFixed(3)) });
    if (guides.length === 8) break;
  }
  let candidates = [];
  if (catalog && validDate(today)) {
    const rows = [['event', catalog.events], ['place', catalog.places]].flatMap(([kind, entries]) => entries
      .filter(row => safeUrl(row.officialUrl) && candidateFits(row, kind, state, today))
      .map(row => ({ ...normalizeCandidate(row, kind, catalog.checkedAt, state), _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || [])].join(' ') })));
    const namedAcronyms = String(query).match(/\b[A-Z][A-Z0-9]{2,11}\b/g)?.filter(term => !['BART', 'MUNI', 'SFO', 'SJC', 'OAK', 'USD', 'USA', 'THE', 'AND', 'BAYLINK'].includes(term)) || [];
    const selectionRank = row => state.selectedCandidateIds.findIndex(id => id === row.id || id === row.candidateId);
    candidates = scorer(rows, terms).filter(row => {
      if (schoolRequest || ['newcomer', 'transit'].includes(state.goal)) return false;
      // Explicit selected identities still pass candidateFits above. Query
      // shorthand or an acronym cannot hide an otherwise eligible chosen stop.
      if (selectionRank(row) >= 0) return true;
      if (namedAcronyms.length && !namedAcronyms.some(term => new RegExp(`\\b${term}\\b`, 'i').test(row.text))) return false;
      // A general venue/utility/transport question must not receive arbitrary
      // nearby festivals merely because they satisfy city and date filters.
      return ['day-plan', 'discover'].includes(state.goal) || row.score > 0;
    }).sort((a, b) => {
      const rankA = selectionRank(a), rankB = selectionRank(b);
      if (rankA >= 0 || rankB >= 0) return rankA < 0 ? 1 : rankB < 0 ? -1 : rankA - rankB;
      return b.score - a.score || a.id.localeCompare(b.id);
    }).slice(0, 6).map(({ text, score, _cacheKey, ...row }) => withAdmissionFacts({ ...row, relevance: Number(score.toFixed(3)) }, state, { today }));
  }
  const origins = catalog && state.originCandidateId ? [['event', catalog.events], ['place', catalog.places]].flatMap(([kind, entries]) => entries
    .filter(row => row.id === state.originCandidateId && row.location?.precision === 'venue'
      && Number.isFinite(row.location.lat) && Number.isFinite(row.location.lng)
      && row.location.lat >= 36 && row.location.lat <= 40 && row.location.lng >= -124 && row.location.lng <= -120)
    .map(row => normalizeCandidate(row, kind, catalog.checkedAt, state))) : [];
  const originCandidate = origins.length === 1 ? origins[0] : null;
  const sources = [
    ...guides.map(guide => ({ id: guide.evidenceId, evidenceId: guide.evidenceId, title: guide.title, url: guide.url, sourceKind: guide.sourceKind, verification: guide.verification, recordedAt: guide.updatedAt, verifiedLive: false })),
    ...candidates.map(row => ({ id: row.evidenceId, evidenceId: row.evidenceId, title: row.title, titleOrigin: 'candidate', url: row.officialUrl, sourceKind: row.sourceKind, verification: row.verification, recordedAt: row.recordedAt, sourceSpecificity: row.sourceSpecificity, verifiedLive: false })),
  ];
  return { guides, candidates, sources, ...(originCandidate ? { originCandidate } : {}) };
}

module.exports = { buildSiteEvidence };
