const crypto = require('node:crypto');
const { namedEntities, namedEntitiesV2, queryAliases, dateRangeFor } = require('./entityAliases');
const { loadPlannerCatalog, eventOccursOn, active, priceOf, admissionLowerBound, validDate, REGIONS } = require('./planner');
const { canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate } = require('./bayAreaSearchScope');
const { validateTaskState } = require('./baybayState');
const { withAdmissionFacts } = require('./baybayFacts');
const { isSchoolRequest, isSchoolGuide, guideEditionMonth, guideEditionThroughDate, isGuideArchived } = require('./guideConversation');
const { isLibraryServiceQuestion } = require('./publicResearch');
const { foodRequest, matchesFoodEvidence } = require('./foodEvidence');
const { eventStatus, eventHalted, soldOut, eventStatusLabel, eventStatusNote } = require('./eventStatus');
const { englishAlias } = require('./baybayQuality');
const { railFit } = require('./baybayTransit');

const STOP = new Set('a an and are as at be by for from how i in is it me my of on or our the this to us we what where with you your can do does would please today tomorrow day plan event events san francisco bay area california'.split(' '));
const CJK_STOP = new Set(['什么', '什麼', '怎么', '怎麼', '可以', '今天', '明天', '安排', '推荐', '推薦', '一下', '有没有', '有沒有', '湾区', '灣區']);
const SYNONYMS = [
  ['wheelchair-access', 'limited-walking', 'stroller-access', '少走路', '不想走太多', '无障碍', '無障礙', 'accessible', 'accessibility', 'wheelchair', 'stroller', '平坦'],
  ['with-seniors', '老人', '长辈', '長輩', 'senior', 'elderly', 'benches', '休息'],
  ['transit', '公共交通', '公交', 'no-car', '不开车', '不開車', 'bart', 'muni', 'caltrain', '交通', '转乘', '轉乘'],
  ['family', '亲子', '親子', '孩子', '小孩', '儿童', '兒童', '全年龄', '全年齡', 'all ages', 'all-ages', 'kids', 'children', 'playground'],
  ['毛绒', '毛絨', '绒毛', '絨毛', 'fuzzy', 'plush'],
  ['utilities', '水电', '水電', '开户', '開戶', '搬家', '供水', '电力', '電力', '垃圾', 'internet', 'water', 'electricity', 'waste'],
  ['shopping', '购物', '購物', 'outlet', 'mall', '商场', '商場', '折扣'],
  ['vegetarian', '素食', 'vegan'],
  // API-BB-4B: a library branch is a library (列治文分馆 for 旧金山图书馆).
  ['library', 'libraries', '图书馆', '圖書館', '分馆', '分館'],
  ['arts', 'museum', 'museums', '博物馆', '博物館', '艺术', '藝術', '展览', '展覽'],
  ['music', 'concert', 'concerts', '音乐', '音樂', '演唱会', '演唱會'],
  ['food', 'restaurant', 'restaurants', 'dining', 'cafe', 'cafes', 'bakery', 'bakeries', '美食', '餐厅', '餐廳', '吃饭', '吃飯', '好吃', '咖啡店', '烘焙店', '饮茶', '飲茶', '点心', '點心', 'dim sum'],
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
  ['deadlines', /期限|时限|時限|\b(?:deadlines?|time limits?|within\s+\d+\s+days?)\b|(?<!\d)\d+\s*(?:天|days?\b)/i],
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

// SYNONYMS compiled once (API-BB-4B, first-sentence speed): a word with Latin letters matches
// as a whole word, a CJK word as a substring; `terms` are the word's own tokens.
let SYNONYM_MATCHERS_CACHE = null;
const synonymMatchers = () => SYNONYM_MATCHERS_CACHE ||= SYNONYMS.map(group => group.map(word => ({ word,
  pattern: /[a-z]/i.test(word) ? new RegExp(`(?:^|[^a-z])${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z])`, 'i') : null, terms: tokens(word) })));

function queryTokens(query, state) {
  const SYNONYM_MATCHERS = synonymMatchers();
  // A correction such as “do not apply Brand A's rules” excludes that
  // provider as evidence; it must not outrank the provider now being asked
  // about. Keep other negatives (price, age and access constraints) intact.
  const focusedQuery = query.replace(/(?:别|別|不要)(?:再)?把[^。！？!?\n,，;；]{0,100}(?:套(?:过|過)?(?:来|來|去)|混用|混在一起)[^。！？!?\n,，;；]*/g, ' ')
    .replace(/\b(?:do not|don['’]t)\s+(?:apply|use|mix in)\b[^.!?\n,;]{0,100}\brules?\b[^.!?\n,;]*/gi, ' ');
  let semanticQuery = normalizeCityMentions(focusedQuery).replace(/\b([a-z0-9]+)['’]s\b/gi, '$1')
    .replace(/有什么地方去|有什麼地方去|有什么|有什麼|有没有|有沒有|帮我|幫我|请问|請問|怎么样|怎麼樣|怎么办|怎麼辦|怎么|怎麼|不想|太多|安排一天|安排一下|推荐一下|推薦一下/gi, ' ');
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
  for (const group of SYNONYM_MATCHERS) if (group.some(({ word, pattern }) => pattern ? pattern.test(lower) : lower.includes(word))) for (const { terms } of group) terms.forEach(term => expanded.add(term));
  return { base, expanded };
}

// `keep(document, score)` (API-BB-4B, first-sentence speed): a caller that drops most
// documents right after scoring (the ~3,000 guide paragraphs, of which a question matches a
// few dozen) gets only the kept ones back, so the rest are never copied. Scores, order and
// the kept rows are exactly what the full list filtered by the same test would give.
// The token index of a record's text. A catalog row is searched with more than one text (the
// candidate text, the city-recall text with its category, an English ask's text with its English
// aliases), so the index is kept per text: which one a process happened to build first never
// changes another question's scores (API-BB-4B; before, the first text built was reused).
function documentEntry(document) {
  const cacheKey = document._cacheKey || document;
  let byText = DOCUMENT_INDEXES.get(cacheKey);
  if (!byText) { byText = new Map(); DOCUMENT_INDEXES.set(cacheKey, byText); }
  const text = String(document.text ?? ''), title = String(document.title || ''), variant = `${title}\u0000${text}`;
  let entry = byText.get(variant);
  if (!entry) {
    const words = tokens(text); const counts = new Map();
    words.forEach(word => counts.set(word, (counts.get(word) || 0) + 1));
    entry = { length: words.length, counts, title: new Set(tokens(title)) };
    byText.set(variant, entry);
  }
  return entry;
}
/** BM25 of one document (terms in the query's order, so every caller sums identically). */
function documentScore({ length, counts, title }, query, size, frequencies, averageLength) {
  let score = 0; let covered = 0;
  for (const term of query.expanded) {
    const count = counts.get(term) || 0; const inTitle = title.has(term);
    if (!count && !inTitle) continue;
    const weight = query.base.has(term) ? 1 : 0.42;
    const idf = Math.log(1 + (size - (frequencies.get(term) || 0) + 0.5) / ((frequencies.get(term) || 0) + 0.5));
    score += weight * idf * (count * 2.2 / (count + 1.2 * (0.25 + 0.75 * length / averageLength)) + (inTitle ? 1.8 : 0));
    if (query.base.has(term)) covered++;
  }
  return score + covered / Math.max(query.base.size, 1) * 2;
}
// API-BB-5 (API-SYNC-3c follow-up 2): a day word in the question is a date constraint (candidateFits applies
// it), and 两个 / 几个 a count, not a subject. A catalog row whose title says 周末 or 周六 ("感恩节周末桌游夜", "创意周六") no longer
// outranks the asked subject whatever its day; guide paragraphs still use every question term.
const DAY_TERMS = new Set(tokens('周末 週末 周六 週六 周日 週日 星期六 星期日 星期天 礼拜六 礼拜天 禮拜六 禮拜天 今天 明天 后天 後天 这周 這週 本周 本週 下周 下週 weekend weekends saturday saturdays sunday sundays today tomorrow tonight 一个 一個 两个 兩個 三个 三個 几个 幾個'));
// Not a subject in an English ask: a day of the month, a month, or a function word ("Are there any …").
const MONTH_TERMS = /^(?:\d+(?:st|nd|rd|th)?|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|there|any|anything|some|something|which|when|who|that|have|has|should|could|will|if|about|also|just|so|them|they|their|these|those|good|nice|fun|things?|places?|ideas?|options?|recommend\w*|suggest\w*)$/;
// Where, not what, in an English ask (review round 1).
const REGION_TERMS = /^(?:south|north|east|west|southern|northern|eastern|western|peninsula|bay|area|areas|near|nearby|around|close|local|region|downtown)$/;
const withoutDayTerms = terms => ({ base: new Set([...terms.base].filter(term => !DAY_TERMS.has(term))), expanded: new Set([...terms.expanded].filter(term => !DAY_TERMS.has(term))) });
// API-SYNC-3f: the numbers that write the asked date (11月14日, 12月, 12/5) are a date constraint too, not a subject.
// With web #47's winter rows, "12" of 12月 matched "建议 5–12 岁" (a Home Depot paragraph led a Christmas parade ask) and
// "11" + "14" of 11月14日 matched every row dated 11/14 (ZooLights and the ice rink pushed a Cantonese film out of a
// Chinese book club ask). Only for an ask with a date (24/7 is not one), only a calendar month and day, matched on the
// NFKC form (tokens fold １２月 to 12), and a bare day after 月 counts unless a count or age follows (12月26带娃, not 12月3个).
const DATE_NUMBERS = /(?<!\d)(\d{1,2})\s*月(?:\s*(\d{1,2})(?:\s*[日号號]|(?![\d岁歲个個点點])))?|(?<![\d/.])(\d{1,2})\/(\d{1,2})(?![\d/.])/g;
const calendarDay = (month, day) => Number(month) >= 1 && Number(month) <= 12 && (day === undefined || (Number(day) >= 1 && Number(day) <= 31));
function withoutDateNumbers(terms, message, state) {
  if (!state || !(state.date || state.dateRange)) return terms;
  const numbers = new Set([...String(message || '').normalize('NFKC').matchAll(DATE_NUMBERS)].flatMap(match => {
    const [month, day] = match[1] ? [match[1], match[2]] : [match[3], match[4]];
    return calendarDay(month, day) ? [month, day].filter(Boolean) : [];
  }));
  return numbers.size ? { base: new Set([...terms.base].filter(term => !numbers.has(term))), expanded: new Set([...terms.expanded].filter(term => !numbers.has(term))) } : terms;
}
function scorer(documents, query, keep) {
  const frequencies = new Map();
  let totalLength = 0;
  const entries = new Array(documents.length);
  for (let index = 0; index < documents.length; index++) {
    const entry = documentEntry(documents[index]);
    // Only query terms need document frequencies. Walking the entire bilingual
    // vocabulary on every request wastes CPU without changing any BM25 score.
    for (const word of query.expanded) if (entry.counts.has(word)) frequencies.set(word, (frequencies.get(word) || 0) + 1);
    totalLength += entry.length;
    entries[index] = entry;
  }
  const averageLength = totalLength / Math.max(documents.length, 1) || 1;
  const scored = [];
  for (let index = 0; index < documents.length; index++) {
    const score = documentScore(entries[index], query, documents.length, frequencies, averageLength);
    if (!keep || keep(documents[index], score)) scored.push({ ...documents[index], score });
  }
  return scored;
}

// API-BB-4B (first-sentence speed): the guide paragraphs (~3,000) are scored on every
// question, and a question shares terms with a few dozen of them. A term → paragraph index
// over the whole cached corpus (built once per catalog snapshot) finds those, and only they
// are scored; the rest score exactly 0. Document frequencies, lengths and the output (kept
// rows in input order, the same scores to the bit) are those of scorer() on the same subset.
const CORPUS_INDEXES = new WeakMap();
function corpusIndex(corpus) {
  let index = CORPUS_INDEXES.get(corpus);
  if (!index) {
    const positions = new Map(), entries = new Array(corpus.length), postings = new Map(), titles = new Map();
    const post = (map, term, at) => { const list = map.get(term); if (list) list.push(at); else map.set(term, [at]); };
    corpus.forEach((document, at) => {
      positions.set(document, at);
      const entry = entries[at] = documentEntry(document);
      for (const term of entry.counts.keys()) post(postings, term, at);
      for (const term of entry.title) post(titles, term, at);
    });
    index = { positions, entries, postings, titles, stamp: new Uint32Array(corpus.length), generation: 0 };
    CORPUS_INDEXES.set(corpus, index);
  }
  return index;
}
/** scorer(documents, query, keep) for documents that are all rows of `corpus`, in corpus order. */
function scoreCorpusSubset(corpus, documents, query, keep) {
  const index = corpusIndex(corpus);
  if (documents.some(document => !index.positions.has(document))) return scorer(documents, query, keep);
  const { positions, entries, postings, titles, stamp } = index;
  // A fresh stamp marks this question's subset (wraps after 4 billion questions).
  index.generation = index.generation >= 0xfffffffe ? 1 : index.generation + 1;
  const generation = index.generation;
  if (generation === 1) stamp.fill(0);
  let totalLength = 0;
  const at = new Array(documents.length);
  for (let i = 0; i < documents.length; i++) { const position = at[i] = positions.get(documents[i]); stamp[position] = generation; totalLength += entries[position].length; }
  const frequencies = new Map(), matched = new Set();
  for (const term of query.expanded) {
    let frequency = 0;
    for (const position of postings.get(term) || []) if (stamp[position] === generation) { frequency++; matched.add(position); }
    if (frequency) frequencies.set(term, frequency);
    for (const position of titles.get(term) || []) if (stamp[position] === generation) matched.add(position);
  }
  const averageLength = totalLength / Math.max(documents.length, 1) || 1;
  const scored = [];
  for (let i = 0; i < documents.length; i++) {
    const score = matched.has(at[i]) ? documentScore(entries[at[i]], query, documents.length, frequencies, averageLength) : 0;
    if (!keep || keep(documents[i], score)) scored.push({ ...documents[i], score });
  }
  return scored;
}

// A published guide heading, normalised once (catalog text only, never the question).
const HEADING_NAMES = new Map();
function headingName(heading) {
  let name = HEADING_NAMES.get(heading);
  if (name === undefined) { name = normalize(heading); if (HEADING_NAMES.size >= 20000) HEADING_NAMES.clear(); HEADING_NAMES.set(heading, name); }
  return name;
}

function balancedGuideRows(rows, query, comparedCities = []) {
  const subjects = REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(query)).slice(0, 8);
  const multipart = subjects.length >= 2;
  const comparingVisits = /值得(?:看|去)|(?:带娃|帶娃|带孩子|帶孩子).{0,30}(?:玩|转|轉|看)|散步|水边|水邊|景点|景點|游玩|遊玩|\b(?:things? to (?:do|see)|places? to visit|waterfront|walks?|sights?)\b/i.test(query);
  const entities = [...new Set((String(query).match(/\b[A-Z][A-Za-z0-9]*(?:[ -]+[A-Z][A-Za-z0-9]*){0,5}\b/g) || [])
    .filter(value => (value.includes(' ') || /^[A-Z]{3,12}$/.test(value)) && !canonicalCity(value)))].slice(0, 6).map(value => {
      const words = value.split(/[ -]+/), initials = words.map(word => word[0]).join('');
      return [...new Set([normalize(value), ...(words.length > 1 ? [initials.toLowerCase(), `${words.slice(0, -1).map(word => word[0]).join('').toLowerCase()} ${words.at(-1).toLowerCase()}`] : [])])];
    });
  const facetRows = rows.map(row => {
    const heading = row._contentHeading || '', primary = subjects.filter(([, pattern]) => pattern.test(heading));
    const topics = primary.length ? primary : subjects.filter(([, pattern]) => pattern.test(row.text));
    // Without a named entity in the question the heading is never compared (API-BB-4B: the
    // heading's city normalisation ran for every scored paragraph of every question).
    const named = entities.length ? headingName(heading) : '';
    const entityIds = entities.flatMap((aliases, index) => aliases.some(alias => ` ${named.replace(/[^\p{L}\p{N} ]/gu, ' ')} `.includes(` ${alias} `)) ? [index] : []);
    const visitContent = row._isOutingGuide && (!/^City guide:/.test(heading) || /\[(?:city|nearby)\]/.test(row.text));
    const cityFacets = comparedCities.filter(city => (!comparingVisits || visitContent) && row._primaryCities.includes(city)).map(city => `city:${city}`);
    return { row, primaryTopics: primary.length, facets: [...cityFacets, ...(multipart ? topics.flatMap(([id]) => [`topic:${id}`, ...(primary.length ? entityIds.map(index => `entity:${index}:${id}`) : [])]) : [])] };
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
      // A link card restates a paragraph next to it: in a multi-part question it counts half,
      // so it does not push another section's rule out of the excerpt (API-BB-4B, DMV case).
      const score = (multipart && row._linkCard ? row.score / 2 : row.score) + headingBoost + facets.filter(facet => !covered.has(facet))
        .reduce((sum, facet) => sum + (facet.startsWith('city:') ? rows[0]?.score || 0 : boost), 0);
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

// A guide's link card (a title such as "加州车辆法 12505(c)：…", at most one summary line, then a
// bare official URL). It restates a nearby paragraph; its URL reaches the model as a source.
const isLinkCard = chunk => { const lines = String(chunk).trim().split('\n').map(line => line.trim()).filter(Boolean);
  return lines.length >= 2 && lines.length <= 3 && /^https:\/\/\S+$/.test(lines.at(-1)) && lines.slice(0, -1).join('').length <= 160; };
function guideParagraphs(guide, catalogCities = []) {
  const slug = textValue(guide.slug); const url = siteUrl(guide.url, slug);
  if (!url || !guide.title || typeof guide.content !== 'string') return [];
  const titleCities = [...new Set([...mentionedCities([guide.title, ...(guide.keywords || [])].join(' ')), ...catalogCities])];
  const schoolRegions = isSchoolGuide(guide) ? REGIONS.includes(guide.region) ? [guide.region]
    : mentionedRegions([guide.slug, guide.title, ...(guide.keywords || [])].join(' ')) : [];
  const isOutingGuide = /游玩|遊玩|出游|出遊|城市指南|景点|景點|博物馆|博物館|美术馆|美術館|公园|公園|野餐|散步|一日|半日|一天|周末|週末|免费|免費|活动|活動|亲子|親子|交通|通勤|购物|購物|餐厅|餐廳|美食|\b(?:outings?|attractions?|museums?|parks?|picnic|day trip|weekend|events?|transit|accessible|accessibility|shopping|dining)\b/i.test([guide.title, guide.summary, ...(guide.keywords || [])].join(' '));
  // The bilingual 101-city directory is larger than 150k characters. Keep a
  // bounded whole-corpus index (cached once), not a prefix that silently loses
  // the final counties. Per-request output remains eight short paragraphs.
  const raw = guide.content.slice(0, 400000).split(/\n\s*\n/).map(part => part.trim()).filter(Boolean);
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
    const directoryHeading = paragraph.match(/^City guide:\s*([^|\n]+)\s*\|[^\n]*/)?.[0];
    const directoryCity = directoryHeading && canonicalCity(directoryHeading.match(/^City guide:\s*([^|\n]+)/)[1].trim());
    const headingCity = directoryCity || leadingLines[1] || leadingLines[0];
    // Carry a short city section's scope into the following paragraphs. This
    // prevents an Oakland utility number under a heading being used for Alameda.
    if (headingCity) { sectionCities = [headingCity]; heading = directoryHeading || headingCity; }
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
        editionMonth: guideEditionMonth(guide), editionThroughDate: guideEditionThroughDate(guide) || undefined,
        sourceKind: 'site-guide', verification: 'site-record', verifiedLive: false,
        cities: scope, _primaryCities: headingCity ? [headingCity] : titleCities.length === 1 ? titleCities : [], _guideCities: titleCities, _isOutingGuide: isOutingGuide, _schoolRegions: schoolRegions,
        _contentKey: fingerprint(chunks[chunkIndex].trim()),
        // A link card: a title, at most one line, then the official URL (API-BB-4B).
        _linkCard: isLinkCard(chunks[chunkIndex]), _section: heading,
        // Inline editorial records carry their own first-line heading. A plain
        // prose paragraph instead belongs to the preceding section heading;
        // incidental mentions of other services are not its primary subject.
        _contentHeading: directoryHeading || (chunks[chunkIndex].includes('\n') ? chunks[chunkIndex].trim().split('\n')[0] : heading || chunks[chunkIndex].trim()),
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

// v2 (BAYBAY_ENGINE=v2): a city question also accepts paragraphs scoped to its
// county (San Jose -> the Santa Clara County line of a county-by-county list).
const COUNTY_CITIES = {
  'Santa Clara': ['San Jose', 'Sunnyvale', 'Santa Clara', 'Cupertino', 'Palo Alto', 'Stanford', 'Mountain View', 'Milpitas', 'Campbell', 'Los Gatos', 'Saratoga', 'Los Altos', 'Los Altos Hills', 'Gilroy', 'Morgan Hill', 'Monte Sereno'],
  'San Mateo': ['San Mateo', 'Redwood City', 'Daly City', 'South San Francisco', 'Burlingame', 'Millbrae', 'San Bruno', 'Foster City', 'Belmont', 'San Carlos', 'Menlo Park', 'Half Moon Bay', 'Pacifica', 'East Palo Alto', 'Hillsborough', 'Brisbane', 'Atherton', 'Woodside'],
  Alameda: ['Oakland', 'Berkeley', 'Fremont', 'Hayward', 'Alameda', 'San Leandro', 'Union City', 'Newark', 'Pleasanton', 'Livermore', 'Dublin', 'Emeryville', 'Albany', 'Piedmont', 'Castro Valley'],
  'Contra Costa': ['Richmond', 'Concord', 'Walnut Creek', 'Antioch', 'Pleasant Hill', 'San Ramon', 'Danville', 'Martinez', 'Pittsburg', 'El Cerrito', 'Lafayette', 'Orinda', 'Moraga', 'Brentwood', 'Hercules', 'Pinole'],
  Marin: ['San Rafael', 'Novato', 'Mill Valley', 'Sausalito', 'Tiburon', 'Larkspur', 'Corte Madera', 'Fairfax', 'Point Reyes Station'],
  Sonoma: ['Santa Rosa', 'Petaluma', 'Rohnert Park', 'Healdsburg', 'Sonoma', 'Sebastopol', 'Windsor'],
  Napa: ['Napa', 'St. Helena', 'Calistoga', 'Yountville', 'American Canyon'],
  Solano: ['Vallejo', 'Fairfield', 'Vacaville', 'Benicia', 'Suisun City'],
  'San Francisco': ['San Francisco'],
};
const CITY_COUNTY = new Map(Object.entries(COUNTY_CITIES).flatMap(([county, cities]) => cities.map(city => [city, county])));
const COUNTY_REGION = { 'Santa Clara': 'south-bay', 'San Mateo': 'peninsula', 'San Francisco': 'sf', Alameda: 'east-bay', 'Contra Costa': 'east-bay', Marin: 'north-bay', Sonoma: 'north-bay', Napa: 'north-bay', Solano: 'north-bay' };
// H73 (audit 10-13, BB-1013-10; API-BB-4B): how near a record is to the asker's stated home or
// starting city when the ask names no destination ("We live in Fremont … this Sunday"): 0 the
// same city, 1 the same county, 2 the same region, 3 a neighbouring region (by bridge or
// freeway), 4 elsewhere or unknown. A coarse order by county and region, not a distance: the
// catalog has no coordinates for a home city.
const NEIGHBOUR_REGIONS = { sf: ['peninsula', 'east-bay', 'north-bay'], peninsula: ['sf', 'south-bay', 'east-bay'], 'south-bay': ['peninsula', 'east-bay'], 'east-bay': ['sf', 'south-bay', 'north-bay', 'peninsula'], 'north-bay': ['sf', 'east-bay'] };
function originNearness(state) {
  const origin = canonicalCity(state?.origin);
  if (!origin || state.city || (state.region && state.region !== 'all')) return null;
  const county = CITY_COUNTY.get(origin), region = COUNTY_REGION[county];
  if (!region) return null;
  return row => {
    const cities = rowCities(row);
    if (cities.includes(origin)) return 0;
    if (cities.some(city => CITY_COUNTY.get(city) === county)) return 1;
    const rowRegion = row.region || COUNTY_REGION[CITY_COUNTY.get(cities[0])];
    return rowRegion === region ? 2 : NEIGHBOUR_REGIONS[region].includes(rowRegion) ? 3 : 4;
  };
}
const countyPattern = county => new RegExp(`${county.replace(/ /g, '\\s+')}(?:\\s*County|\\s*[县縣])`, 'i');
const COUNTY_PATTERNS = new Map(Object.keys(COUNTY_CITIES).map(county => [county, countyPattern(county)]));
function rowInCity(row, city, county) {
  if (!county) return row.cities.includes(city);
  return row.cities.includes(city) || row.cities.includes(county) || COUNTY_PATTERNS.get(county).test(row.text || '');
}

function paragraphFits(row, state, schoolRegions = [], countyScope = false) {
  if (['day-plan', 'discover'].includes(state.goal) && !row._isOutingGuide) return false;
  if (schoolRegions.length && row._schoolRegions.length && !row._schoolRegions.some(region => schoolRegions.includes(region))) return false;
  const county = countyScope && state.city ? CITY_COUNTY.get(state.city) : null;
  if (state.city && row._guideCities.length === 1 && row._guideCities[0] !== state.city && row._guideCities[0] !== county) return false;
  if (row._guideCities.length === 1 && state.excludedCities.includes(row._guideCities[0])) return false;
  if (state.city && row.cities.length && !rowInCity(row, state.city, county)) return false;
  return !(row.cities.length && row.cities.every(city => state.excludedCities.includes(city)));
}

function sourceSpecificity(url) {
  try {
    const path = new URL(url).pathname.replace(/\/+$/, '').toLowerCase();
    return !path || /^\/(?:events?|calendar|activities|whats-on|things-to-do)(?:\/calendar)?$/.test(path) ? 'directory' : 'direct';
  } catch { return 'unknown'; }
}

function isGenerallyFree(row) {
  // “Mixed” can describe free public admission with separately priced
  // parking/food. Require both an explicit zero admission and an admission
  // statement; a free gift, sample or eligibility-only ticket is insufficient.
  const publicAdmission = row.cost === 'free' || row.cost === 'mixed' && row.planning?.admissionUsd === 0
    && /活动免费|活動免費|免门票|免門票|免费(?:入场|入館|入馆)|免費(?:入場|入館)|\bfree\s+(?:public\s+)?(?:admission|entry|event)\b|\b(?:admission|entry)\s+(?:is\s+)?free\b/i.test(row.costLabel || '');
  return publicAdmission && priceOf(row) === 0 && !row.planning?.admissionEligibility && !row.planning?.admission?.eligibility
    && !/(?:居民|会员|會員|学生|學生|\d\s*[岁歲]|\b(?:residents?|members?|students?|under\s+\d|children))[^。;；]{0,35}(?:免费|免費|\bfree\b)|\bfree\b[^。.;；]{0,35}\b(?:for|to)\s+(?:(?:eligible|qualifying|local|all)\s+)?(?:residents?|members?|students?|children|kids?|under\s+\d|library card holders?)\b|(?<!无|無|不)(?:仅限|僅限|须|須|需要|需)(?:先)?(?:购买|購買|消费|消費)|\bfree\b[^。.;；]{0,35}\bwith (?:a )?purchase\b|\b(?:members?|residents?|students?|cardholders?) only\b|(?:仅限|僅限)(?:会员|會員|居民|学生|學生)/i.test([row.costLabel, ...(row.plan || [])].filter(Boolean).join(' '));
}

/** The editorial status as a reason a named event is only a reference: cancelled and postponed always, sold out
 * while the event is not over (an ended one stays "past"). */
function statusReason(row, today) {
  const status = eventStatus(row);
  return status === 'cancelled' || status === 'postponed' || (status === 'sold_out' && !(row.endDate < today)) ? status : null;
}

function candidateFits(row, kind, state, today) {
  // A sold-out, postponed or cancelled event is never a candidate; a named one stays a nearMiss reference with its status.
  if (!active(row) || eventHalted(row) || soldOut(row)) return false;
  if (state.goal === 'day-plan' && row.id === state.originCandidateId) return false;
  const cities = rowCities(row);
  if (state.city && !cities.includes(state.city)) return false;
  if (cities.length && cities.every(city => state.excludedCities.includes(city))) return false;
  if (state.region && state.region !== 'all' && !state.city && row.region !== state.region) return false;
  if (state.excludedCandidateIds.includes(row.id) || state.excludedCandidateIds.includes(`${kind}:${row.id}`)) return false;
  if (kind === 'event') {
    if (state.dateRange && (row.endDate < state.dateRange.start || row.startDate > state.dateRange.end || (row.occurrenceDates && !row.occurrenceDates.some(date => date >= state.dateRange.start && date <= state.dateRange.end)))) return false;
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
    // A row's own read date only: the catalog's export date is not when this row was checked
    // (API-BB-4B, API-SYNC-3a follow-up 3; every place, and 11 offers, have none).
    ...(validDate(row.verifiedAt) ? { recordedAt: row.verifiedAt } : validDate(row.updatedAt) ? { recordedAt: row.updatedAt } : {}),
    sourceSpecificity: sourceSpecificity(url),
    catalogDateMatch: kind === 'event' && !!state.date && eventOccursOn(row, state.date),
    // The catalog preserves editorial facts and source links, but does not
    // establish current opening, a reservation, or live ticket availability.
    requiresVerification: ['current-status', ...(kind === 'place' ? ['opening-hours'] : ['session-time']), 'admission-conditions', 'availability'],
  };
}

function paragraphMentionsDate(text, date) {
  if (!validDate(date)) return false;
  const wantedYear = date.slice(0, 4);
  for (const match of text.matchAll(/(?<!\d)(?:(20\d{2})\s*(?:年|[-/])\s*)?(\d{1,2})\s*(?:月|[/])\s*(\d{1,2})(?!\d)(?:\s*\/\s*(20\d{2}))?|\b(20\d{2})-(\d{2})-(\d{2})\b/g)) {
    const year = match[1] || match[4] || match[5] || wantedYear, month = match[2] || match[6], day = match[3] || match[7];
    if (`${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}` === date) return true;
  }
  return false;
}

function boostRelatedDatedTerms(rows, query, state) {
  if (!validDate(state.date) || !/免费|免費|免票|资格|資格|票价|票價|\b(?:free|eligib\w*|admission|tickets?|discounts?)\b/i.test(query) || !rows.length) return rows;
  // A colloquial place name can first retrieve its ordinary visit guide.
  // Bring in that venue's dated terms through an exact official reference,
  // without treating the nickname as an established venue identity or using
  // every reference in a large regional roundup as a relevance signal.
  const anchor = rows[0];
  const references = anchor.sourceUrls.length ? anchor.sourceUrls : anchor._guideSources.length <= 12 ? anchor._guideSources : [];
  const urls = new Set(references.map(source => referenceKey(source.url)));
  if (!urls.size) return rows;
  const topScore = rows[0].score;
  return rows.map(row => paragraphMentionsDate(row.text, state.date)
    && row.sourceUrls.some(source => urls.has(referenceKey(source.url)))
    ? { ...row, score: row.score + topScore } : row)
    .sort((a, b) => b.score - a.score || a.evidenceId.localeCompare(b.evidenceId));
}

function candidateSnapshotText(row) {
  // Whole editorial fields, not a claimed page-read quotation. In particular,
  // an uncomputed party total must not erase published adult/child price tiers.
  const fields = [row.title, row.dateLabel, row.costLabel, row.summary, ...(row.plan || [])].filter(value => typeof value === 'string' && value.trim());
  const parts = ['BAYLINK editorial catalog snapshot; not a live official-page read.'];
  let length = parts[0].length;
  for (const field of fields) if (length + field.length + 2 <= 1700) { parts.push(field); length += field.length + 2; }
  return parts.join('\n\n');
}

/** Relevant site paragraphs and strict catalog matches share provenance, while
 * staying explicitly separate from subsequently fetched official-page facts. */
function buildSiteEvidence({ query = '', originalQuery, state: inputState, guideCatalog = [], catalog: suppliedCatalog, today = bayAreaDate(), currentPath = '/', selectedGuideUrls, boostGuideUrls = [], v2 = false } = {}) {
  const state = validateTaskState(inputState);
  const catalog = loadPlannerCatalog(suppliedCatalog);
  // v2: colloquial names add their canonical terms (舰队周 -> Fleet Week) and
  // name entities by their core name; city questions accept county-scoped rows.
  if (v2) query = [String(query), ...queryAliases(originalQuery ?? query).terms].join(' ');
  const named = (text, rows) => v2 ? namedEntitiesV2(text, rows, { cityTokens: CITY_TOKENS }) : namedEntities(text, rows);
  // Locale aliases may translate ordinary words inside an institution's proper
  // name. Retain the original question for named-entity and subject balancing.
  const intentQuery = typeof originalQuery === 'string' ? originalQuery.slice(0, 4000) : String(query).slice(0, 4000);
  const requestedFood = foodRequest(intentQuery);
  const explicitArticle = /这篇|這篇|本文|这份|這份|当前(?:文章|攻略)|當前(?:文章|攻略)|正在读|正在讀|\b(?:this|current) (?:article|guide)\b/i.test(intentQuery);
  // Resolved public selections take precedence over the physical page. An
  // explicit empty selection must not silently restore that page's authority.
  // Only exact published URLs can choose a guide; titles supplied by clients
  // never become retrieval evidence. Direct callers retain the page fallback.
  const requestedGuideUrls = selectedGuideUrls === undefined ? [currentPath] : Array.isArray(selectedGuideUrls) ? selectedGuideUrls.slice(0, 3) : [];
  const focusedGuideUrls = new Set(explicitArticle ? (Array.isArray(guideCatalog) ? guideCatalog : []).filter(guide => requestedGuideUrls.includes(siteUrl(guide.url, guide.slug))).map(guide => siteUrl(guide.url, guide.slug)) : []);
  // The guide being read (and a professional topic's pillar guide) is boosted,
  // not exclusive: its best-matching current paragraphs always reach the
  // evidence, even when a city filter would drop them (San Jose asks; the record
  // says Santa Clara County), while other guides still compete normally. A
  // passive open tab never revives an archived edition.
  const boostedGuideUrls = new Set(focusedGuideUrls.size ? [] : (Array.isArray(guideCatalog) ? guideCatalog : [])
    .map(guide => siteUrl(guide.url, guide.slug)).filter(url => url && (requestedGuideUrls.includes(url) || (Array.isArray(boostGuideUrls) && boostGuideUrls.slice(0, 3).includes(url)))));
  const schoolRequest = isSchoolRequest(intentQuery);
  const libraryRequest = ['information', 'newcomer'].includes(state.goal) && isLibraryServiceQuestion(intentQuery);
  const schoolSlugs = schoolRequest ? new Set(guideCatalog.filter(isSchoolGuide).map(guide => guide.slug)) : null;
  const schoolRegions = schoolRequest ? requestedSchoolRegions(intentQuery, state, catalog) : [];
  const retrievalState = schoolRequest && mentionedCities(intentQuery).length > 1 ? { ...state, city: null } : state;
  const terms = queryTokens(String(query).slice(0, 4000), state);
  const comparedCities = state.goal === 'information' && !state.city && !libraryRequest ? mentionedCities(intentQuery) : [];
  const activityDiscovery = /(?:有什么|有什麼|有没有|有沒有|推荐|推薦).{0,35}(?:活动|活動|参加|參加|去处|去處|玩)|(?:想|打算).{0,35}(?:晃晃|逛逛|透透气|透透氣)|(?:白天|周末|週末).{0,12}(?:挑|选|選).{0,8}(?:个|個)|\b(?:things? to do|something to do|events? (?:this|that|on)|recommend.{0,20}(?:events?|activities))\b/i.test(intentQuery);
  const noPurchaseDiscovery = activityDiscovery && /不(?:用|需要|必)?(?:先)?买东西|不(?:用|需要|必)?(?:先)?買東西|不要.{0,8}(?:买东西|買東西|消费|消費)|\b(?:no purchase|without (?:buying|shopping)|don['’]t (?:need|have) to buy)\b/i.test(intentQuery);
  // Within education guides, the named cities identify the relevant district
  // comparison. Removing both names would rank generic enrollment prose from
  // unrelated regions above the actual boundary-check paragraph.
  if (schoolRequest || comparedCities.length > 1) for (const term of tokens(mentionedCities(intentQuery).join(' '))) { terms.base.add(term); terms.expanded.add(term); }
  // Eligibility is evaluated on every request; only immutable source parsing
  // and tokenization are cached. No query, filter result or model answer is cached.
  const corpus = indexedGuideDocuments(guideCatalog, catalog);
  let documents = corpus.filter(row =>
    focusedGuideUrls.has(row.url) || (boostedGuideUrls.has(row.url) && !isGuideArchived(row, today)) || (!isGuideArchived(row, today)
      && (!schoolSlugs || schoolSlugs.has(row.slug)) && paragraphFits(row, retrievalState, schoolRegions, v2)));
  // "This guide" is a request about the selected article's published body,
  // not about other articles that happen to share generic preparation words.
  // Archived/locality-specific prose remains reference material; candidate
  // eligibility below still applies the user's original dates and exclusions.
  if (focusedGuideUrls.size) documents = documents.filter(row => focusedGuideUrls.has(row.url));
  if (requestedFood && !focusedGuideUrls.size) documents = documents.filter(row => matchesFoodEvidence(row, requestedFood));
  if (libraryRequest && !focusedGuideUrls.size) {
    const libraryDocuments = documents.filter(row => isLibraryServiceQuestion(row.text));
    // Sparse catalogs can have only a general benefits paragraph with a
    // library source link. Do not erase that lead when no topical text exists.
    if (libraryDocuments.length) documents = libraryDocuments;
  }
  const cityScored = scoreCorpusSubset(corpus, documents, terms, (row, score) => score > 0 || focusedGuideUrls.has(row.url)).map(row => focusedGuideUrls.has(row.url) ? { ...row, score: Math.max(1, row.score) } : row).filter(row => row.score > 0).map(row => ({ ...row, score: row.score * (state.city && row.cities.length === 1 && row.cities[0] === state.city ? 1.6 : 1) }));
  if (boostedGuideUrls.size) {
    // Only paragraphs that share terms with the question are boosted (top 3 per
    // guide); an unrelated open page never displaces the requested topic.
    const ceiling = Math.max(1, ...cityScored.filter(row => !boostedGuideUrls.has(row.url)).map(row => row.score));
    // "Which number do I call" is answered by a paragraph with a phone number,
    // which rarely shares words with the question itself.
    const contactQuestion = /电话|電話|号码|號碼|打给|打給|打哪|热线|熱線|联系|聯繫|聯絡|\b(?:phone|call|number|hotline|contact)\b/i.test(intentQuery);
    const contactRank = row => contactQuestion && /(?<!\d)(?:1-)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)/.test(row.text) ? 1 : 0;
    // A synonym-only match (交通 for "transit") is too weak to outrank the
    // requested topic; a boosted paragraph must share an actual question term
    // or answer a contact question with a phone number.
    const asked = row => contactRank(row) || tokens(row.text).some(term => terms.base.has(term));
    const lifted = new Set();
    for (const url of boostedGuideUrls) cityScored.filter(row => row.url === url && asked(row)).sort((a, b) => contactRank(b) - contactRank(a) || b.score - a.score).slice(0, 3).forEach(row => lifted.add(row));
    for (const row of lifted) row.score += ceiling + 1;
    // Boosted guides were exempt from the eligibility filters only for these lifted rows.
    for (let index = cityScored.length - 1; index >= 0; index--) {
      const row = cityScored[index];
      if (boostedGuideUrls.has(row.url) && !lifted.has(row) && (isGuideArchived(row, today) || (schoolSlugs && !schoolSlugs.has(row.slug)) || !paragraphFits(row, retrievalState, schoolRegions, v2))) cityScored.splice(index, 1);
    }
  }
  const guideScores = boostRelatedDatedTerms(cityScored.sort((a, b) => b.score - a.score || a.evidenceId.localeCompare(b.evidenceId)), intentQuery, state);
  const sourceRankings = new Map(); const guides = [];
  const selectedRows = balancedGuideRows(guideScores, intentQuery, comparedCities.length > 1 ? comparedCities : []);
  // API-BB-4B: in a multi-part question a link card that did not get a slot of its own still
  // gives its official URL, through the first selected paragraph of its guide section.
  const chosen = new Set(selectedRows), folded = new Set();
  const unchosenCards = REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(intentQuery)).length >= 2 ? guideScores.filter(row => row._linkCard && !chosen.has(row)) : [];
  for (const selectedRow of selectedRows) {
    const cards = selectedRow._linkCard ? [] : unchosenCards.filter(card => !folded.has(card) && card.slug === selectedRow.slug && card._section === selectedRow._section);
    cards.forEach(card => folded.add(card));
    const row = cards.length ? { ...selectedRow, sourceUrls: [...selectedRow.sourceUrls, ...cards.flatMap(card => card.sourceUrls)] } : selectedRow;
    const { score, _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, _linkCard, _section, ...guide } = row;
    guides.push({ ...guide, archived: isGuideArchived(guide, today), sectionHeading: _contentHeading, requestedTopics: REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(intentQuery) && pattern.test(guide.text)).map(([id]) => id),
      cities: [...guide.cities], sourceUrls: selectedGuideSources(row, terms, retrievalState, sourceRankings), relevance: Number(score.toFixed(3)) });
    if (guides.length === 8) break;
  }
  let candidates = [];
  // API-BB-4B (API-SYNC-3b follow-up): Chinese-language programmes are written in Chinese; an
  // English ask also searches their English aliases ("Hong Kong action classic Hard Boiled,
  // screened in Cantonese"), so "Any Cantonese film screenings …" finds them as the Chinese ask does.
  const englishAsk = !/[㐀-鿿]/.test(intentQuery);
  if (catalog && validDate(today)) {
    const namedIds = new Set(named(intentQuery, catalog).map(({ kind, row }) => `${kind}:${row.id}`));
    const rows = [['event', catalog.events], ['place', catalog.places]].flatMap(([kind, entries]) => entries
      .filter(row => safeUrl(row.officialUrl) && candidateFits(row, kind, state, today)
        && matchesFoodEvidence(row, requestedFood, kind)
        && (!noPurchaseDiscovery || isGenerallyFree(row)))
      .map(row => ({ ...normalizeCandidate(row, kind, catalog.checkedAt, state), _cacheKey: row, text: englishText([row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || []), ...(englishAsk ? englishAliases(row) : [])].join(' '), englishAsk) })));
    const namedAcronyms = String(query).match(/\b[A-Z][A-Z0-9]{2,11}\b/g)?.filter(term => !['BART', 'MUNI', 'SFO', 'SJC', 'OAK', 'USD', 'USA', 'THE', 'AND', 'BAYLINK'].includes(term)) || [];
    const selectionRank = row => state.selectedCandidateIds.findIndex(id => id === row.id || id === row.candidateId);
    // API-BB-4B (API-SYNC-3a follow-up): BAYLINK's readers are Chinese families. On a Chinese-
    // community ask, or a library or free list ask asked in Chinese, a Chinese-language or
    // Chinese-community event is not displaced from the six candidates by generic events of
    // similar fit: it ranks with a quarter of the best score added (这周六旧金山图书馆有什么免费活动 →
    // the Richmond branch's Cantonese film). Review 10-14: never on other asks (a Halloween or
    // concert ask keeps its most relevant events first), a day plan, an ask with a start, finish
    // or travel-mode constraint, or a family ask, so a lifted adults-only screening never
    // displaces a stop that fits a stated constraint (K-TIME-1 keeps Ferry Plaza).
    const scoredRows = scorer(rows, withoutDateNumbers(withoutDayTerms(terms), intentQuery, state));
    const familyAsk = state.childAges.length > 0 || FAMILY_ASK.test(intentQuery);
    const liftAsk = state.community === 'chinese' || (/[㐀-鿿]/.test(intentQuery) && COMMUNITY_LIFT_ASK.test(intentQuery));
    const constrained = state.goal === 'day-plan' || !!state.finishBy || !!state.startTime || !!state.travelMode;
    const communityLift = liftAsk && !constrained && !familyAsk ? Math.max(0, ...scoredRows.map(row => row.score)) * 0.25 : 0;
    const ranked = row => row.score + (communityLift && row.kind === 'event' && isChineseRecord(row) ? communityLift : 0);
    // (An outing phrased in a way goalOf misses still orders from home when it reads as one.)
    const near = activityDiscovery || ['day-plan', 'discover'].includes(state.goal) || ACTIVITY_INTENT.test(intentQuery) ? originNearness(state) : null;
    // API-BB-5: "我们坐 BART 去" with no city: places the named rail system reaches come first.
    const rail = railFit(state);
    candidates = scoredRows.filter(row => {
      if (schoolRequest || ['newcomer', 'transit'].includes(state.goal)) return false;
      // Explicit selected identities still pass candidateFits above. Query
      // shorthand or an acronym cannot hide an otherwise eligible chosen stop.
      if (selectionRank(row) >= 0) return true;
      if (namedIds.has(row.candidateId)) return true;
      if (namedAcronyms.length && !namedAcronyms.some(term => new RegExp(`\\b${term}\\b`, 'i').test(row.text))) return false;
      // A general venue/utility/transport question must not receive arbitrary
      // nearby festivals merely because they satisfy city and date filters.
      return ['day-plan', 'discover'].includes(state.goal) || row.score > 0
        || activityDiscovery && row.kind === 'event' && !!state.date && !!(state.city || state.region);
    }).sort((a, b) => {
      const rankA = selectionRank(a), rankB = selectionRank(b);
      if (rankA >= 0 || rankB >= 0) return rankA < 0 ? 1 : rankB < 0 ? -1 : rankA - rankB;
      if (rail && rail(a) !== rail(b)) return rail(a) - rail(b);
      // A dated activity request should see eligible dated programs before
      // unrelated permanent shops which happen to share a word with it.
      if (activityDiscovery && a.kind !== b.kind) return a.kind === 'event' ? -1 : 1;
      // H73: from a stated home city with no destination, nearer records first.
      const nearer = near ? near(a) - near(b) : 0;
      return nearer || ranked(b) - ranked(a) || a.id.localeCompare(b.id);
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
    ...candidates.map(row => ({ id: row.evidenceId, evidenceId: row.evidenceId, title: row.title, titleOrigin: 'candidate', url: row.officialUrl, sourceKind: row.sourceKind, verification: row.verification, recordedAt: row.recordedAt, sourceSpecificity: row.sourceSpecificity, verifiedLive: false,
      ...(candidates.filter(other => other.officialUrl === row.officialUrl).length === 1 ? { text: candidateSnapshotText(row) } : {}) })),
  ];
  const nearMiss = named(intentQuery, catalog).filter(({ kind, row }) => kind === 'event' && !candidateFits(row, kind, state, today)).map(({ kind, row }) => ({ kind, id: row.id, title: row.title, startDate: row.startDate, endDate: row.endDate, occurrenceDates: row.occurrenceDates, summary: row.summary, officialUrl: row.officialUrl, reason: statusReason(row, today) || (state.date && !eventOccursOn(row, state.date) ? 'date_mismatch' : row.endDate < today ? 'past' : 'constraints_mismatch') })).slice(0, 3);
  return { guides, candidates, sources, nearMiss, ...(originCandidate ? { originCandidate } : {}),
    ...(requestedFood ? { foodEvidence: { kind: requestedFood.kind, status: candidates.length || guides.some(row => matchesFoodEvidence(row, requestedFood)) ? 'matched' : 'needs-confirmation', scope: 'retrieved-site-records' } } : {}) };
}

// ---- BAYBAY_ENGINE=v2 fast-path evidence (API-BB-ENGINE) -------------------
// One compact evidence list for a single model call: the page-independent top
// 8–10 items, each <=400 characters, with weekday dates and the BAYLINK page
// first. Built on buildSiteEvidence (v2 options) plus three recalls the model
// used to attempt with search_site: named entities by alias, places/events in
// a named city, and the offers/openings catalog (ENGINE-10).
const CITY_TOKENS = new Set([
  ...Object.values(COUNTY_CITIES).flat().flatMap(city => city.toLowerCase().split(/[\s.]+/)),
  ...Object.keys(COUNTY_CITIES).flatMap(county => county.toLowerCase().split(/\s+/)),
  ...Object.values(require('../data/city-search-aliases.json')).flat().flatMap(alias => {
    const run = String(alias).toLowerCase();
    return /[㐀-鿿]/.test(run) ? Array.from({ length: Math.max(0, run.length - 1) }, (_, index) => run.slice(index, index + 2)) : run.split(/\s+/);
  }),
].filter(Boolean));
const FAST_LIMIT = 10;
const ITEM_CHARS = 400;
const SITE = 'https://www.baylink.us';
const ISO = /^\d{4}-\d{2}-\d{2}$/;
const WEEKDAY_ZH = '日一二三四五六', WEEKDAY_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'], MONTH_EN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** "10月17日（周六）", "10月17日（週六）", "Sat, Oct 17": how dates reach the model and the reader, never ISO. */
function readerDate(value, locale = 'zh-Hans') {
  if (typeof value !== 'string' || !ISO.test(value)) return '';
  const date = new Date(`${value}T12:00:00Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) return '';
  const weekday = date.getUTCDay();
  if (locale === 'en') return `${WEEKDAY_EN[weekday]}, ${MONTH_EN[date.getUTCMonth()]} ${date.getUTCDate()}`;
  return `${date.getUTCMonth() + 1}月${date.getUTCDate()}日（${locale === 'zh-Hant' ? '週' : '周'}${WEEKDAY_ZH[weekday]}）`;
}
function readerRange(start, end, locale) {
  const first = readerDate(start, locale), last = readerDate(end, locale);
  if (!first) return last;
  return last && end !== start ? `${first}${locale === 'en' ? ' – ' : ' 至 '}${last}` : first;
}
const PHONE = /(?<!\d)(?:1-)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)/;
const CONTACT_QUESTION = /电话|電話|号码|號碼|打给|打給|打哪|热线|熱線|联系|聯繫|聯絡|\b(?:phone|call|number|hotline|contact)\b/i;
/** The most relevant whole sentences of a text, in their original order, within `limit` characters. */
function snippet(text, terms, limit = ITEM_CHARS, contact = false) {
  const clean = String(text || '').replace(/[ \t]+/g, ' ').replace(/(?<!\s)\s*\n\s*/g, '\n').trim();
  if (clean.length <= limit) return clean;
  const sentences = clean.split(/(?<=[。！？；;!?\n])|(?<=\.)\s+/).map(value => value.trim()).filter(Boolean);
  const scored = sentences.map((value, index) => {
    const words = new Set(tokens(value));
    return { value, index, score: [...terms.base].filter(term => words.has(term)).length + [...terms.expanded].filter(term => !terms.base.has(term) && words.has(term)).length * 0.4 + (contact && PHONE.test(value) ? 3 : 0) + (index === 0 ? 0.5 : 0) };
  }).sort((a, b) => b.score - a.score || a.index - b.index);
  const chosen = []; let length = 0;
  for (const row of scored) { if (length + row.value.length + 1 > limit) continue; chosen.push(row); length += row.value.length + 1; }
  if (!chosen.length) return `${clean.slice(0, limit - 1)}…`;
  return chosen.sort((a, b) => a.index - b.index).map(row => row.value).join(' ');
}

function temporalOf(row, today) {
  const start = row.startDate, end = row.endDate || row.startDate;
  if (['inactive', 'ended', 'expired'].includes(row.status) || row.active === false || eventHalted(row)) return 'inactive';
  if (Array.isArray(row.occurrenceDates) && row.occurrenceDates.length && !row.occurrenceDates.some(date => date >= today)) return 'past';
  if (end && end < today) return 'past';
  if (start && start > today || ['announced', 'coming-soon'].includes(row.status)) return 'upcoming';
  return 'current';
}
const TEMPORAL = { past: ['已结束', '已結束', 'ended'], inactive: ['已暂停或下架', '已暫停或下架', 'paused or withdrawn'], upcoming: ['尚未开始', '尚未開始', 'not started yet'] };
const localeAt = locale => locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;

const DISCOVERY_DOCS = new WeakMap();
const discoveryText = row => [row?.title, row?.summary, ...(Array.isArray(row?.details) ? row.details : []), row?.costLabel, row?.dateLabel, row?.city, row?.sourceLabel].filter(value => typeof value === 'string').join(' ');
/** Offers/openings index. `discoveries.english` (the en catalog) is indexed with
 * its zh record, so an English question finds a record and the reader gets the
 * record in its own locale. */
function discoveryDocuments(discoveries, locale = 'zh-Hans') {
  if (!discoveries || !Array.isArray(discoveries.items)) return [];
  let byLocale = DISCOVERY_DOCS.get(discoveries);
  if (!byLocale) { byLocale = new Map(); DISCOVERY_DOCS.set(discoveries, byLocale); }
  const key = locale === 'en' ? 'en' : 'zh';
  let docs = byLocale.get(key);
  if (!docs) {
    const english = new Map((discoveries.english?.items || []).filter(row => row?.id).map(row => [`${row.kind}:${row.id}`, row]));
    docs = discoveries.items.filter(row => ['offer', 'opening'].includes(row?.kind) && /^[A-Za-z0-9_-]{1,160}$/.test(row.id || '') && typeof row.title === 'string').map(canonical => {
      const translation = english.get(`${canonical.kind}:${canonical.id}`);
      const row = key === 'en' && translation ? { ...canonical, ...Object.fromEntries(['title', 'summary', 'details', 'costLabel', 'dateLabel'].filter(field => translation[field] !== undefined).map(field => [field, translation[field]])) } : canonical;
      // Region: the record's own, else the cities its title and summary name (a Santa Rosa family day is North Bay).
      const regions = canonical.region ? [canonical.region] : [...new Set(mentionedCities(`${canonical.title} ${canonical.summary || ''}`).map(city => COUNTY_REGION[CITY_COUNTY.get(city)]).filter(Boolean))];
      return { kind: row.kind, id: row.id, title: `${canonical.title} ${translation?.title || ''}`.trim(), row, regions, _cacheKey: canonical, text: `${discoveryText(canonical)} ${discoveryText(translation)}` };
    });
    byLocale.set(key, docs);
  }
  return docs;
}
function discoveryActive(row, today) {
  if (['inactive', 'ended', 'expired'].includes(row.status)) return false;
  if (row.kind === 'offer' && row.status === 'dated') return (row.endDate || row.startDate || '') >= today;
  return true;
}
// API-BB-5: a dated offer that does not fall on the asked day or span ("12/5" on an October 18 ask), or one held
// only on another weekday (IKEA's 仅周三 kids' meals on a Sunday ask), is not an option for that ask.
const OFFER_WEEKDAY = /(?:仅|僅|只在?|限)(?:周|週|星期)([一二三四五六日天])|\bonly on (sun|mon|tue|wed|thu|fri|sat)[a-z]*days?\b|\b(sun|mon|tue|wed|thu|fri|sat)[a-z]*days only\b|^(sun|mon|tue|wed|thu|fri|sat)[a-z]*days\s*:/i;
// Review (API-BB-5 round 1): an offer held on a list or range of other weekdays is not an option either: AMC's 周二、周三
// half-price tickets, the Tea Garden's 周一、三、五 hour, Chabot's Fridays and Saturdays, a museum open Tuesday–Saturday.
// Days named as closed (Cantor: 周二、周三闭馆 / Closed Mondays) are not offer days. Full English day names count alone;
// abbreviations only inside a list ("Fri and Sat"), so "sun" or "sat" in prose is not a day.
const ZH_DAY_RUN = /(?:周|週|星期|礼拜|禮拜)([一二三四五六日天](?:[ \t]{0,2}(?:[、，,和与與及]|至|到|~|～|-|–|—)?[ \t]{0,2}(?:周|週|星期|礼拜|禮拜)?[一二三四五六日天](?![整早次个個起样樣定直])){0,6})/g;
const EN_DAY_TOKEN = String.raw`(?:sun(?:days?)?|mon(?:days?)?|tue(?:s(?:days?)?)?|wed(?:nesdays?)?|thu(?:r(?:s(?:days?)?)?)?|fri(?:days?)?|sat(?:urdays?)?)`;
const EN_DAY_RUN = new RegExp(String.raw`\b(${EN_DAY_TOKEN}(?:\s{0,2}(?:,\s{0,2}(?:and\s+)?|and|&|or|-|–|—|to|through|thru)\s{0,2}${EN_DAY_TOKEN}){0,6})\b`, 'gi');
const EN_FULL_DAY = /^(?:sundays?|mondays?|tuesdays?|wednesdays?|thursdays?|fridays?|saturdays?)$/i;
const CLOSED_AFTER = /^\s*(?:闭馆|閉館|休息|休館|关闭|關閉|不开放|不開放|公休|closed)/i;
const CLOSED_BEFORE = /(?:closed|闭馆|閉館|休息|休館|关闭|關閉|公休)(?:\s*(?:on|：|:))?\s*$/i;
/** The weekdays (0 = Sunday) a label names as open, from runs like 周一、三、五 / 周二至周日 / Fridays and Saturdays, and
 * (runs.closed) the ones it names as closed (周二、周三闭馆 / Closed Mondays). */
function openWeekdays(text) {
  const runs = [];
  runs.closed = new Set();
  const read = (run, index, length, dayOf, separators) => {
    const closed = CLOSED_AFTER.test(text.slice(index + length, index + length + 8)) || CLOSED_BEFORE.test(text.slice(Math.max(0, index - 12), index));
    const parts = run.split(separators);
    const days = new Set();
    for (let at = 0; at < parts.length; at += 2) {
      const day = dayOf(parts[at]);
      if (day < 0) return;
      const separator = parts[at - 1];
      const previous = at >= 2 ? dayOf(parts[at - 2]) : -1;
      if (separator && /至|到|~|～|-|–|—|to|through|thru/i.test(separator) && previous >= 0) for (let step = (previous + 1) % 7, guard = 0; step !== day && guard < 7; step = (step + 1) % 7, guard++) days.add(step);
      days.add(day);
    }
    if (closed) for (const day of days) runs.closed.add(day);
    else runs.push(days);
  };
  for (const match of text.matchAll(ZH_DAY_RUN)) {
    read(match[1].replace(/周|週|星期|礼拜|禮拜/g, ''), match.index, match[0].length, value => { const day = value.trim(); return day.length === 1 ? '日一二三四五六'.indexOf(day === '天' ? '日' : day) : -1; }, /([ \t]*(?:[、，,和与與及]|至|到|~|～|-|–|—)?[ \t]*)/);
  }
  for (const match of text.matchAll(EN_DAY_RUN)) {
    const tokens = match[1].split(/\s*(?:,\s*(?:and\s+)?|\band\b|&|\bor\b|-|–|—|\bto\b|\bthrough\b|\bthru\b)\s*/i);
    if (tokens.length < 2 && !EN_FULL_DAY.test(tokens[0])) continue;
    read(match[1], match.index, match[0].length, value => ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].indexOf(value.trim().slice(0, 3).toLowerCase()), /(\s*(?:,\s*(?:and\s+)?|\band\b|&|\bor\b|-|–|—|\bto\b|\bthrough\b|\bthru\b)\s*)/i);
  }
  return runs;
}
function offerOnAskedDays(row, state) {
  const span = state.dateRange || (state.date ? { start: state.date, end: state.date } : null);
  if (!span || row.kind !== 'offer') return true;
  if (validDate(row.startDate) && validDate(row.endDate || row.startDate) && ((row.endDate || row.startDate) < span.start || row.startDate > span.end)) return false;
  const only = OFFER_WEEKDAY.exec(row.title || '') || OFFER_WEEKDAY.exec(`${row.dateLabel || ''} ${row.costLabel || ''}`);
  const allowed = new Set();
  if (only) {
    const english = only[2] || only[3] || only[4];
    allowed.add(only[1] ? (only[1] === '天' ? 0 : '日一二三四五六'.indexOf(only[1])) : ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].indexOf(english.toLowerCase()));
  }
  // A list or range of days restricts the offer to every day the title and date label name as open.
  const runs = openWeekdays(`${row.title || ''}\n${row.dateLabel || ''}`);
  if (runs.some(days => days.size >= 2) || only) for (const days of runs) for (const day of days) allowed.add(day);
  const asked = [];
  for (let day = span.start, guard = 0; day <= span.end && guard < 32; day = addDays(day, 1), guard++) asked.push(new Date(`${day}T12:00:00Z`).getUTCDay());
  // Closed on every asked day (Cantor on a Tuesday).
  if (asked.length && asked.every(day => runs.closed.has(day))) return false;
  if (!allowed.size) return true;
  for (let day = span.start, guard = 0; day <= span.end && guard < 32; day = addDays(day, 1), guard++) if (allowed.has(new Date(`${day}T12:00:00Z`).getUTCDay())) return true;
  return false;
}
/** Offers and openings that share real question terms, inside the asked city/region. */
function searchDiscoveries({ discoveries, terms, state, today, limit = 4, locale, floor = 2, kind }) {
  // Inside the asked city or region; chain-wide offers (no city/region) stay.
  const region = state.city ? COUNTY_REGION[CITY_COUNTY.get(state.city)] : state.region !== 'all' ? state.region : null;
  const docs = discoveryDocuments(discoveries, locale).filter(doc => (!kind || doc.kind === kind) && discoveryActive(doc.row, today) && offerOnAskedDays(doc.row, state)
    && !(state.city && doc.row.city && doc.row.city !== state.city)
    // A record in the asked city is in its area, whatever region label it carries (Palo Alto's
    // openings say peninsula; its county is South Bay) (API-BB-4B).
    && !(region && doc.regions.length && !doc.regions.includes(region) && !(state.city && doc.row.city === state.city)));
  if (!docs.length || !terms.base.size) return [];
  // termHits on the record's cached token index (the same tokens of the same text).
  return scorer(docs, terms, (doc, score) => score > 0).filter(doc => termHits(doc.text, terms, documentEntry(doc).counts) >= floor)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, limit);
}
/** Question terms in a text: each distinct question term counts 1, a synonym-only
 * term 0.5. One shared bigram (下午, 一下) is noise, not relevance. */
function termHits(text, terms, indexed) {
  const words = indexed || new Set(tokens(text));
  let hits = 0;
  for (const term of terms.expanded) if (words.has(term)) hits += terms.base.has(term) ? 1 : 0.5;
  return hits;
}

const FOOD_CATEGORY = /^(?:food|restaurant|cafe|bakery|dessert)$/i;
// An ask about a new or newly opened place (API-BB-4B).
const OPENING_ASK = /新开|新開|新店|开业|開業|开张|開張|开了吗|開了嗎|开了没|開了沒|开门了|開門了|\b(?:new(?:ly)?[- ]open(?:ed|ing)?|just opened|grand opening|new (?:shop|store|restaurant|cafe|bakery|place)s?|open(?:ed)? yet)\b/i;
// Going, doing or eating somewhere: the questions where a named city should
// bring its places even without shared words ("明天下午想去 Berkeley 走走").
const ACTIVITY_INTENT = /走走|逛|玩|去哪|地方|去处|去處|拍照|打卡|好去处|好去處|景点|景點|散步|活动|活動|半天|一日|吃|喝|餐|咖啡|饮茶|飲茶|\b(?:things? to do|(?:can|could) (?:i|we) do|visit|walk|explore|go to|eat|food|restaurants?|cafes?|coffee|fun)\b/i;
/** Places and dated events in the named city, ranked by the question's terms (forced city recall). */
function cityRecall({ catalog, state, today, terms, requestedFood, message = '', limit = 3 }) {
  if (!catalog || !state.city || !(requestedFood || ['day-plan', 'discover'].includes(state.goal) || ACTIVITY_INTENT.test(message))) return [];
  const rows = [['place', catalog.places], ['event', catalog.events]].flatMap(([kind, entries]) => (entries || [])
    .filter(row => rowCities(row).includes(state.city) && candidateFits(row, kind, state, today)
      && (!requestedFood || kind === 'place' && (FOOD_CATEGORY.test(row.category || '') || matchesFoodEvidence(row, requestedFood, kind))))
    .map(row => ({ ...row, kind, _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, row.category, ...(row.plan || [])].filter(Boolean).join(' ') })));
  if (!rows.length) return [];
  return scorer(rows, terms).sort((a, b) => b.score - a.score || (a.kind === b.kind ? 0 : a.kind === 'place' ? -1 : 1) || a.id.localeCompare(b.id)).slice(0, limit);
}

const BORED = /无聊|無聊|没事做|沒事做|闷|悶|去哪玩|去哪兒玩|\b(?:bored|nothing to do)\b/i;
/** Dated events on the asked day or weekend, for an outing question without a city ("这周末有什么拍照好看的地方"). */
function dateRecall({ catalog, state, today, terms, message = '', limit = 3 }) {
  if (!catalog || state.city || !(ACTIVITY_INTENT.test(message) || BORED.test(message) || ['day-plan', 'discover'].includes(state.goal))) return [];
  const range = state.dateRange || (state.date ? { start: state.date, end: state.date } : dateRangeFor(message, today) || (BORED.test(message) ? dateRangeFor('这周末', today) : null));
  if (!range) return [];
  const scoped = { ...state, dateRange: range };
  const rows = (catalog.events || []).filter(row => candidateFits(row, 'event', scoped, today))
    .map(row => ({ ...row, kind: 'event', _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || [])].filter(Boolean).join(' ') }));
  // Without a subject, prefer free, family-friendly and multi-day weekend events.
  const appeal = row => (isGenerallyFree(row) ? 2 : 0) + ((row.audience || []).some(value => /家庭|亲子|親子|所有年龄|各年龄|各年齡|全家|all ages|famil/i.test(value)) ? 1 : 0) + (row.startDate !== row.endDate ? 0.5 : 0);
  const near = originNearness(state), rail = railFit(state);
  return scorer(rows, terms).sort((a, b) => (rail ? rail(a) - rail(b) : 0) || (near ? near(a) - near(b) : 0) || b.score - a.score || appeal(b) - appeal(a) || a.id.localeCompare(b.id)).slice(0, limit);
}

// "哪些完全免费" / "适合全家" on a known day and area must see every fitting event (BBL-06):
// the free ones when free-only, family and child-friendly ones first for a family.
const FAMILY_ASK = /亲子|親子|全家|一家|孩子|小孩|儿童|兒童|宝宝|寶寶|带娃|帶娃|\b(?:family|families|kids?|children|child)\b/i;
// API-BB-5: 全家 and 各年龄 are family audiences too (Pleasanton's parade and tree lighting says 全家).
const FAMILY_AUDIENCE = /家庭|亲子|親子|儿童|兒童|孩子|幼儿|幼兒|所有年龄|所有年齡|全年龄|全年齡|各年龄|各年齡|全家|all ages|famil|kid|child/i;
// One dated happening (a parade, a book sale) rather than a weekly series that also falls on the asked day.
const oneOff = row => Array.isArray(row.occurrenceDates) ? row.occurrenceDates.length <= 1 : row.startDate === row.endDate;
/** Dated events on the asked day or weekend in the asked city or area, ranked by audience
 * fit then free; a weekend takes the best of each day in turn, so Sunday is not crowded out. */
function audienceRecall({ catalog, state, today, message = '', limit = 4 }) {
  const family = state.childAges.length > 0 || FAMILY_ASK.test(message);
  if (!catalog || !(state.freeOnly || family) || !(state.city || (state.region && state.region !== 'all'))) return [];
  // A household with children on a known day is an outing even when this turn only adds a budget.
  if (!(['day-plan', 'discover'].includes(state.goal) || ACTIVITY_INTENT.test(message) || state.childAges.length)) return [];
  const range = state.dateRange || (state.date ? { start: state.date, end: state.date } : null);
  if (!range) return [];
  const scoped = { ...state, dateRange: range };
  const fit = row => (family && (row.audience || []).some(value => FAMILY_AUDIENCE.test(value)) ? 2 : 0) + (isGenerallyFree(row) ? 1 : 0);
  const ranked = (catalog.events || []).filter(row => candidateFits(row, 'event', scoped, today))
    .map(row => ({ ...row, kind: 'event', _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || [])].filter(Boolean).join(' ') }))
    // API-BB-5 (live 10-15, D2): on a dated family ask the day's one-off events (12/5: Pleasanton's parade and
    // tree lighting, Danville's book sale) come before weekly series that also fall on it; before, the series that
    // started earliest took the four slots. API-SYNC-3e: family audience, then one-off, then the free bonus, so free
    // weekly series (the Oakland storytimes, free from web #45) do not push a one-off of unstated cost out.
    .sort((a, b) => (fit(b) & 2) - (fit(a) & 2) || Number(oneOff(b)) - Number(oneOff(a)) || fit(b) - fit(a) || a.startDate.localeCompare(b.startDate) || a.id.localeCompare(b.id));
  // The first day of the range each event occurs on; one-day ranges keep the plain order.
  const dayOf = row => (Array.isArray(row.occurrenceDates) ? row.occurrenceDates.find(date => date >= range.start && date <= range.end) : null) || (row.startDate > range.start ? row.startDate : range.start);
  const days = [...new Set(ranked.map(dayOf))].sort();
  if (days.length < 2) return ranked.slice(0, limit);
  const queues = days.map(day => ranked.filter(row => dayOf(row) === day)), picked = [];
  for (let round = 0; picked.length < limit && queues.some(queue => queue.length); round++) for (const queue of queues) if (queue.length && picked.length < limit) picked.push(queue.shift());
  return picked;
}

// H17 (audit 10-13, BB-1013-02): a Chinese-community ask (state.community) sees the catalog's
// Chinese-language and Chinese-community events first: those on the asked day or weekend, or,
// when none is, the nearest ones in the next three weeks, marked so the answer says the day
// asked has none and gives their own dates.
// 双语 alone is not one: San Bruno's Día de los Muertos has Spanish-English stories.
const CHINESE_RECORD = /中文|华语|華語|國語|国语|普通话|普通話|粤语|粵語|广东话|廣東話|华人|華人|华裔|華裔|华埠|華埠|唐人街|中国城|中國城|重阳|重陽|中秋|农历|農曆|\b(?:Chinese|Mandarin|Cantonese|Chinatown)\b/i;
const addDays = (day, count) => { const date = new Date(`${day}T12:00:00Z`); date.setUTCDate(date.getUTCDate() + count); return date.toISOString().slice(0, 10); };
// The asks on which Chinese programmes keep their slot (with state.community === 'chinese').
const COMMUNITY_LIFT_ASK = /图书馆|圖書館|分馆|分館|免[费費]|\b(?:librar(?:y|ies)|free)\b/i;
const englishAliases = row => (Array.isArray(row.aliases) ? row.aliases : []).filter(alias => typeof alias === 'string' && /[a-z]/i.test(alias) && !/[㐀-鿿]/.test(alias));
// The text plus the plural of each English word ("market" also counts for "markets"); API-BB-5.
const withPlurals = text => `${text} ${(String(text).match(/[A-Za-z][A-Za-z-]{2,38}/g) || []).filter(word => !/s$/i.test(word)).map(word => `${word}s`).join(' ')}`;
const englishText = (text, englishAsk) => englishAsk ? withPlurals(text) : text;
const isChineseRecord = row => CHINESE_RECORD.test([row.title, row.shortTitle, row.dek, row.summary, ...(row.audience || []), ...(row.aliases || []), ...(row.plan || [])].filter(value => typeof value === 'string').join(' '));
function communityRecall({ catalog, state, today, limit = 4 }) {
  if (!catalog || state.community !== 'chinese') return { matching: [], nearest: [] };
  const rows = (catalog.events || []).filter(isChineseRecord)
    .map(row => ({ ...row, kind: 'event', _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || [])].filter(Boolean).join(' ') }));
  const range = state.dateRange || (state.date ? { start: state.date, end: state.date } : null);
  const firstDay = (row, from) => (Array.isArray(row.occurrenceDates) ? row.occurrenceDates.filter(day => day >= from).sort()[0] : null) || (row.startDate > from ? row.startDate : from);
  const byDate = from => (a, b) => firstDay(a, from).localeCompare(firstDay(b, from)) || a.id.localeCompare(b.id);
  const fitting = rows.filter(row => candidateFits(row, 'event', range ? { ...state, date: null, dateRange: range } : state, today)).sort(byDate(range?.start || today));
  // API-BB-4B (API-SYNC-3b follow-up): a weekend takes each day in turn, as audienceRecall does, so
  // four Saturday programmes no longer push Millbrae's Sunday storytime out.
  const days = range ? [...new Set(fitting.map(row => firstDay(row, range.start)))].sort() : [];
  let matching = fitting.slice(0, limit);
  if (days.length > 1) {
    const queues = days.map(day => fitting.filter(row => firstDay(row, range.start) === day));
    matching = [];
    while (matching.length < limit && queues.some(queue => queue.length)) for (const queue of queues) if (queue.length && matching.length < limit) matching.push(queue.shift());
  }
  if (matching.length || !range) return { matching, nearest: [] };
  const after = range.end >= today ? addDays(range.end, 1) : today;
  const nearest = rows.filter(row => candidateFits(row, 'event', { ...state, date: null, dateRange: { start: after, end: addDays(after, 21) } }, today)).sort(byDate(after)).slice(0, 2);
  return { matching, nearest };
}

/** A retrieved guide's county-by-county contact line for the asked city's county
 * ("Santa Clara：408-350-3200" for San Jose), which shares no words with the question. */
function countyContactLines({ guideCatalog, catalog, state, today, guides = [], limit = 1 }) {
  const county = state.city ? CITY_COUNTY.get(state.city) : null;
  if (!county || !guides.length) return [];
  const slugs = new Set(guides.map(guide => guide.slug));
  const line = new RegExp(`${county.replace(/ /g, '\\s+')}(?:\\s*(?:County|[县縣]))?\\s*[：:]\\s*(?:1-)?\\(?\\d{3}`, 'i');
  return indexedGuideDocuments(guideCatalog, catalog).filter(row => slugs.has(row.slug) && !isGuideArchived(row, today) && line.test(row.text)).slice(0, limit)
    .map(({ _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, _linkCard, _section, ...guide }) => ({ ...guide, sectionHeading: _contentHeading, cities: [...guide.cities] }));
}

/** Directory paragraphs whose own heading is the asked city (101-city utilities and city guides). */
function cityGuideSections({ guideCatalog, catalog, state, terms, message, today, limit = 1 }) {
  if (!state.city || !['information', 'newcomer', 'discover', 'day-plan'].includes(state.goal)) return [];
  const newcomer = state.goal === 'newcomer' || /搬[来來到家]|刚到|剛到|新来|新來|开户|開戶|水电|水電|\b(?:moved?|moving|utilities|new resident)\b/i.test(message);
  const outing = !newcomer && (['discover', 'day-plan'].includes(state.goal) || ACTIVITY_INTENT.test(message));
  if (!newcomer && !outing) return [];
  const want = newcomer ? /utilit|水电|水電/i : /explor|city guide|游玩|遊玩|探索/i;
  const rows = indexedGuideDocuments(guideCatalog, catalog).filter(row => row._primaryCities.includes(state.city) && !isGuideArchived(row, today) && want.test(`${row.slug} ${row.title} ${row._contentHeading || ''}`));
  if (!rows.length) return [];
  return scorer(rows, terms).sort((a, b) => b.score - a.score || a.evidenceId.localeCompare(b.evidenceId)).slice(0, limit)
    .map(({ score, _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, _linkCard, _section, ...guide }) => ({ ...guide, sectionHeading: _contentHeading, cities: [...guide.cities], sourceUrls: guide.sourceUrls, relevance: Number(score.toFixed(3)) }));
}

function siteUrlOf(kind, row) {
  if (kind === 'event') return `/events/${row.id}`;
  if (kind === 'offer' || kind === 'opening') return row.path && /^\/(?:offers|openings)\/[A-Za-z0-9_-]+$/.test(row.path) ? row.path : `/${kind}s/${row.id}`;
  if (row.path && /^\/openings\/[A-Za-z0-9_-]+$/.test(row.path)) return row.path;
  return row.guideSlug && /^[A-Za-z0-9_-]+$/.test(row.guideSlug) ? `/guides/${row.guideSlug}` : null;
}
/** A planner place that mirrors an opening (id "opening-<x>", path /openings/<x>) is that opening. */
function entityKey(kind, row) {
  const mirror = kind === 'place' && /^\/openings\/([A-Za-z0-9_-]+)$/.exec(row.path || '');
  return mirror ? `opening:${mirror[1]}` : `${kind}:${row.id}`;
}

function entityItem(kind, row, { locale, today, terms, contact, mismatch, openings }) {
  const temporal = temporalOf(row, today);
  // "已售罄" / "已延期，新日期未公布" / "已取消" before the generic label; an ended event still reads "已结束".
  const label = (temporal !== 'past' && kind === 'event' && eventStatusLabel(eventStatus(row), locale)) || TEMPORAL[temporal]?.[localeAt(locale)];
  const when = kind === 'event' || (kind === 'offer' && row.startDate) ? readerRange(row.startDate, row.endDate, locale) : '';
  // API-BB-4B (API-SYNC-3a follow-up): a planner place that mirrors an opening carries only its
  // address and summary; the opening's own date line and details (Burlingame's Old Post Office:
  // "周末早午餐 11:00–14:00 … 10/17 周六是否供应未能确认") come from the opening record. All of
  // an event's plan lines are offered (BORP's third line has both celebration times); the
  // snippet still keeps the most relevant sentences within ITEM_CHARS.
  const mirror = kind === 'place' && openings ? openings.get(/^\/openings\/([A-Za-z0-9_-]+)$/.exec(row.path || '')?.[1]) : null;
  const details = Array.isArray(row.details) ? row.details : Array.isArray(mirror?.details) ? mirror.details : [];
  const facts = [row.dateLabel || mirror?.dateLabel, row.venue, row.address, row.costLabel, row.summary, ...details.slice(0, 3), ...(Array.isArray(row.plan) ? row.plan.slice(0, 6) : [])]
    .filter(value => typeof value === 'string' && value.trim());
  const url = siteUrlOf(kind, row);
  const official = safeUrl(row.officialUrl || row.sourceUrl);
  const isOpening = kind === 'place' && /^\/openings\//.test(url || '');
  // API-BB-5 (API-SYNC-3c follow-up 4): the API planner catalog is Chinese; an English reader's model sees an
  // event's or place's English name (its English alias, as the cards already show), not the Chinese title.
  const title = locale === 'en' && ['event', 'place'].includes(kind) && !isOpening ? englishAlias(row, kind) || row.title : row.title;
  return { kind: isOpening ? 'opening' : kind, id: isOpening ? url.split('/').pop() : row.id, catalogKind: kind, catalogId: row.id, title: String(title).slice(0, 200),
    page: url ? `${SITE}${url}` : official, ...(official ? { official } : {}),
    ...(when ? { when } : {}), ...(row.city ? { city: row.city } : {}), ...(typeof row.costLabel === 'string' && row.costLabel ? { cost: row.costLabel.slice(0, 120) } : {}),
    ...(label ? { status: label } : {}), ...(mismatch ? { mismatch } : {}), temporalStatus: temporal,
    text: snippet(facts.join('\n'), terms, ITEM_CHARS, contact), row };
}
function guideItem(guide, { terms, contact }) {
  const text = [guide.sectionHeading && !String(guide.text).startsWith(guide.sectionHeading) ? guide.sectionHeading : '', guide.text].filter(Boolean).join('\n');
  return { kind: 'guide', id: guide.slug, title: String(guide.title).slice(0, 200), page: `${SITE}${guide.url}`, guideUrl: guide.url,
    ...(guide.archived ? { status: 'archived edition' } : {}), text: snippet(text, terms, ITEM_CHARS, contact), guide };
}

/** v2 evidence. Returns buildSiteEvidence's shape (guides, candidates, sources,
 * nearMiss, foodEvidence, originCandidate) plus `items`: the compact list the
 * model sees, refs e1..eN in priority order. The page being viewed is not an
 * item (it is currentPage, cited as [[page]]). */
function buildFastEvidence({ query = '', originalQuery, state: inputState, guideCatalog = [], catalog: suppliedCatalog, discoveries, today = bayAreaDate(), currentPath = '/', selectedGuideUrls, boostGuideUrls = [], locale = 'zh-Hans', pageKeys = [], pageTitles = [], limit = FAST_LIMIT, audience = false } = {}) {
  const state = validateTaskState(inputState);
  const catalog = loadPlannerCatalog(suppliedCatalog);
  const message = typeof originalQuery === 'string' ? originalQuery : String(query);
  // "还有吗" / "这个要会员吗" on an event, offer or opening page: retrieve around the
  // page's subject so a similar current option can be offered.
  if (pageTitles.length) query = `${query} ${pageTitles.slice(0, 2).map(title => String(title).slice(0, 120)).join(' ')}`;
  const site = buildSiteEvidence({ query, originalQuery, state, guideCatalog, catalog, today, currentPath, selectedGuideUrls, boostGuideUrls, v2: true });
  const terms = queryTokens(`${String(query).slice(0, 4000)} ${queryAliases(message).terms.join(' ')}`, state);
  const contact = CONTACT_QUESTION.test(message);
  const requestedFood = foodRequest(message);
  // Openings in the reader's locale, for the planner places that mirror them (entityItem).
  const openings = new Map(discoveryDocuments(discoveries, locale).filter(doc => doc.kind === 'opening').map(doc => [doc.id, doc.row]));
  const options = { locale, today, terms, contact, openings };
  // A how-to question (DMV, Medi-Cal, library card, …): a record that only shares a
  // word such as 预约 or 中文 is not evidence for it. The page being read, selected
  // stops, named entities and the city's directory sections are kept regardless.
  const { onSubject } = queryAliases(message);
  const onTopic = value => !onSubject || onSubject(value);
  const seen = new Set(pageKeys);
  const lists = { named: [], audience: [], guides: [], candidates: [], discoveries: [], city: [] };
  // API-BB-QUALITY: a record a later list also found must not be lost because an earlier
  // list claimed it past its own slice (Top Dog and Hoagie's fell out of a Berkeley dinner
  // follow-up as the 5th and 6th opening). Named and audience records still block every
  // other list; the others are de-duplicated when the items are assembled.
  const push = (list, item, key) => {
    if (!item || seen.has(key)) return;
    if (audience && !['named', 'audience'].includes(list)) { if (!lists[list].some(entry => entry._key === key)) lists[list].push(Object.assign(item, { _key: key })); return; }
    seen.add(key); lists[list].push(item);
  };
  // 1. Named entities (alias or core name), including ones the date/constraints exclude.
  const named = namedEntitiesV2(message, catalog, { discoveries, cityTokens: CITY_TOKENS });
  const nearMissIds = new Map((site.nearMiss || []).map(row => [row.id, row.reason]));
  for (const { kind, row } of named) {
    // A status always marks the record (nearMiss keeps only three), so it never becomes a plan candidate below.
    const mismatch = kind === 'event' ? nearMissIds.get(row.id) || statusReason(row, today) || undefined : undefined;
    push('named', { ...entityItem(kind, row, { ...options, mismatch }), named: true }, entityKey(kind, row));
  }
  // 1a. H17: Chinese-language and Chinese-community events first, for a Chinese-community ask.
  const community = communityRecall({ catalog, state, today });
  for (const row of community.matching) push('audience', entityItem('event', row, options), entityKey('event', row));
  for (const row of community.nearest) push('audience', { ...entityItem('event', row, options), nearest: true }, entityKey('event', row));
  // 1b. v2 quality (BBL-06): every free or family-fitting event on the asked day and area.
  if (audience) for (const row of audienceRecall({ catalog, state, today, message, limit: state.freeOnly ? 5 : 4 })) if (onTopic(row.text || row.title)) push('audience', entityItem('event', row, options), entityKey('event', row));
  // A shared weak bigram is not relevance: keep a paragraph or candidate that shares
  // two question terms (one for a one- or two-term question), the guide being read
  // and a professional topic's pillar guide, and every user-selected stop.
  const floor = Math.min(2, Math.max(1, terms.base.size - 1));
  const boosted = new Set([currentPath, ...(Array.isArray(selectedGuideUrls) ? selectedGuideUrls : []), ...(Array.isArray(boostGuideUrls) ? boostGuideUrls : [])]);
  const selected = new Set(state.selectedCandidateIds || []);
  // API-BB-5: in an English ask, "there", "any", a month or a day number is not a subject. A guide paragraph needs the
  // question's subject words ("parades"), with plurals, not "Are there any …" (a renter's checklist answered a parade ask).
  const englishAsk = !/[㐀-鿿]/.test(message);
  const dayless = withoutDayTerms(terms);
  // Review (API-BB-5 round 1): the asked city's own words ("jose") and region or direction words ("south", "bay") are
  // where, not what: "a Christmas tree in the South Bay" matched Opera San José on "south".
  const placeWords = new Set(mentionedCities(message).flatMap(city => city.toLowerCase().split(/[\s.]+/)));
  const subject = term => !MONTH_TERMS.test(term) && !REGION_TERMS.test(term) && !placeWords.has(term);
  const subjectTerms = { base: new Set([...dayless.base].filter(subject)), expanded: new Set([...dayless.expanded].filter(subject)) };
  const subjectFloor = Math.min(2, Math.max(1, subjectTerms.base.size - 1));
  // API-SYNC-3f: nor, for a guide paragraph in any ask, the numbers that write its date (the 12 of 12月 matched "5–12 岁").
  // A catalog candidate below already fits the asked date (candidateFits), so there the date in its text may still count
  // beside one subject word, as before (the Calistoga lighted tractor parade, 游行 and 12/5, for a 12月 parade ask).
  const undated = withoutDateNumbers(terms, message, state);
  const undatedFloor = undated === terms ? floor : Math.min(2, Math.max(1, undated.base.size - 1));
  const guideMatched = text => englishAsk && subjectTerms.base.size ? termHits(withPlurals(text), subjectTerms) >= Math.min(floor, subjectTerms.base.size) : termHits(text, undated) >= undatedFloor;
  // 2. Guide paragraphs (boosted current guide first; balanced across subjects).
  for (const guide of site.guides || []) {
    const text = `${guide.title}\n${guide.sectionHeading || ''}\n${guide.text}`;
    if (boosted.has(guide.url) || (onTopic(text) && guideMatched(text))) push('guides', guideItem(guide, options), `guide:${guide.evidenceId}`);
  }
  // 3. Catalog candidates that fit the task's city/date/constraints.
  // API-BB-5 (live 10-15, L08): an English ask's terms are matched against the row's English aliases too, with
  // plurals ("farmers markets" / "Farmers' Market"); the Chinese text alone shares no English word, so the
  // Downtown Berkeley and Grand Lake markets were retrieved but never reached the model.
  for (const row of site.candidates || []) {
    const text = [row.title, row.summary, row.venue, row.costLabel, ...(row.plan || []), ...(englishAsk ? englishAliases(row) : [])].filter(Boolean).join(' ');
    // An English reader's text for a Chinese row is its English name; it needs the question's subject words (a day, a
    // month, a number, the asked city or a region is a constraint, never the subject), with the usual floor: an
    // information ask ("my child has a fever at night in San Jose") is not matched by one incidental word ("Night Market").
    // An outing ask (discover, day-plan) takes every fitting row, as before. A dated ask ("Any Cantonese film screenings
    // in San Francisco on November 14?") is about that day's events, which already fit the day: one subject word in the
    // row's English name is enough ("Hard Boiled, screened in Cantonese").
    const dated = !!(state.date || state.dateRange);
    const matched = text => englishAsk ? subjectTerms.base.size > 0 && (termHits(withPlurals(text), subjectTerms) >= subjectFloor
      || (dated && termHits(withPlurals(englishAliases(row).join(' ')), subjectTerms) >= 1)) : termHits(text, terms) >= floor;
    if (selected.has(row.id) || (onTopic(text) && (['day-plan', 'discover'].includes(state.goal) || matched(text)))) push('candidates', entityItem(row.kind, row, options), entityKey(row.kind, row));
  }
  // 4. Offers and openings (not searchable before v2). API-BB-4B (API-SYNC-3a follow-up): an ask
  // about a new place in a named city or area ("Palo Alto 新开的奶茶店开了吗") needs one shared term
  // with an opening there (奶茶), not two; those openings come first.
  const openingAsk = OPENING_ASK.test(message) && !!(state.city || (state.region && state.region !== 'all'));
  const openingDocs = openingAsk ? searchDiscoveries({ discoveries, terms, state, today, locale, floor: 1, kind: 'opening', limit: 3 }) : [];
  for (const doc of [...openingDocs, ...searchDiscoveries({ discoveries, terms, state, today, locale, floor })]) {
    const item = entityItem(doc.kind, doc.row, options);
    if (item && onTopic(`${item.title}\n${item.text || ''}`)) push('discoveries', item, `${doc.kind}:${doc.id}`);
  }
  // 5. Forced city recall: the named city's own section of the city directories
  // (utilities for a newcomer, places for an outing) and its places/events, even
  // when the question shares no words with them.
  // API-BB-QUALITY: for a meal or an outing the city's own places and events come before its
  // directory sections, and a county phone line is not evidence for a meal.
  const entitiesFirst = audience && (requestedFood || ['day-plan', 'discover'].includes(state.goal));
  const cityEntities = () => {
    for (const row of cityRecall({ catalog, state, today, terms, requestedFood, message })) if (onTopic(row.text || row.title)) push('city', entityItem(row.kind, row, options), entityKey(row.kind, row));
    for (const row of dateRecall({ catalog, state, today, terms, message })) if (onTopic(row.text || row.title)) push('city', entityItem('event', row, options), entityKey('event', row));
  };
  // The county's own phone line (San Jose -> Santa Clara 408-350-3200) always leads the city queue.
  if (!(audience && requestedFood && !contact)) for (const guide of countyContactLines({ guideCatalog, catalog, state, today, guides: site.guides })) push('city', guideItem(guide, options), `guide:${guide.evidenceId}`);
  if (entitiesFirst) cityEntities();
  for (const guide of cityGuideSections({ guideCatalog, catalog, state, terms, message, today })) push('city', guideItem(guide, options), `guide:${guide.evidenceId}`);
  if (!entitiesFirst) cityEntities();
  const items = [...lists.named.slice(0, 3), ...lists.audience];
  const queues = [lists.guides.slice(0, 5), lists.candidates.slice(0, 4), lists.discoveries.slice(0, 4), lists.city.slice(0, 3)];
  const taken = new Set();
  // Each queue offers its next record not already taken (the first one, outside quality mode).
  const next = queue => { while (queue.length) { const item = queue.shift(); if (!item._key || !taken.has(item._key)) { if (item._key) taken.add(item._key); return item; } } return null; };
  for (let round = 0; items.length < limit && queues.some(queue => queue.length); round++) {
    for (const queue of queues) if (queue.length && items.length < limit) { const item = next(queue); if (item) items.push(item); }
  }
  for (const item of items) delete item._key;
  items.forEach((item, index) => { item.ref = `e${index + 1}`; });
  // Plan candidates stay events/places; offers/openings join only as citable records.
  const candidateIds = new Set((site.candidates || []).map(row => `${row.kind}:${row.id}`));
  const extraCandidates = items.filter(item => ['event', 'place'].includes(item.catalogKind) && !candidateIds.has(`${item.catalogKind}:${item.catalogId}`) && !item.mismatch && !item.nearest)
    .map(item => withAdmissionFacts({ ...normalizeCandidate(item.row, item.catalogKind, catalog?.checkedAt, state), relevance: 0 }, state, { today }));
  const foodEvidence = site.foodEvidence && requestedFood && items.some(item => item.kind !== 'guide' && ['place', 'opening'].includes(item.kind) && (FOOD_CATEGORY.test(item.row?.category || '') || matchesFoodEvidence(item.row, requestedFood, 'place')))
    ? { ...site.foodEvidence, status: 'matched' } : site.foodEvidence;
  return { ...site, candidates: [...(site.candidates || []), ...extraCandidates], ...(foodEvidence ? { foodEvidence } : {}), items, terms: { base: [...terms.base] } };
}

/** The model's view of fast-path items: no internal rows, fixed key order. */
function modelItems(items) {
  return items.map(item => ({ ref: item.ref, kind: item.kind, title: item.title, page: item.page, ...(item.official && item.official !== item.page ? { official: item.official } : {}),
    ...(item.when ? { when: item.when } : {}), ...(item.city ? { city: item.city } : {}), ...(item.cost ? { cost: item.cost } : {}), ...(item.status ? { status: item.status } : {}),
    ...(item.nearest ? { note: 'Chinese-language or Chinese-community event NOT on the asked day: the nearest one after it. Say plainly that the asked day has none listed, then give this one with its own date.' } : {}),
    ...(item.mismatch ? { note: item.mismatch === 'past' ? 'Ended. Not a current option; say it ended and when.' : eventStatusNote(item.mismatch) || 'Does not match the asked date or conditions; correct the premise, never recommend it as matching.' } : {}),
    text: item.text }));
}

/** Share of the question's terms found in a text (same tokenizer as retrieval). */
function queryOverlap(query, text) {
  const wanted = [...new Set(tokens(String(query || '').slice(0, 4000)))];
  if (!wanted.length) return { matched: 0, total: 0, ratio: 0 };
  const present = new Set(tokens(String(text || '').slice(0, 20000)));
  const matched = wanted.filter(term => present.has(term)).length;
  return { matched, total: wanted.length, ratio: matched / wanted.length };
}

function primeSiteEvidence({ guideCatalog, catalog }) {
  if (!catalog || !Array.isArray(guideCatalog)) return;
  // Tokenises every paragraph once and builds the term index the questions score with.
  corpusIndex(indexedGuideDocuments(guideCatalog, catalog));
}
module.exports = { buildSiteEvidence, primeSiteEvidence, queryOverlap, buildFastEvidence, modelItems, readerDate, readerRange, snippet, searchDiscoveries, offerOnAskedDays, withoutDateNumbers, CITY_COUNTY };
