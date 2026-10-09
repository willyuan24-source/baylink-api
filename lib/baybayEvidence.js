const crypto = require('node:crypto');
const { namedEntities, namedEntitiesV2, queryAliases, dateRangeFor } = require('./entityAliases');
const { loadPlannerCatalog, eventOccursOn, active, priceOf, admissionLowerBound, validDate, REGIONS } = require('./planner');
const { canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate } = require('./bayAreaSearchScope');
const { validateTaskState } = require('./baybayState');
const { withAdmissionFacts } = require('./baybayFacts');
const { isSchoolRequest, isSchoolGuide, guideEditionMonth, guideEditionThroughDate, isGuideArchived } = require('./guideConversation');
const { isLibraryServiceQuestion } = require('./publicResearch');
const { foodRequest, matchesFoodEvidence } = require('./foodEvidence');

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
    const named = normalize(heading);
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
      const score = row.score + headingBoost + facets.filter(facet => !covered.has(facet))
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

function candidateFits(row, kind, state, today) {
  if (!active(row)) return false;
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
    recordedAt: validDate(row.verifiedAt) ? row.verifiedAt : checkedAt,
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
  let documents = indexedGuideDocuments(guideCatalog, catalog).filter(row =>
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
  const cityScored = scorer(documents, terms).map(row => focusedGuideUrls.has(row.url) ? { ...row, score: Math.max(1, row.score) } : row).filter(row => row.score > 0).map(row => ({ ...row, score: row.score * (state.city && row.cities.length === 1 && row.cities[0] === state.city ? 1.6 : 1) }));
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
  for (const row of balancedGuideRows(guideScores, intentQuery, comparedCities.length > 1 ? comparedCities : [])) {
    const { score, _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, ...guide } = row;
    guides.push({ ...guide, archived: isGuideArchived(guide, today), sectionHeading: _contentHeading, requestedTopics: REQUEST_SUBJECTS.filter(([, pattern]) => pattern.test(intentQuery) && pattern.test(guide.text)).map(([id]) => id),
      cities: [...guide.cities], sourceUrls: selectedGuideSources(row, terms, retrievalState, sourceRankings), relevance: Number(score.toFixed(3)) });
    if (guides.length === 8) break;
  }
  let candidates = [];
  if (catalog && validDate(today)) {
    const namedIds = new Set(named(intentQuery, catalog).map(({ kind, row }) => `${kind}:${row.id}`));
    const rows = [['event', catalog.events], ['place', catalog.places]].flatMap(([kind, entries]) => entries
      .filter(row => safeUrl(row.officialUrl) && candidateFits(row, kind, state, today)
        && matchesFoodEvidence(row, requestedFood, kind)
        && (!noPurchaseDiscovery || isGenerallyFree(row)))
      .map(row => ({ ...normalizeCandidate(row, kind, catalog.checkedAt, state), _cacheKey: row, text: [row.title, row.summary, row.venue, row.costLabel, ...(row.audience || []), ...(row.plan || [])].join(' ') })));
    const namedAcronyms = String(query).match(/\b[A-Z][A-Z0-9]{2,11}\b/g)?.filter(term => !['BART', 'MUNI', 'SFO', 'SJC', 'OAK', 'USD', 'USA', 'THE', 'AND', 'BAYLINK'].includes(term)) || [];
    const selectionRank = row => state.selectedCandidateIds.findIndex(id => id === row.id || id === row.candidateId);
    candidates = scorer(rows, terms).filter(row => {
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
      // A dated activity request should see eligible dated programs before
      // unrelated permanent shops which happen to share a word with it.
      if (activityDiscovery && a.kind !== b.kind) return a.kind === 'event' ? -1 : 1;
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
    ...candidates.map(row => ({ id: row.evidenceId, evidenceId: row.evidenceId, title: row.title, titleOrigin: 'candidate', url: row.officialUrl, sourceKind: row.sourceKind, verification: row.verification, recordedAt: row.recordedAt, sourceSpecificity: row.sourceSpecificity, verifiedLive: false,
      ...(candidates.filter(other => other.officialUrl === row.officialUrl).length === 1 ? { text: candidateSnapshotText(row) } : {}) })),
  ];
  const nearMiss = named(intentQuery, catalog).filter(({ kind, row }) => kind === 'event' && !candidateFits(row, kind, state, today)).map(({ kind, row }) => ({ kind, id: row.id, title: row.title, startDate: row.startDate, endDate: row.endDate, occurrenceDates: row.occurrenceDates, summary: row.summary, officialUrl: row.officialUrl, reason: state.date && !eventOccursOn(row, state.date) ? 'date_mismatch' : row.endDate < today ? 'past' : 'constraints_mismatch' })).slice(0, 3);
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
  const clean = String(text || '').replace(/[ \t]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
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
  if (['inactive', 'ended', 'expired'].includes(row.status) || row.active === false) return 'inactive';
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
/** Offers and openings that share real question terms, inside the asked city/region. */
function searchDiscoveries({ discoveries, terms, state, today, limit = 4, locale, floor = 2 }) {
  // Inside the asked city or region; chain-wide offers (no city/region) stay.
  const region = state.city ? COUNTY_REGION[CITY_COUNTY.get(state.city)] : state.region !== 'all' ? state.region : null;
  const docs = discoveryDocuments(discoveries, locale).filter(doc => discoveryActive(doc.row, today)
    && !(state.city && doc.row.city && doc.row.city !== state.city)
    && !(region && doc.regions.length && !doc.regions.includes(region)));
  if (!docs.length || !terms.base.size) return [];
  return scorer(docs, terms).filter(doc => doc.score > 0 && termHits(doc.text, terms) >= floor)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, limit);
}
/** Question terms in a text: each distinct question term counts 1, a synonym-only
 * term 0.5. One shared bigram (下午, 一下) is noise, not relevance. */
function termHits(text, terms) {
  const words = new Set(tokens(text));
  let hits = 0;
  for (const term of terms.expanded) if (words.has(term)) hits += terms.base.has(term) ? 1 : 0.5;
  return hits;
}

const FOOD_CATEGORY = /^(?:food|restaurant|cafe|bakery|dessert)$/i;
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
  const appeal = row => (isGenerallyFree(row) ? 2 : 0) + ((row.audience || []).some(value => /家庭|亲子|親子|所有年龄|all ages|famil/i.test(value)) ? 1 : 0) + (row.startDate !== row.endDate ? 0.5 : 0);
  return scorer(rows, terms).sort((a, b) => b.score - a.score || appeal(b) - appeal(a) || a.id.localeCompare(b.id)).slice(0, limit);
}

/** A retrieved guide's county-by-county contact line for the asked city's county
 * ("Santa Clara：408-350-3200" for San Jose), which shares no words with the question. */
function countyContactLines({ guideCatalog, catalog, state, today, guides = [], limit = 1 }) {
  const county = state.city ? CITY_COUNTY.get(state.city) : null;
  if (!county || !guides.length) return [];
  const slugs = new Set(guides.map(guide => guide.slug));
  const line = new RegExp(`${county.replace(/ /g, '\\s+')}(?:\\s*(?:County|[县縣]))?\\s*[：:]\\s*(?:1-)?\\(?\\d{3}`, 'i');
  return indexedGuideDocuments(guideCatalog, catalog).filter(row => slugs.has(row.slug) && !isGuideArchived(row, today) && line.test(row.text)).slice(0, limit)
    .map(({ _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, ...guide }) => ({ ...guide, sectionHeading: _contentHeading, cities: [...guide.cities] }));
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
    .map(({ score, _primaryCities, _guideCities, _isOutingGuide, _schoolRegions, _guideSources, _contentKey, _contentHeading, ...guide }) => ({ ...guide, sectionHeading: _contentHeading, cities: [...guide.cities], sourceUrls: guide.sourceUrls, relevance: Number(score.toFixed(3)) }));
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

function entityItem(kind, row, { locale, today, terms, contact, mismatch }) {
  const temporal = temporalOf(row, today);
  const label = TEMPORAL[temporal]?.[localeAt(locale)];
  const when = kind === 'event' || (kind === 'offer' && row.startDate) ? readerRange(row.startDate, row.endDate, locale) : '';
  const facts = [row.dateLabel, row.venue, row.address, row.costLabel, row.summary, ...(Array.isArray(row.details) ? row.details.slice(0, 2) : []), ...(Array.isArray(row.plan) ? row.plan.slice(0, 2) : [])]
    .filter(value => typeof value === 'string' && value.trim());
  const url = siteUrlOf(kind, row);
  const official = safeUrl(row.officialUrl || row.sourceUrl);
  const isOpening = kind === 'place' && /^\/openings\//.test(url || '');
  return { kind: isOpening ? 'opening' : kind, id: isOpening ? url.split('/').pop() : row.id, catalogKind: kind, catalogId: row.id, title: String(row.title).slice(0, 200),
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
function buildFastEvidence({ query = '', originalQuery, state: inputState, guideCatalog = [], catalog: suppliedCatalog, discoveries, today = bayAreaDate(), currentPath = '/', selectedGuideUrls, boostGuideUrls = [], locale = 'zh-Hans', pageKeys = [], pageTitles = [], limit = FAST_LIMIT } = {}) {
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
  const options = { locale, today, terms, contact };
  // A how-to question (DMV, Medi-Cal, library card, …): a record that only shares a
  // word such as 预约 or 中文 is not evidence for it. The page being read, selected
  // stops, named entities and the city's directory sections are kept regardless.
  const { onSubject } = queryAliases(message);
  const onTopic = value => !onSubject || onSubject(value);
  const seen = new Set(pageKeys);
  const lists = { named: [], guides: [], candidates: [], discoveries: [], city: [] };
  const push = (list, item, key) => { if (!item || seen.has(key)) return; seen.add(key); lists[list].push(item); };
  // 1. Named entities (alias or core name), including ones the date/constraints exclude.
  const named = namedEntitiesV2(message, catalog, { discoveries, cityTokens: CITY_TOKENS });
  const nearMissIds = new Map((site.nearMiss || []).map(row => [row.id, row.reason]));
  for (const { kind, row } of named) {
    const mismatch = kind === 'event' ? nearMissIds.get(row.id) : undefined;
    push('named', { ...entityItem(kind, row, { ...options, mismatch }), named: true }, entityKey(kind, row));
  }
  // A shared weak bigram is not relevance: keep a paragraph or candidate that shares
  // two question terms (one for a one- or two-term question), the guide being read
  // and a professional topic's pillar guide, and every user-selected stop.
  const floor = Math.min(2, Math.max(1, terms.base.size - 1));
  const boosted = new Set([currentPath, ...(Array.isArray(selectedGuideUrls) ? selectedGuideUrls : []), ...(Array.isArray(boostGuideUrls) ? boostGuideUrls : [])]);
  const selected = new Set(state.selectedCandidateIds || []);
  // 2. Guide paragraphs (boosted current guide first; balanced across subjects).
  for (const guide of site.guides || []) {
    const text = `${guide.title}\n${guide.sectionHeading || ''}\n${guide.text}`;
    if (boosted.has(guide.url) || (onTopic(text) && termHits(text, terms) >= floor)) push('guides', guideItem(guide, options), `guide:${guide.evidenceId}`);
  }
  // 3. Catalog candidates that fit the task's city/date/constraints.
  for (const row of site.candidates || []) {
    const text = [row.title, row.summary, row.venue, row.costLabel, ...(row.plan || [])].filter(Boolean).join(' ');
    if (selected.has(row.id) || (onTopic(text) && (['day-plan', 'discover'].includes(state.goal) || termHits(text, terms) >= floor))) push('candidates', entityItem(row.kind, row, options), entityKey(row.kind, row));
  }
  // 4. Offers and openings (not searchable before v2).
  for (const doc of searchDiscoveries({ discoveries, terms, state, today, locale, floor })) {
    const item = entityItem(doc.kind, doc.row, options);
    if (item && onTopic(`${item.title}\n${item.text || ''}`)) push('discoveries', item, `${doc.kind}:${doc.id}`);
  }
  // 5. Forced city recall: the named city's own section of the city directories
  // (utilities for a newcomer, places for an outing) and its places/events, even
  // when the question shares no words with them.
  for (const guide of countyContactLines({ guideCatalog, catalog, state, today, guides: site.guides })) push('city', guideItem(guide, options), `guide:${guide.evidenceId}`);
  for (const guide of cityGuideSections({ guideCatalog, catalog, state, terms, message, today })) push('city', guideItem(guide, options), `guide:${guide.evidenceId}`);
  for (const row of cityRecall({ catalog, state, today, terms, requestedFood, message })) if (onTopic(row.text || row.title)) push('city', entityItem(row.kind, row, options), entityKey(row.kind, row));
  for (const row of dateRecall({ catalog, state, today, terms, message })) if (onTopic(row.text || row.title)) push('city', entityItem('event', row, options), entityKey('event', row));
  const items = [...lists.named.slice(0, 3)];
  const queues = [lists.guides.slice(0, 5), lists.candidates.slice(0, 4), lists.discoveries.slice(0, 4), lists.city.slice(0, 3)];
  for (let round = 0; items.length < limit && queues.some(queue => queue.length); round++) {
    for (const queue of queues) if (queue.length && items.length < limit) items.push(queue.shift());
  }
  items.forEach((item, index) => { item.ref = `e${index + 1}`; });
  // Plan candidates stay events/places; offers/openings join only as citable records.
  const candidateIds = new Set((site.candidates || []).map(row => `${row.kind}:${row.id}`));
  const extraCandidates = items.filter(item => ['event', 'place'].includes(item.catalogKind) && !candidateIds.has(`${item.catalogKind}:${item.catalogId}`) && !item.mismatch)
    .map(item => withAdmissionFacts({ ...normalizeCandidate(item.row, item.catalogKind, catalog?.checkedAt, state), relevance: 0 }, state, { today }));
  const foodEvidence = site.foodEvidence && requestedFood && items.some(item => item.kind !== 'guide' && ['place', 'opening'].includes(item.kind) && (FOOD_CATEGORY.test(item.row?.category || '') || matchesFoodEvidence(item.row, requestedFood, 'place')))
    ? { ...site.foodEvidence, status: 'matched' } : site.foodEvidence;
  return { ...site, candidates: [...(site.candidates || []), ...extraCandidates], ...(foodEvidence ? { foodEvidence } : {}), items, terms: { base: [...terms.base] } };
}

/** The model's view of fast-path items: no internal rows, fixed key order. */
function modelItems(items) {
  return items.map(item => ({ ref: item.ref, kind: item.kind, title: item.title, page: item.page, ...(item.official && item.official !== item.page ? { official: item.official } : {}),
    ...(item.when ? { when: item.when } : {}), ...(item.city ? { city: item.city } : {}), ...(item.cost ? { cost: item.cost } : {}), ...(item.status ? { status: item.status } : {}),
    ...(item.mismatch ? { note: item.mismatch === 'past' ? 'Ended. Not a current option; say it ended and when.' : 'Does not match the asked date or conditions; correct the premise, never recommend it as matching.' } : {}),
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
  scorer(indexedGuideDocuments(guideCatalog, catalog), { base: new Set(), expanded: new Set() });
}
module.exports = { buildSiteEvidence, primeSiteEvidence, queryOverlap, buildFastEvidence, modelItems, readerDate, readerRange, snippet, searchDiscoveries, CITY_COUNTY };
