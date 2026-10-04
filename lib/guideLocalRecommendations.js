const { loadPlannerCatalog, inferFilters, inferDestination, eventOccursOn, priceOf, recommend, validDate } = require('./planner');
const { bayAreaDate } = require('./eventEngagement');
const { canonicalCity, mentionedCities } = require('./bayAreaSearchScope');
const cityAliases = require('../data/city-search-aliases.json');

const DISCOVERY = /活动|活動|好去处|好去處|地方好去|去哪(?:里)?玩|去哪逛|景点|景點|博物馆|博物館|公园|公園|\b(?:events?|things to do|what to do|where to go|places to (?:go|visit)|attractions?|museums?|parks?)\b/i;
const PLACES = /好去处|好去處|地方好去|去哪(?:里)?玩|去哪逛|景点|景點|博物馆|博物館|公园|公園|\b(?:things to do|what to do|where to go|places to (?:go|visit)|attractions?|museums?|parks?)\b/i;
const NOT_DISCOVERY = /这篇|這篇|总结|總結|翻译|翻譯|发布|發佈|發表|取消|我的活动|我的活動|\b(?:this (?:guide|article)|summari[sz]e|translate|publish|cancel|my events?)\b/i;
const isGuideLocalDiscovery = (query, message = query) => DISCOVERY.test(String(query || '')) && !NOT_DISCOVERY.test(String(message || ''));
const OUTSIDE = /上海|北京|中国|中國|纽约|紐約|洛杉矶|洛杉磯|西雅图|西雅圖|香港|台北|臺北|东京|東京|\b(?:Shanghai|Beijing|China|New York|Los Angeles|Seattle|Hong Kong|Taipei|Tokyo|London|Paris|Sacramento|San Diego)\b/i;
const WHOLE_BAY = /全湾区|全灣區|整个湾区|整個灣區|湾区都可以|灣區都可以|\b(?:anywhere (?:in |across )?(?:the )?bay area|(?:whole|entire|all of the) bay area)\b/i;
const sameCity = (a, b) => String(a || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase() === String(b || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
const safeUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; } catch { return false; } };
const recurrenceNeedsDates = row => row.startDate !== row.endDate && row.occurrenceDates === undefined && /每(?:周|週|星期|月)|\bevery\s+(?:week|month|mon|tue|wed|thu|fri|sat|sun)/i.test(`${row.dateLabel || ''} ${row.summary || ''}`);
const unrestrictedFreeAdmission = row => row.cost === 'free' && priceOf(row) === 0
  && !/(?:居民|会员|會員|学生|學生|\d\s*[岁歲]|\b(?:residents?|members?|students?|under\s+\d|children))[^。;；]{0,35}(?:免费|免費|\bfree\b)|(?:免费|免費|\bfree\b)[^。;；]{0,35}(?:仅限|僅限|with (?:a )?purchase|members? only|residents? only)|\bfree\b[^。.;；]{0,35}\b(?:for|to)\s+(?:(?:eligible|qualifying|local|all)\s+)?(?:residents?|members?|students?|children|kids?|under\s+\d|library card holders?)\b|(?:须|須|需要|需先)(?:购买|購買|消费|消費)/i.test([row.costLabel, ...(row.plan || []).filter(text => /入场|入場|门票|門票|参加|參加|\b(?:admission|entry|tickets?)\b/i.test(text))].filter(Boolean).join(' '));
const canonicalCities = catalog => [...new Set([...catalog.events, ...catalog.places].flatMap(row => String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/)).filter(Boolean))];
function normalizeCities(message) {
  const aliases = Object.entries(cityAliases).flatMap(([city, names]) => [city, city.replace(/\s+/g, ''), ...names].map(name => ({ city, name }))).sort((a, b) => b.name.length - a.name.length);
  const matches = [];
  for (const { city, name } of aliases) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const match of message.matchAll(new RegExp(`${/^[a-z]/i.test(name) ? '(?<![a-z])' : ''}${escaped}${/[a-z]$/i.test(name) ? '(?![a-z])' : ''}`, 'gi'))) {
      if (!matches.some(item => item.start < match.index + match[0].length && item.end > match.index)) matches.push({ start: match.index, end: match.index + match[0].length, city });
    }
  }
  for (const match of matches.sort((a, b) => b.start - a.start)) message = message.slice(0, match.start) + match.city + message.slice(match.end);
  return message;
}
function removeGeography(message, catalog) {
  const names = [...canonicalCities(catalog), 'San José', 'SF', '旧金山', '舊金山', '三藩市', '圣何塞', '聖荷西', '东湾', '東灣', '南湾', '南灣', '北湾', '北灣', '半岛', '半島', 'East Bay', 'South Bay', 'North Bay', 'Peninsula'].sort((a, b) => b.length - a.length);
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    message = message.replace(new RegExp(`${/^[a-z]/i.test(name) ? '(?<![a-z])' : ''}${escaped}${/[a-z]$/i.test(name) ? '(?![a-z])' : ''}`, 'gi'), ' ');
  }
  return message;
}

const words = locale => locale === 'en' ? {
  area: 'the Bay Area', areas: { sf: 'San Francisco', 'east-bay': 'the East Bay', 'south-bay': 'the South Bay', peninsula: 'the Peninsula', 'north-bay': 'the North Bay' },
  intro: (date, area, checked) => `For ${date} in ${area}, these published site records match the date (catalog checked ${checked}). This is not a live search or confirmation of availability.`,
  events: 'Dated events', places: 'Permanent places to consider — opening hours for this date still need official confirmation',
  empty: 'I did not find a matching dated event in the site records for these filters. This does not mean that no events are taking place.',
  emptyPlaces: 'I did not find a matching place in the site records for these filters. This does not mean there are no suitable places.',
  date: 'Published schedule', location: 'Location', price: 'Published admission and conditions', rules: 'Participation details', source: 'Official source',
  unknown: 'Admission unconfirmed; do not assume it is free.', free: 'Recorded admission: $0. Confirm eligibility; extras, transport and purchases are separate.',
  record: 'Record text (original wording)', footer: 'Showing at most three options per category. Check the linked official page for session times, eligibility, reservations, fees and temporary changes before leaving. No ticket availability or booking is guaranteed.',
  note: 'Filtered published site records by date and destination; no new web search was performed.',
} : locale === 'zh-Hant' ? {
  area: '全灣區', areas: { sf: '舊金山', 'east-bay': '東灣', 'south-bay': '南灣', peninsula: '半島', 'north-bay': '北灣' },
  intro: (date, area, checked) => `${date} · ${area}：以下站內記錄符合所選日期（目錄核對日期 ${checked}），不代表已即時確認當天營業或餘票。`,
  events: '符合日期的活動', places: '常設去處備選：所選日期的開放時間仍待官方確認',
  empty: '站內記錄未找到符合這一天與篩選條件的活動；這不代表當地沒有活動。',
  emptyPlaces: '站內記錄未找到符合篩選條件的常設去處；這不代表當地沒有合適地點。',
  date: '收錄時段', location: '地點', price: '收錄入場費與條件', rules: '參加細節', source: '官方來源', unknown: '入場費未確認，不能當作免費。',
  free: '收錄入場費 $0；仍需核對適用資格，附加項目、交通及消費另計。', record: '記錄原文',
  footer: '每類最多列出三項。出發前打開官方來源，確認場次、資格、預約、費用與臨時調整；不保證餘票，也未代為預約。',
  note: '已按日期與目的地篩選站內收錄記錄；本次沒有新增網頁查詢。',
} : {
  area: '全湾区', areas: { sf: '旧金山', 'east-bay': '东湾', 'south-bay': '南湾', peninsula: '半岛', 'north-bay': '北湾' },
  intro: (date, area, checked) => `${date} · ${area}：以下站内记录符合所选日期（目录核对日期 ${checked}），不代表已即时确认当天营业或余票。`,
  events: '符合日期的活动', places: '常设去处备选：所选日期的开放时间仍待官方确认',
  empty: '站内记录未找到符合这一天与筛选条件的活动；这不代表当地没有活动。',
  emptyPlaces: '站内记录未找到符合筛选条件的常设去处；这不代表当地没有合适地点。',
  date: '收录时段', location: '地点', price: '收录入场费与条件', rules: '参加细节', source: '官方来源', unknown: '入场费未确认，不能当作免费。',
  free: '收录入场费 $0；仍需核对适用资格，附加项目、交通及消费另计。', record: '记录原文',
  footer: '每类最多列出三项。出发前打开官方来源，确认场次、资格、预约、费用与临时调整；不保证余票，也未代为预约。',
  note: '已按日期与目的地筛选站内收录记录；本次没有新增网页查询。',
};

/** Deterministic catalog discovery, deliberately narrower than general guide chat.
 * No network, model, account or mutation. A null result leaves unsupported,
 * ambiguous or non-discovery questions to the caller. Catalog quotations remain
 * verbatim unless a reviewed locale dictionary is supplied; never machine-guess
 * a translation that could lose age, admission or reservation restrictions.
 */
async function buildGuideLocalRecommendations({ message, locale = 'zh-Hans', today = bayAreaDate(Date.now()), searchContext = {}, catalog: suppliedCatalog, translations = {}, guideCatalog = [] } = {}) {
  if (typeof message !== 'string' || message.length > 800 || !validDate(today) || !DISCOVERY.test(message) || NOT_DISCOVERY.test(message) || OUTSIDE.test(message)) return null;
  const catalog = loadPlannerCatalog(suppliedCatalog);
  if (!catalog) return null;
  try {
    const wholeBay = WHOLE_BAY.test(message);
    // The server's explicit Bay Area search prefix names the region, not SF
    // city. Preserve the user's separate destination after removing that bias.
    const normalized = normalizeCities(message.replace(/San Francisco Bay Area(?:,?\s*California(?:,?\s*(?:United States|USA|US))?)?/gi, 'Bay Area'));
    const query = wholeBay ? removeGeography(normalized, catalog) : normalized;
    // Include recognized cities with no catalog rows: they must produce zero
    // matches, not accidentally fall back to a Bay-wide list.
    const recognizedCities = mentionedCities(query);
    const destinationCatalog = { ...catalog, places: [...catalog.places, ...recognizedCities.map(city => ({ city }))] };
    const destination = inferDestination(query, destinationCatalog);
    const inferred = inferFilters(destination.analysisMessage, today, { en: locale === 'en' });
    const date = inferred.date || searchContext.date;
    if (!validDate(date) || date < today) return null;
    const filters = { date };
    if (destination.city) filters.city = destination.city;
    if (!wholeBay && !destination.city && searchContext.city) {
      const contextualCity = canonicalCity(searchContext.city);
      if (!contextualCity) return null;
      filters.city = contextualCity;
    }
    if (!wholeBay && !destination.city && !inferred.region && searchContext.region && searchContext.region !== 'all') filters.region = searchContext.region;
    // An inferred explicit city overrides stale UI context, never vice versa.
    const freeOnly = inferred.freeOnly === true;
    const eligibleCatalog = { ...catalog,
      events: catalog.events.filter(row => eventOccursOn(row, date) && !recurrenceNeedsDates(row) && safeUrl(row.officialUrl)
        && (!freeOnly || unrestrictedFreeAdmission(row))),
      places: catalog.places.filter(row => safeUrl(row.officialUrl) && (!freeOnly || (unrestrictedFreeAdmission(row)
        && !/每(?:周|週|星期|月)|\bevery\s+(?:week|month|mon|tue|wed|thu|fri|sat|sun)/i.test(row.costLabel || '')))),
    };
    // The eligible catalog may have no rows left in the requested city. Keep
    // the resolved city filter, without asking the smaller catalog to interpret
    // an excluded/origin city again as a new destination.
    const result = await recommend({ body: { message: destination.analysisMessage, filters, locale }, catalog: eligibleCatalog, now: () => Date.parse(`${today}T19:00:00Z`), isTest: true });
    const eventMap = new Map(eligibleCatalog.events.map(row => [row.id, row]));
    const placeMap = new Map(eligibleCatalog.places.map(row => [row.id, row]));
    const events = result.suggestions.map(item => eventMap.get(item.eventId)).filter(Boolean);
    const placesRequested = PLACES.test(message);
    const places = placesRequested ? result.placeSuggestions.map(item => placeMap.get(item.placeId)).filter(Boolean) : [];
    // Defense in depth: a site answer must never broaden the resolved city.
    const cityMatches = row => !result.filters.city || String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/).some(city => sameCity(city, result.filters.city));
    if ([...events, ...places].some(row => !cityMatches(row))) return null;
    const w = words(locale);
    const normalizedKey = value => String(value || '').trim().replace(/\s+/g, ' ');
    const tr = value => translations[normalizedKey(value)] || String(value || '');
    const sourceRows = [...events, ...places];
    const sources = sourceRows.map(row => ({ title: tr(row.title), url: row.officialUrl }));
    const quote = value => value ? tr(value) : '';
    const sections = [w.intro(date, result.filters.city || w.areas[result.filters.region] || w.area, catalog.checkedAt)];
    const describe = (row, index, isPlace) => {
      const original = locale === 'zh-Hans' ? '' : ` (${w.record})`;
      const location = [...new Set([row.city, row.venue].filter(Boolean))].map(quote).join(' · ');
      const lines = [`${index + 1}. ${quote(row.title)}${original}`, `${w.location}：${location}`];
      if (!isPlace) lines.push(`${w.date}：${quote(row.dateLabel) || date}`);
      lines.push(`${w.price}：${quote(row.costLabel) || (priceOf(row) === 0 ? w.free : w.unknown)}`);
      // Keep the complete checked restrictions, including paid add-ons and age
      // rules; a zero admission field must not erase them.
      if (row.plan?.length) lines.push(`${w.rules}：${row.plan.map(quote).join(' ')}`);
      if (isPlace && row.planning?.schedule?.note) lines.push(quote(row.planning.schedule.note));
      lines.push(`${w.source}：[${index + 1}]`);
      return lines.join('\n');
    };
    if (events.length) sections.push(w.events, ...events.map((row, index) => describe(row, index, false)));
    else if (!placesRequested || !result.placeSuggestions.length) sections.push(placesRequested ? w.emptyPlaces : w.empty);
    if (places.length) sections.push(w.places, ...places.map((row, index) => describe(row, events.length + index, true)));
    sections.push(w.footer);
    const guideMap = new Map(guideCatalog.map(row => [row.slug, row]));
    const suggestedGuides = [...new Set(places.map(row => row.guideSlug).filter(Boolean))].map(slug => guideMap.get(slug) || catalog.guides.find(row => row.slug === slug)).filter(Boolean).map(row => ({ slug: row.slug, title: tr(row.title), url: `/guides/${row.slug}` }));
    return { answer: sections.join('\n\n'), sources, suggestedGuides, eventIds: events.map(row => row.id), placeIds: places.map(row => row.id), filters: result.filters, checkedAt: catalog.checkedAt, matchNote: w.note };
  } catch { return null; }
}

module.exports = { buildGuideLocalRecommendations, isGuideLocalDiscovery };
