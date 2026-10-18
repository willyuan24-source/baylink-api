const crypto = require('node:crypto');
const { dateRangeFor, askedDateRange } = require('./entityAliases');
const { railSystemsIn } = require('./baybayTransit');
const { inferFilters, inferDestination, allowsPaidAdmission, validDate, REGIONS } = require('./planner');
const { canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate } = require('./bayAreaSearchScope');
const { planningDirective, planningClauses } = require('./baybayPlanningIntent');
const { safeUrl } = require('./plannerWebSearch');
const { requestedStopLimit } = require('./baybayPlanEdits');
const { isSchoolRequest } = require('./guideConversation');
const { isLibraryServiceQuestion } = require('./publicResearch');

const VERSION = 1;
const TOKEN_TTL = 24 * 60 * 60;
const TOKEN_LIMIT = 16384;
const GOALS = ['day-plan', 'discover', 'transit', 'newcomer', 'shopping', 'information'];
const MODES = ['any', 'drive', 'transit', 'walk'];
const TOPICS = ['any', 'comedy', 'music', 'sports', 'arts', 'food', 'community', 'technology'];
const FIELDS = ['goal', 'city', 'region', 'date', 'origin', 'originCandidateId', 'travelMode', 'partySize', 'childAges', 'budget', 'budgetScope', 'freeOnly', 'setting', 'startTime', 'finishBy', 'maxStops', 'returnToOrigin', 'topic', 'preferences', 'excludedCities', 'community', 'family'];
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const clean = (value, max = 160) => typeof value === 'string' && value.trim().length <= max && !/[\u0000-\u001f\u007f]/.test(value) ? value.trim() : null;
const unique = values => [...new Set(values)];
const ids = value => Array.isArray(value) ? unique(value.filter(item => typeof item === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_:-]{0,159}$/.test(item))).slice(0, 24) : [];
const time = value => typeof value === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value) ? value : null;
const list = value => Array.isArray(value) ? unique(value.map(item => clean(item, 120)).filter(Boolean)).slice(0, 12) : [];
const CITY_CLEAR = /不(?:限|限定|限制)(?:定)?(?:城市|地区|地區)|(?:城市|地区|地區)(?:不限|随便|隨便|都可以)|全湾区|全灣區|整个湾区|整個灣區|\b(?:any city|no city preference|anywhere (?:in |across )?(?:the )?bay area|(?:whole|entire) bay area)\b/i;
const DATE_CLEAR = /日期不限|不(?:限|限定|限制)日期|哪天都可以|什么日期都可以|什麼日期都可以|\b(?:any day|any date|no date preference|clear (?:the )?date)\b/i;
const BUDGET_CLEAR = /预算不限|預算不限|不限预算|不限預算|\b(?:no budget limit|unlimited budget|clear (?:the )?budget)\b/i;

const CHINESE_COMMUNITY = /华人|華人|华裔|華裔|中文|华语|華語|國語|国语|粤语|粵語|广东话|廣東話|普通话|普通話|华埠|華埠|唐人街|中国城|中國城|重阳|重陽|\b(?:Chinese|Mandarin|Cantonese|Chinatown)\b/i;
const ANSWER_LANGUAGE = /(?:用|以|请用|請用)(?:简体|簡體|繁体|繁體)?中文(?:回答|回覆|回复|说|說|讲|講|解释|解釋|写|寫)|\b(?:answer|reply|respond|explain|write)\b[^.?!]{0,20}\bin (?:Chinese|Mandarin)\b/i;
const COMMUNITY_CLEAR = /不限语言|不限語言|语言不限|語言不限|不一定(?:要)?(?:是)?(?:中文|华人|華人)|\b(?:any language|not (?:only|just) (?:Chinese|Mandarin))\b/i;
// The facet is for event and activity asks only: 会说中文的儿科医生, 中文学校, 华人超市 and
// "Chinese restaurant" mention the same words but ask for a doctor, a school, a shop or food.
const COMMUNITY_EVENT = /活动|活動|故事会|故事會|故事时间|故事時間|讲座|講座|节日|節日|[阳陽秋春午宵]节|[阳陽秋春午宵]節|灯会|燈會|庆祝|慶祝|庆典|慶典|聚会|聚會|表演|演出|展览|展覽|音乐会|音樂會|游园|遊園|庙会|廟會|游行|遊行|敬老|好玩|去哪玩|哪里玩|哪裡玩|好去处|好去處|\b(?:events?|activit(?:y|ies)|story ?times?|festivals?|celebrations?|things to do|happening|meetups?|workshops?|performances?|concerts?|parades?)\b/i;
const COMMUNITY_OTHER_SUBJECT = /医生|醫生|医院|醫院|诊所|診所|牙医|牙醫|律师|律師|会计师|會計師|学校|學校|超市|餐厅|餐廳|饭店|飯店|餐馆|餐館|\b(?:doctors?|pediatricians?|dentists?|clinics?|hospitals?|lawyers?|schools?|supermarkets?|grocer(?:y|ies)|restaurants?)\b/i;
/** Whitelist all persisted fields. A client object is never trusted task state. */
function validateTaskState(input = {}) {
  const value = plain(input) ? input : {};
  const result = {
    version: VERSION,
    revision: Number.isInteger(value.revision) && value.revision >= 0 && value.revision <= 100000 ? value.revision : 0,
    goal: GOALS.includes(value.goal) ? value.goal : null,
    city: canonicalCity(value.city),
    region: [...REGIONS, 'all'].includes(value.region) ? value.region : null,
    date: validDate(value.date) ? value.date : null,
    ...(value.dateRange && validDate(value.dateRange.start) && validDate(value.dateRange.end) && value.dateRange.start <= value.dateRange.end ? { dateRange: { start: value.dateRange.start, end: value.dateRange.end } } : {}),
    ...(typeof value.dateContextMonth === 'string' && /^20\d{2}-(?:0[1-9]|1[0-2])$/.test(value.dateContextMonth) ? { dateContextMonth: value.dateContextMonth } : {}),
    origin: clean(value.origin, 120),
    originCandidateId: ids([value.originCandidateId])[0] || null,
    travelMode: MODES.includes(value.travelMode) ? value.travelMode : null,
    partySize: Number.isInteger(value.partySize) && value.partySize >= 1 && value.partySize <= 50 ? value.partySize : null,
    childAges: Array.isArray(value.childAges) ? value.childAges.filter(age => Number.isInteger(age) && age >= 0 && age <= 17).slice(0, 10) : [],
    budget: typeof value.budget === 'number' && Number.isFinite(value.budget) && value.budget >= 0 && value.budget <= 10000 ? value.budget : null,
    budgetScope: ['person', 'total'].includes(value.budgetScope) ? value.budgetScope : null,
    freeOnly: typeof value.freeOnly === 'boolean' ? value.freeOnly : null,
    setting: ['any', 'indoor', 'outdoor', 'mixed'].includes(value.setting) ? value.setting : null,
    startTime: time(value.startTime),
    finishBy: time(value.finishBy),
    ...(Number.isInteger(value.maxStops) && value.maxStops >= 1 && value.maxStops <= 6 ? { maxStops: value.maxStops } : {}),
    ...(typeof value.returnToOrigin === 'boolean' ? { returnToOrigin: value.returnToOrigin } : {}),
    topic: TOPICS.includes(value.topic) ? value.topic : null,
    // H17: a Chinese-language or Chinese-community ask, kept across follow-ups (only set when asked).
    ...(value.community === 'chinese' ? { community: 'chinese' } : {}),
    // API-BB-7 (live 10-16, L09): a family / children ask (亲子, 带娃, with kids), kept across follow-ups (only set when asked).
    ...(value.family === true ? { family: true } : {}),
    excludedCities: Array.isArray(value.excludedCities) ? unique(value.excludedCities.map(canonicalCity).filter(Boolean)).slice(0, 30) : [],
    excludedCandidateIds: ids(value.excludedCandidateIds),
    selectedCandidateIds: ids(value.selectedCandidateIds),
    preferences: list(value.preferences),
    clearedFields: Array.isArray(value.clearedFields) ? unique(value.clearedFields.filter(key => FIELDS.includes(key))) : [],
  };
  if (result.partySize !== null && result.childAges.length > result.partySize) result.partySize = null;
  if (result.city && result.excludedCities.includes(result.city)) result.city = null;
  result.selectedCandidateIds = result.selectedCandidateIds.filter(id => !result.excludedCandidateIds.includes(id));
  return result;
}

function normalizeCatalog(catalog) {
  return { events: Array.isArray(catalog?.events) ? catalog.events : [], places: Array.isArray(catalog?.places) ? catalog.places : [] };
}

const preciseLocation = location => location?.precision === 'venue'
  && Number.isFinite(location.lat) && Number.isFinite(location.lng)
  && location.lat >= 36 && location.lat <= 40 && location.lng >= -124 && location.lng <= -120;

/** Match an explicit named departure point against the existing catalog only.
 * Longer exact names win; an alias shared by records remains ambiguous. */
function matchOriginCandidate(message, catalog) {
  // Every match needs a departure word (从 / from / leaving / departing) right before the
  // name, and no city name contains one: a message without one has no origin (API-BB-4B:
  // this skips one compiled pattern per catalog name on most questions).
  if (!/从|從|from|leaving|departing/i.test(message)) return null;
  const matches = [];
  for (const [kind, rows] of [['event', catalog.events], ['place', catalog.places]]) for (const row of rows) {
    if (!preciseLocation(row.location)) continue;
    for (const alias of unique([row.title, row.venue, row.location.label, ...publishedVenueNames(row, kind)].map(value => clean(value, 300)).filter(Boolean))) {
      // A city-only row label is not proof of a specific departure point.
      if (canonicalCity(alias) || alias.length < 3) continue;
      const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const match of message.matchAll(new RegExp(escaped, 'giu'))) {
        const prefix = message.slice(Math.max(0, match.index - 80), match.index);
        const city = canonicalCity(row.city);
        const departurePrefix = city ? normalizeCityMentions(prefix).replace(new RegExp(`${city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*(?:的\\s*)?$`, 'i'), '') : prefix;
        const suffix = message.slice(match.index + match[0].length);
        if (!/(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*$/i.test(departurePrefix)) continue;
        if (/(?:不是|并非|並非|不要|不想|别|別|\bnot|\bdon['’]t|\bdo not)\s*(?:从|從|from|leaving|departing(?: from)?)\s*$/i.test(departurePrefix)) continue;
        if (/^[a-z0-9]/i.test(suffix) && /[a-z0-9]$/i.test(alias) && !/^\d{1,2}(?::\d{2}|点|點|时|時)/.test(suffix)) continue;
        matches.push({ row, start: match.index, end: match.index + match[0].length, length: match[0].length });
      }
    }
  }
  const longest = matches.filter(match => !matches.some(other => other.start <= match.start && other.end >= match.end && other.length > match.length));
  const rows = [...new Map(longest.map(match => [match.row, match])).values()];
  return rows.length === 1 ? rows[0] : null;
}

/** Retain a user's named public station even when the catalog cannot verify
 * its coordinates. This is a label only, never a catalog identity or location. */
function publicStationOrigin(message) {
  const labels = [];
  for (const match of message.matchAll(/(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*([^，,。.!！？?；;\n]{1,120})/giu)) {
    const before = message.slice(Math.max(0, match.index - 30), match.index);
    if (/(?:不要|不想|别|別|不是|\bnot|\bdon['’]t|\bdo not)\s*$/i.test(before)) continue;
    const label = match[1].match(/^(.{2,80}?(?:\b(?:BART|Caltrain|Muni)(?:\s*(?:站|车站|車站)|\s+(?:station|stop)\b)?|\bstation\b|火车站|火車站|地铁站|地鐵站))(?=\s*(?:出发|出發|前往|到|去|\bat\b|\bto\b|\bfor\b|$))/i)?.[1]?.trim();
    if (!label || /或者|还是|還是|或|和|我家|家附近|\b(?:or|and|home|house)\b/i.test(label)) continue;
    labels.push(label);
  }
  const distinct = unique(labels);
  return distinct.length === 1 ? distinct[0] : null;
}

function nearbyStationOrigin(message) {
  const match = message.match(/\b(?:I(?:['’]m| am)|we(?:['’]re| are))\s+near\s+([^，,。.!！？?；;\n]{1,120})|我(?:们|們)?在\s*([^，,。.!！？?；;\n]{1,120}?)\s*附近(?=[，,。.!！？?；;\n]|$)/i);
  if (!match) return null;
  const station = publicStationOrigin(`from ${match[1] || match[2]}`);
  return station ? { phrase: match[0], station, label: `${station} 附近` } : null;
}

const normalizeVenueName = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[’‘]/g, "'").toLowerCase();
const PUBLISHED_VENUE_NAMES = new WeakMap();
function publishedVenueNames(row, kind) {
  let cached = PUBLISHED_VENUE_NAMES.get(row);
  if (cached?.[kind]) return cached[kind];
  const published = [row.title, ...(kind === 'place' ? [row.venue, row.location?.label, ...(Array.isArray(row.aliases) ? row.aliases : [])] : [])]
    .map(value => clean(value, 300)).filter(Boolean);
  const names = published.flatMap(value => [value, value.split(/\s+[·|]\s+|\s*：\s*/)[0]]);
  // A published library branch URL can supply its short branch name. Require
  // the identical word in the full library title: /locations/king/ + King,
  // Jr. Library establishes "King Library", not a fuzzy semantic name guess.
  if (kind === 'place' && /\blibrary\b/i.test(row.title || '')) {
    try {
      const slug = new URL(row.officialUrl).pathname.match(/^\/locations\/([a-z][a-z-]{2,39})\/?$/i)?.[1];
      const words = slug?.replace(/-/g, ' ');
      if (words && new RegExp(`\\b${words.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(row.title)) names.push(`${words} Library`);
    } catch { /* Missing published branch identity means no shortened alias. */ }
  }
  const result = unique(names.map(normalizeVenueName).filter(name => name.length >= 3 && !canonicalCity(name)
    && !/^(?:museum|library|park|garden|cafe|restaurant|museum of art|public library|visitor center|博物馆|博物館|美术馆|美術館|图书馆|圖書館|公园|公園|艺术馆|藝術館)$/.test(name)));
  if (!cached) { cached = {}; PUBLISHED_VENUE_NAMES.set(row, cached); }
  cached[kind] = result;
  return result;
}

/** Only an explicit visit request establishes a desired stop. A venue's bare
 * mention in a price/question/comparison is not a selection. */
function matchDesiredCandidates(message, catalog, state) {
  // "Not only A, but also B" affirms both visits; it is not "do not visit A".
  message = message.replace(/不(?:只是|只|仅仅|僅僅|仅|僅)(?:要)?去/g, '想去')
    .replace(/\bnot only\s+(?=[^.!?;\n]{1,180}\bbut also\b)/gi, 'visit ');
  if (state.goal !== 'day-plan' || !orderedVisitRequest(message) && !/想去|要去|希望去|想看|只去|参观|參觀|游览|遊覽|先去|再去|逛|加入|严格按|嚴格按|安排.{0,10}(?:去|参观|參觀)|\b(?:visit|visiting|go to|include|want to see|stops? (?:at|are))\b/i.test(message)) return null;
  const text = normalizeVenueName(message); const found = [];
  for (const [kind, rows] of [['place', catalog.places], ['event', catalog.events]]) for (const row of rows) {
    if (!row.id || row.id === state.originCandidateId) continue;
    for (const alias of publishedVenueNames(row, kind)) {
      // A published numbered name remains the same venue when its optional
      // letter/number space is omitted (PIER39 / PIER 39); boundaries still
      // reject different numbers and longer names such as PIER399.
      const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/(?<=[a-z])\s+(?=\d)/g, '\\s*');
      const pattern = new RegExp(`${/^[a-z0-9]/i.test(alias) ? '(?<![a-z0-9])' : ''}${escaped}${/[a-z0-9]$/i.test(alias) ? '(?![a-z0-9])' : ''}`, 'gu');
      for (const match of text.matchAll(pattern)) {
        const before = text.slice(Math.max(0, match.index - 60), match.index);
        if (!affirmativeGoal(text.slice(0, match.index + match[0].length), new RegExp(`${escaped}$`))) continue;
        const city = canonicalCity(row.city);
        const departurePrefix = city ? normalizeCityMentions(before).replace(new RegExp(`${city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'i'), '') : before;
        if (/(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*$/i.test(departurePrefix)) continue;
        const directives = [...before.matchAll(/(?:不要|不想|不去|别|別|排除|避开|避開)(?:去|看|参观|參觀)?|\b(?:not|skip|except|avoid|without|don't|do not)(?: want to)?(?: go to| visit| include)?|想去|要去|希望去|想看|只去|参观|參觀|游览|遊覽|先去|再去|逛|加入|\b(?:visit|visiting|go to|include|want to see)\b/gu)];
        if (/^(?:不要|不想|不去|别|別|排除|避开|避開|not\b|skip\b|except\b|avoid\b|without\b|don't\b|do not\b)/.test(directives.at(-1)?.[0] || '')) continue;
        found.push({ id: row.id, row, kind, start: match.index, end: match.index + match[0].length, alias });
      }
    }
  }
  const longest = found.filter(item => !found.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start));
  const positions = new Map();
  for (const item of longest) {
    const key = `${item.start}:${item.end}`;
    if (!positions.has(key)) positions.set(key, []);
    if (!positions.get(key).some(previous => previous.id === item.id)) positions.get(key).push(item);
  }
  for (const [key, rows] of positions) {
    if (rows.length < 2 || rows.some(item => item.kind !== 'place')) continue;
    const primary = rows.filter(item => normalizeVenueName(String(item.row.title || '').split(/\s+[·|]\s+|\s*：\s*/)[0]) === item.alias);
    if (primary.length !== 1) continue;
    const chosen = primary[0], source = safeUrl(chosen.row.officialUrl), city = canonicalCity(chosen.row.city);
    // Prefer a unique exact primary venue title over an overview/location alias
    // only when the official source and city agree. A shop's title suffix is
    // never a primary venue name; conflicting locations remain ambiguous.
    if (source && city && rows.every(item => safeUrl(item.row.officialUrl) === source && canonicalCity(item.row.city) === city
      && (!preciseLocation(item.row.location) || !preciseLocation(chosen.row.location)
        || item.row.location.lat === chosen.row.location.lat && item.row.location.lng === chosen.row.location.lng))) positions.set(key, [chosen]);
  }
  if ([...positions.values()].some(rows => rows.length > 1)) return { clarification: '这个地点名称对应多个站内记录，请补充完整名称或具体分店后再安排。' };
  const ordered = [...positions.values()].map(rows => rows[0]).sort((a, b) => a.start - b.start);
  for (let index = 1; index < ordered.length; index++) if (ordered[index - 1].id !== ordered[index].id && /\b(?:or|versus|vs)\b|或者|还是|還是|或/.test(text.slice(ordered[index - 1].end, ordered[index].start))) return { clarification: '你列出了备选地点，请确认要去哪些地点，再生成路线。' };
  const selected = unique(ordered.map(row => row.id));
  if (selected.length > 6) return { clarification: '这次点名了超过六个地点，请先选定最多六站再安排行程。' };
  return selected.length ? { ids: selected } : null;
}

function affirmativeGoal(message, pattern) {
  return [...message.matchAll(new RegExp(pattern.source, 'gi'))].some(match => {
    const prefix = message.slice(Math.max(0, match.index - 80), match.index);
    // Only an adjacent negative directive suppresses this particular intent.
    // A different clause (or a later positive request) can still establish it.
    return !/(?:不要|不想|不需要|不用|不必|不是|不|别|別|无需|無需|避免|取消|停止)(?:再|先|必须|必須|给我|給我|帮我|幫我|为我|為我|向我|只|任何|推荐|推薦|安排|规划|規劃|做|找|查|看|去|的|一[个個份条條]|旅游|旅遊|观光|觀光|景点|景點|活动|活動|或|和|完整|详细|詳細|\s)*$/.test(prefix)
      && !/\b(?:no|not|never|without|avoid|skip|stop|cancel|do not|don['’]t)(?:\s+(?:want|need|interested|in|give|show|me|us|to|a|an|the|any|more|recommend|suggest|plan|arrange|create|make|sightseeing|tourist|travel|attractions?|events?|routes?|itineraries|and|or))*\s*$/i.test(prefix);
  });
}

function declinesPlan(message) {
  // "Do not change the itinerary" preserves the task; it does not decline
  // planning. Remove only the bounded preservation phrase so an independent
  // request to stop planning later in the same turn can still take effect.
  const intent = message
    .replace(/(?:不要|不需要|不需|不想|不用|不必|无需|無需|别|別|不)\s*(?:修改|更改|改变|改變|改动|改動|调整|調整|改)(?:\s*(?:这(?:个|份|次)?|這(?:個|份|次)?|原(?:来|來|有)?|当前|當前|刚才|剛才|现有|現有|既有|的))*\s*(?:行程|一日游|一日遊|旅游路线|旅遊路線|安排路线|安排路線)/gi, ' ')
    .replace(/\b(?:do not|don['’]t|no need to|without)\s+(?:chang(?:e|ing)|modif(?:y|ying)|alter(?:ing)?|replan(?:ning)?|rearrang(?:e|ing))(?:\s+(?:the|our|my|this|current|existing|original))*\s+(?:itinerary|day plan|day trip|route)\b/gi, ' ');
  return /(?:不要|不想|不需要|不用|不必|不|别|別|无需|無需|取消|停止)[^，,。.!！？?；;\n]{0,18}(?:行程|一日游|一日遊|旅游路线|旅遊路線|安排路线|安排路線)|\b(?:no|not|without|skip|cancel|do not|don['’]t)(?:\s+(?:want|need|give|show|me|us|to|a|an|the|any|plan|arrange|create|make|sightseeing|tourist|travel))*\s+(?:itinerary|day plan|day trip|route)\b/i.test(intent);
}

function orderedVisitRequest(message) {
  if (declinesPlan(message)) return false;
  // Spoken requests can omit 去 between the named stops. Require an explicit
  // scheduling request so "first compare A, then B" remains information.
  if (affirmativeGoal(message, /(?:帮我|幫我|帮我们|幫我們|请|請)?(?:排|安排)得(?:松|轻松|輕鬆)(?:一[点點些])?/)
    && affirmativeGoal(message, /先[^，,。.!！？?；;\n]{1,80}?再[^，,。.!！？?；;\n]{1,80}/)) return true;
  const pattern = /(?:严格按|嚴格按|按照?|依照)[^，,。.!！？?；;\n]{1,100}(?:顺序|順序)(?:走|游览|遊覽|参观|參觀)(?![过過完])|先(?:去|逛|参观|參觀)(?![过過完])[^，,。.!！？?；;\n]{1,80}?再(?:去|逛|参观|參觀)(?![过過完])[^，,。.!！？?；;\n]{1,80}|\b(?:visit|tour)\b[^.!?;\n]{1,100}\bin (?:this|that|the following) order\b/gi;
  return [...message.matchAll(pattern)].some(match => {
    const prefix = message.slice(0, match.index).split(/[，,。.!！？?；;\n]/).at(-1);
    return !/已经|已經|曾经|曾經|之前|过去|過去|上次|昨天|昨日|\b(?:already|previously)\b/i.test(prefix) && affirmativeGoal(message.slice(0, match.index + match[0].length), new RegExp(pattern.source, 'i'));
  });
}

function goalAfterPlanningPause(directive) {
  const goal = goalOf(directive.tail);
  // Comparing activities while explicitly declining an itinerary is an
  // information task; preserve the multi-date comparison exception.
  if (goal === 'discover' && /比较|比較|对比|對比|分别|分別|各给|各給|\b(?:compare|comparison|separately)\b/i.test(directive.tail)) return 'information';
  return goal || 'information';
}

function pausesPlanRequest(message) {
  const directive = planningDirective(message);
  if (directive?.kind === 'plan') return false;
  if (directive?.kind === 'pause') return !['newcomer', 'shopping', 'discover'].includes(goalAfterPlanningPause(directive));
  // A plain pause is different from "don't pack the day too tightly" or
  // "don't change this itinerary". Keep the boundary at the end of a clause.
  const pattern = /(?:^|[，,。.!！？?；;\n])\s*(?:(?:先|暂时|暫時)(?:就)?)?(?:别|別|不用|不要)(?:再)?(?:排|排了|排啦|排行程|安排行程)(?:了|啦)?(?=\s*(?:[，,。.!！？?；;\n]|$))|(?:^|[,.!?;\n])\s*(?:please\s+)?(?:pause|stop)\s+(?:planning|the itinerary)(?:\s+for now)?(?=\s*(?:[,.!?;\n]|$))/gi;
  const match = [...String(message || '').matchAll(pattern)].at(-1);
  if (!match) return false;
  const after = String(message).slice(match.index + match[0].length);
  // A new service/shopping request is a real topic switch, not a temporary
  // pause to discuss the same route. Evaluate only the text after the pause.
  return !['newcomer', 'shopping', 'discover'].includes(goalOf(after))
    && !affirmativeGoal(after, /重新安排|重新规划|重新規劃|重排|\b(?:resume planning|replan)\b/i);
}

// H73 (API-BB-4B, review 10-14): outing words. 好玩吗 / 好不好玩 about one place is a yes/no question
// (Exploratorium 好玩吗？), not a list ask. 去哪儿 is an outing only with a companion or a day before
// it and no errand after it (周日带 3 岁孩子去哪儿？, not 去哪里办驾照).
const OUTING_ZH = /活动|活動|好去处|好去處|去哪玩|哪里玩|哪裡玩|哪儿玩|哪兒玩|有什么地方去|有什麼地方去|景点|景點|(?<!不)好玩(?![吗嗎么麼不])|玩什么|玩什麼|出去玩|出门玩|出門玩|去哪(?:儿|兒|里|裡)(?:玩|逛|走走|散步)/;
// API-BB-5: "这周六带 4 岁和 8 岁的孩子在 Fremont 玩" (an outing with the companions, a place and 玩/逛) was an
// information question, so the city's places and events needed shared words to reach the answer. Not 在家玩,
// 玩具, 玩法, 玩手机 / 游戏 / 电脑.
const OUTING_ZH_PLACE = /(?:带|帶|陪)[^，,。.!！？?；;\n]{0,24}(?:在|去|到)\s*[^，,。.!！？?；;\n]{1,24}?(?<!家|家里|家裡|屋里|屋裡)(?:玩|逛|走走)(?!具|法|手机|手機|游戏|遊戲|电|電|家)|(?:带|帶|陪)[^，,。.!！？?；;\n]{0,16}(?:出门|出門|出去)(?!办|辦|买|買|看病|看醫|看医|上班|上学|上學)|(?:带|帶|陪)[^，,。.!！？?；;\n]{0,16}(?:去|到)\s*(?:博物[馆館]|美[术術][馆館]|科学馆|科學館|公园|公園|动物园|動物園|水族[馆館]|植物园|植物園|海边|海邊|海滩|海灘|农场|農場|游乐场|遊樂場|游乐园|遊樂園|景点|景點)/;
const OUTING_ZH_FRAME = /(?:带|帶|陪|(?:周|週)[一二三四五六日天末]|星期[一二三四五六日天]|礼拜[一二三四五六日天]|禮拜[一二三四五六日天]|今天|明天|后天|後天|这周|這週|这个周末|這個週末|下周|下週|假期|放假|长周末|長週末)[^，,。.!！？?；;\n]{0,15}去哪(?:儿|兒|里|裡)?(?![儿兒里裡]|办|辦|申请|申請|买|買|考|交|补|補|换|換|领|領|打|看病|看医|看醫|看急|检查|檢查|修|寄|取|拿|报|報|登记|登記|开户|開戶|学|學|上课|上課)/;
// "What to do / where to go / what can we do" is an outing ask only in an outing frame (a day or
// time, kids or family, fun, or a named place), and never "what to do if/when/after …", "where
// to go to/for <a service>", "what to do with <a thing>" or "where should I take my car (for
// repairs)": those are how-to questions (What to do when the power goes out? What to do if my car
// gets towed in San Francisco? Where should I take my car for repairs in Oakland this Saturday?).
// A pet is company on an outing (Where can we take our dog this Sunday?) unless it is taken for a service.
const OUTING_PHRASE_EN = /\b(?:what (?:to do|(?:can|could|should) (?:we|i) do)|where (?:to (?:go|take)|(?:can|could|should) (?:we|i) (?:go|take)))\b(?!\s+(?:(?:my|our|the|his|her|a|an|this|that) (?:old |broken |used )?(?:car|truck|van|vehicle|tires?|phone|iphone|laptop|computer|tv|bike|e-?bike|scooter|package|parcel|mail|clothes|shoes|watch|furniture|couch|sofa|mattress|trash|recycling|e-?waste|electronics|batteries|paint|documents?|passport|car seat)s?\b|(?:\S+\s+){1,3}for (?:repairs?|service|servicing|recycling|disposal|grooming|shots|vaccines?|an? (?:oil change|smog check|inspection|tune-up|check-?up|vet visit)|(?:a |an |my |our |the )?(?:flu|covid|vaccin\w*|shots?|tests?|licen[cs]e|passport|id|dmv|help|tax(?:es)?|doctor|dentist|medical|urgent|emergency|blood|x-?rays?|repairs?|green card|ssn|social security|notary|legal))\b|if|when|whenever|after|before|about|once|because|since|during|in (?:an?|the|case) (?:emergency|earthquake|fire|flood|outage|power outage|accident|of)|to (?:get|renew|apply|file|see (?:a|the) (?:doctor|dentist)|report|pay|fix|replace|vote|register|sign up)\b|for (?:a |an |my |our |the )?(?:flu|covid|vaccin\w*|shots?|tests?|licen[cs]e|passport|id|dmv|help|tax(?:es)?|doctor|dentist|medical|urgent|emergency|blood|x-?rays?|repairs?|green card|ssn|social security|notary|legal)\b|with (?!(?:the |our |my |a |two |three |\d+ )?(?:kids?|children|family|toddlers?|bab(?:y|ies)|parents|grandparents|in-laws|visitors|guests|friends)\b)))/;
const OUTING_CUE_EN = /\b(?:today|tonight|tomorrow|this (?:weekend|week|morning|afternoon|evening|saturday|sunday|monday|tuesday|wednesday|thursday|friday|fall|autumn|month)|next (?:weekend|week|saturday|sunday)|saturdays?|sundays?|weekends?|holidays?|with (?:the |our |my |a )?(?:kids?|children|family|toddlers?|bab(?:y|ies)|parents|grandparents|in-laws|(?:\d+|two|three|four|five)[- ]year[- ]olds?)|for (?:the |a |an )?(?:kids|family|families|day|afternoon|weekend|date night|outing)|fun|outings?|day trips?|sightseeing|tourists?)\b/i;
const OUTING_PLACE_EN = /\b(?:in|around|near) (?:the )?(?:Bay Area|[A-Z][a-z]+)/;

function goalOf(message) {
  if (isSchoolRequest(message)) return 'information';
  message = planningClauses(message).join('，');
  const directive = planningDirective(message);
  if (directive?.kind === 'plan') return 'day-plan';
  if (directive?.kind === 'pause') return goalAfterPlanningPause(directive);
  const positive = pattern => affirmativeGoal(message, pattern);
  if (pausesPlanRequest(message)) return 'information';
  // An explicit ordered visit is a plan even without the word "itinerary".
  // Require movement/visits so ordered prices or a museum comparison stay informational.
  if (orderedVisitRequest(message)) return 'day-plan';
  if (positive(/(?:怎么|怎麼|如何)(?:排|安排)(?:比较|比較|才|会|會)?(?:轻松|輕鬆|合适|合適|好)?/)
    && positive(/想去|要去|先去|再去|游览|遊覽|参观|參觀|逛/)) return 'day-plan';
  // API-BB-6: 排 alone also arranges a 行程 ("帮我排行程", "排个一天的行程"); 排行榜 is a ranking, not a plan.
  if (positive(/安排[^，,。.!！？?；;\n]{0,16}(?:一天|一日|半天|半日|行程)|(?<!安)排(?:个|個|一个|一個|一下|下)?\s*(?:(?:一天|一日|半天|半日|周[六日天]|週[六日天])的?)?\s*行程|一天[^，,。.!！？?；;\n]{0,16}(?:安排|怎么玩|怎麼玩)|一日游|一日遊|\b(?:plan (?:my |our |a |the )?(?:day|half[- ]day|itinerary)|day plan|day trip|itinerary)\b/)) return 'day-plan';
  if (positive(/(?:规划|規劃|安排)[^，,。.!！？?；;\n]{0,60}(?:路线|路線)/)
    && positive(/严格按|嚴格按|顺序|順序|不加其他景点|不加其他景點|→|(?:先去|再去)|\b(?:in order|ordered stops)\b/)) return 'day-plan';
  const arranging = positive(/安排|规划|規劃|\b(?:plan|arrange|schedule)\b/);
  const calculateTravel = positive(/核算|计算|計算|车程|車程|交通时间|交通時間|\b(?:travel time|driving time|drive times|journey times)\b/);
  const returnToStart = positive(/回(?:到)?(?:出发点|出發點|起点|起點|出发地|出發地|同一站|原站|家)|返回|\b(?:back|return)(?:ing)?\b/);
  const severalVisits = positive(/(?:想去|要去|游览|遊覽|参观|參觀|逛).{0,150}(?:和|及|还有|還有|以及)|\b(?:multiple stops|several stops|visits|visit.{0,100}\band\b)\b/);
  // A requested schedule with visits/return constraints is a day plan even if
  // the user never says "one day". A single route/time question stays transit.
  if (arranging && ((calculateTravel && (returnToStart || severalVisits)) || (returnToStart && severalVisits))) return 'day-plan';
  if (positive(/搬家|搬到|剛搬|刚搬|新来|新來|刚来|剛來|开户|開戶|水电|水電|电力|電力|供水|供电|供電|垃圾.{0,12}(?:转名|轉名|服务|服務|电话|電話|开户|開戶)|\b(?:newcomer|moving to|move[ds]? to|utilities|electricity|water service|trash service|settling in)\b/)) return 'newcomer';
  if (positive(/怎么买|怎麼買|买东西|買東西|购物|購物|\b(?:shopping|outlets?|malls?)\b/)) return 'shopping';
  if (positive(/(?:怎么|怎麼|如何).{0,15}(?:去|到|转乘|轉乘)|(?:从|從).{0,70}(?:到|去).{0,70}(?:多久|多长时间|多長時間|车程|車程|怎么走|怎麼走)|\b(?:how (?:do|can|to).{0,20}(?:get|travel)|how long.{0,35}(?:drive|travel|get)|directions|transfer|route|travel time|driving time)\b/)) return 'transit';
  if (declinesPlan(message) && positive(/比较|比較|对比|對比|分别|分別|各给|各給|\b(?:compare|comparison|separately)\b/)) return 'information';
  // H73 (API-BB-4B): "anything fun this Sunday", "有什么好玩的", "周日带孩子去哪儿" are outing asks too;
  // "what to do / where to go / what can we do" only in an outing frame (OUTING_PHRASE_EN). Review round 4: "What is
  // fun for kids in December?" too. Review round 5: not about one venue or fare ("at the Oakland Zoo", "on Muni");
  // review round 6: a kind of place is still an outing ("at the beach", "at parks", "at museums").
  if (positive(OUTING_ZH) || positive(OUTING_ZH_FRAME) || positive(OUTING_ZH_PLACE) || positive(/\b(?:events?|things to do|places to visit|attractions?|anything fun|something fun|fun things|fun to do|(?:anything|something|stuff)(?: (?:free|fun|good|cheap|nice|special|new|indoors?|outdoors?))? (?:to do )?(?:for|with) (?:the |our |my )?(?:kids?|children|family|families|toddlers?|seniors|parents)|what(?:['’]s| is| are)(?: there)? (?:fun|free) (?:to do )?(?:for|with) (?:the |our |my )?(?:kids?|children|family|families|toddlers?)(?! (?:under \d+ |aged? \d+ )?(?:at|on) (?!(?:this|next|the weekend|weekends?|sat|sun|mon|tue|wed|thu|fri|\d|oct|nov|dec|jan|feb|mar|apr|may|jun|jul|aug|sep|(?:the |a |an )?(?:beach(?:es)?|parks?|playgrounds?)\b|museums\b)))|(?:what|where) can (?:the |my |our )?(?:kids?|children|toddlers?|little ones|family) (?:do|go)|(?:kids?|children['’]?s?|family) activities|activities for (?:the )?(?:kids?|children|families|family|toddlers?))\b/)
    || (positive(OUTING_PHRASE_EN) && (OUTING_CUE_EN.test(message) || OUTING_PLACE_EN.test(message)))) return 'discover';
  if (declinesPlan(message)) return 'information';
  return null;
}

// API-BB-7 (block N held-out N-10 "Sunset圖書館"; block O dev): a neighbourhood names its city. Only names that are not
// also a Bay Area city or a common street word: "Richmond District" is San Francisco, "Richmond" alone is the East Bay
// city; "Sunset" counts only as the district (Inner / Outer Sunset, Sunset District / 区 / 圖書館 / library / branch).
const NEIGHBOURHOODS = [
  ['San Francisco', /\b(?:Mission District|Noe Valley|(?:Inner |Outer )Sunset|Sunset (?:District|branch|library)|(?:Inner |Outer )Richmond|Richmond District|Excelsior District|Bayview[- ]Hunters Point|Visitacion Valley|Potrero Hill|Hayes Valley|Haight[- ]Ashbury|Pacific Heights|Marina District|Glen Park|Bernal Heights|Parkside (?:District|branch|library)|West Portal|Outer Mission|Portola District|South of Market)\b|Sunset\s*(?:区|區|圖書館|图书馆|分館|分馆)|日落区|日落區|列治文区|列治文區/gi],
  // Review 10-16: "tenderloin steak" is food, not the district (the message can reach here lowercased).
  ['San Francisco', /\b(?:Excelsior|Bayview|Dogpatch|Ingleside|SoMa)\b|\bTenderloin\b(?!\s+(?:steaks?|beef|pork|roast|cuts?|tips?|medallions?))/gi],
  ['Oakland', /\b(?:Rockridge|Temescal|Fruitvale|Montclair|Jack London Square|Dimond District|Laurel District)\b/gi],
  // "Lake Berryessa" is the Napa County lake, not San Jose's Berryessa.
  ['San Jose', /\b(?:Willow Glen|Almaden Valley|Cambrian Park|Alum Rock|Santana Row)\b|(?<!Lake\s+)\bBerryessa\b/gi],
];
/** Whether a text names one of these neighbourhoods (review of API-BB-9: "Excelsior" is the SF district before it is
 *  San Rafael's Excelsior opening). `search` ignores the patterns' global lastIndex. */
const namesNeighbourhood = text => NEIGHBOURHOODS.some(([, pattern]) => String(text || '').search(pattern) >= 0);
// A neighbourhood names its city only when the message names no city itself ("Parkside Hall in San Jose" stays San Jose).
// Review 10-17: when the message does name a city, the city parse reads it without the neighbourhood, so "Richmond
// District" / "Outer Richmond" beside 旧金山 / San Francisco / SF is not also the East Bay city of Richmond.
const withNeighbourhoodCities = message => {
  const without = NEIGHBOURHOODS.reduce((text, [, pattern]) => text.replace(pattern, ' '), message);
  return mentionedCities(normalizeCityMentions(without)).length ? without
    : NEIGHBOURHOODS.reduce((text, [city, pattern]) => text.replace(pattern, ' ' + city + ' '), message);
};
function cityContext(message) {
  let result = normalizeCityMentions(withNeighbourhoodCities(message));
  // An administrative county mention is not its namesake incorporated city.
  for (const city of mentionedCities(result)) {
    const name = city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(`\\bCounty of\\s+${name}\\b|${name}\\s*(?:县|縣|County\\b)`, 'gi'), ' county ');
    result = result.replace(new RegExp(`((?:从|從)\\s*${name})(?=[a-z])`, 'gi'), '$1 ');
  }
  return result
    .replace(/(?:我(?:们|們)?\s*)?(?:原来|原來|以前|之前|过去|過去|曾经|曾經)(?:住在?|居住在|居住于|居住於)|\b(?:(?:I|we)\s+)?(?:used to live|previously lived|formerly lived|previously resided|formerly resided)\s+in\b/gi, 'from ')
    .replace(/我(?:们|們)?住(?!在)|居住于|居住於|\b(?:I|we) reside in\b/gi, 'from ');
}

// H73 (API-BB-4B): a county-scoped outing ask ("这周末圣马刁县图书馆有什么免费活动", "events in San Mateo
// County") is that county's region. The county mention itself is not its namesake city (cityContext).
const COUNTIES = [
  ['peninsula', 'San Mateo', '圣马刁|圣马特奥|聖馬刁|聖馬特奧'], ['south-bay', 'Santa Clara', '圣塔?克拉拉|聖塔?克拉拉'],
  ['east-bay', 'Alameda', '阿拉米达|阿拉米達'], ['east-bay', 'Contra Costa', '康特拉科斯塔|康郡'],
  ['north-bay', 'Marin', '马林|馬林'], ['north-bay', 'Sonoma', '索诺玛|索諾瑪'], ['north-bay', 'Napa', '纳帕|納帕'], ['north-bay', 'Solano', '索拉诺|索拉諾'],
].map(([region, name, chinese]) => [region, new RegExp(`\\bCounty of\\s+${name}\\b|\\b${name}\\s+County\\b|(?:${name}|${chinese})\\s*(?:县|縣)`, 'i')]);
function countyRegion(message) {
  const regions = unique(COUNTIES.filter(([, pattern]) => pattern.test(message)).map(([region]) => region));
  return regions.length === 1 ? regions[0] : null;
}

// Destination ambiguity must not discard an independently stated departure.
// These are city hints only; a precise origin still requires a catalog match.
function originCitiesIn(message) {
  const cities = mentionedCities(message).sort((a, b) => b.length - a.length);
  if (!cities.length) return [];
  const pattern = new RegExp(`(?<![a-z])(?:${cities.map(city => city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![a-z])`, 'gi');
  const origins = [];
  for (const match of message.matchAll(pattern)) {
    const prefix = message.slice(Math.max(0, match.index - 80), match.index);
    const suffix = message.slice(match.index + match[0].length, match.index + match[0].length + 20);
    const from = /(?:从|從|住在|居住在|家在|\bfrom|\bleaving|\bdeparting|\blive in|\bliving in|\bbased in)\s*$/i.test(prefix);
    const departure = /^\s*(?:(?:集合)?(?:出发|出發)|(?:to\b|[-=]?>|→))/i.test(suffix);
    if (!from && !departure) continue;
    if (/(?:不要|不想|别|別|不是|\bnot|\bdon['’]t|\bdo not)\s*(?:从|從|from|leaving|departing)?\s*$/i.test(prefix)) continue;
    origins.push(canonicalCity(match[0]));
  }
  return unique(origins.filter(Boolean));
}

/** Exact published venue identities supply their actual city, not city words
 * inside a brand name. Negated venues are removed without excluding a city. */
function venueCityContext(message, catalog) {
  const normalized = normalizeVenueName(message), matches = [];
  for (const [kind, rows] of [['place', catalog.places], ['event', catalog.events]]) for (const row of rows) {
    const city = canonicalCity(row.city);
    if (!city) continue;
    for (const alias of publishedVenueNames(row, kind)) {
      // The pattern is the literal alias (case-sensitive, both lowercase), so a message
      // without that text cannot match: skip compiling it (API-BB-4B, first-sentence speed).
      if (!normalized.includes(alias)) continue;
      const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const match of normalized.matchAll(new RegExp(`${/^[a-z0-9]/i.test(alias) ? '(?<![a-z0-9])' : ''}${escaped}${/[a-z0-9]$/i.test(alias) ? '(?![a-z0-9])' : ''}`, 'gu'))) {
        matches.push({ city, start: match.index, end: match.index + match[0].length, alias });
      }
    }
  }
  const longest = matches.filter(item => !matches.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start));
  const positions = new Map();
  for (const item of longest) {
    const key = `${item.start}:${item.end}`;
    if (!positions.has(key)) positions.set(key, { ...item, cities: [] });
    positions.get(key).cities.push(item.city);
  }
  let result = normalized;
  const positiveCities = new Set();
  for (const item of [...positions.values()].sort((a, b) => b.start - a.start)) {
    const prefix = normalized.slice(Math.max(0, item.start - 80), item.start);
    const negative = !affirmativeGoal(normalized.slice(0, item.end), new RegExp(item.alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'));
    const origin = /(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*$/i.test(prefix);
    const cities = negative || origin ? [] : unique(item.cities);
    for (const city of cities) positiveCities.add(city);
    result = result.slice(0, item.start) + ` ${cities.join(' 和 ')} ` + result.slice(item.end);
  }
  if (positiveCities.size === 1) {
    result = normalizeCityMentions(result);
    // A user's "is it in CITY?" is a location question, not a second choice.
    for (const city of mentionedCities(result)) {
      const escaped = city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(`(?:是在|位于|位於|在)\\s*${escaped}\\s*(?:市区|市區|市|城里|城裡)?\\s*(?:吗|嗎|么|麼)[？?]?|\\bis (?:it|that) in\\s+${escaped}\\s*\\?`, 'gi'), ' ');
    }
  }
  return result;
}

const venuePriceQuestion = message => /门票|門票|票价|票價|\b(?:tickets?|admission)\b/i.test(message) && /吗|嗎|是不是|是否|\b(?:is|are|does|do|would)\b/i.test(message);

function totalBudgetLimitIn(message) {
  const match = message.match(/(?:总共|總共|一共|全程|整趟|总预算|總預算)\s*(?:请|請)?\s*(?:不要|不能|不|别|別)(?:超过|超過|多于|多於|超出)\s*(?:\$|USD\s*)?(\d+(?:\.\d{1,2})?)(?:\s*(?:美元|美金|USD|dollars?))?|\b(?:total(?: budget)?|in total|for the whole (?:group|trip))\s*(?:of\s+)?(?:no more than|not more than|at most|under)\s*(?:\$|USD\s*)?(\d+(?:\.\d{1,2})?)/i);
  if (!match) return null;
  const clause = message.slice(0, match.index).split(/[，,。.!！？?；;\n]/).at(-1) + message.slice(match.index).split(/[，,。.!！？?；;\n]/)[0];
  // A quoted venue's ticket-price question does not set the outing budget.
  if (venuePriceQuestion(clause)) return null;
  return Number(match[1] || match[2]);
}

function withoutPermittedOverages(message) {
  // A permitted overage is not a new cap, including the legacy "$N" shortcut.
  // Remove only the permission phrase so a separate explicit budget still wins.
  return message.replace(/(?:总共|總共|一共|全程|整趟)?\s*(?:超过|超過|多于|多於|超出)\s*(?:\$|USD\s*)?\d+(?:\.\d{1,2})?\s*(?:美元|美金|USD|dollars?)?\s*(?:(?:也|都)?(?:可以|没关系|沒關係|能接受))/gi,
    (match, offset) => /(?:不要|不能|不|别|別)\s*$/.test(message.slice(0, offset)) ? match : ' ');
}

function libraryEligibilityComparison(message) {
  if (!/区分|區分|比较|比較|分别|分別|各自|\b(?:compare|comparison|versus|differences?)\b/i.test(message)
    || !/图书证|圖書證|借书证|借書證|居住地|资格|資格|办卡|辦卡|\b(?:library cards?|eligibility|residen(?:cy|ts?))\b/i.test(message)) return false;
  const systems = [
    /\b(?:SFPL|San Francisco Public Library)\b|旧金山公共图书馆|舊金山公共圖書館/i,
    /\b(?:SMCL|San Mateo County Libraries)\b/i,
    /\b(?:AC Library|Alameda County Library)\b/i,
  ];
  return systems.filter(pattern => pattern.test(message)).length > 1
    && !affirmativeGoal(message, /搬到|搬去|迁到|遷到|去|前往|出发|出發|参观|參觀|\b(?:move|moving|moved|relocate|visit|going to|go to|travel to|depart)\b/);
}

function libraryInstitutionReference(message) {
  if (!isLibraryServiceQuestion(message) || affirmativeGoal(message, /搬到|搬去|迁到|遷到|改去|去|前往|出发|出發|参观|參觀|\b(?:move|moving|moved|relocate|visit|going to|go to|travel to|depart)\b/)) return false;
  const normalized = normalizeCityMentions(message);
  return /\b(?:SFPL|SMCL|AC Library|Alameda County Library|San Mateo County Libraries|San Francisco Public Library)\b/i.test(message)
    || mentionedCities(normalized).some(city => new RegExp(`${city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*(?:的\\s*)?(?:图书馆|圖書館|图书证|圖書證|卡|library|public library)`, 'i').test(normalized));
}

function withoutNegatedBudget(message) {
  // Remove only rejected budget scopes/amounts. An affirmative cap elsewhere
  // in the same turn still applies, and "no more than" remains a real cap.
  const scope = '(?:每人|每位|人均|全家(?:总预算|總預算)?|总预算|總預算|总共|總共|预算|預算|per person|each person|a head|(?:a |the )?total(?: (?:family |group )?budget)?|budget)';
  const amount = '(?:\\$|USD\\s*)?\\d+(?:\\.\\d{1,2})?(?:\\s*(?:美元|美金|USD|dollars?))?';
  const negative = '(?:不是(?:按)?|并非|並非|不要按|不用按|\\bnot)\\s*';
  return message
    .replace(new RegExp(`${negative}${scope}\\s*(?:预算|預算|budget)?\\s*(?:改为|改為|是|为|為|of|is|:)?\\s*(?:${amount})?`, 'gi'), ' ')
    .replace(new RegExp(`${negative}${amount}\\s*(?:${scope})`, 'gi'), ' ');
}

// API-BB-7 (block N held-out N-02 "three, almost four"; block O dev): the child's age now. "快四岁了" / "almost four" is 3,
// and next to the age now ("三岁多，快四岁了", "two, almost three") it adds nothing. "My son is two" (a child's age with no
// "years old") is read too.
const AGE_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen'];
const AGE_EN = `(\\d{1,2}|${AGE_WORDS.join('|')})`;
const AGE_ZH = '(\\d{1,2}|十[一二三四五六七]?|[一二两兩三四五六七八九])';
const ageNumber = value => {
  if (/^\d+$/.test(value)) return Number(value);
  const english = AGE_WORDS.indexOf(String(value).toLowerCase());
  if (english >= 0) return english;
  const digits = '零一二三四五六七八九';
  const plain = String(value).replace(/[两兩]/g, '二');
  return plain.startsWith('十') ? 10 + (plain.length > 1 ? digits.indexOf(plain[1]) : 0) : digits.indexOf(plain);
};
const ALMOST_ZH = new RegExp(`(?:快要?|将近|將近|马上(?:就)?(?:要)?|馬上(?:就)?(?:要)?|就要)(?:满|滿|到)?\\s*${AGE_ZH}\\s*(?:周)?[岁歲](?:了)?`, 'g');
// Review 10-16: English "almost N" is an age only next to a child word ("my son is two, almost three", "our daughter is
// almost 6") or before "years old"; "it is almost 3", "almost 5 blocks", "nearly 15 stalls" are not. "is one of" is not an age.
// "he" / "she" count only as "she is" / "he turns" / "she's" ("She says it is almost 3" is a clock).
const CHILD_NOUN_EN = `(?:son|daughter|child|kid|boy|girl|toddler|baby|little one|grandson|granddaughter|(?:he|she)(?=\\s+(?:is|turns)\\b|['’]s\\b))`;
const NOT_AGE_UNITS = `(?:months?|weeks?|days?|hours?|minutes?|dollars?|bucks|percent|%|miles?|blocks?|stops?|stalls?|events?|items?|spots?|tickets?|people|times|o['’]clock|pm|am)`;
const ALMOST_EN = new RegExp(`(?<=\\b${CHILD_NOUN_EN}\\b[^.!?;\\n]{0,24}?)\\b(?:almost|nearly|about to turn|soon to be|turning)\\s+${AGE_EN}\\b(?![\\s-]*${NOT_AGE_UNITS}\\b)|\\b(?:almost|nearly|about to turn|soon to be|turning)\\s+${AGE_EN}(?=[\\s-]*years?[\\s-]*old\\b)`, 'gi');
const CHILD_IS_EN = new RegExp(`\\b(?:son|daughter|child|kid|boy|girl|toddler|baby|little one|grandson|granddaughter)\\s+(?:is|turned|just turned)\\s+${AGE_EN}\\b(?!\\s+of\\b)(?![\\s-]*${NOT_AGE_UNITS}\\b)`, 'i');
function almostAges(text) {
  const spans = [];
  const ages = [];
  for (const pattern of [ALMOST_ZH, ALMOST_EN]) for (const match of text.matchAll(pattern)) {
    spans.push(match[0]);
    const age = ageNumber(match[1] || match[2]) - 1;
    if (age >= 0 && age <= 17) ages.push(age);
  }
  const current = CHILD_IS_EN.exec(text);
  const now = current ? ageNumber(current[1]) : null;
  return { spans, ages: now !== null && now >= 0 && now <= 17 ? [now] : ages };
}
const withoutAlmostAges = (message, spans) => spans.reduce((text, span) => text.split(span).join(' '.repeat(span.length)), message);
// API-BB-7 (block N held-out N-06 "Sensory Sunday" on 12/13; block O dev "Family Saturday", "Super Sunday"): beside a full
// date, a weekday word that is part of an event's own name (a capitalised word before or after it) is not a second date.
const FULL_DATE = /\d{4}\s*年\s*\d{1,2}\s*月\s*\d{1,2}|\d{1,2}\s*月\s*\d{1,2}\s*(?:日|号|號)|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2}\b|\b\d{1,2}\/\d{1,2}\b/i;
const NAME_NEIGHBOUR = /^(?:On|This|Next|Last|Every|Each|Saturday|Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|And|Or|The|A|An|I|We)$/;
function withoutNamedWeekdays(message, original = message) {
  if (!FULL_DATE.test(original)) return message;
  const names = [];
  for (const match of original.matchAll(/\b([A-Z][a-z]+)\s+((?:Satur|Sun|Mon|Tues|Wednes|Thurs|Fri)days?)\b|\b((?:Satur|Sun|Mon|Tues|Wednes|Thurs|Fri)days?)\s+([A-Z][a-z]+)\b/g)) {
    const [, before, day, day2, after] = match;
    if (before && !NAME_NEIGHBOUR.test(before)) names.push([before, day, true]);
    else if (after && !NAME_NEIGHBOUR.test(after)) names.push([after, day2, false]);
  }
  return names.reduce((text, [word, day, first]) => text.replace(new RegExp(first ? `\\b(${word})\\s+${day}\\b` : `\\b${day}\\s+(${word})\\b`, 'gi'),
    (match, kept) => first ? `${kept}${' '.repeat(match.length - kept.length)}` : `${' '.repeat(match.length - kept.length)}${kept}`), message);
}
const NEARBY_HOME = /附近|周边|週邊|家门口|家門口|\bnear(?:by| me| us| home| where we live)\b/i;
const NO_KIDS = /不带孩子|不帶孩子|没有孩子同行|沒有孩子同行|(?:^|[，,。.!！？?；;\n])\s*(?:这次|這次)?(?:孩子|小孩|娃)(?:都)?(?:不去了|不去|不同行|不参加|不參加)(?=[，,。.!！？?；;\n\s]|$)|\b(?:no kids|no children|adults only|without (?:the )?(?:kids|children))\b/i;
const FAMILY_SIGNAL = /亲子|親子|带娃|帶娃|遛娃|孩子|小孩|小朋友|儿童|兒童|宝宝|寶寶|幼儿|幼兒|全家|\b(?:kids?|children|child|toddlers?|famil(?:y|ies))\b/i;
// "family doctor", 家庭医生 and the like are not an outing with children.
const FAMILY_NOT_KIDS = /\bfamily (?:doctors?|physicians?|medicine|law|lawyers?|court|planning|members? of)\b|孩子(?:的)?(?:医疗|醫療|保险|保險|签证|簽證)/gi;
// Review 10-16: "no money for parking" or "no money worries" is not a zero admission budget, and "预算0-50美元" /
// "budget is 0-20 dollars" is a range, not zero.
const ZERO_BUDGET = /(?:门票|門票|入场|入場)?(?:预算|預算)(?:现在|現在)?(?:改成|改为|改為|变成|變成|降到|降为|降為|是|为|為|=)?\s*(?:零|0)(?:\s*(?:元|美元|块|塊|刀))?(?![\d.])(?!\s*(?:[-–~到至]|to)\s*\$?\d)|\b(?:admission |ticket |entry )?budget (?:is )?(?:now )?(?:exactly )?(?:zero|0|\$0|nothing)\b(?!\s*(?:[-–~]|to)\s*\$?\d)|\bno (?:admission|ticket) money\b|\bno money (?:left )?for (?:tickets|admission|entry)\b/i;
function withoutRejectedChildAges(message) {
  return message.replace(/(?:不是|并非|並非)\s*\d{1,2}\s*[岁歲]|\bnot\s+\d{1,2}\s*(?:years? old|[- ]year[- ]old)\b/gi, ' ');
}

function withoutTravelModeComparisons(message) {
  const modes = [/开车|開車|驾车|駕車|\bdriv(?:e|ing)\b/i, /公交|公共交通|公[车車]|大[众眾][运運][输輸]|坐车|坐車|搭车|搭車|\b(?:transit|bus|train)\b/i, /步行|走路|\bwalk(?:ing)?\b/i];
  return message.replace(/[^，,。.!！？?；;\n]+/g, clause => {
    const comparing = /还是|還是|或者|\bor\b|\bversus\b|\bvs\b|比较|比較|哪个|哪個|\b(?:compare|which|easier|better)\b/i.test(clause);
    if (!comparing || modes.filter(pattern => pattern.test(clause)).length < 2) return clause;
    return clause.replace(/开车|開車|驾车|駕車|公交|公共交通|公[车車]|大[众眾][运運][输輸]|坐车|坐車|搭车|搭車|步行|走路|\b(?:driv(?:e|ing)|transit|bus|train|walk(?:ing)?)\b/gi, ' ');
  });
}

function excludedCitiesIn(message) {
  const exclusions = [];
  for (const city of mentionedCities(message)) {
    const escaped = city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const match of message.matchAll(new RegExp(escaped, 'gi'))) {
      const before = message.slice(Math.max(0, match.index - 65), match.index);
      if (/(?:不要|不去|不想去|别去|別去|排除|避开|避開|除了?|不是|\boutside(?: of)?|\bnot in|\bexcept(?: for)?|\binstead of|\brather than|\bavoid(?:ing)?(?: going to| visiting)?|\b(?:do not|don't|don’t|not|never)\s+(?:want to |plan to |intend to )?(?:go to|visit|be in|travel to))\s*$/i.test(before)) exclusions.push(city);
    }
  }
  return unique(exclusions);
}

function clockValue(hours, minutes, period) {
  const digits = { 零: 0, 〇: 0, 一: 1, 二: 2, 两: 2, 兩: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9 };
  const numeral = value => /^\d+$/.test(value) ? Number(value) : Object.hasOwn(digits, value) ? digits[value]
    : /^([一二])?十([一二三四五六七八九])?$/.test(value) ? (digits[value.split('十')[0]] || 1) * 10 + (digits[value.split('十')[1]] || 0) : NaN;
  let hour = numeral(String(hours)); const minute = Number(minutes || 0);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23 || minute < 0 || minute > 59 || (/^(?:am|pm)$/i.test(period || '') && (hour < 1 || hour > 12))) return null;
  if (/下午|晚上|傍晚|pm/i.test(period || '') && hour < 12) hour += 12;
  if (/早上|上午|凌晨|am/i.test(period || '') && hour === 12) hour = 0;
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function userTimeContext(message, index, length) {
  // A source's schedule or a question about an event is not a personal time
  // constraint. Inspect the clock's own clause so a later explicit departure
  // can coexist with an earlier opening-hours question or quotation.
  const before = message.slice(0, index).split(/[，,。.!！？?；;\n]|(?:但是|但|所以|那么|那麼|那就)|\b(?:but|however|so|then)\b/i).at(-1);
  const after = message.slice(index + length).split(/[，,。.!！？?；;\n]|(?:但是|但|所以|那么|那麼|那就)|\b(?:but|however|so|then)\b/i)[0];
  const clause = before + message.slice(index, index + length) + after;
  const sourceLanguage = /官网|官網|网站|網站|网页|網頁|海报|海報|页面|頁面|资料|資料|听说|聽說|据说|據說|写着|寫著|标注|標註|\b(?:according to|website|webpage|poster|page says|page lists|advertised|listed|reportedly)\b/i;
  const reported = sourceLanguage.test(clause);
  const quoted = /[“「『][^”」』]*$|"[^"]*$/.test(before) && /[”」』"]/.test(after);
  if (reported || quoted) return { before, after, allowed: false };
  const personal = /(?:我(?:们|們)?|咱(?:们|們))(?:可以|能否|能不能|想|要|打算|必须|必須)?\s*(?:早上|上午|下午|晚上)?\s*$/.test(before)
    || /^\s*(?:早上|上午|下午|晚上)?\s*$/.test(before) && /^(?:再)?(?:出发|出發|开车|開車|驾车|駕車|乘车|乘車)|^(?:从|從).{1,80}(?:出发|出發)/.test(after.trimStart())
    || /(?:请|請)[^，,。.!！？?；;\n]{0,16}(?:安排|规划|規劃)|^(?:再)?(?:开始|開始)(?:安排|规划|規劃|行程)/.test(before + after)
    || /\b(?:I|we)\s+(?:(?:can|could|should|will|want to|need to|must)\s+)?(?:leave|depart|start|return|finish|be back)?(?:\s+at|\s+by)?\s*$/i.test(before);
  const sentencePrefix = message.slice(0, index).split(/[。.!！？?；;\n]|(?:但是|但|所以|那么|那麼|那就)|\b(?:but|however|so|then)\b/i).at(-1);
  if (!personal && sourceLanguage.test(sentencePrefix)) return { before, after, allowed: false };
  const question = /是不是|是否|会不会|會不會|几点|幾點|吗|嗎|么|麼|\b(?:does|is|are|will)\s+(?:it|the |this |that )/i.test(clause);
  const externalSubject = /活动|活動|场馆|場館|门店|門店|每家|工作坊|讲座|講座|市集|演出|电影|電影|博物馆|博物館|\b(?:event|workshop|store|museum|concert|movie|show|tour|it)\b/i.test(before)
    || /^(?:开始|開始)(?:的|之)?(?:活动|活動|场次|場次)|^\s*(?:start(?:s|ing)?|finish(?:es|ing)?)\s+(?:of|for)\b/i.test(after);
  return { before, after, allowed: personal || !(question || externalSubject) };
}

function timesIn(message, { afternoon = false } = {}) {
  const result = {};
  // H38 (audit 10-13): a space between the number and 点 ("下午 4 点前回家", the site's own
  // spaced style) is the same clock; 时/時 counts as 点 (not 时间/时候/时段).
  // Spaced minutes need 分 (3 点 15 分), so 4 点 2 个人 is not 4:02; 半 may follow a space too.
  // Digits and Chinese numerals never mix, so 周六10点 is 10:00 (六10 is not an hour).
  const zh = /(早上|上午|中午|下午|晚上|凌晨|傍晚)?\s*(\d{1,2}|[零〇一二两兩三四五六七八九十]{1,3})(?:[:：](\d{2})|[ \t　]?(?:[点點]|[时時](?![间間候段]))(?:(\d{1,2})分?|[ \t　](\d{1,2})[ \t　]?分|[ \t　]?(半))?)(?:钟|鐘)?/g;
  let finishBare = false;
  for (const match of message.matchAll(zh)) {
    const context = userTimeContext(message, match.index, match[0].length);
    if (!context.allowed) continue;
    const before = context.before.slice(-40), after = context.after.trimStart();
    const value = clockValue(match[2], match[6] ? '30' : match[3] || match[4] || match[5], match[1]);
    if (!value) continue;
    if (/(?:不是|不要|不用|别|別)\s*$/.test(before)) continue;
    const bare = !match[1];
    if (/^(?:前)?\s*在[^，,。；;\n]{1,80}(?:结束|結束)/.test(after)) result.returnToOrigin = /^(?:前)?\s*在\s*(?:出发点|出發點|起点|起點|原地|同一站|出发地|出發地)(?:结束|結束)/.test(after);
    if (/^(?:之)?前.{0,8}(?:回来|回來|回家|回到|回原地|回出发点|回出發點|回起点|回起點|返回|返程|结束|結束|到家)|^(?:回来|回來|回家|回到|回原地|回出发点|回出發點|回起点|回起點|返回|结束|結束)|^回[^，,。；;\n]{1,60}站|^(?:前)?\s*在[^，,。；;\n]{1,80}(?:结束|結束)|^(?:前)?(?:就)?(?:得|要|必须|必須)(?:走|离开|離開)(?:了|啦)?\s*$|(?:最晚|必须|必須).{0,8}$/.test(after) || /(?:最晚|必须|必須|回程|返程).{0,8}$/.test(before)) { result.finishBy = value; finishBare = bare; }
    else if (/^(?:从|從)[^，,。；;\n]{1,80}(?:出发|出發)|^(?:再)?(?:开始|開始|出发|出發|开车|開車|驾车|駕車|坐车|坐車|乘车|乘車|搭车|搭車)|(?:从|從|开始|開始|出发|出發)(?:时间|時間)?[：:]?\s*$/.test(after) || /(?:从|從|开始|開始|出发|出發)(?:时间|時間)?[：:]?\s*$/.test(before)) result.startTime = value;
  }
  for (const match of message.matchAll(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b|\b(\d{1,2}):(\d{2})\b/gi)) {
    const context = userTimeContext(message, match.index, match[0].length);
    if (!context.allowed) continue;
    const before = context.before.slice(-40), after = context.after;
    const value = clockValue(match[1] || match[4], match[2] || match[5], match[3]);
    if (!value) continue;
    if (/\b(?:not|rather than)\s*$/i.test(before)) continue;
    // v2 (review round 1): "back by 3:30" without am/pm is a bare hour too.
    if (/\b(?:by|before|home at|return at|finish at|back at)\s*$/i.test(before)) { result.finishBy = value; finishBare = afternoon && !match[3]; }
    else if (/\b(?:start(?:ing)?|leave|leaving|depart(?:ing)?|from)(?: at)?\s*$/i.test(before) || /^\s*(?:start|departure|drive|driving|depart|leave)/i.test(after)) result.startTime = value;
  }
  // A bare finish hour (no 上午 / 下午) at or before the start is the afternoon or evening
  // (10 点出发，5 点前回家 is 17:00); one that is still not after the start is dropped.
  if (finishBare && result.startTime && result.finishBy <= result.startTime) {
    const hour = Number(result.finishBy.slice(0, 2));
    const later = hour < 12 ? `${String(hour + 12).padStart(2, '0')}${result.finishBy.slice(2)}` : null;
    if (later && later > result.startTime) result.finishBy = later; else delete result.finishBy;
  }
  // Review (API-BB-5 round 1, v2): "need to be back by 3" / "done by 4" with no am/pm reads as the zh rule below does.
  if (afternoon && !result.finishBy) {
    const bare = message.match(/\b(?:back|home|done|finished|finish|wrapped up|wrap up|out)\s+(?:by|before)\s+(\d{1,2})(?:\s*o['’]?clock)?\b(?!\s*(?::\d|am\b|pm\b|a\.m\.|p\.m\.|%|\$|dollars?|kids?|people|year|yo\b|-year))/i);
    const hour = bare ? Number(bare[1]) : 0;
    if (hour >= 1 && hour <= 12) {
      const value = `${String(hour <= 7 ? hour + 12 : hour).padStart(2, '0')}:00`;
      if (!result.startTime || value > result.startTime) result.finishBy = value;
    }
  }
  // API-BB-5 (v2): "3 点前要结束" with no start time and no 上午 / 凌晨 is 15:00, not 03:00; an outing that ends
  // between 1 and 7 o'clock ends in the afternoon. 8-12 stay as written.
  if (afternoon && finishBare && !result.startTime && result.finishBy) {
    const hour = Number(result.finishBy.slice(0, 2));
    if (hour >= 1 && hour <= 7) result.finishBy = `${String(hour + 12).padStart(2, '0')}${result.finishBy.slice(2)}`;
  }
  return result;
}

function returnToOriginIn(message) {
  let result;
  const pattern = /(?:(?:不|不要|不用|无需|無需)(?:再)?)?(?:回|返回)(?:到)?(?:出发点|出發點|起点|起點|原点|原點|原地|同一站|原站|出发地|出發地)|\b(?:(?:do not|don't|no need to|not)\s+)?(?:return|go back|back)(?:\s+to)?\s+(?:the |our )?(?:starting point|origin|same station)\b/gi;
  for (const match of message.matchAll(pattern)) {
    if (!userTimeContext(message, match.index, match[0].length).allowed) continue;
    result = !/^(?:不|不要|不用|无需|無需|do not\b|don't\b|no need to\b|not\b)/i.test(match[0]);
  }
  return result;
}

function preferencePhrases(message) {
  const found = [];
  for (const [pattern, label] of [
    [/不开车|不開車|没车|沒車|\b(?:no car|without (?:a )?car|not driving|don't drive|do not drive)\b/i, 'no-car'],
    [/少走路|不想走太多|不想走路|走路别太多|走路別太多|走一(?:会|會|下)(?:儿|兒)?就累|\b(?:less walking|limited walking|avoid long walks)\b/i, 'limited-walking'],
    [/轮椅|輪椅|\bwheelchair\b/i, 'wheelchair-access'],
    [/婴儿车|嬰兒車|\bstroller\b/i, 'stroller-access'],
    [/素食|\bvegetarian\b/i, 'vegetarian'],
    [/带老人|帶老人|\bwith (?:my |our )?(?:elderly parents|seniors)\b/i, 'with-seniors'],
    [/人少(?:一)?点|人少(?:一)?點|不想挤|不想擠|避开人群|避開人群|\b(?:less crowded|avoid crowds)\b/i, 'avoid-crowds'],
    [/不要太赶|不要太趕|别(?:太)?赶|別(?:太)?趕|中间歇|中間歇|别排太满|別排太滿|不折腾|不折騰|(?:排|安排)(?:比较|比較)?(?:轻松|輕鬆)|(?:排|安排)得(?:松|轻松|輕鬆)|\b(?:not too rushed|take it slow|relaxed pace)\b/i, 'relaxed-pace'],
    [/顺路|順路|别跑远|別跑遠|别太远|別太遠|\b(?:on the way|nearby stops|don't go far)\b/i, 'nearby-stops'],
    [/能坐着歇|能坐著歇|坐着休息|坐著休息|中间歇|中間歇|\b(?:rest breaks|somewhere to sit|sit and rest)\b/i, 'rest-breaks'],
    [/午饭后|午飯後|吃完午饭|吃完午飯|\bafter lunch\b/i, 'after-lunch'],
  ]) if (pattern.test(message)) found.push(label);
  const duration = message.match(/(?:出去|出门|出門|玩|逛|行程|安排)(?:个|個|大概|约|約|就|最多|不超过|不超過|只有|只|\s){0,5}([1-9]|[一二两兩三四五六七八九])(?:个|個)?(?:小时|小時)(?!车程|車程|公交)|\b(?:out for|only have|have just)\s+(one|two|three|four|five|six|[1-6])\s+hours?\b/i);
  if (duration) {
    const value = (duration[1] || duration[2]).toLowerCase();
    const hours = /^\d$/.test(value) ? Number(value) : /两|兩/.test(value) ? 2 : value.length === 1 ? '一二三四五六七八九'.indexOf(value) + 1 : ['one', 'two', 'three', 'four', 'five', 'six'].indexOf(value) + 1;
    if (hours >= 1 && hours <= 9) found.push(`outing-duration:${hours * 60}-minutes`);
  }
  if (!duration) for (const match of message.matchAll(/半天|半日|\bhalf(?:[- ]a)?[- ]day\b/gi)) {
    const context = userTimeContext(message, match.index, match[0].length);
    if (context.allowed && !/上次|昨天|昨日|之前|过去|過去|曾经|曾經|\b(?:yesterday|previously|last week|last time|already)\b/i.test(context.before)
      && affirmativeGoal(context.before + match[0], /半天|半日|\bhalf(?:[- ]a)?[- ]day\b/)) {
      // Keep the speaker's qualitative limit without inventing hours or clocks.
      found.push('outing-duration:half-day'); break;
    }
  }
  return found;
}

// ---- v2 follow-up carry (API-BB-QUALITY, BBL-07, BBENG-15) -----------------------
// Only BAYBAY_ENGINE=v2 passes `carry`; v1 and the planner keep their state exactly.
// "帮我排成周六半天" / "排到下午" ask for a plan as plainly as 安排…行程 does.
// Every whitespace run sits between required tokens, so matching stays linear (no ReDoS).
const PLAN_SHAPE = /(?:排|安排)(?:成|到|在|进|進)\s*(?:(?:这|這|本)?(?:周|週|星期)[一二三四五六日天]的?\s*)?(?:(?:上午|下午|晚上)\s*)?(?:半天|一天|半日|一日|行程)|(?:排|安排)(?:个|個|一个|一個)(?:半天|一天|半日|一日)|(?:排|安排)\s*(?:(?:这|這|本|下)?(?:周|週|星期)[一二三四五六日天]的?\s*)(?:(?:上午|下午|晚上)\s*)?(?:半天|一天|半日|一日|行程)|(?:帮我|幫我|给我|給我)\s*(?:排|安排|规划|規劃)\s*(?:一下|下)?\s*(?:(?:这|這|本|下)?\s*(?:个|個)?\s*(?:周|週|星期)[一二三四五六日天])?(?=[\s，,。.!！？?；;]|$)/;
// API-BB-5: "帮我排一下" is a plan ask only beside an outing ("出去玩半天，帮我排一下"), not "帮我安排一下预约".
const PLAN_OUTING = /半天|一天|半日|一日|行程|玩|逛|出去|出门|出門|走走|地方|去处|去處|景点|景點/;
// Review (API-BB-5 round 1): English plan asks beside PLAN_SHAPE: "Plan a Saturday for us", "Can you plan our Sunday?",
// "half-day plan"; "plan it" / "make it a plan" only after an outing turn. Not "plan a trip to Japan" or "plan a visit".
const PLAN_SHAPE_EN = /\bplan (?:out )?(?:(?:a|an|our|my|the|this|next|that)\s+)?(?:(?:this|next)\s+)?(?:sat(?:urday)?|sun(?:day)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|morning|afternoon|outing)\b|\b(?:half|full|whole)[- ]day (?:plan|itinerary|outing)\b/i;
const PLAN_IT_EN = /\b(?:plan (?:it|that|this|one)(?: out)?|make (?:it|that|this) (?:a |into a )?plan|turn (?:it|that|this) into a plan)\b/i;
// Riding a named system: 坐 Caltrain, 搭 VTA 轻轨, "take the ferry". BART, Muni and 公交
// are already read by the planner; these add the systems it does not know.
const TRANSIT_WORDS = String.raw`(?:Caltrain|BART|VTA|Muni|SamTrans|AC\s*Transit|轻轨|輕軌|地铁|地鐵|火车|火車|渡轮|渡輪|公交车?|公車|巴士|捷运|捷運|light\s*rail|ferry|bus(?:es)?|trains?|public\s+transit)`;
const TRANSIT_RIDE = new RegExp(String.raw`(?<!不|别|別|不要|不想|不能|不用|没法|沒法)(?:坐|搭|乘|改坐|改搭|改乘|换坐|換坐)\s*(?:${TRANSIT_WORDS})|\b(?<!not |n't |never )(?:take|taking|ride|riding|by|via|using)\s+(?:the\s+)?(?:${TRANSIT_WORDS})\b`, 'i');
// 预算每人 20 刀 / 每人 20 美元: an amount per person (the planner reads the scope only).
// API-BB-5: also "每人最多 15 刀" / "每人不超过 20 美元".
const PER_PERSON_BUDGET = /(?:预算|預算)\s*(?:(?:是|为|為)\s*)?(?:每人|每位|人均|一个人|一個人)\s*(?:(?:\$|USD)\s*)?(\d{1,5}(?:\.\d{1,2})?)|(?:每人|每位|人均|一个人|一個人)\s*(?:(?:预算|預算)\s*)?(?:(?:最多|不超过|不超過|顶多|頂多|上限)\s*)?(?:(?:\$|USD)\s*)?(\d{1,5}(?:\.\d{1,2})?)\s*(?:刀|美元|美金|块|塊|元|dollars?|bucks)/i;
// "哪些完全免费？" after a list: show every free option (BBL-06), not the previous shortlist.
const FREE_FOLLOWUP = /哪(?:些|个|個|几个|幾個|几项|幾項)(?:是|是不是)?(?:完全)?免[费費]|(?:完全)?免[费費]的(?:有哪些|是哪些|有什么|有什麼|呢)|\bwhich (?:ones |of (?:them|these) )?(?:are|is) free\b|\b(?:any|only (?:the )?)free ones\b|\b(?:any|some) free (?:things|stuff|events?|activities|options)\b/i;
// 明天下午 / 改成下午: the part of the day, kept as a preference (no clock is invented).
function timeOfDay(text) {
  if (/还是|還是|或者|\bor\b/i.test(text) && (text.match(/上午|早上|中午|下午|傍晚|晚上|\b(?:morning|afternoon|evening)\b/gi) || []).length > 1) return null;
  // API-BB-5: "下午 5 点前要回家" is a finish time (finishBy), not a wish to go in the afternoon.
  const zh = text.match(/(上午|早上|中午|下午|傍晚|晚上)(?![茶饭飯餐])(?!\s*\d)/);
  if (zh) return { 上午: 'morning', 早上: 'morning', 中午: 'midday', 下午: 'afternoon', 傍晚: 'evening', 晚上: 'evening' }[zh[1]];
  const en = text.match(/\b(?:this |tomorrow |saturday |sunday )?(morning|afternoon|evening|tonight)\b/i);
  return en ? (en[1].toLowerCase() === 'tonight' ? 'evening' : en[1].toLowerCase()) : null;
}
// The household does not shrink because one turn names one child ("只挑一个最适合 4 岁的"):
// only an explicit change (孩子年龄改为…, 只带 4 岁的, 7 岁的不去) replaces the list.
function keepsHousehold(previousAges = [], ages = [], text = '') {
  return previousAges.length > ages.length && ages.every(age => previousAges.includes(age))
    && !/只带|只帶|就带|就帶|(?:\d{1,2})\s*(?:岁|歲)的?(?:那个|那個)?(?:不去|不来|不來|不参加|不參加)|\bonly (?:bring|take|taking|bringing)\b/i.test(text);
}

// API-BB-5: "周末一般去哪玩", "we usually go on weekends": weekends in general, not the coming one.
// Review (API-BB-5 round 1): a weekend named after a holiday is that holiday's, not the coming one ("感恩节周末带孩子去哪玩"
// read as 10/17-18 offered this weekend's events); like the base engine, it sets no date and the holiday's own words find
// its events. Review round 2: the connective forms too (感恩节那个周末, 那周末, 圣诞节这个周末, 感恩节放假的周末); 长 is not
// the tail of 家长/校长 (家长这个周末 is this weekend). Review round 4: 长 (long) only directly before 周末 (长周末), and the
// connectives only after a holiday's name (学长这个周末, 院长这个周末, 时间长这个周末 are this weekend).
const HOLIDAY_WEEKEND = /(?:感恩|圣诞|聖誕|万圣|萬聖|国庆|國慶|退伍军人|退伍軍人|老兵|劳工|勞工|阵亡将士|陣亡將士|独立|獨立|元旦|新年|春|中秋|复活|復活|假日|节日|節日)\s*(?:节|節|日)?\s*(?:那|这|這)?\s*(?:个|個)?\s*(?:放假|假期|长假|長假)?\s*(?:的)?\s*(?:周末|週末)|(?<![家校班队隊组組市州部局学學园園院间間])(?:长|長)(?:周末|週末)|\b(?:thanksgiving|christmas|xmas|halloween|veterans['’]?\s*day|labor\s*day|memorial\s*day|independence\s*day|new\s*year['’]?s?|easter|holiday|long)\s+weekends?\b/i;
const REGULAR_WEEKEND = /平常|平时|平時|通常|一般|常规|常規|每(?:个|個)?(?:周|週|星期)|每逢|\b(?:usually|normally|regularly|generally|every weekend|on weekends|weekends)\b/i;
/** `value` with every case-insensitive occurrence of `part` replaced by spaces (positions kept). */
function blankText(value, part) {
  const lower = value.toLowerCase(), wanted = part.toLowerCase();
  let out = value;
  for (let at = wanted ? lower.indexOf(wanted) : -1; at >= 0; at = lower.indexOf(wanted, at + wanted.length)) out = out.slice(0, at) + ' '.repeat(wanted.length) + out.slice(at + wanted.length);
  return out;
}
/** The span of days an ask names (askedDateRange); a month only bounds an outing ask. */
// A month bounds an outing ask, or an ask about events ("12月有什么圣诞点灯或者游行"), never "我1月要回国".
const EVENT_NOUN = /活动|活動|游行|遊行|点灯|點燈|市集|集市|展览|展覽|演出|音乐会|音樂會|节日|節日|庆典|慶典|\b(?:events?|parades?|festivals?|markets?|fairs?|concerts?|shows?|tree lightings?|lightings?)\b/i;
function spanFor(text, today, goal) {
  let span = askedDateRange(text, today);
  // Review round 3: the 这个周末 of "感恩节这个周末" / "圣诞节这周末" is the holiday's weekend, not this one (like 那个周末);
  // a separate 这周末 elsewhere in the ask still is ("感恩节周末不在，这周末去哪").
  const holiday = span?.kind === 'weekend' && HOLIDAY_WEEKEND.exec(text);
  if (holiday) span = askedDateRange(blankText(text, holiday[0]), today);
  if (!span || (span.kind === 'month' && !['discover', 'day-plan'].includes(goal) && !EVENT_NOUN.test(text))) return null;
  return span;
}

/** Merge only explicit user conditions. The caller must pass only a verified
 * token's state as previous; raw client taskState is not an authority.
 * `carry` (BAYBAY_ENGINE=v2): also read follow-up constraints the planner does not
 * (other transit systems, per-person amounts, "which are free", the part of the day,
 * "排成半天") and never shrink the household's child ages to the one child named. */
function resolveTaskState({ message = '', previous, searchContext = {}, today = bayAreaDate(), catalog, preferences, carry = false } = {}) {
  const text = typeof message === 'string' ? message.slice(0, 4000) : '';
  const previousState = previous?.state || previous;
  const state = validateTaskState(previousState);
  state.revision += 1;
  const cleared = new Set(state.clearedFields);
  const set = (field, value) => { state[field] = value; cleared.delete(field); if (field === 'date' && validDate(value)) delete state.dateContextMonth; };
  const clear = field => { state[field] = field === 'childAges' || field === 'preferences' ? [] : null; cleared.add(field); if (field === 'date') delete state.dateContextMonth; };
  let clarification;
  if (!validDate(today)) return { state, clarification: '请确认有效的湾区日期后再安排行程。' };
  // UI hints only initialize absent conditions, never resurrect cleared ones.
  for (const key of ['city', 'region', 'date']) if (state[key] === null && !cleared.has(key) && searchContext[key]) {
    const valid = validateTaskState({ [key]: searchContext[key] })[key];
    if (valid !== null) set(key, valid);
  }
  if (!previousState && Array.isArray(preferences)) state.preferences = list(preferences);
  if (!previousState && plain(preferences)) {
    // The caller supplies server account defaults or the separately validated,
    // explicitly shared public preferences. The latest turn takes precedence.
    const defaults = validateTaskState({ travelMode: preferences.travelMode, setting: preferences.setting, budget: preferences.admissionBudgetUsd });
    for (const key of ['travelMode', 'setting', 'budget']) if (state[key] === null && defaults[key] !== null) state[key] = defaults[key];
    const regions = Array.isArray(preferences.regions) ? preferences.regions.filter(region => REGIONS.includes(region)) : [];
    if (!state.city && !state.region && regions.length === 1) state.region = regions[0];
    state.preferences = list(preferences.interests);
  }
  const goal = goalOf(text);
  if (goal && !(state.goal === 'day-plan' && ['discover', 'shopping'].includes(goal) && !declinesPlan(text))) set('goal', goal);
  // Review round 2: after an outing turn, a bare 帮我排一下 is a plan ask like English "plan it" (it needs no outing word).
  if (carry && state.goal !== 'day-plan' && ((PLAN_SHAPE.test(text) && (PLAN_OUTING.test(text) || ['discover', 'day-plan'].includes(previousState?.goal))) || PLAN_SHAPE_EN.test(text)
    || (PLAN_IT_EN.test(text) && ['discover', 'day-plan'].includes(previousState?.goal))) && !declinesPlan(text) && !pausesPlanRequest(text)) set('goal', 'day-plan');
  if (previousState?.goal === 'day-plan' && state.goal !== 'day-plan' && !pausesPlanRequest(text)) { clear('maxStops'); clear('returnToOrigin'); }
  if (!state.goal && text.length > 10) set('goal', 'information');
  // H17 (audit 10-13, BB-1013-02): 华人 / 中文 / 国语 / 粤语 / 普通话 / 华埠 / 重阳 asks keep a
  // Chinese-community facet in the task, so a follow-up such as 明天有吗 keeps it. Asking for
  // the answer in Chinese is not one; 不限语言 / any language clears it. Only an event or
  // activity ask sets it, and a later ask about something else (会说中文的医生, 中文学校, a move,
  // shopping, an information question) ends it; a bare follow-up (明天有吗, 那周日呢) keeps it.
  const eventAsk = COMMUNITY_EVENT.test(text);
  if (COMMUNITY_CLEAR.test(text)) clear('community');
  else if (CHINESE_COMMUNITY.test(text) && !ANSWER_LANGUAGE.test(text) && eventAsk) set('community', 'chinese');
  else if (state.community === 'chinese' && !eventAsk && ((CHINESE_COMMUNITY.test(text) && !ANSWER_LANGUAGE.test(text)) || COMMUNITY_OTHER_SUBJECT.test(text) || ['information', 'newcomer', 'shopping'].includes(goal))) clear('community');
  const informational = ['information', 'newcomer'].includes(state.goal);
  // API-BB-5 (API-SYNC-3c follow-ups 1-2, v2 only): the span of days this ask names, and a bare 周末.
  const askedSpan = carry ? spanFor(text, today, state.goal) : null;
  const spanText = askedSpan && !(askedSpan.kind === 'days' && state.goal === 'day-plan') && ['days', 'weekend-of', 'nth-weekend', 'holiday-weekend', 'month'].includes(askedSpan.kind) ? askedSpan.text : '';
  let informationAlternatives = false;
  let informationCities = false;
  const stopLimit = requestedStopLimit(text);
  if (Number.isInteger(stopLimit) && stopLimit >= 1 && stopLimit <= 6) set('maxStops', stopLimit);
  // In an eligibility comparison, the library system's published name is the
  // subject of the question, not a request to travel to its namesake city.
  const comparingLibraries = ['information', 'newcomer'].includes(state.goal) && libraryEligibilityComparison(text);
  const libraryReference = ['information', 'newcomer'].includes(state.goal)
    && ['information', 'newcomer'].includes(previousState?.goal) && !!(previousState?.city || previousState?.origin)
    && libraryInstitutionReference(text);
  const schoolComparison = isSchoolRequest(text) && mentionedCities(text).length > 1;
  const budgetText = withoutNegatedBudget(text);
  const totalLimit = totalBudgetLimitIn(budgetText);
  const factualBudget = venuePriceQuestion(budgetText) && totalLimit === null && !affirmativeGoal(budgetText, /预算|預算|\bbudget\b/);

  const priorOrigin = /(?:从|從)\s*(?:原来的地方|原來的地方|原来的起点|原來的起點|刚才的地方|剛才的地方|同一个地方|同一個地方)(?=\s*(?:出发|出發))|\bfrom\s+(?:the\s+)?(?:same|previous|original)\s+(?:place|starting point)\b/gi;
  const hasPriorOrigin = new RegExp(priorOrigin.source, 'i').test(text);
  const originText = text
    .replace(/(?:起点|起點|出发地|出發地)(?:不是|不在)[^，,。.!！？?；;\n]{1,30}[，,]\s*我(?:说的是|說的是|指的是)\s*/g, 'from ')
    .replace(/出发地(?:点|點)?(?:改为|改為|设为|設為|是|：|:)|出發地(?:點)?(?:改為|設為|是|：|:)|\b(?:origin|starting point)\s*(?:change(?:d)? to|set to|is|:)\s*/gi, 'from ')
    .replace(priorOrigin, ' ')
    .replace(/不是(?:要|想)?(?:去|到|前往)\s*/g, '不去 ');
  if (hasPriorOrigin && !state.origin) clarification ||= '原来的出发地点尚未确定，请提供一个公共地点或车站。';
  const destinationCatalog = normalizeCatalog(catalog);
  const explicitOrigin = matchOriginCandidate(originText, destinationCatalog);
  const nearbyOrigin = explicitOrigin ? null : nearbyStationOrigin(originText);
  const stationOrigin = explicitOrigin ? null : nearbyOrigin?.label || publicStationOrigin(originText);
  const locationText = nearbyOrigin ? originText.replace(nearbyOrigin.phrase, `from ${nearbyOrigin.station}`) : originText;
  // Remove the entire matched venue before destination parsing. Its title can
  // itself include a different city from the intended destination.
  let normalized = cityContext(venueCityContext(explicitOrigin
    ? originText.slice(0, explicitOrigin.start) + ' '.repeat(explicitOrigin.length) + originText.slice(explicitOrigin.end)
    : locationText, destinationCatalog));
  if (state.goal === 'day-plan') for (const city of mentionedCities(normalized)) {
    normalized = normalized.replace(new RegExp(`(?:回到|回|返回)\\s*(${city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})(?=\\s|BART|站|$|[，,。])`, 'gi'), ' from $1 ');
  }
  const originCities = originCitiesIn(normalized);
  const originDirective = originText.match(/(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*(\S[\s\S]{0,100})/i);
  if (originDirective && !/^(?:\d|\$|USD\b|上午|早上|下午|晚上|凌晨|傍晚)/i.test(originDirective[1])) { clear('origin'); clear('originCandidateId'); }
  if (explicitOrigin) {
    set('originCandidateId', explicitOrigin.row.id);
    set('origin', explicitOrigin.row.location.label || canonicalCity(explicitOrigin.row.city) || explicitOrigin.row.title);
  }
  destinationCatalog.places = [...destinationCatalog.places, ...mentionedCities(normalized).map(city => ({ city }))];
  const excluded = excludedCitiesIn(normalized);
  state.excludedCities = unique([...state.excludedCities, ...excluded]);
  if (state.city && excluded.includes(state.city)) { clear('city'); clear('region'); }
  if (CITY_CLEAR.test(text)) { clear('city'); set('region', 'all'); }
  let destination = {};
  try { destination = inferDestination(normalized, destinationCatalog); }
  catch (error) {
    // A retained positive destination can resolve a new exclusion elsewhere.
    // Only explicit information subjects waive the single-city itinerary gate.
    // A venue alias that maps to two cities is still an unresolved identity,
    // and a newcomer service setup still needs its actual service city.
    if (state.goal === 'information' && mentionedCities(text).length > 1 && error.message === '请先选择一个目的城市，再生成方案。') {
      informationAlternatives = true; informationCities = true;
      clear('city'); set('region', 'all');
    } else if (!comparingLibraries && !libraryReference && !schoolComparison && !(excluded.length && state.city && !excluded.includes(state.city)) && !CITY_CLEAR.test(text)) clarification = error.message;
  }
  if (comparingLibraries || schoolComparison && !destination.city) { clear('city'); clear('region'); }
  else if (destination.city && !libraryReference) {
    set('city', canonicalCity(destination.city));
    state.excludedCities = state.excludedCities.filter(city => city !== state.city);
    set('region', destination.region || null);
  }
  if (originCities.length === 1 && !explicitOrigin) {
    const retainedStation = !originDirective && state.origin && publicStationOrigin(`from ${state.origin}`)
      && mentionedCities(state.origin).includes(originCities[0]);
    if (!retainedStation) set('origin', originCities[0]);
    clear('originCandidateId');
  }
  if (stationOrigin && originCities.length <= 1) { set('origin', stationOrigin); clear('originCandidateId'); }
  // API-BB-7 (block O dev "我住Richmond District，週日附近圖書館…"): a nearby ask from home with no other destination is
  // about the home city.
  if (carry && !state.city && !destination.city && originCities.length === 1 && !excluded.includes(originCities[0]) && NEARBY_HOME.test(text)) {
    try { const home = inferDestination(`在 ${originCities[0]}`, destinationCatalog); if (home.city) { set('city', canonicalCity(home.city)); set('region', home.region || null); } } catch { /* an unknown home city stays the origin only */ }
  }
  if (originCities.length === 1 && explicitOrigin && canonicalCity(explicitOrigin.row.city) !== originCities[0]) clarification = '请确认这次从哪个地点出发。';
  if (originCities.length > 1) clarification = '请确认这次从哪个地点出发。';
  const airportOrigin = normalized.match(/(?:从|從|\bfrom|\bleaving|\bdeparting)\s*(SFO|OAK|SJC|San Francisco International Airport|Oakland International Airport|San Jose International Airport)(?=\b|\s|出发|出發|到|去)/i);
  if (airportOrigin) { set('origin', airportOrigin[1].toUpperCase().replace('SAN FRANCISCO INTERNATIONAL AIRPORT', 'SFO').replace('OAKLAND INTERNATIONAL AIRPORT', 'OAK').replace('SAN JOSE INTERNATIONAL AIRPORT', 'SJC')); clear('originCandidateId'); }
  try {
    // Several interests are useful for a day plan, not a reason to discard all
    // other explicit constraints. selectedTopic prevents the legacy one-topic gate.
    let analysisMessage = destination.analysisMessage || normalized;
    for (const city of excluded) analysisMessage = analysisMessage.replace(new RegExp(city.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), ' ');
    const regularWeekday = /平常|通常|一般|常规|常規|每(?:周|週|星期)|\b(?:usually|normally|regular|every (?:mon|tue|wed|thu|fri|sat|sun))\b/i.test(text)
      && !/今天|明天|后天|後天|下周|下週|下星期|\b(?:today|tomorrow|next)\b|\d{1,2}(?:月|\/|-)\d{1,2}/i.test(text);
    if (regularWeekday) analysisMessage = analysisMessage.replace(/(?:周|週|星期)[日天一二三四五六]|\b(?:sun(?:day)?s?|mon(?:day)?s?|tue(?:sday)?s?|wed(?:nesday)?s?|thu(?:rsday)?s?|fri(?:day)?s?|sat(?:urday)?s?)\b/gi, ' ');
    // "Does Nov 11 run on the Sunday schedule?" names one travel date and a
    // timetable type, not two alternative travel dates.
    if (informational || state.goal === 'transit') analysisMessage = analysisMessage
      .replace(/((?:按(?:照)?|依照|采用|採用)\s*)(?:周|週|星期)[日天一二三四五六](?=\s*(?:的)?(?:跑|班表|时刻表|時刻表|时间表|時間表|运行|運行|行驶|行駛|发车|發車|服务|服務))/g, '$1 ')
      .replace(/(\b(?:use|follow|run on|operate on)\s+(?:(?:a|the)\s+)?)(?:sun(?:day)?|mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?)(?=\s+(?:schedule|timetable|service)\b)/gi, '$1 ');
    // API-BB-5: a two-day, weekend-of, Nth-weekend or month ask is one span (state.dateRange below), not
    // several dates to choose from ("11月21日、22日" asked "pick one day") or this weekend ("12月第一个周末").
    // A day plan still picks one day of a two-day span.
    // The span's own 周末 / weekend is part of it, not a second date (this Saturday).
    if (spanText) analysisMessage = blankText(analysisMessage, spanText)
      .replace(/周末|週末|\bweekends?\b/gi, match => ' '.repeat(match.length));
    // Review (API-BB-5 round 1, v2 only): "有没有室内的" asks for indoor; the planner read 没有 as "not indoor" and set outdoor.
    // Review round 2: "(有没有)不是室内的 / 非室内的" asks for the outdoor ones (the planner read 室内 alone).
    // Review round 4: not the question "是不是室内的" (is it indoor?) or "除非室内" (unless indoor).
    if (carry) analysisMessage = analysisMessage.replace(/(?:(?<!是)不是|并非|並非|(?<!除)非)\s*(?:室内|室內)/g, match => `${' '.repeat(match.length - 2)}户外`)
      .replace(/有(?:没|沒)有(?=\s*(?:什么|什麼|好的|好玩的)?\s*(?:的)?\s*(?:室内|室內|户外|戶外))/g, match => `有${' '.repeat(match.length - 1)}`);
    const almost = carry ? almostAges(text) : { spans: [], ages: [] };
    const inferred = inferFilters(withoutTravelModeComparisons(withoutRejectedChildAges(withoutNegatedBudget(withoutPermittedOverages(carry ? withoutNamedWeekdays(withoutAlmostAges(analysisMessage, almost.spans), text) : analysisMessage)))), today, { selectedTopic: 'any', allowMultipleDates: informational });
    if (informational && inferred.date === null) {
      informationAlternatives = true;
    }
    const changedDay = text.match(/(?:改(?:成|到|为|為)|换(?:成|到)|換(?:成|到)|就(?:选|選|定))\s*(\d{1,2})\s*(?:号|號|日)(?!期)/);
    if (!Object.hasOwn(inferred, 'date') && changedDay && affirmativeGoal(text, new RegExp(changedDay[0]))) {
      const month = previousState?.dateContextMonth || previousState?.date?.slice(0, 7);
      if (month) {
        const date = `${month}-${changedDay[1].padStart(2, '0')}`;
        if (validDate(date)) inferred.date = date;
        else { clear('date'); clarification ||= '这个月份没有所说的日期，请确认几月几日。'; }
      }
    }
    const explicitFreeFilter = /(?:只看|只要|仅限|僅限|仅看|僅看|只找|限定).{0,6}(?:免费|免費)|(?:不要|不想要|排除)(?:收费|收費|付费|付費)|\b(?:free[- ]only|only (?:show |find |want )?free)\b/i.test(text);
    if (explicitFreeFilter) { inferred.freeOnly = true; if (inferred.budget === undefined) inferred.budget = 0; }
    const lookingForOptions = /找|推荐|推薦|安排|去哪|哪里|哪裡|有什么|有什麼|有哪些|(?:免费|免費)(?:活动|活動|景点|景點|去处|去處)|\b(?:find|recommend|plan|looking for|where|what|anything|something|free (?:events?|activities|places?|options?))\b/i.test(text);
    const shortFreeFollowup = text.length <= 35 && /^(?:免费|免費|free)(?:的|就好|only| options?)?[？?。.!\s]*$/i.test(text.trim());
    const freeRuleQuestion = /(?:免费|免費).{0,30}(?:公共空间|公共空間|区域|區域|规则|規則|限制|资格|資格)|\bfree (?:public (?:spaces?|areas?)|admission (?:rules?|eligibility|conditions?))/i.test(text)
      || /(?:不要|别|別|不能|不应|不應)(?:直接|自动|自動)?(?:假设|假設|认定|認定|以为|以為|当作|當作)[^，,。.!！？?；;\n]{0,35}(?:免费|免費)|(?:不保证|不保證|未确认|未確認|没有确认|沒有確認)[^，,。.!！？?；;\n]{0,12}(?:免费|免費)|\b(?:do not|don['’]t|never) (?:assume|treat)\b[^,.!?;\n]{0,55}\bfree\b|\b(?:not guaranteed|unconfirmed)\b[^,.!?;\n]{0,25}\bfree\b/i.test(text);
    const freeFilterIntent = explicitFreeFilter || (!freeRuleQuestion && ['day-plan', 'discover', 'shopping'].includes(state.goal) && (lookingForOptions || shortFreeFollowup));
    const suppressImplicitFree = inferred.freeOnly === true && !freeFilterIntent;
    for (const key of ['date', 'budget', 'budgetScope', 'partySize', 'freeOnly', 'setting', 'travelMode', 'topic']) if (inferred[key] !== undefined) {
      if (key === 'date' && inferred.date === null) {
        clear('date');
        if (inferred.dateContextMonth) state.dateContextMonth = inferred.dateContextMonth;
        continue;
      }
      if (factualBudget && ['budget', 'budgetScope'].includes(key)) continue;
      // Asking whether a venue has free public areas is a fact question, not a
      // new $0 budget that should remove the paid venue from the evidence set.
      if (suppressImplicitFree && (key === 'freeOnly' || (key === 'budget' && inferred.budget === 0 && !/预算|預算|\bbudget\b/i.test(text)))) continue;
      set(key, inferred[key]);
    }
    const ages = inferred.childAges || (inferred.childAge !== undefined && inferred.childAge !== null ? [inferred.childAge] : null) || (almost.ages.length ? almost.ages : null);
    if (ages && !(carry && keepsHousehold(previousState?.childAges, ages, text))) set('childAges', ages);
    if (!state.city && inferred.region && !CITY_CLEAR.test(text) && !comparingLibraries && !libraryReference) set('region', inferred.region);
    else if (state.city && !state.region && inferred.region && !libraryReference) set('region', inferred.region);
    const county = !state.city && !inferred.region && ['discover', 'day-plan'].includes(state.goal) && !CITY_CLEAR.test(text) ? countyRegion(text) : null;
    if (county) set('region', county);
  } catch (error) {
    if (clarification === '请先选择一个目的城市，再生成方案。') clarification = error.message;
    else clarification ||= error.message;
  }
  if (DATE_CLEAR.test(text)) { clear('date'); if (['day-plan', 'discover'].includes(state.goal)) clarification = '日期限制已清除；安排具体行程前，请选定一天。'; }
  const broadWeekend = /周末|週末|\bweekend\b/i.test(text)
    && !/(?:周|週|星期)[六日天]|\b(?:saturday|sunday)\b|\d{1,4}\s*(?:年|月|\/|-)/i.test(text);
  if (broadWeekend) {
    if (!previousState?.date) clear('date');
    else if (/(?:改|换|換).{0,5}(?:周末|週末)|\b(?:change|move|switch).{0,20}\bweekend\b/i.test(text)) { clear('date'); clarification ||= '周末包含两天，请确认具体哪一天；其他条件保留。'; }
    else set('date', previousState.date);
  }
  // A comparison's city names are subjects. Do not let legacy region inference
  // silently filter the evidence to whichever city appeared first.
  if (informationCities) { clear('city'); set('region', 'all'); }
  const correctedWeekday = text.match(/(?:我(?:说的|說的|指的)?是|改(?:成|到)?|换成|換成)\s*(?:周|週|星期)([日天一二三四五六])(?=[，,。.!！？?；;\n\s]|$)/);
  if (previousState?.date && correctedWeekday && !/这周|這周|本周|本週|下周|下週|下星期|\d{1,4}\s*(?:年|月|\/|-)/.test(text)) {
    const desiredDay = '日一二三四五六'.indexOf(correctedWeekday[1].replace('天', '日'));
    if (new Date(`${previousState.date}T12:00:00Z`).getUTCDay() === desiredDay) set('date', previousState.date);
    else { clear('date'); clarification ||= `你之前选的是 ${previousState.date}；请确认这次所说的周${correctedWeekday[1]}是几月几日。`; }
  }
  if (BUDGET_CLEAR.test(text)) clear('budget');
  if (allowsPaidAdmission(text)) { set('freeOnly', false); if (state.budget === 0) clear('budget'); }
  if (/不限免费|不限免費|\b(?:not limited to free|clear free-only|any admission price)\b/i.test(text)) { set('freeOnly', false); if (state.budget === 0) clear('budget'); }
  const clearCommands = [
    ['origin', /清除出发地|清除出發地|\bclear (?:the )?(?:origin|starting point)\b/i],
    ['partySize', /清除同行人数|清除同行人數|\bclear (?:the )?(?:party size|number of people)\b/i],
    ['childAges', /清除孩子年龄|清除孩子年齡|\bclear (?:the )?(?:child(?:ren['’]s)? ages|kids['’] ages)\b/i],
    ['travelMode', /出行方式不限|\b(?:any travel mode|clear (?:the )?travel mode)\b/i],
    ['setting', /室内外不限|室內外不限|\b(?:any setting|clear (?:the )?setting)\b/i],
    ['startTime', /清除开始时间|清除開始時間|\bclear (?:the )?start time\b/i],
    ['finishBy', /清除结束时间|清除結束時間|\bclear (?:the )?(?:finish|end|return) time\b/i],
    ['maxStops', /站数不限|站數不限|不限站数|不限站數|清除站数限制|清除站數限制|\b(?:no stop limit|clear (?:the )?(?:stop limit|max stops))\b/i],
    ['returnToOrigin', /清除返回要求|\bclear (?:the )?return requirement\b/i],
    ['excludedCities', /清除排除城市|\bclear (?:the )?excluded cities\b/i],
  ];
  for (const [field, pattern] of clearCommands) if (pattern.test(text)) {
    clear(field);
    if (field === 'origin') clear('originCandidateId');
    if (field === 'excludedCities') state[field] = [];
    if (field === 'travelMode') state.preferences = state.preferences.filter(value => value !== 'no-car');
  }
  const partyPatch = text.match(/(?:同行总人数|同行總人數|party size|number of people)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(\d{1,3})/i);
  if (partyPatch) set('partySize', Number(partyPatch[1]));
  const agePatch = text.match(/(?:孩子年龄|孩子年齡|child ages|children['’]s ages)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(\d{1,2}(?:\s*(?:、|,|和|及|and|&)\s*\d{1,2})*)/i);
  if (agePatch) set('childAges', agePatch[1].match(/\d+/g).map(Number));
  const budgetPatch = budgetText.match(/(?:(每人|总|總|per person|total)\s*)?(?:预算|預算|budget)\s*(?:改为|改為|设为|設為|降到|降为|降為|提高到|增加到|change(?:d)? to|set to|reduce(?:d)? to|is|:|：)\s*(?:\$|USD\s*)?(\d+(?:\.\d{1,2})?)/i);
  // API-BB-7 (block N held-out N-36-2; block O dev "预算改成0了", "no money for tickets now"): an admission budget changed
  // to zero is a free-only ask, on any goal (the household's outing carries on in the next turn).
  if (carry && ZERO_BUDGET.test(budgetText)) { set('budget', 0); set('freeOnly', true); }
  if (budgetPatch) { set('budget', Number(budgetPatch[2])); if (budgetPatch[1]) set('budgetScope', /每人|per person/i.test(budgetPatch[1]) ? 'person' : 'total'); }
  const totalBudgetPatch = budgetText.match(/(?:预算|預算|budget)\s*(?:总共|總共|合计|合計|一共|total(?: of)?)\s*(?:\$|USD\s*)?(\d+(?:\.\d{1,2})?)/i);
  if (totalBudgetPatch && !/(?:每人|每位|人均|per person)\s*$/i.test(budgetText.slice(0, totalBudgetPatch.index))) { set('budget', Number(totalBudgetPatch[1])); set('budgetScope', 'total'); }
  if (totalLimit !== null) { set('budget', totalLimit); set('budgetScope', 'total'); }
  const modePatch = text.match(/(?:出行方式|travel mode)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(drive|transit|walk|any)\b/i);
  if (modePatch) set('travelMode', modePatch[1].toLowerCase());
  const settingPatch = text.match(/(?:场景|場景|setting)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(indoor|outdoor|mixed|any)\b/i);
  if (settingPatch) set('setting', settingPatch[1].toLowerCase());
  if (NO_KIDS.test(text)) { clear('childAges'); delete state.family; cleared.add('family'); }
  // API-BB-7 (live 10-16, L09 "San Jose 室内亲子"): 亲子 / 带娃 / 孩子 / 小朋友 / with kids / family is the family signal,
  // so a 亲子 ask with no age is still a family ask and its follow-up (那周日呢) keeps it.
  else if (state.childAges.length || FAMILY_SIGNAL.test(text.replace(FAMILY_NOT_KIDS, ' '))) { state.family = true; cleared.delete('family'); }
  if (/时间不限|時間不限|\bno time constraints?\b/i.test(text)) { clear('startTime'); clear('finishBy'); }
  const parsedTimes = timesIn(text, { afternoon: carry });
  Object.entries(parsedTimes).forEach(([key, value]) => set(key, value));
  const changedPeriod = text.match(/(?:改(?:成|到|为|為|在)?|换到|換到|那就)\s*(上午|下午|晚上)(?=[吧啊呀，,。.!！？?；;\n\s]|$)/);
  if (changedPeriod && previousState?.goal === 'day-plan' && !parsedTimes.startTime) {
    const hour = state.startTime ? Number(state.startTime.slice(0, 2)) : null;
    const compatible = hour !== null && (changedPeriod[1] === '上午' ? hour < 12 : changedPeriod[1] === '下午' ? hour >= 12 && hour < 18 : hour >= 18);
    if (!compatible) { clear('startTime'); clarification ||= `已改为${changedPeriod[1]}，请补充具体几点出发；其他已确认条件保留。`; }
  }
  const returnIntent = returnToOriginIn(text);
  if (returnIntent !== undefined) set('returnToOrigin', returnIntent);
  for (const [key, label] of [['startTime', '开始时间|開始時間|start time'], ['finishBy', '最晚结束时间|最晚結束時間|finish by|end time|return time']]) {
    const match = text.match(new RegExp(`(?:${label})\\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\\s*((?:[01]?\\d|2[0-3]):[0-5]\\d)`, 'i'));
    if (match && userTimeContext(text, match.index + match[0].lastIndexOf(match[1]), match[1].length).allowed) set(key, match[1].padStart(5, '0'));
  }
  const newPreferences = preferencePhrases(text);
  if (newPreferences.some(value => value.startsWith('outing-duration:')) || /时间不限|時間不限|\bno time constraints?\b/i.test(text)) state.preferences = state.preferences.filter(value => !value.startsWith('outing-duration:'));
  state.preferences = list([...state.preferences, ...newPreferences]);
  if (carry) {
    // "开车还是坐 Caltrain 更方便？" compares two modes; it chooses neither.
    const comparesModes = /还是|還是|或者|\bor\b|\bvs\.?|比较|比較/i.test(text) && /开车|開車|驾车|駕車|\bdriv(?:e|ing)\b/i.test(text) && new RegExp(TRANSIT_WORDS, 'i').test(text);
    if (comparesModes && !modePatch) state.travelMode = previousState?.travelMode ?? null;
    else if (!modePatch && TRANSIT_RIDE.test(withoutTravelModeComparisons(text))) set('travelMode', 'transit');
    const perPerson = !budgetPatch && totalLimit === null && !factualBudget ? budgetText.match(PER_PERSON_BUDGET) : null;
    if (perPerson) { set('budget', Number(perPerson[1] || perPerson[2])); set('budgetScope', 'person'); }
    if (['discover', 'day-plan'].includes(state.goal) && FREE_FOLLOWUP.test(text) && !allowsPaidAdmission(text)) set('freeOnly', true);
    const slot = timeOfDay(text);
    if (slot) state.preferences = list([...state.preferences.filter(value => !value.startsWith('time-of-day:')), `time-of-day:${slot}`]);
    // API-BB-5: the rail system the party rides (坐 BART 去) is kept, so places it cannot reach rank behind
    // the ones it can (baybayTransit.railFit); another travel mode clears it.
    const rail = railSystemsIn(withoutTravelModeComparisons(text));
    if (rail.length && state.travelMode === 'transit') state.preferences = list([...state.preferences.filter(value => !value.startsWith('rail:')), ...rail.map(system => `rail:${system}`)]);
  }
  if (/可以开车|可以開車|改成开车|改成開車|那就开车|那就開車|\b(?:we can drive|I can drive|let's drive|will drive)\b/i.test(withoutTravelModeComparisons(text))) state.preferences = state.preferences.filter(value => value !== 'no-car');
  if (state.preferences.includes('no-car') && state.travelMode === 'drive') clear('travelMode');
  if (state.travelMode !== 'transit') state.preferences = state.preferences.filter(value => !value.startsWith('rail:'));
  const desired = matchDesiredCandidates(text, normalizeCatalog(catalog), state);
  if (desired?.ids) {
    state.selectedCandidateIds = desired.ids;
    state.excludedCandidateIds = state.excludedCandidateIds.filter(id => !desired.ids.includes(id.replace(/^(?:event|place):/, '')));
    const selectedVenues = desired.ids.map(id => [...destinationCatalog.places, ...destinationCatalog.events].find(row => row.id === id));
    if (unique(selectedVenues.map(venue => canonicalCity(venue?.city)).filter(Boolean)).length > 1) clarification ||= '请先选择一个目的城市，再生成方案。';
    // A single exact published destination can establish its own city even
    // when the user omitted the optional space in a numbered venue name.
    // Never use the origin, replace an explicit city, or bypass ambiguity.
    if (!state.city && !clarification && !CITY_CLEAR.test(text) && desired.ids.length === 1) {
      const venue = selectedVenues[0];
      const city = canonicalCity(venue?.city);
      if (city && !state.excludedCities.includes(city)) { set('city', city); set('region', venue.region || null); }
    }
  }
  if (desired?.clarification) clarification ||= desired.clarification;
  if (clarification === '请先选择一个目的城市，再生成方案。' && desired?.ids?.length > 1
    && /(?:跨城|跨市).{0,20}(?:是否|能否|现实|現實|可行)|(?:是否|能否).{0,20}(?:跨城|跨市)|\b(?:feasib(?:le|ility)|realistic|possible)\b.{0,60}\b(?:across|between|both|cities)\b|\b(?:cross[- ]city|across cities|between cities)\b.{0,60}\b(?:feasib(?:le|ility)|realistic|possible)\b/i.test(text)) {
    const selectedCities = unique(desired.ids.map(id => canonicalCity([...destinationCatalog.places, ...destinationCatalog.events].find(row => row.id === id)?.city)).filter(Boolean));
    const namedDestinations = mentionedCities(normalized).filter(city => !originCities.includes(city) && !excluded.includes(city));
    // Both exact venues are desired, not city alternatives. Let the assistant
    // evaluate feasibility; the plan engine still requires verified route legs.
    if (selectedCities.length > 1 && namedDestinations.every(city => selectedCities.includes(city))) {
      clear('city'); set('region', 'all'); clarification = undefined;
    }
  }
  if (state.goal) {
    // Service and factual questions have the same geographic boundary as trips.
    // Use the normalized residence markers above so an outside origin does not
    // veto an explicitly requested Bay Area destination.
    const outsideText = cityContext(text).replace(/Shanghai Dumpling(?:s| King| Shop)?|New York[- ]style|Jack London Square/gi, match => ' '.repeat(match.length));
    const outside = outsideText.matchAll(/上海|北京|深圳|广州|廣州|香港|澳门|澳門|纽约|紐約|洛杉矶|洛杉磯|西雅图|西雅圖|台北|臺北|东京|東京|\b(?:Shanghai|Beijing|Shenzhen|Guangzhou|Hong Kong|Macau|Macao|New York|Los Angeles|LA|Seattle|Taipei|Tokyo|Sacramento|San Diego)\b/gi);
    for (const match of outside) {
      if (match[0].toLowerCase() === 'la' && match[0] !== 'LA') continue;
      const prefix = outsideText.slice(Math.max(0, match.index - 60), match.index);
      if (/(?:从|從|住在|居住在|家在|不要|不去|不问|不問|不查|别查|別查|不考虑|不考慮|避开|避開|不是|\bfrom|\bleaving|\blive in|\bliving in|\bbased in|\bnot (?:in|about)|\b(?:do not|don['’]t) mean|\boutside(?: of)?|\bexcept|\binstead of)\s*$/i.test(prefix)) continue;
      if (!destination.city || /(?:改去|换成|換成|前往|到|去|\bto|\bin|\bat)\s*$/i.test(prefix)) {
        clear('city'); clear('region'); clarification = 'BayBay 当前提供旧金山湾区的本地资料与行程。请确认一个湾区城市，或说明这次是在查询湾区以外的资料。';
        break;
      }
    }
  }
  state.clearedFields = [...cleared];
  // API-BB-5: after an ask about a span ("12月第一个周末", "11月21日、22日"), a follow-up that names only a weekday
  // ("帮我排成周六半天", "那周日呢") means that weekday inside the span, not this week's.
  // Review round 2: also after the span was narrowed to one future day ("What about Saturday?" → 12/05), the same
  // weekday named again ("Can you plan Saturday for us?") is that day, not this week's.
  // Review round 4: a carried day after this week stands for the days of its week (never before
  // today), so the other day of that weekend ("What about Sunday?" after 12/05, "那周日呢") is 12/06, not 10/18.
  // Review round 5: its Monday-to-Sunday week, so 周日 after a Monday (12/07) is 12/13, not the 12/06 before it.
  const dayShift = (day, days) => new Date(Date.parse(`${day}T12:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
  const carriedDay = validDate(previousState?.date) && previousState.date > today ? previousState.date : null;
  const nextMonday = dayShift(today, 7 - ((new Date(`${today}T12:00:00Z`).getUTCDay() + 6) % 7));
  const carriedWeekday = carriedDay ? (new Date(`${carriedDay}T12:00:00Z`).getUTCDay() + 6) % 7 : 0;
  const carriedSpan = previousState?.dateRange
    || (carriedDay && carriedDay >= nextMonday ? { start: [dayShift(carriedDay, -carriedWeekday), today].sort().at(-1), end: dayShift(carriedDay, 6 - carriedWeekday) }
      : carriedDay ? { start: carriedDay, end: carriedDay } : null);
  if (carry && carriedSpan && state.date && !askedSpan) {
    // Every English weekday spelling (Saturday, Tues, Thurs …), not only Sun/Mon/Fri + "day" (review round 1).
    const bare = text.match(/(?:周|週|星期|礼拜|禮拜)([六日天一二三四五])|\b(sun(?:day)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:r(?:s(?:day)?)?)?|fri(?:day)?|sat(?:urday)?)\b/i);
    const qualified = /(?:这|這|本|(?<!一)下|(?<![晚早])上)\s*(?:个|個)?\s*(?:周|週|星期|礼拜|禮拜)|今天|明天|后天|後天|\d{1,2}\s*(?:月|\/|-)\s*\d|\b(?:this|next|last|today|tomorrow|tonight)\b/i.test(text);
    if (bare && !qualified) {
      const weekday = bare[1] ? (['日', '天'].includes(bare[1]) ? 0 : '日一二三四五六'.indexOf(bare[1])) : ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].indexOf(bare[2].slice(0, 3).toLowerCase());
      // Review round 6: in English a weekday (Monday-Friday) after a carried day is the first one on or after it
      // ("What about Monday?" after Sat 12/05 is 12/07, not 11/30); Saturday and Sunday keep the carried day's weekend,
      // and Chinese keeps its Monday-to-Sunday week (周一呢 after 12月5号 is that week's Monday, 11/30).
      const span = bare[2] && weekday >= 1 && weekday <= 5 && !previousState?.dateRange && carriedDay && carriedDay >= nextMonday
        ? { start: carriedDay, end: dayShift(carriedDay, 6) } : carriedSpan;
      for (let day = span.start, guard = 0; day <= span.end && guard < 32; day = new Date(Date.parse(`${day}T12:00:00Z`) + 86400000).toISOString().slice(0, 10), guard++) {
        if (new Date(`${day}T12:00:00Z`).getUTCDay() === weekday) { set('date', day); break; }
      }
    }
  }
  // Review round 5: an explicit weekend or span of days that does not hold the carried day ("这周末呢" / "What about
  // this weekend?" after 12月5号) replaces it; a span that holds it ("这周末还有别的吗" after 周六) keeps the day.
  // Review round 6: days the user lists themselves ("12月5、6号两天都行", "Dec 5 or 6 both work") replace the carried day
  // even when they hold it.
  if (carry && askedSpan && ['weekend', 'weekend-of', 'nth-weekend', 'holiday-weekend', 'days'].includes(askedSpan.kind) && !(askedSpan.kind === 'days' && state.goal === 'day-plan')
    && validDate(state.date) && state.date === previousState?.date
    && (state.date < askedSpan.start || state.date > askedSpan.end || (askedSpan.kind === 'days' && askedSpan.start < askedSpan.end))) {
    state.date = null;
    delete state.dateContextMonth;
  }
  const bareWeekend = carry && !askedSpan && broadWeekend && !previousState?.date && !previousState?.dateRange && ['discover', 'day-plan'].includes(state.goal) && !REGULAR_WEEKEND.test(text) && !HOLIDAY_WEEKEND.test(text);
  const requestedRange = !carry ? dateRangeFor(text, today)
    : askedSpan && !(askedSpan.kind === 'days' && state.goal === 'day-plan') ? { start: askedSpan.start, end: askedSpan.end }
      : bareWeekend ? dateRangeFor('这周末', today) : null;
  if (requestedRange && !state.date) state.dateRange = requestedRange;
  else if (state.date || DATE_CLEAR.test(text)) delete state.dateRange;
  if (carry && askedSpan && state.dateRange && state.dateRange.end < today && ['day-plan', 'discover'].includes(state.goal)) clarification ||= '这段日期已经过去；请确认是查询历史活动，还是改选未来日期。';
  if (state.date && state.date < today && ['day-plan', 'discover'].includes(state.goal)) clarification ||= '这个日期已经过去；请确认是查询历史活动，还是改选未来日期。';
  if (state.startTime && state.finishBy && state.finishBy <= state.startTime) clarification ||= '返回时间不晚于出发时间；请确认是否跨夜，或修改其中一个时间。';
  return { state: validateTaskState(state), planningPaused: pausesPlanRequest(text), ...(informationAlternatives ? { informationAlternatives: true } : {}), ...(clarification ? { clarification } : {}), ...(desired?.ids ? { explicitCandidateIds: [...desired.ids] } : {}) };
}

/** A model patch is an extraction proposal, not permission to invent settings.
 * Only values re-derived from this message can replace validated task fields. */
function applyTaskStatePatch({ state, patch, message, today, catalog } = {}) {
  const result = validateTaskState(state);
  if (!plain(patch)) return result;
  const extracted = resolveTaskState({ message, today, catalog }).state;
  for (const field of FIELDS) {
    if (!(field in patch) || field === 'goal') continue;
    const proposed = validateTaskState({ [field]: patch[field] })[field];
    if (proposed !== null && JSON.stringify(proposed) === JSON.stringify(extracted[field]) && (!Array.isArray(proposed) || proposed.length)) { result[field] = proposed; result.clearedFields = result.clearedFields.filter(key => key !== field); }
    if (patch[field] === null && extracted.clearedFields.includes(field)) { result[field] = extracted[field]; result.clearedFields = unique([...result.clearedFields, field]); }
  }
  return validateTaskState(result);
}

function planRefs(value) {
  if (!plain(value)) return null;
  const selectedIds = ids(value.selectedIds);
  const refs = new Map();
  for (const ref of Array.isArray(value.selectedRefs) ? value.selectedRefs.slice(0, 24) : []) {
    if (!plain(ref) || !selectedIds.includes(ref.id) || refs.has(ref.id)) continue;
    const id = ids([ref.id])[0], title = clean(ref.title, 160), city = canonicalCity(ref.city);
    const sourceUrl = typeof ref.sourceUrl === 'string' && ref.sourceUrl.length <= 1024 ? safeUrl(ref.sourceUrl) : null;
    if (!id || !title || !city || !sourceUrl || !['event', 'place'].includes(ref.previousKind)) continue;
    // These are identity hints for a fresh read, never evidence of today's
    // admission, type, schedule, opening status, coordinates or availability.
    refs.set(id, { id, title, city, sourceUrl, previousKind: ref.previousKind });
  }
  const selectedRefs = selectedIds.flatMap(id => refs.has(id) ? [refs.get(id)] : []).slice(0, 6);
  return {
    candidateIds: ids(value.candidateIds), selectedIds,
    ...(selectedRefs.length ? { selectedRefs } : {}),
    ...(clean(value.title, 160) ? { title: clean(value.title, 160) } : {}),
    ...(validDate(value.date) ? { date: value.date } : {}),
  };
}
const validTaskSecret = value => typeof value === 'string' && value.length >= 16;
// Keep task-memory signing separate from account authentication. An older
// deployment can retain its existing sufficiently long JWT key as a fallback.
const resolveTaskSecret = (config = process.env) => [config?.BAYBAY_STATE_SECRET, config?.JWT_SECRET].find(validTaskSecret) || null;
const secretOf = options => Object.prototype.hasOwnProperty.call(options || {}, 'secret') ? options.secret : resolveTaskSecret();
const nowSeconds = options => Math.floor((typeof options?.now === 'function' ? options.now() : options?.now ?? Date.now()) / 1000);

/** A short-lived, purpose-bound HMAC token is stateless and contains no account
 * credentials. Missing signing configuration disables persistence, not checks. */
function encodeTaskToken(payload, options = {}) {
  const secret = secretOf(options);
  if (!validTaskSecret(secret)) return null;
  const issuedAt = nowSeconds(options);
  const body = Buffer.from(JSON.stringify({ v: VERSION, purpose: 'baybay-task', iat: issuedAt, exp: issuedAt + TOKEN_TTL, state: validateTaskState(payload?.state || payload), lastPlan: planRefs(payload?.lastPlan) })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  const token = `${body}.${signature}`;
  return token.length <= TOKEN_LIMIT ? token : null;
}

function decodeTaskToken(token, options = {}) {
  const secret = secretOf(options);
  if (typeof token !== 'string' || token.length > TOKEN_LIMIT || !validTaskSecret(secret) || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)) return null;
  try {
    const [body, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', secret).update(body).digest();
    const actual = Buffer.from(signature, 'base64url');
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    const now = nowSeconds(options);
    if (!plain(parsed) || parsed.v !== VERSION || parsed.purpose !== 'baybay-task' || !Number.isInteger(parsed.iat) || !Number.isInteger(parsed.exp)
      || parsed.iat > now + 60 || parsed.exp <= now || parsed.exp - parsed.iat !== TOKEN_TTL || !plain(parsed.state)) return null;
    return { state: validateTaskState(parsed.state), lastPlan: planRefs(parsed.lastPlan), issuedAt: parsed.iat, expiresAt: parsed.exp };
  } catch { return null; }
}

module.exports = { VERSION, TOKEN_TTL, TOKEN_LIMIT, validateTaskState, resolveTaskState, applyTaskStatePatch, resolveTaskSecret, encodeTaskToken, decodeTaskToken, pausesPlanRequest, namesNeighbourhood };
