const crypto = require('node:crypto');
const { inferFilters, inferDestination, allowsPaidAdmission, validDate, REGIONS } = require('./planner');
const { canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate } = require('./bayAreaSearchScope');
const { safeUrl } = require('./plannerWebSearch');

const VERSION = 1;
const TOKEN_TTL = 24 * 60 * 60;
const TOKEN_LIMIT = 16384;
const GOALS = ['day-plan', 'discover', 'transit', 'newcomer', 'shopping', 'information'];
const MODES = ['any', 'drive', 'transit', 'walk'];
const TOPICS = ['any', 'comedy', 'music', 'sports', 'arts', 'food', 'community', 'technology'];
const FIELDS = ['goal', 'city', 'region', 'date', 'origin', 'originCandidateId', 'travelMode', 'partySize', 'childAges', 'budget', 'budgetScope', 'freeOnly', 'setting', 'startTime', 'finishBy', 'topic', 'preferences', 'excludedCities'];
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const clean = (value, max = 160) => typeof value === 'string' && value.trim().length <= max && !/[\u0000-\u001f\u007f]/.test(value) ? value.trim() : null;
const unique = values => [...new Set(values)];
const ids = value => Array.isArray(value) ? unique(value.filter(item => typeof item === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_:-]{0,159}$/.test(item))).slice(0, 24) : [];
const time = value => typeof value === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value) ? value : null;
const list = value => Array.isArray(value) ? unique(value.map(item => clean(item, 120)).filter(Boolean)).slice(0, 12) : [];
const CITY_CLEAR = /不(?:限|限定|限制)(?:定)?(?:城市|地区|地區)|(?:城市|地区|地區)(?:不限|随便|隨便|都可以)|全湾区|全灣區|整个湾区|整個灣區|\b(?:any city|no city preference|anywhere (?:in |across )?(?:the )?bay area|(?:whole|entire) bay area)\b/i;
const DATE_CLEAR = /日期不限|不(?:限|限定|限制)日期|哪天都可以|什么日期都可以|什麼日期都可以|\b(?:any day|any date|no date preference|clear (?:the )?date)\b/i;
const BUDGET_CLEAR = /预算不限|預算不限|不限预算|不限預算|\b(?:no budget limit|unlimited budget|clear (?:the )?budget)\b/i;

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
    topic: TOPICS.includes(value.topic) ? value.topic : null,
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
  const matches = [];
  for (const row of [...catalog.events, ...catalog.places]) {
    if (!preciseLocation(row.location)) continue;
    for (const alias of unique([row.title, row.venue, row.location.label].map(value => clean(value, 300)).filter(Boolean))) {
      // A city-only row label is not proof of a specific departure point.
      if (canonicalCity(alias) || alias.length < 3) continue;
      const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const match of message.matchAll(new RegExp(escaped, 'giu'))) {
        const prefix = message.slice(Math.max(0, match.index - 55), match.index);
        const suffix = message.slice(match.index + match[0].length);
        if (!/(?:从|從|\bfrom|\bleaving|\bdeparting(?: from)?)\s*$/i.test(prefix)) continue;
        if (/(?:不要|不想|别|別|\bnot|\bdon['’]t|\bdo not)\s*(?:从|從|from|leaving|departing(?: from)?)\s*$/i.test(prefix)) continue;
        if (/^[a-z0-9]/i.test(suffix) && /[a-z0-9]$/i.test(alias)) continue;
        matches.push({ row, start: match.index, end: match.index + match[0].length, length: match[0].length });
      }
    }
  }
  const longest = matches.filter(match => !matches.some(other => other.start <= match.start && other.end >= match.end && other.length > match.length));
  const rows = [...new Map(longest.map(match => [match.row, match])).values()];
  return rows.length === 1 ? rows[0] : null;
}

function goalOf(message) {
  if (/安排.{0,16}(?:一天|一日|行程)|一天.{0,16}(?:安排|怎么玩|怎麼玩)|一日游|一日遊|\b(?:plan (?:my |our |a |the )?(?:day|itinerary)|day plan|day trip|itinerary)\b/i.test(message)) return 'day-plan';
  const arranging = /安排|规划|規劃|\b(?:plan|arrange|schedule)\b/i.test(message);
  const calculateTravel = /核算|计算|計算|车程|車程|交通时间|交通時間|\b(?:travel time|driving time|drive times|journey times)\b/i.test(message);
  const returnToStart = /回(?:到)?(?:出发点|出發點|起点|起點|出发地|出發地|家)|返回|\b(?:back|return)(?:ing)?\b/i.test(message);
  const severalVisits = /(?:想去|要去|游览|遊覽|参观|參觀|逛).{0,150}(?:和|及|还有|還有|以及)|\b(?:multiple stops|several stops|visits|visit.{0,100}\band\b)\b/i.test(message);
  // A requested schedule with visits/return constraints is a day plan even if
  // the user never says "one day". A single route/time question stays transit.
  if (arranging && calculateTravel && (returnToStart || severalVisits)) return 'day-plan';
  if (/搬家|新来|新來|开户|開戶|水电|水電|\b(?:newcomer|moving to|move to|utilities|settling in)\b/i.test(message)) return 'newcomer';
  if (/怎么买|怎麼買|买东西|買東西|购物|購物|\b(?:shopping|outlets?|malls?)\b/i.test(message)) return 'shopping';
  if (/(?:怎么|怎麼|如何).{0,15}(?:去|到|转乘|轉乘)|(?:从|從).{0,70}(?:到|去).{0,70}(?:多久|多长时间|多長時間|车程|車程|怎么走|怎麼走)|\b(?:how (?:do|can|to).{0,20}(?:get|travel)|how long.{0,35}(?:drive|travel|get)|directions|transfer|route|travel time|driving time)\b/i.test(message)) return 'transit';
  if (/活动|活動|好去处|好去處|去哪玩|哪里玩|哪裡玩|有什么地方去|有什麼地方去|景点|景點|\b(?:events?|things to do|places to visit|attractions?)\b/i.test(message)) return 'discover';
  return null;
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

function timesIn(message) {
  const result = {};
  const zh = /(早上|上午|中午|下午|晚上|凌晨|傍晚)?\s*([\d零〇一二两兩三四五六七八九十]{1,3})(?:[:：](\d{2})|[点點](?:(\d{1,2})分?|(半))?)(?:钟|鐘)?/g;
  for (const match of message.matchAll(zh)) {
    const before = message.slice(Math.max(0, match.index - 20), match.index);
    const after = message.slice(match.index + match[0].length, match.index + match[0].length + 25).trimStart();
    const value = clockValue(match[2], match[5] ? '30' : match[3] || match[4], match[1]);
    if (!value) continue;
    if (/(?:不是|不要|不用|别|別)\s*$/.test(before)) continue;
    if (/^(?:之)?前.{0,8}(?:回来|回來|回家|回到|回出发点|回出發點|回起点|回起點|返回|返程|结束|結束|到家)|^(?:回来|回來|回家|回到|回出发点|回出發點|回起点|回起點|返回|结束|結束)|(?:最晚|必须|必須).{0,8}$/.test(after) || /(?:最晚|必须|必須|回程|返程).{0,8}$/.test(before)) result.finishBy = value;
    else if (/^(?:再)?(?:开始|開始|出发|出發|开车|開車|驾车|駕車|坐车|坐車|乘车|乘車|搭车|搭車)|(?:从|從|开始|開始|出发|出發)(?:时间|時間)?[：:]?\s*$/.test(after) || /(?:从|從|开始|開始|出发|出發)(?:时间|時間)?[：:]?\s*$/.test(before)) result.startTime = value;
  }
  for (const match of message.matchAll(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b|\b(\d{1,2}):(\d{2})\b/gi)) {
    const before = message.slice(Math.max(0, match.index - 40), match.index);
    const after = message.slice(match.index + match[0].length, match.index + match[0].length + 24);
    const value = clockValue(match[1] || match[4], match[2] || match[5], match[3]);
    if (!value) continue;
    if (/\b(?:not|rather than)\s*$/i.test(before)) continue;
    if (/\b(?:by|before|home at|return at|finish at|back at)\s*$/i.test(before)) result.finishBy = value;
    else if (/\b(?:start(?:ing)?|leave|leaving|depart(?:ing)?|from)(?: at)?\s*$/i.test(before) || /^\s*(?:start|departure|drive|driving|depart|leave)/i.test(after)) result.startTime = value;
  }
  return result;
}

function preferencePhrases(message) {
  const found = [];
  for (const [pattern, label] of [
    [/不开车|不開車|没车|沒車|\b(?:no car|without (?:a )?car|not driving|don't drive|do not drive)\b/i, 'no-car'],
    [/少走路|不想走太多|不想走路|\b(?:less walking|limited walking|avoid long walks)\b/i, 'limited-walking'],
    [/轮椅|輪椅|\bwheelchair\b/i, 'wheelchair-access'],
    [/婴儿车|嬰兒車|\bstroller\b/i, 'stroller-access'],
    [/素食|\bvegetarian\b/i, 'vegetarian'],
    [/带老人|帶老人|\bwith (?:my |our )?(?:elderly parents|seniors)\b/i, 'with-seniors'],
  ]) if (pattern.test(message)) found.push(label);
  return found;
}

/** Merge only explicit user conditions. The caller must pass only a verified
 * token's state as previous; raw client taskState is not an authority. */
function resolveTaskState({ message = '', previous, searchContext = {}, today = bayAreaDate(), catalog, preferences } = {}) {
  const text = typeof message === 'string' ? message.slice(0, 4000) : '';
  const previousState = previous?.state || previous;
  const state = validateTaskState(previousState);
  state.revision += 1;
  const cleared = new Set(state.clearedFields);
  const set = (field, value) => { state[field] = value; cleared.delete(field); };
  const clear = field => { state[field] = field === 'childAges' || field === 'preferences' ? [] : null; cleared.add(field); };
  let clarification;
  if (!validDate(today)) return { state, clarification: '请确认有效的湾区日期后再安排行程。' };
  // UI hints only initialize absent conditions, never resurrect cleared ones.
  for (const key of ['city', 'region', 'date']) if (state[key] === null && !cleared.has(key) && searchContext[key]) {
    const valid = validateTaskState({ [key]: searchContext[key] })[key];
    if (valid !== null) set(key, valid);
  }
  if (!previousState && Array.isArray(preferences)) state.preferences = list(preferences);
  if (!previousState && plain(preferences)) {
    // This object must come from the authenticated server account, not request
    // JSON. Apply saved preferences as defaults before reading the user's turn.
    const defaults = validateTaskState({ travelMode: preferences.travelMode, setting: preferences.setting, budget: preferences.admissionBudgetUsd });
    for (const key of ['travelMode', 'setting', 'budget']) if (state[key] === null && defaults[key] !== null) state[key] = defaults[key];
    const regions = Array.isArray(preferences.regions) ? preferences.regions.filter(region => REGIONS.includes(region)) : [];
    if (!state.city && !state.region && regions.length === 1) state.region = regions[0];
    state.preferences = list(preferences.interests);
  }
  const goal = goalOf(text);
  if (goal && !(state.goal === 'day-plan' && ['discover', 'shopping'].includes(goal))) set('goal', goal);
  if (!state.goal && text.length > 10) set('goal', 'information');

  const originText = text.replace(/出发地(?:点|點)?(?:改为|改為|设为|設為|是|：|:)|出發地(?:點)?(?:改為|設為|是|：|:)|\b(?:origin|starting point)\s*(?:change(?:d)? to|set to|is|:)\s*/gi, 'from ');
  const destinationCatalog = normalizeCatalog(catalog);
  const explicitOrigin = matchOriginCandidate(originText, destinationCatalog);
  // Remove the entire matched venue before destination parsing. Its title can
  // itself include a different city from the intended destination.
  const normalized = normalizeCityMentions(explicitOrigin
    ? originText.slice(0, explicitOrigin.start) + ' '.repeat(explicitOrigin.length) + originText.slice(explicitOrigin.end)
    : originText);
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
    if (!(excluded.length && state.city && !excluded.includes(state.city)) && !CITY_CLEAR.test(text)) clarification = error.message;
  }
  if (destination.city) {
    set('city', canonicalCity(destination.city));
    state.excludedCities = state.excludedCities.filter(city => city !== state.city);
    set('region', destination.region || null);
  }
  if (destination.origins?.length === 1) { set('origin', destination.origins[0]); clear('originCandidateId'); }
  if (destination.origins?.length > 1) clarification = '请确认这次从哪个地点出发。';
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
    const inferred = inferFilters(analysisMessage, today, { selectedTopic: 'any' });
    const explicitFreeFilter = /(?:只看|只要|仅限|僅限|仅看|僅看|只找|限定).{0,6}(?:免费|免費)|\b(?:free[- ]only|only (?:show |find |want )?free)\b/i.test(text);
    const lookingForOptions = /找|推荐|推薦|安排|去哪|哪里|哪裡|有什么|有什麼|有哪些|(?:免费|免費)(?:活动|活動|景点|景點|去处|去處)|\b(?:find|recommend|plan|looking for|where|what|free (?:events?|activities|places?|options?))\b/i.test(text);
    const shortFreeFollowup = text.length <= 35 && /^(?:免费|免費|free)(?:的|就好|only| options?)?[？?。.!\s]*$/i.test(text.trim());
    const freeRuleQuestion = /(?:免费|免費).{0,30}(?:公共空间|公共空間|区域|區域|规则|規則|限制|资格|資格)|\bfree (?:public (?:spaces?|areas?)|admission (?:rules?|eligibility|conditions?))/i.test(text);
    const freeFilterIntent = explicitFreeFilter || (!freeRuleQuestion && ['day-plan', 'discover', 'shopping'].includes(state.goal) && (lookingForOptions || shortFreeFollowup));
    const suppressImplicitFree = inferred.freeOnly === true && !freeFilterIntent;
    for (const key of ['date', 'budget', 'budgetScope', 'partySize', 'freeOnly', 'setting', 'travelMode', 'topic']) if (inferred[key] !== undefined) {
      // Asking whether a venue has free public areas is a fact question, not a
      // new $0 budget that should remove the paid venue from the evidence set.
      if (suppressImplicitFree && (key === 'freeOnly' || (key === 'budget' && inferred.budget === 0 && !/预算|預算|\bbudget\b/i.test(text)))) continue;
      set(key, inferred[key]);
    }
    if (inferred.childAges) set('childAges', inferred.childAges);
    else if (inferred.childAge !== undefined && inferred.childAge !== null) set('childAges', [inferred.childAge]);
    if (!state.city && inferred.region && !CITY_CLEAR.test(text)) set('region', inferred.region);
    else if (state.city && !state.region && inferred.region) set('region', inferred.region);
  } catch (error) { clarification ||= error.message; }
  if (DATE_CLEAR.test(text)) { clear('date'); if (['day-plan', 'discover'].includes(state.goal)) clarification = '日期限制已清除；安排具体行程前，请选定一天。'; }
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
  const budgetPatch = text.match(/(?:(每人|总|總|per person|total)\s*)?(?:预算|預算|budget)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(?:\$|USD\s*)?(\d+(?:\.\d{1,2})?)/i);
  if (budgetPatch) { set('budget', Number(budgetPatch[2])); if (budgetPatch[1]) set('budgetScope', /每人|per person/i.test(budgetPatch[1]) ? 'person' : 'total'); }
  const modePatch = text.match(/(?:出行方式|travel mode)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(drive|transit|walk|any)\b/i);
  if (modePatch) set('travelMode', modePatch[1].toLowerCase());
  const settingPatch = text.match(/(?:场景|場景|setting)\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\s*(indoor|outdoor|mixed|any)\b/i);
  if (settingPatch) set('setting', settingPatch[1].toLowerCase());
  if (/不带孩子|不帶孩子|没有孩子同行|沒有孩子同行|\b(?:no kids|no children|adults only|without (?:the )?(?:kids|children))\b/i.test(text)) clear('childAges');
  if (/时间不限|時間不限|\bno time constraints?\b/i.test(text)) { clear('startTime'); clear('finishBy'); }
  Object.entries(timesIn(text)).forEach(([key, value]) => set(key, value));
  for (const [key, label] of [['startTime', '开始时间|開始時間|start time'], ['finishBy', '最晚结束时间|最晚結束時間|finish by|end time|return time']]) {
    const match = text.match(new RegExp(`(?:${label})\\s*(?:改为|改為|设为|設為|change(?:d)? to|set to|is|:|：)\\s*((?:[01]?\\d|2[0-3]):[0-5]\\d)`, 'i'));
    if (match) set(key, match[1].padStart(5, '0'));
  }
  state.preferences = list([...state.preferences, ...preferencePhrases(text)]);
  if (/可以开车|可以開車|改成开车|改成開車|\b(?:we can drive|I can drive|let's drive|will drive)\b/i.test(text)) state.preferences = state.preferences.filter(value => value !== 'no-car');
  if (state.preferences.includes('no-car') && state.travelMode === 'drive') clear('travelMode');
  if (['day-plan', 'discover', 'shopping', 'transit'].includes(state.goal)) {
    const outside = text.replace(/Shanghai Dumpling(?:s| King| Shop)?|New York[- ]style|Jack London Square/gi, 'local venue')
      .matchAll(/上海|北京|深圳|广州|廣州|香港|澳门|澳門|纽约|紐約|洛杉矶|洛杉磯|西雅图|西雅圖|台北|臺北|东京|東京|\b(?:Shanghai|Beijing|Shenzhen|Guangzhou|Hong Kong|Macau|Macao|New York|Los Angeles|Seattle|Taipei|Tokyo|Sacramento|San Diego)\b/gi);
    for (const match of outside) {
      const prefix = text.slice(Math.max(0, match.index - 35), match.index);
      if (/(?:从|從|不要|不去|避开|避開|不是|\bfrom|\bleaving|\bnot in|\boutside(?: of)?|\bexcept|\binstead of)\s*$/i.test(prefix)) continue;
      if (!destination.city || /(?:改去|换成|換成|前往|到|去|\bto|\bin|\bat)\s*$/i.test(prefix)) {
        clear('city'); clear('region'); clarification = 'BayBay 当前安排旧金山湾区的行程。请确认一个湾区目的地，或说明这次是在查询湾区以外的资料。';
        break;
      }
    }
  }
  state.clearedFields = [...cleared];
  if (state.date && state.date < today && ['day-plan', 'discover'].includes(state.goal)) clarification ||= '这个日期已经过去；请确认是查询历史活动，还是改选未来日期。';
  if (state.startTime && state.finishBy && state.finishBy <= state.startTime) clarification ||= '返回时间不晚于出发时间；请确认是否跨夜，或修改其中一个时间。';
  return { state: validateTaskState(state), ...(clarification ? { clarification } : {}) };
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
const secretOf = options => options?.secret || process.env.JWT_SECRET;
const nowSeconds = options => Math.floor((typeof options?.now === 'function' ? options.now() : options?.now ?? Date.now()) / 1000);

/** A short-lived, purpose-bound HMAC token is stateless and contains no account
 * credentials. Missing signing configuration disables persistence, not checks. */
function encodeTaskToken(payload, options = {}) {
  const secret = secretOf(options);
  if (typeof secret !== 'string' || secret.length < 16) return null;
  const issuedAt = nowSeconds(options);
  const body = Buffer.from(JSON.stringify({ v: VERSION, purpose: 'baybay-task', iat: issuedAt, exp: issuedAt + TOKEN_TTL, state: validateTaskState(payload?.state || payload), lastPlan: planRefs(payload?.lastPlan) })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  const token = `${body}.${signature}`;
  return token.length <= TOKEN_LIMIT ? token : null;
}

function decodeTaskToken(token, options = {}) {
  const secret = secretOf(options);
  if (typeof token !== 'string' || token.length > TOKEN_LIMIT || typeof secret !== 'string' || secret.length < 16 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)) return null;
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

module.exports = { VERSION, TOKEN_TTL, TOKEN_LIMIT, validateTaskState, resolveTaskState, applyTaskStatePatch, encodeTaskToken, decodeTaskToken };
