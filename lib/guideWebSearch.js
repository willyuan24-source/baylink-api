const { inferFilters, inferDestination, loadPlannerCatalog, allowsPaidAdmission } = require('./planner');
const { validateSearchInput } = require('./plannerWebSearch');
const { AREA: BAY_AREA, canonicalCity, normalizeCityMentions, mentionedCities } = require('./bayAreaSearchScope');
const { isNonVisitorResearch, isPublicInformationRequest } = require('./publicResearch');
const { isSchoolRequest } = require('./guideConversation');

const MODES = ['smart', 'web', 'site'];
let publicCatalog;
const privateRequest = text => /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b(?:\+?1[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b(?:I|we)\s+(?:live|reside)\s+(?:at|on)\s+\d{1,6}\s+(?:[A-Za-z.'-]+\s+){1,5}(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|way|boulevard|blvd)\b|密码|密碼|验证码|驗證碼|身份证|身分證|我的(?:预约|預約|订单|訂單|私信|住址)|(?:孩子|小孩|学生|學生).{0,8}(?:姓名|名字|名叫|叫做)|(?:出生日期|DOB|date of birth)\s*[:：]?\s*\d|\b(?:my (?:child|son|daughter)(?:['’]s)?\s+(?:name|is named)|password|verification code|my (?:booking|reservation|address|messages)|social security)\b/i.test(text);
const privateSchoolAddress = text => isSchoolRequest(text) && /\b\d{1,6}\s+(?:[A-Za-z.'-]+\s+){1,5}(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|way|boulevard|blvd)\b/i.test(text);
function privateChildIdentity(value) {
  const text = String(value || '');
  if (/(?:孩子|小孩|儿子|兒子|女儿|女兒)\s*叫(?:做)?\s*[^，,。.!！？?；;\n]{1,40}/u.test(text)) return true;
  // Capitalized personal names after a possessive child noun; ordinary
  // "my son is six / starts first grade" is not a name declaration.
  if (/\b(?:[Mm]y|[Oo]ur)\s+(?:[Cc]hild|[Ss]on|[Dd]aughter|[Kk]id)\s+[A-Z][\p{L}'’-]{1,39}(?:\s+[A-Z][\p{L}'’-]{1,39}){0,2}(?=\s+(?:was|is|needs|will|would|can|has|starts|turns)\b|[,.;])/u.test(text)) return true;
  const dates = /(?:19|20)\d{2}\s*(?:年|[-/])\s*\d{1,2}\s*(?:月|[-/])\s*\d{1,2}(?:日|号|號)?|\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}\b|\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?\s*,?\s*(?:19|20)\d{2}\b/gi;
  for (const date of text.matchAll(dates)) {
    const before = text.slice(Math.max(0, date.index - 100), date.index), after = text.slice(date.index + date[0].length);
    const personal = /(?:我|孩子|小孩|儿子|兒子|女儿|女兒)|\b(?:my|our|I|we)\b/i.test(before);
    if (personal && (/(?:born\s*(?:on)?|生日\s*(?:是|为|為)?)\s*$/i.test(before) || /^\s*(?:出生|生的)/.test(after))) return true;
  }
  return false;
}
const hasPrivateSearchData = text => privateRequest(text) || privateSchoolAddress(text) || privateChildIdentity(text);
const discoveryQuestion = text => /地方好去|哪[里裡兒儿]好[玩去]|去哪|\b(?:what(?:['’]s| is)\s+(?:on|happening)|things to do|places to (?:go|visit)|where (?:can|should|could) (?:we|I) go)\b/i.test(text);
const localRequest = text => discoveryQuestion(text) || /湾区|灣區|周末|週末|活动|活動|景点|景點|优惠|優惠|免费|免費|新店|营业|營業|门票|門票|票价|票價|最新|\b(?:bay area|weekend|events?|attractions?|deals?|freebies?|free|opening|hours|tickets?|prices?|latest|museums?|cafes?|restaurants?)\b/i.test(text);
const followup = text => /^(?:还有|還有|再|这些|這些|这个|這個|那个|那個|只想|只要|不要|换|換|太|便宜|免费|免費|预算|預算|那|\b(?:any more|more|only|instead|cheaper|free|too |what about|how about|those|these|that|this|another)\b)/i.test(text.trim());
// Reset only an explicit leading instruction, never a negation or quoted phrase.
const resetRequest = text => /^(?:(?:请|請)\s*|please\s+)?(?:重新开始|重新開始|重来|重來|换个话题|換個話題|新话题|新話題|清除(?:之前|以前|搜索)?(?:条件|條件)|忽略(?:之前|前面|上文|历史|歷史)(?:的)?(?:条件|條件|对话|對話)|start over|start a new search|new topic|reset (?:the )?(?:search|filters)|forget (?:the )?(?:previous|earlier) (?:search|filters|context))(?=$|[\s,，.!！。?？;；:：])/i.test(String(text || '').trim());
const isSearchReset = resetRequest;
const bayWide = text => /(?:全|整个|整個)湾区|(?:全|整個)灣區|(?:城市|地区|地區|区域|區域|地点|地點)(?:不限|不限制|随便|隨便|都(?:可以|行))|(?:不限定|不限制|不限)(?:城市|地区|地區|区域|區域|地点|地點)|\b(?:anywhere in (?:the )?bay area|(?:whole|entire) (?:san francisco )?bay area|any bay area city|any (?:city|location|region)|no (?:city|location|region) (?:restriction|preference|limit)s?)\b/i.test(text);
const anyDate = text => /(?:日期|日子)(?:不限|不限制|随便|隨便|都(?:可以|行))|(?:不限定|不限制|不限)(?:日期|日子)|哪天都(?:可以|行)|任何一天|\bany (?:day|date)\b|\bno (?:date|day) (?:restriction|preference|limit)s?\b/i.test(text);
function publicConstraintFollowup(text) {
  if (bayWide(text) || anyDate(text) || allowsPaidAdmission(text)) return true;
  const value = String(text).trim().replace(/[?？!！。.,，]+$/g, '').trim();
  const city = normalizeCityMentions(value).replace(/^(?:那(?:就)?|改(?:成|为|為|去|到)|换(?:成|去|到)|換(?:成|去|到)|只去|\b(?:in|to|only|switch to|change to|go to|how about|what about))\s*/i, '').replace(/(?:呢|吧|就好|\s+instead)$/i, '').trim();
  if (canonicalCity(city)) return true;
  return /^(?:那(?:就)?|改(?:成|为|為|到)|换成|換成|\b(?:on|how about|what about|change to|switch to))?\s*(?:今天|明天|后天|後天|昨天|前天|(?:这|這|本|下)?(?:周|週|星期)(?:末|[日天一二三四五六])|(?:20\d{2}[-/年])?\d{1,2}[-/月]\d{1,2}(?:日|号|號|\/20\d{2})?|today|tomorrow|yesterday|day after tomorrow|(?:(?:this|next)\s+)?(?:weekend|sun(?:day)?|mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?))\s*(?:呢|吧|就好|instead)?$/i.test(value);
}
const timelessRequest = text => /历史|歷史|起源|沿革|由来|由來|如何使用|怎么用|怎麼用|\b(?:history|origins?|how (?:does|do|to)\b[^?？]{0,60}\b(?:work|use)|what (?:is|are)\b[^?？]{0,40}\b(?:difference|meaning))\b/i.test(text);
// Explicit non-local destinations should receive a scope explanation, not be
// silently rewritten into a Bay Area trip. Origins and cuisine names are not destinations.
const outsidePlace = /上海|北京|广州|廣州|深圳|香港|台北|臺北|中国|中國|东京|東京|新加坡|洛杉矶|洛杉磯|西雅图|西雅圖|纽约|紐約|圣地亚哥|聖地牙哥|拉斯维加斯|拉斯維加斯|\b(?:Shanghai|Beijing|Guangzhou|Shenzhen|Hong Kong|Taipei|China|Tokyo|Singapore|Los Angeles|Seattle|New York|San Diego|Las Vegas|Sacramento|London|Portland)\b/gi;
function outsideDestination(text) {
  const discovery = discoveryQuestion(text) || /景点|景點|旅游|旅遊|\b(?:attractions?|sightseeing|places to visit)\b/i.test(text)
    || topics.some(([expression]) => expression.test(text));
  for (const match of text.matchAll(outsidePlace)) {
    const before = text.slice(Math.max(0, match.index - 45), match.index);
    const after = text.slice(match.index + match[0].length, match.index + match[0].length + 45);
    if (/(?:从|從|来自|來自|\bfrom|\bleaving|\bdeparting)\s*$/i.test(before)
      || /^\s*(?:(?:出发|出發|飞来|飛來)|to\b|[-=]?>|→)/i.test(after)
      || /(?:不要|不去|不是|而非|\bnot|\bexcept)\s*$/i.test(before)
      || (/中国|中國/.test(match[0]) && /^城/.test(after))
      || (/^London$/i.test(match[0]) && /^\s+Breed\b/i.test(after))
      || (/^London$/i.test(match[0]) && /\bJack\s+$/i.test(before) && /^\s+Square\b/i.test(after))
      || /(?:\bborn in|出生于|出生於|生于|生於)\s*$/i.test(before)
      || /^\s*[-–]?\s*(?:的\s*)?(?:出生|生人|户籍|戶籍|籍贯|籍貫|国籍|國籍|驾照|駕照|驾驶证|駕駛證|护照|護照|\b(?:born|citizenship|passport|driver['’]?s? licen[cs]e|driving licen[cs]e)\b)/i.test(after)
      || /^\s*[-–]?\s*(?:菜|菜系|风味|風味|小笼|小籠|生煎|烤鸭|烤鴨|茶餐厅|茶餐廳|\b(?:cuisine|style|food|dumplings?|street|st|avenue|ave|road|rd)\b)/i.test(after)) continue;
    const explicitDestination = /(?:去|到|前往|在|游览|遊覽|旅游|旅遊|目的地(?:是|为|為)?|\bin|\bto|\bvisit(?:ing)?|\bdestination[:：]?)\s*$/i.test(before);
    if (discovery || explicitDestination) return true;
  }
  return false;
}
const scopeExplanation = locale => ({ search: false, status: 'not_applicable', question: locale === 'en'
  ? 'BAYLINK covers the San Francisco Bay Area in California, United States. Your requested destination is outside this area; I have not searched or changed it to a Bay Area destination.'
  : locale === 'zh-Hant' ? 'BAYLINK 提供美國加州舊金山灣區資訊。你指定的目的地不在服務範圍，本次沒有搜尋，也沒有將它改成灣區行程。'
    : 'BAYLINK 提供美国加州旧金山湾区资讯。你指定的目的地不在服务范围，本次没有搜索，也没有将它改成湾区行程。' });
const topics = [
  [/博物馆|博物館|\bmuseums?\b/i, 'museums'], [/咖啡|\bcaf[eé]s?|coffee\b/i, 'cafes'],
  [/餐厅|餐廳|吃饭|吃飯|美食|\brestaurants?|food\b/i, 'restaurants'], [/新店|\bnew openings?\b/i, 'new openings'],
  [/优惠|優惠|福利|\bdeals?|freebies?\b/i, 'local offers'], [/户外|戶外|散步|徒步|\b(?:outdoors?|hikes?|walks?)\b/i, 'outdoor activities'],
  [/看展|展览|展覽|\bexhibitions?\b/i, 'exhibitions'], [/活动|活動|周末|去哪|\b(?:events?|weekend)\b/i, 'local events'],
];

function validateChatSearchMode(value) {
  if (value === undefined) return 'smart';
  if (!MODES.includes(value)) throw Object.assign(new Error('搜索模式无效。'), { status: 400 });
  return value;
}
function validateChatSearchContext(value) {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['date', 'region', 'city'].includes(key))) throw Object.assign(new Error('搜索条件只接受日期、地区和城市。'), { status: 400 });
  const { query, locale, ...context } = validateSearchInput({ query: 'public search', ...value });
  return context;
}

/** Carry only a deterministic public topic and bounded filter fields. Raw prior
 * messages, saved plans and account data never become a web-provider payload. */
function buildChatWebRequest({ message, history = [], searchMode, searchContext = {}, locale, today, siteService = false, school = false }) {
  // Service scope also applies to site-only responses, which must not silently
  // answer a Shanghai request with San Francisco suggestions.
  if (outsideDestination(message)) return scopeExplanation(locale);
  const siteOnly = searchMode === 'site' || (searchMode === 'smart' && /站内(?:资料|指南|攻略|内容)|站內(?:資料|指南|攻略|內容)|仅站内|僅站內|\b(?:current guides|published guides|site (?:guides|information)|according to (?:the |this )?(?:guide|article))\b/i.test(message));
  if (hasPrivateSearchData(message) || (siteService && searchMode !== 'web')) return { search: false, status: 'not_applicable' };
  if (school || isNonVisitorResearch(message)) {
    if (!school && searchMode !== 'web' && !isPublicInformationRequest(message)) return { search: false, status: 'not_requested' };
    // School years, enrollment ages and service rates are not outing dates or
    // admission budgets. Only carry bounded public topic/location context.
    const previous = history.filter(item => item.role === 'user' && !hasPrivateSearchData(item.content) && isSchoolRequest(item.content)).at(-1);
    const query = school && previous && (followup(message) || publicConstraintFollowup(message)) && !isSchoolRequest(message)
      ? `${previous.content}. ${message}` : message;
    const cities = mentionedCities(message);
    const city = cities.length === 1 ? cities[0] : cities.length ? null : canonicalCity(searchContext.city);
    const input = validateSearchInput({ query: `${BAY_AREA}. ${query}`.slice(0, 500), locale, ...(city ? { city } : {}), region: 'all' });
    return siteOnly ? { search: false, status: 'not_requested', input } : { search: true, input };
  }
  const prior = history.filter(item => item.role === 'user' && !hasPrivateSearchData(item.content)).slice(-4);
  const continuation = followup(message) || publicConstraintFollowup(message);
  const restarting = resetRequest(message);
  const requestedLocal = localRequest(message) || (continuation && !restarting && prior.some(item => localRequest(item.content)));
  if ((searchMode === 'smart' || siteOnly) && !requestedLocal) return { search: false, status: 'not_requested' };
  let filters = {}, topic, origins = [], outside = false, dateUnrestricted = false;
  publicCatalog ||= loadPlannerCatalog() || { events: [], places: [] };
  const consume = (text, current = false) => {
    if (resetRequest(text)) { filters = {}; topic = undefined; origins = []; outside = false; dateUnrestricted = false; }
    if (outsideDestination(text)) { filters = {}; topic = undefined; origins = []; outside = true; dateUnrestricted = false; return; }
    // inferFilters alone treats an origin such as "from Fremont" as an East
    // Bay destination. Remove origin names with inferDestination first.
    const normalizedText = normalizeCityMentions(text);
    // A recognized city with no published rows must remain a destination; an
    // empty catalog result is not permission to recommend other cities.
    const destinationCatalog = { ...publicCatalog, places: [...publicCatalog.places, ...mentionedCities(normalizedText).map(city => ({ city }))] };
    const destination = inferDestination(normalizedText, destinationCatalog);
    const parsed = inferFilters(destination.analysisMessage.replace(/\bindoors\b/gi, 'indoor').replace(/\boutdoors\b/gi, 'outdoor'), today);
    if (anyDate(text)) { delete filters.date; delete parsed.date; dateUnrestricted = true; }
    else if (parsed.date) dateUnrestricted = false;
    if (bayWide(text)) { delete filters.city; delete parsed.region; filters.region = 'all'; outside = false; }
    else if (destination.city) {
      filters.city = destination.city;
      delete filters.region;
      if (destination.region || parsed.region) filters.region = destination.region || parsed.region;
      outside = false;
    } else if (parsed.region) { delete filters.city; filters.region = parsed.region; outside = false; }
    if (allowsPaidAdmission(text) && !parsed.freeOnly) {
      delete filters.freeOnly;
      if (filters.budget === 0) delete filters.budget;
    }
    if (parsed.budget > 0 && !parsed.freeOnly) delete filters.freeOnly;
    Object.assign(filters, parsed);
    if (destination.origins.length) origins = destination.origins;
    topic = topics.find(([expression]) => expression.test(text))?.[1] || (discoveryQuestion(text) ? 'local events and places to visit' : current && !continuation ? undefined : topic);
  };
  for (const item of restarting ? [] : prior) {
    // An ambiguous historical request is not authority for the next query.
    try { consume(item.content); } catch { /* Keep the last valid public constraints. */ }
  }
  if (!restarting) {
    if (searchContext.date) { filters.date = searchContext.date; dateUnrestricted = false; }
    if (searchContext.region && searchContext.region !== 'all') { delete filters.city; filters.region = searchContext.region; outside = false; }
    if (searchContext.city) {
      filters.city = canonicalCity(searchContext.city) || searchContext.city;
      delete filters.region;
      outside = !canonicalCity(searchContext.city);
    }
  }
  try { consume(message, true); }
  catch {
    return { search: false, status: 'not_requested', question: locale === 'en' ? 'Please confirm one date and destination before I continue searching.' : locale === 'zh-Hant' ? '請先確認一個日期和目的地，我再繼續查找。' : '请先确认一个日期和目的地，我再继续查找。' };
  }
  if (outside) return scopeExplanation(locale);
  if (continuation && !topic) return { search: false, status: 'not_requested', question: locale === 'en'
    ? 'Which city or area, and what kind of place or event should I continue looking for?'
    : locale === 'zh-Hant' ? '要繼續找哪個城市或地區、哪類活動或地點？' : '要继续找哪个城市或地区、哪类活动或地点？' };
  if (dateUnrestricted) return { search: false, status: 'not_requested', question: locale === 'en'
    ? 'I cleared the previous date. Date-matched outing recommendations currently use one day at a time. Which day would you like to check?'
    : locale === 'zh-Hant' ? '已清除之前的日期條件。目前按日期篩選的出遊推薦一次查一天，你想先查哪一天？'
      : '已清除之前的日期条件。目前按日期筛选的出游推荐一次查一天，你想先查哪一天？' };
  // Discovery and operational questions default to the server's Pacific day.
  // General history/how-to questions do not acquire a date merely from an old trip.
  if (timelessRequest(message) && !continuation && !searchContext.date) {
    try {
      if (!inferFilters(message, today).date) delete filters.date;
    } catch { /* The current request was already checked above. */ }
  } else if (!filters.date && localRequest(`${message} ${topic || ''}`)) filters.date = today;
  if (filters.date && filters.date < today) return { search: false, status: 'not_requested', question: locale === 'en'
    ? `The selected date (${filters.date}) is in the past. Are you checking a historical event, or would you like to choose today or a future date for an outing?`
    : locale === 'zh-Hant' ? `目前日期條件（${filters.date}）已經過去。你要查歷史活動，還是改選今天或未來日期安排出遊？`
      : `目前日期条件（${filters.date}）已经过去。你要查历史活动，还是改选今天或未来日期安排出游？` };
  const context = { ...(filters.date ? { date: filters.date } : {}), region: filters.region || 'all', ...(filters.city ? { city: filters.city } : {}) };
  const clauses = [
    BAY_AREA, context.city ? `destination: ${context.city}` : context.region !== 'all' ? `destination region: ${context.region}` : 'entire Bay Area; no city restriction', topic,
    origins.length ? `departure only, not a destination restriction: ${origins.map(city => `from ${city}`).join(', ')}` : '',
    filters.setting && filters.setting !== 'any' ? filters.setting : '',
    filters.travelMode && filters.travelMode !== 'any' ? `transport: ${filters.travelMode}` : '',
    filters.budget != null ? `admission budget: USD ${filters.budget}` : '',
    filters.freeOnly ? 'free admission only; conditions must be confirmed' : '',
  ];
  const query = `${clauses.filter(Boolean).join('; ')}. ${message}`.slice(0, 500);
  const input = validateSearchInput({ query, locale, ...context });
  return siteOnly ? { search: false, status: 'not_requested', input } : { search: true, input };
}

module.exports = { validateChatSearchMode, validateChatSearchContext, buildChatWebRequest, isSearchReset, hasPrivateSearchData };
