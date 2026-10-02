const { inferFilters, inferDestination, loadPlannerCatalog } = require('./planner');
const { validateSearchInput } = require('./plannerWebSearch');

const MODES = ['smart', 'web', 'site'];
let publicCatalog;
const privateRequest = text => /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b(?:\+?1[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b|密码|密碼|验证码|驗證碼|身份证|身分證|我的(?:预约|預約|订单|訂單|私信|住址)|\b(?:password|verification code|my (?:booking|reservation|address|messages)|social security)\b/i.test(text);
const localRequest = text => /湾区|灣區|周末|活动|活動|景点|景點|去哪|优惠|優惠|免费|免費|新店|营业|營業|门票|門票|票价|票價|最新|\b(?:bay area|weekend|events?|attractions?|deals?|freebies?|free|opening|hours|tickets?|prices?|latest|museums?|cafes?|restaurants?)\b/i.test(text);
const followup = text => /^(?:还有|還有|再|这些|這些|这个|這個|那个|那個|只想|只要|不要|换|換|太|便宜|免费|免費|预算|預算|那|\b(?:any more|more|only|instead|cheaper|free|too |what about|how about|those|these|that|this|another)\b)/i.test(text.trim());
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
  if (searchMode === 'site') return { search: false, status: 'not_requested' };
  if (searchMode === 'smart' && /站内(?:资料|指南|攻略|内容)|站內(?:資料|指南|攻略|內容)|仅站内|僅站內|\b(?:current guides|published guides|site (?:guides|information)|according to (?:the |this )?(?:guide|article))\b/i.test(message)) return { search: false, status: 'not_requested' };
  if (privateRequest(message) || school || (siteService && searchMode !== 'web')) return { search: false, status: 'not_applicable' };
  const prior = history.filter(item => item.role === 'user' && !privateRequest(item.content)).slice(-4);
  const continuation = followup(message);
  const previous = continuation ? prior.map(item => item.content).join('\n') : '';
  const inputText = `${previous}\n${message}`;
  if (searchMode === 'smart' && !localRequest(inputText)) return { search: false, status: 'not_requested' };
  const filters = {};
  publicCatalog ||= loadPlannerCatalog() || { events: [], places: [] };
  for (const text of [...(continuation ? prior.map(item => item.content) : []), message]) {
    try {
      Object.assign(filters, inferFilters(text.replace(/\bindoors\b/gi, 'indoor').replace(/\boutdoors\b/gi, 'outdoor'), today));
      const destination = inferDestination(text, publicCatalog);
      if (destination.city) { filters.city = destination.city; if (destination.region) filters.region = destination.region; }
    } catch {
      if (text === message) return { search: false, status: 'not_requested', question: locale === 'en' ? 'Please confirm one date and destination before I continue searching.' : locale === 'zh-Hant' ? '請先確認一個日期和目的地，我再繼續查找。' : '请先确认一个日期和目的地，我再继续查找。' };
    }
  }
  const context = { ...searchContext, ...(filters.date ? { date: filters.date } : {}), ...(filters.region ? { region: filters.region } : {}), ...(filters.city ? { city: filters.city } : {}) };
  let query = message;
  if (continuation) {
    const topic = topics.find(([expression]) => expression.test(message))?.[1]
      || [...prior].reverse().map(item => topics.find(([expression]) => expression.test(item.content))?.[1]).find(Boolean);
    if (!topic || (!context.city && !context.region && !/湾区|灣區|\bbay area\b/i.test(inputText))) return { search: false, status: 'not_requested', question: locale === 'en'
      ? 'Which city or area, and what kind of place or event should I continue looking for?'
      : locale === 'zh-Hant' ? '要繼續找哪個城市或地區、哪類活動或地點？' : '要继续找哪个城市或地区、哪类活动或地点？' };
    const clauses = [topic, context.city || context.region || 'Bay Area', filters.setting && filters.setting !== 'any' ? filters.setting : '', filters.travelMode && filters.travelMode !== 'any' ? `transport: ${filters.travelMode}` : '', filters.budget != null ? `admission budget: USD ${filters.budget}` : '', filters.freeOnly ? 'free admission only; conditions must be confirmed' : ''];
    query = `${clauses.filter(Boolean).join('; ')}. ${message}`.slice(0, 500);
  }
  return { search: true, input: validateSearchInput({ query, locale, ...context }) };
}

module.exports = { validateChatSearchMode, validateChatSearchContext, buildChatWebRequest };
