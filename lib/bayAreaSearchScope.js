const aliases = require('../data/city-search-aliases.json');
const { loadPlannerCatalog, inferDestination, inferFilters } = require('./planner');

const TIMEZONE = 'America/Los_Angeles';
const AREA = 'San Francisco Bay Area, California, United States';
const catalog = loadPlannerCatalog() || { events: [], places: [] };
const normalize = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
const cities = new Map(Object.entries(aliases).map(([city, names]) => [city, new Set([city, city.replace(/\s+/g, ''), ...names, ...(city === 'San Jose' ? ['San José'] : [])])]));
for (const row of [...catalog.events, ...catalog.places]) for (const city of String(row.city || '').split(/\s*(?:\/|;|,|·)\s*/)) {
  if (city && !/bay area|湾区|灣區/i.test(city) && !cities.has(city)) cities.set(city, new Set([city]));
}
const cityPattern = name => new RegExp(`${/^[a-z]/i.test(name) ? '(?<![a-z])' : ''}${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${/[a-z]$/i.test(name) ? '(?![a-z])' : ''}`, 'giu');
// The public alias dictionary is immutable. Compile its matchers once rather
// than rebuilding hundreds of expressions for every indexed guide paragraph.
// No user text, query result or private location is retained in these indexes.
const canonicalCities = new Map();
const cityMatchers = [];
for (const [city, names] of cities) for (const name of names) {
  const key = normalize(name);
  if (!canonicalCities.has(key)) canonicalCities.set(key, city);
  cityMatchers.push({ city, pattern: cityPattern(name) });
}
const canonicalCity = value => canonicalCities.get(normalize(value)) || null;
const withoutAreaName = value => String(value || '').replace(/San Francisco Bay Area|旧金山湾区|舊金山灣區/gi, ' Bay Area ');
function cityMentions(text) {
  const found = [];
  for (const { city, pattern } of cityMatchers) for (const match of text.matchAll(pattern)) found.push({ city, start: match.index, end: match.index + match[0].length });
  return [...new Map(found.filter(item => !found.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start)).map(item => [`${item.start}:${item.end}`, item])).values()];
}
const mentionedCities = text => [...new Set(cityMentions(withoutAreaName(text)).map(item => item.city))];
function normalizeCityMentions(value) {
  let text = withoutAreaName(value);
  for (const item of cityMentions(text).sort((a, b) => b.start - a.start)) text = text.slice(0, item.start) + item.city + text.slice(item.end);
  return text;
}
const bayAreaDate = (now = Date.now) => new Intl.DateTimeFormat('en-CA', { timeZone: TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(now()));
const safeModel = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_.:/-]{0,119}$/i.test(value) ? value : undefined;
const verificationFailed = reason => Object.assign(new Error('The search result did not pass location/date checks. Please use the published catalog or try again.'), { status: 503, code: 'SEARCH_VERIFICATION_FAILED', reason });

function searchScope(input, now) {
  const today = bayAreaDate(now);
  let destination = {}, filters = {};
  try { destination = inferDestination(normalizeCityMentions(input.query), { ...catalog, places: [...catalog.places, ...[...cities.keys()].map(city => ({ city }))] }); filters = inferFilters(destination.analysisMessage || withoutAreaName(input.query), today); } catch { /* Caller handles ambiguous queries; never infer a private location. */ }
  const city = canonicalCity(input.city) || canonicalCity(destination.city);
  const date = input.date || filters.date || today;
  const weekday = new Intl.DateTimeFormat('en-US', { weekday: 'long', timeZone: 'UTC' }).format(new Date(`${date}T12:00:00Z`));
  return { area: AREA, country: 'US', region: 'California', timezone: TIMEZONE, city, date, weekday, today, requestedRegion: input.region || filters.region || 'all' };
}

function scopeInstructions(scope) {
  return `MANDATORY LOCATION AND DATE SCOPE: This is the ${AREA} in the USA, NOT the Guangdong-Hong Kong-Macao Greater Bay Area and NOT Shanghai. The user's language is a display preference, never a location signal. Default to the whole nine-county Bay Area (San Francisco, San Mateo, Santa Clara, Alameda, Contra Costa, Marin, Sonoma, Napa, Solano), not just San Francisco city. Requested destination: ${scope.city || scope.requestedRegion}; never substitute another city. The tool location is only a search bias, not the user's physical location. Include the requested city/area and date in the answer so its scope is explicit. Server date in ${TIMEZONE}: ${scope.today}. Selected date: ${scope.date}, ${scope.weekday}. In every search query explicitly include the destination and California USA, plus the exact year/date for events. A weekly Wednesday free offer is not a Sunday offer. Only label an event as on the selected day when its organizer's dated schedule supports it. Distinguish a festival's overall date range from individual performances, parades and air shows. Generic city homepages and calendars do not establish an event's date or prove that no events exist. If no date-specific options are established, say you could not verify any in this lookup; NEVER say the city has no events. Mark permanent attractions separately from dated events; do not invent today's hours or free admission. Prefer the specific official event page over aggregators and ticket resellers. Do not fill a requested city with neighboring cities unless the user explicitly asks to expand the area.`;
}

// This is a conservative rejection layer, not a claim that every remaining fact
// is verified. Source citations alone do not establish geographic/date accuracy.
function assertSearchScope(result, input, scope = searchScope(input)) {
  const answer = String(result.answer || '');
  const foreign = /上海|北京|深圳|广州|廣州|香港|澳门|澳門|台北|臺北|东京|東京|纽约|紐約|洛杉矶|洛杉磯|\b(?:Shanghai|Beijing|Shenzhen|Guangzhou|Hong Kong|Macau|Macao|Taipei|Tokyo|New York|Los Angeles|Seattle|San Diego|London|Singapore)\b/gi;
  // Reject affirmative foreign destination claims, but allow scope explanations
  // and names such as "Shanghai Dumpling in San Francisco".
  for (const original of answer.split(/[\n。!?！？]/)) {
    const segment = original.replace(/\bJack London Square\b|\bLondon Breed\b|\bShanghai Dumpling(?:s| King| Shop)?\b|\bNew York[- ]style\b/gi, 'local name');
    if (!foreign.test(segment)) { foreign.lastIndex = 0; continue; }
    foreign.lastIndex = 0;
    if (/不是|不在|非(?:上海|中国|中國|香港)|而非|不涵盖|不涵蓋|outside|not (?:in|the)|does not cover/i.test(segment)) continue;
    if (!mentionedCities(segment).length || /(?:上海|北京|深圳|广州|廣州|香港|台北|臺北|东京|東京)(?:市)?(?:有|的|举行|舉行|举办|舉辦)|\b(?:in|around|across)\s+(?:Shanghai|Beijing|Shenzhen|Guangzhou|Hong Kong|Taipei|Tokyo|New York|Los Angeles|Seattle|London|Singapore)\b/i.test(segment)) throw verificationFailed('outside_bay_area');
  }
  for (const candidate of result.candidates || []) {
    if (!candidate.city) continue;
    const city = canonicalCity(candidate.city);
    if (!city && !/^(?:San Francisco )?Bay Area$|^湾区$|^灣區$/i.test(candidate.city)) throw verificationFailed('unknown_candidate_city');
    if (scope.city && city && city !== scope.city) throw verificationFailed('wrong_candidate_city');
  }
  const openingCities = mentionedCities(answer.slice(0, 200));
  // A caller may explicitly admit cities the user is comparing in an
  // information question. This does not relax destination checks for candidates.
  const answerCities = new Set([scope.city, ...(Array.isArray(input.allowedAnswerCities) ? input.allowedAnswerCities : [])].map(canonicalCity).filter(Boolean));
  if (scope.city && openingCities.length && !openingCities.some(city => answerCities.has(city))) throw verificationFailed('wrong_answer_city');
  if (/(?:今天|当日|當日|该日|該日).{0,12}(?:没有|沒有|无|無)(?:任何|特定的|可参加的|可參加的)?\s*(?:活动|活動)|\b(?:there are no|has no|no)\s+(?:scheduled\s+|specific\s+)?events\s+(?:today|on\s+\d|in\s+\w)/i.test(answer)) throw verificationFailed('unsupported_absence_claim');
  const weekdays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const hanDays = ['日天', '一', '二', '三', '四', '五', '六'];
  const todayWeekday = weekdays[new Date(`${scope.today}T12:00:00Z`).getUTCDay()];
  for (let index = 0; index < 7; index++) {
    if (weekdays[index] === todayWeekday) continue;
    const weekday = `(?:(?:周|週|星期)[${hanDays[index]}]|${weekdays[index]})`;
    if (new RegExp(`${weekday}\\s*[（(]\\s*(?:今天|today)\\s*[）)]|(?:今天|today)\\s*(?:是|is)?\\s*[（(，,：:]?\\s*${weekday}`, 'i').test(answer)) throw verificationFailed('wrong_weekday');
  }
  for (const match of answer.matchAll(/(?:今天|today)\s*[（(，,:：]?\s*(20\d{2})\s*[-/年]\s*(\d{1,2})\s*[-/月]\s*(\d{1,2})(?:日|号|號)?/gi)) {
    const claimed = `${match[1]}-${match[2].padStart(2, '0')}-${match[3].padStart(2, '0')}`;
    if (claimed !== scope.today) throw verificationFailed('wrong_today_date');
  }
  for (const match of answer.matchAll(/(20\d{2})[-/年](\d{1,2})[-/月](\d{1,2})(?:日|号|號)?\s*(?:is|是)\s*(?:today|今天)/gi)) {
    if (`${match[1]}-${match[2].padStart(2, '0')}-${match[3].padStart(2, '0')}` !== scope.today) throw verificationFailed('wrong_today_date');
  }
  return result;
}

module.exports = { TIMEZONE, AREA, canonicalCity, mentionedCities, normalizeCityMentions, bayAreaDate, safeModel, searchScope, scopeInstructions, assertSearchScope, verificationFailed };
