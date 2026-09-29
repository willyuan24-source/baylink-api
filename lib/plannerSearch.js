// Catalog-only matching. These helpers never fetch places or invent availability.
const normalized = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[’']/g, '').replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const CATEGORY_TERMS = {
  restaurant: /餐厅|餐廳|餐馆|餐館|吃饭|吃飯|午餐|晚餐|\b(?:restaurants?|dining|dinner|lunch|eat)\b/gi,
  cafe: /咖啡|甜品|甜点|甜點|奶茶|\b(?:cafes?|cafés?|coffee|desserts?|boba|bakery)\b/gi,
  shop: /商店|购物|購物|零售|\b(?:shops?|shopping|retail|stores?)\b/gi,
  attraction: /景点|景點|博物馆|博物館|美术馆|美術館|公园|公園|花园|花園|\b(?:attractions?|museums?|parks?|gardens?|sightseeing)\b/gi,
};
const OPENING = /新店|新开|新開|\b(?:new (?:places?|stores?|shops?|restaurants?|cafes?)|newly opened|openings?)\b/gi;
const EVENT_REQUEST = /活动|活動|演出|演唱会|演唱會|音乐会|音樂會|节庆|節慶|\b(?:events?|concerts?|festivals?|after dark|performances?)\b/i;
const negated = prefix => /(?:不要|不想(?:去|要)?|不去|排除|避开|避開|避免)\s*$|\b(?:no|not|without|avoid|exclude|don['’]t want|do not want)\s*$/i.test(prefix);
const positive = (query, regex) => [...query.matchAll(new RegExp(regex.source, 'gi'))].some(match => !negated(query.slice(Math.max(0, match.index - 35), match.index)));
function namedMention(query, row) {
  const q = normalized(query);
  const parts = String(row.title || '').split(/[·|（(]/).map(normalized).filter(part => part.length >= 3);
  for (const part of parts) {
    const at = q.indexOf(part);
    if (at >= 0) return negated(q.slice(Math.max(0, at - 35), at)) ? -1 : 1;
    const first = part.split(' ')[0];
    const match = /^[a-z]{5,}$/.test(first) && !/^(?:museum|restaurant|coffee|garden|place|newly|opening)$/.test(first) && new RegExp(`(?:^| )${first}(?= |$)`).exec(q);
    if (match) return negated(q.slice(Math.max(0, match.index - 35), match.index)) ? -1 : 1;
  }
  return 0;
}
const namedMatch = (query, row) => namedMention(query, row) === 1;
function searchIntent(query, catalog) {
  const categoryQuery = query.replace(/\bcoffee shops?\b/gi, 'coffee');
  const categories = Object.entries(CATEGORY_TERMS).filter(([, regex]) => positive(categoryQuery, regex)).map(([key]) => key);
  const excludedCategories = Object.entries(CATEGORY_TERMS).filter(([, regex]) => new RegExp(regex.source, 'i').test(categoryQuery) && !positive(categoryQuery, regex)).map(([key]) => key);
  const opening = positive(query, OPENING);
  const namedIds = catalog.places.filter(place => namedMatch(query, place)).map(place => place.id);
  const excludedNamedIds = catalog.places.filter(place => namedMention(query, place) === -1).map(place => place.id);
  return { categories, excludedCategories, opening, namedIds, excludedNamedIds, placesOnly: !!(categories.length || opening || namedIds.length) && !EVENT_REQUEST.test(query) };
}
function searchScore(query, row) {
  if (!query.trim()) return 0;
  const title = normalized(row.title); const text = normalized([row.title, row.city, row.summary, row.category].join(' '));
  const tokens = [...new Set(normalized(query).match(/[a-z]{3,}|[\u3400-\u9fff]{2,}/g) || [])].filter(token => !['the', 'for', 'want', 'with', 'find', 'places', 'recommend', 'please'].includes(token));
  return (namedMatch(query, row) ? 100 : 0) + tokens.reduce((sum, token) => sum + (title.includes(token) ? 8 : text.includes(token) ? 2 : 0), 0);
}
function placeMatchesSearch(place, intent) {
  const category = place.category || 'attraction';
  return !intent.excludedNamedIds.includes(place.id) && !intent.excludedCategories.includes(category) && (!intent.categories.length || intent.categories.includes(category))
    && (!intent.opening || place.id.startsWith('opening-') || !!place.openedOn)
    && (!intent.namedIds.length || intent.namedIds.includes(place.id));
}
function placeAvailability(place, date, today) {
  if (place.openingStatus === 'announced' || (place.openedOn && place.openedOn > date)) return 'unopened';
  const schedule = place.planning?.schedule;
  if (!schedule || !/^https?:\/\//.test(schedule.sourceUrl || '') || !/^\d{4}-\d{2}-\d{2}$/.test(schedule.verifiedAt || '')) return 'unknown';
  const age = (Date.parse(`${today}T12:00:00Z`) - Date.parse(`${schedule.verifiedAt}T12:00:00Z`)) / 86400000;
  if (!Number.isFinite(age) || age < 0 || age > 45 || (schedule.validFrom && date < schedule.validFrom) || (schedule.validThrough && date > schedule.validThrough)) return 'unknown';
  const weekday = new Date(`${date}T12:00:00Z`).getUTCDay();
  const windows = schedule.dates && Object.hasOwn(schedule.dates, date) ? schedule.dates[date] : schedule.weekly?.[weekday];
  if (Array.isArray(windows)) return windows.length === 0 ? 'closed' : windows.every(window => /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(window.open) && /^(?:[01]\d|2[0-3]):[0-5]\d$|^24:00$/.test(window.close) && window.open < window.close) ? 'hours' : 'unknown';
  if (Array.isArray(schedule.sessions)) return schedule.sessions.some(session => session.date === date) ? 'sessions' : 'unknown';
  return 'unknown';
}
module.exports = { searchIntent, searchScore, placeMatchesSearch, placeAvailability };
