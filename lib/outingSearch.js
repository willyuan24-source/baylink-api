const crypto = require('node:crypto');

const fail = message => Object.assign(new Error(message), { status: 400 });
const idValid = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,140}$/.test(value);
const dayValid = value => typeof value === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(`${value}T12:00:00Z`)) && new Date(`${value}T12:00:00Z`).toISOString().slice(0, 10) === value;
const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const normalizeCity = value => value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase().replace(/[\s.\-']/g, '');
// Explicit aliases, never substring matching: South San Francisco is a different city.
const CITY_ALIASES = [
  ['San Francisco', 'SF', 'S.F.', '旧金山', '舊金山', '三藩市'],
  ['South San Francisco', 'South SF', '南旧金山', '南舊金山', '南三藩市'],
  ['San Jose', 'San José', '圣何塞', '聖何塞', '圣荷西', '聖荷西'],
  ['Fremont', '弗里蒙特', '佛利蒙', '佛利蒙市'],
  ['Oakland', '奥克兰', '奧克蘭', '屋仑', '屋崙'],
  ['Berkeley', '伯克利', '柏克萊', '柏克莱'],
  ['Sunnyvale', '桑尼维尔', '桑尼維爾', '森尼韋爾'],
  ['Santa Clara', '圣克拉拉', '聖克拉拉'],
  ['Cupertino', '库比蒂诺', '庫比蒂諾', '庫柏蒂諾', '库柏蒂诺'],
  ['Mountain View', '山景城'],
  ['Palo Alto', '帕洛阿尔托', '帕洛阿爾托'],
  ['San Mateo', '圣马特奥', '聖馬特奧', '圣马刁', '聖馬刁'],
  ['Redwood City', '红木城', '紅木城'],
  ['Daly City', '戴利城'],
  ['Hayward', '海沃德'],
  ['Union City', '联合城', '聯合城'],
  ['Milpitas', '米尔皮塔斯', '米爾皮塔斯', '苗必达', '苗必達'],
  ['Pleasanton', '普莱森顿', '普萊森頓'],
  ['Dublin', '都柏林'],
  ['Walnut Creek', '核桃溪'],
  ['Santa Rosa', '圣罗莎', '聖羅莎'],
  ['San Rafael', '圣拉斐尔', '聖拉斐爾'],
  ['San Leandro', '圣利安卓', '聖利安卓'],
  ['San Ramon', '圣拉蒙', '聖拉蒙'],
  ['Burlingame', '伯灵格姆', '伯靈格姆'],
  ['Napa', '纳帕', '納帕'],
];
const cityAliases = value => CITY_ALIASES.find(aliases => aliases.some(alias => normalizeCity(alias) === normalizeCity(value)));
const cityIdentity = value => cityAliases(value) ? normalizeCity(cityAliases(value)[0]) : value.normalize('NFC').toLowerCase().replace(/\s+/g, '');
const cityRegex = value => {
  const aliases = cityAliases(value) || [value];
  // Accent variants are expanded only in escaped literal alternatives. NFD input is accepted too.
  const alternatives = [...new Set(aliases.flatMap(alias => [alias, alias.normalize('NFC'), alias.normalize('NFD')]).concat(value))]
    .map(alias => escapeRegex(alias).replace(/\s+/g, '\\s*'));
  return new RegExp(`^(?:${alternatives.join('|')})$`, 'iu');
};
const TOPIC_ALIASES = [
  ['散步', '步行', '漫步', 'walk', 'walking', 'stroll'],
  ['咖啡', 'coffee', 'cafe', 'café'],
  ['看展', '展览', '展覽', '博物馆', '博物館', 'museum', 'museums', 'exhibition', 'exhibitions'],
  ['徒步', 'hike', 'hiking'],
  ['English practice', 'English conversation', 'practice English', 'practise English', '练英语', '练英文', '練英語', '練英文', '英语练习', '英語練習', '英文练习', '英文練習', '英语角', '英語角'],
];
function topicRegex(value) {
  const aliases = TOPIC_ALIASES.find(group => group.some(alias => alias.toLowerCase() === value.toLowerCase()));
  // Only a whole, explicitly listed theme expands. Other user queries remain escaped literals.
  return new RegExp((aliases || [value]).map(escapeRegex).join('|'), 'iu');
}
const boundedText = (value, maximum, minimum = 0) => {
  if (typeof value !== 'string' || value.length > maximum || value.trim().length < minimum || /[\u0000-\u001f\u007f]/.test(value)) throw fail('搜索条件格式或长度无效。');
  return value.trim();
};
const signature = (encoded, secret) => crypto.createHmac('sha256', secret).update(`outings-cursor-v2:${encoded}`).digest();
const signingKey = secret => { if (typeof secret !== 'string' || !secret) throw Object.assign(new Error('分页暂不可用，请稍后重试。'), { status: 503 }); return secret; };

/** All filters are applied independently of a cursor; a cursor can only move forward within them. */
function outingSearch(query, now, secret) {
  const allowed = ['eventId', 'date', 'city', 'cursor', 'q', 'dateFrom', 'dateTo', 'language', 'seats', 'sort'];
  if (!query || typeof query !== 'object' || Object.keys(query).some(key => !allowed.includes(key))) throw fail('筛选条件无效。');
  const normalized = { eventId: null, date: null, city: null, q: null, dateFrom: null, dateTo: null, language: null, seats: null, sort: 'id' };
  const filters = [{ status: 'open', startAt: { $gt: now } }];
  if (query.eventId !== undefined) { if (!idValid(query.eventId)) throw fail('活动编号无效。'); normalized.eventId = query.eventId; filters.push({ eventId: query.eventId }); }
  if (query.date !== undefined && (query.dateFrom !== undefined || query.dateTo !== undefined)) throw fail('指定日期不能与日期范围同时使用。');
  for (const key of ['date', 'dateFrom', 'dateTo']) if (query[key] !== undefined) { if (!dayValid(query[key])) throw fail('日期无效。'); normalized[key] = query[key]; }
  if (normalized.dateFrom && normalized.dateTo && normalized.dateFrom > normalized.dateTo) throw fail('开始日期不能晚于结束日期。');
  if (normalized.date) filters.push({ date: normalized.date });
  else if (normalized.dateFrom || normalized.dateTo) filters.push({ date: { ...(normalized.dateFrom ? { $gte: normalized.dateFrom } : {}), ...(normalized.dateTo ? { $lte: normalized.dateTo } : {}) } });
  if (query.city !== undefined) { const city = boundedText(query.city, 80, 1); normalized.city = cityIdentity(city); filters.push({ city: cityRegex(city) }); }
  if (query.q !== undefined) {
    const q = boundedText(query.q, 120); normalized.q = q.toLowerCase() || null;
    if (q) { const literal = topicRegex(q); filters.push({ $or: ['title', 'description', 'venue', 'city'].map(field => ({ [field]: literal })) }); }
  }
  if (query.language !== undefined) { if (!['zh', 'en'].includes(query.language)) throw fail('交流语言筛选无效。'); normalized.language = query.language; filters.push({ language: { $in: [query.language, 'any'] } }); }
  if (query.seats !== undefined) { if (query.seats !== 'open') throw fail('名额筛选无效。'); normalized.seats = 'open'; }
  if (query.sort !== undefined) { if (query.sort !== 'soonest') throw fail('排序方式无效。'); normalized.sort = 'soonest'; }
  const fingerprint = crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
  const legacy = !['q', 'dateFrom', 'dateTo', 'language', 'seats', 'sort'].some(key => query[key] !== undefined);
  let useV2 = !legacy;
  if (query.cursor !== undefined) {
    const cursor = query.cursor;
    if (typeof cursor !== 'string' || cursor.length > 1000) throw fail('分页位置无效，请重新搜索。');
    if (cursor.startsWith('v2.')) {
      useV2 = true;
      const match = /^v2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(cursor);
      if (!match) throw fail('分页位置无效，请重新搜索。');
      const raw = Buffer.from(match[1], 'base64url'), supplied = Buffer.from(match[2], 'base64url');
      if (raw.toString('base64url') !== match[1] || supplied.toString('base64url') !== match[2] || supplied.length !== 32
        || !crypto.timingSafeEqual(supplied, signature(match[1], signingKey(secret)))) throw fail('分页位置无效，请重新搜索。');
      let value; try { value = JSON.parse(raw.toString('utf8')); } catch { throw fail('分页位置无效，请重新搜索。'); }
      const keys = normalized.sort === 'soonest' ? ['v', 'sort', 'filters', 'id', 'startAt'] : ['v', 'sort', 'filters', 'id'];
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key))
        || value.v !== 2 || value.sort !== normalized.sort || value.filters !== fingerprint || !idValid(value.id)
        || (normalized.sort === 'soonest' && (!Number.isSafeInteger(value.startAt) || value.startAt < 0 || value.startAt > 8.64e15))) throw fail('分页条件已变化，请重新搜索。');
      filters.push(normalized.sort === 'soonest'
        ? { $or: [{ startAt: { $gt: value.startAt } }, { startAt: value.startAt, id: { $gt: value.id } }] }
        : { id: { $gt: value.id } });
    } else {
      if (!legacy || !idValid(cursor)) throw fail('分页位置无效，请重新搜索。');
      filters.push({ id: { $gt: cursor } });
    }
  }
  return { filter: { $and: filters }, sort: normalized.sort === 'soonest' ? { startAt: 1, id: 1 } : { id: 1 }, openSeats: normalized.seats === 'open',
    cursor: row => {
      if (!useV2) return row.id;
      const value = { v: 2, sort: normalized.sort, filters: fingerprint, id: row.id, ...(normalized.sort === 'soonest' ? { startAt: row.startAt } : {}) };
      const encoded = Buffer.from(JSON.stringify(value)).toString('base64url');
      return `v2.${encoded}.${signature(encoded, signingKey(secret)).toString('base64url')}`;
    },
  };
}

module.exports = { outingSearch, normalizeCity, cityRegex, CITY_ALIASES };
