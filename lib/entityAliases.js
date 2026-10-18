const { mentionedCities } = require('./bayAreaSearchScope');
const indexes = new WeakMap();
const normalize = text => String(text || '').normalize('NFKC').toLowerCase().replace(/[“”"'‘’]/g, '').replace(/\s+/g, ' ').trim();
function aliasesFor(row) {
  const title = String(row.title || row.name || '');
  return [...new Set([title, title.split(/\s*[：:·（(]\s*/)[0], ...(Array.isArray(row.aliases) ? row.aliases : [])].map(normalize).filter(alias => alias.length >= 3 && alias.length <= 180))];
}
function namedEntities(query, catalog) {
  if (!catalog || typeof catalog !== 'object') return [];
  let index = indexes.get(catalog);
  if (!index) { index = [...(catalog.events || []).map(row => ({ kind: 'event', row })), ...(catalog.places || []).map(row => ({ kind: 'place', row }))].map(value => ({ ...value, aliases: aliasesFor(value.row) })); indexes.set(catalog, index); }
  const text = normalize(query);
  return index.filter(item => item.aliases.some(alias => text.includes(alias))).slice(0, 8);
}
function dateRangeFor(message, today) {
  const text = String(message || '');
  const explicit = /(20\d{2}-\d{2}-\d{2})\s*(?:到|至|through|to|[~–])\s*(20\d{2}-\d{2}-\d{2})/i.exec(text);
  if (explicit && explicit[1] <= explicit[2] && [explicit[1], explicit[2]].every(value => Number.isFinite(Date.parse(value)) && new Date(value).toISOString().startsWith(value))) return { start: explicit[1], end: explicit[2] };
  if (!/这(?:个)?周末|這(?:個)?週末|本周末|本週末|下(?:个)?周末|下(?:個)?週末|\b(?:this|next) weekend\b/i.test(text)) return null;
  const day = new Date(`${today}T12:00:00Z`), weekday = day.getUTCDay();
  let delta = weekday === 0 ? -1 : (6 - weekday + 7) % 7;
  if (/下(?:个)?周末|下(?:個)?週末|\bnext weekend\b/i.test(text)) delta += 7;
  const start = new Date(day.getTime() + delta * 86400000).toISOString().slice(0, 10);
  return { start, end: new Date(Date.parse(`${start}T12:00:00Z`) + 86400000).toISOString().slice(0, 10) };
}

// ---- API-BB-5 (API-SYNC-3c follow-up 1): the date forms families type for a weekend or a month ----
// "11月21日、22日" / "11月21日到22日" / "November 21-22", "the weekend of December 5" / "12月5日那个周末",
// "12月第一个周末" / "first weekend of December", "12月" / "12月初" / "in December" / "下个月". dateRangeFor
// (above) is unchanged: v1 and the planner keep reading only ISO ranges and this/next weekend.
const EN_MONTHS = ['jan(?:uary)?', 'feb(?:ruary)?', 'mar(?:ch)?', 'apr(?:il)?', 'may', 'june?', 'july?', 'aug(?:ust)?', 'sep(?:t(?:ember)?)?', 'oct(?:ober)?', 'nov(?:ember)?', 'dec(?:ember)?'];
const EN_MONTH = `(${EN_MONTHS.join('|')})\\.?`;
const EN_MONTH_FULL = '(january|february|march|april|may|june|july|august|september|october|november|december)';
const enMonth = name => EN_MONTHS.findIndex(pattern => new RegExp(`^(?:${pattern})$`, 'i').test(String(name).replace(/\.$/, ''))) + 1;
const ZH_MONTH = '(\\d{1,2}|十[一二]?|[一二三四五六七八九十])';
const zhMonth = value => /^\d+$/.test(value) ? Number(value) : value.length === 1 ? '一二三四五六七八九十'.indexOf(value) + 1 : 10 + '一二'.indexOf(value[1]) + 1;
const ORDINALS = { 一: 1, 1: 1, first: 1, '1st': 1, 二: 2, 2: 2, second: 2, '2nd': 2, 三: 3, 3: 3, third: 3, '3rd': 3, 四: 4, 4: 4, fourth: 4, '4th': 4 };
const isoDay = (year, month, day) => `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
const realDay = value => { const time = Date.parse(`${value}T12:00:00Z`); return Number.isFinite(time) && new Date(time).toISOString().slice(0, 10) === value; };
const plus = (value, days) => new Date(Date.parse(`${value}T12:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
const weekdayOf = value => new Date(`${value}T12:00:00Z`).getUTCDay();
const lastDay = (year, month) => new Date(Date.UTC(year, month, 0, 12)).getUTCDate();
// A month well before this one is next year's (asked in November about January); a month just past stays this year.
const yearOf = (month, today, written) => written ? Number(written) : Number(today.slice(0, 4)) + ((Number(today.slice(5, 7)) - month + 12) % 12 >= 4 && month < Number(today.slice(5, 7)) ? 1 : 0);
// The Saturday and Sunday of the weekend a day is in (Friday and Monday-Thursday: the next one).
const weekendOf = value => { const weekday = weekdayOf(value); const saturday = weekday === 0 ? plus(value, -1) : plus(value, (6 - weekday + 7) % 7); return { start: saturday, end: plus(saturday, 1) }; };
function nthWeekend(year, month, nth) {
  const first = isoDay(year, month, 1);
  const firstSaturday = 1 + ((6 - weekdayOf(first)) + 7) % 7;
  const saturdays = []; for (let day = firstSaturday; day <= lastDay(year, month); day += 7) saturdays.push(day);
  const day = nth === 'last' ? saturdays.at(-1) : saturdays[nth - 1];
  return day ? { start: isoDay(year, month, day), end: plus(isoDay(year, month, day), 1) } : null;
}
// The next date of a holiday a family names (this year's, or next year's once it has passed).
function holidayDate(name, today) {
  const key = String(name).toLowerCase();
  const on = year => /感恩|thanksgiving/.test(key) ? isoDay(year, 11, 22 + (4 - weekdayOf(isoDay(year, 11, 1)) + 7) % 7)
    : /圣诞|聖誕|christmas|xmas/.test(key) ? isoDay(year, 12, 25) : /万圣|萬聖|halloween/.test(key) ? isoDay(year, 10, 31)
      : /元旦|新年|new\s*year/.test(key) ? isoDay(year + 1, 1, 1) : /退伍|老兵|veterans/.test(key) ? isoDay(year, 11, 11) : null;
  const year = Number(today.slice(0, 4));
  const date = on(year);
  if (!date) return null;
  return date >= today ? date : on(year + 1);
}
function monthRange(year, month, part, today) {
  const [from, to] = /初|上旬/.test(part || '') ? [1, 10] : /中/.test(part || '') ? [11, 20] : /底|末|下旬/.test(part || '') ? [21, lastDay(year, month)] : [1, lastDay(year, month)];
  const start = isoDay(year, month, from), end = isoDay(year, month, to);
  if (end < today) return null;
  return { start: start < today ? today : start, end };
}
const RANGE_FORMS = [
  // Two days, or a short span, in one ask (the planner's inferFilters asks to pick one; an outing ask covers both).
  ['days', new RegExp(`(?:(20\\d{2})\\s*年\\s*)?(\\d{1,2})\\s*月\\s*(\\d{1,2})\\s*(?:日|号|號)?\\s*(?:、|，|,|和|与|與|及|跟|或者?|到|至|～|~|-|–|—)\\s*(?:(\\d{1,2})\\s*月\\s*)?(\\d{1,2})\\s*(?:日|号|號)`), match => [match[1], match[2], match[3], match[4] || match[2], match[5]]],
  ['days', new RegExp(`\\b${EN_MONTH}\\s+(\\d{1,2})(?:st|nd|rd|th)?\\s*(?:-|–|—|to|through|thru|and|&|or)\\s*(?:${EN_MONTH}\\s+)?(\\d{1,2})(?:st|nd|rd|th)?\\b(?![\\s-]*(?:am|pm|:|\\d|years?|yrs?|yo\\b|y\\/o|kids?|children|people|adults?|of us|months?))`, 'i'), match => [null, enMonth(match[1]), match[2], match[3] ? enMonth(match[3]) : enMonth(match[1]), match[4]]],
  ['days', /(?<![\d/])(\d{1,2})\/(\d{1,2})\s*(?:-|–|—|~|～|to|and|&|、|和|到|至)\s*(?:(\d{1,2})\/)?(\d{1,2})(?![\d/:]|[\s-]*(?:years?|yrs?|yo\b|y\/o|kids?|children|people|adults?|months?|岁|歲|个月|個月))/i, match => [null, match[1], match[2], match[3] || match[1], match[4]]],
  // The weekend a named day is in.
  ['weekend-of', new RegExp(`\\b(?:the\\s+)?weekend\\s+of\\s+(?:${EN_MONTH}\\s+(\\d{1,2})(?:st|nd|rd|th)?|(\\d{1,2})\\/(\\d{1,2}))\\b`, 'i'), match => match[1] ? [null, enMonth(match[1]), match[2]] : [null, match[3], match[4]]],
  ['weekend-of', new RegExp(`\\b${EN_MONTH}\\s+(\\d{1,2})(?:st|nd|rd|th)?\\s+weekend\\b`, 'i'), match => [null, enMonth(match[1]), match[2]]],
  ['weekend-of', /(?:(20\d{2})\s*年\s*)?(\d{1,2})\s*月\s*(\d{1,2})\s*(?:日|号|號)?\s*(?:那个|那個|那|这个|這個|的|所在的?)\s*(?:周末|週末)/, match => [match[1], match[2], match[3]]],
  // API-BB-10 (live 10-17, Q5 "这周末 10/24 带娃去哪"): a weekend word right beside a Saturday or Sunday the ask writes out is
  // that day's weekend (Sat and Sun), not this weekend and not the Saturday alone. A weekday beside 周末 is left as it was.
  ['weekend-of', /(?:这个|這個|这|這|本)?\s*(?:周末|週末)\s*[（(，,：:]?\s*(?:(\d{1,2})\s*月\s*(\d{1,2})\s*(?:日|号|號)?|(?<![\d/])(\d{1,2})\/(\d{1,2})(?![\d/]))/, match => [null, match[1] || match[3], match[2] || match[4]], { weekendDay: true }],
  ['weekend-of', /(?:(\d{1,2})\s*月\s*(\d{1,2})\s*(?:日|号|號)?|(?<![\d/])(\d{1,2})\/(\d{1,2})(?![\d/]))\s*[）)]?\s*(?:这个|這個|这|這|那个|那個|那|的)?\s*(?:周末|週末)/, match => [null, match[1] || match[3], match[2] || match[4]], { weekendDay: true }],
  ['weekend-of', new RegExp(`\\bweekend\\s*[(,:]?\\s*(?:${EN_MONTH}\\s+(\\d{1,2})(?:st|nd|rd|th)?|(?<![\\d/])(\\d{1,2})\\/(\\d{1,2})(?![\\d/]))`, 'i'), match => match[1] ? [null, enMonth(match[1]), match[2]] : [null, match[3], match[4]], { weekendDay: true }],
  ['weekend-of', new RegExp(`(?:${EN_MONTH}\\s+(\\d{1,2})(?:st|nd|rd|th)?|(?<![\\d/])(\\d{1,2})\\/(\\d{1,2})(?![\\d/]))\\s*\\)?\\s*weekend\\b`, 'i'), match => match[1] ? [null, enMonth(match[1]), match[2]] : [null, match[3], match[4]], { weekendDay: true }],
  // The first, second … or last weekend of a month.
  ['nth-weekend', new RegExp(`(?:(20\\d{2})\\s*年\\s*)?${ZH_MONTH}\\s*月(?:份)?\\s*(?:的)?\\s*(?:第\\s*([一二三四1-4])\\s*(?:个|個)?|(最后|最後)\\s*(?:一)?\\s*(?:个|個)?)\\s*(?:周末|週末)`), match => [match[1], zhMonth(match[2]), match[3] ? ORDINALS[match[3]] : 'last']],
  ['nth-weekend', new RegExp(`\\b(first|second|third|fourth|last|1st|2nd|3rd|4th)\\s+weekend\\s+(?:of|in)\\s+${EN_MONTH}`, 'i'), match => [null, enMonth(match[2]), match[1].toLowerCase() === 'last' ? 'last' : ORDINALS[match[1].toLowerCase()]]],
  // The weekend before or after a holiday ("圣诞节前那个周末", "the weekend after Thanksgiving"); review round 1. A holiday's
  // own weekend ("感恩节周末") stays unset (lib/baybayState.js HOLIDAY_WEEKEND): families mean different days by it.
  ['holiday-weekend', /(感恩|圣诞|聖誕|万圣|萬聖|元旦|新年|退伍军人|退伍軍人|老兵)\s*(?:节|節|日)?\s*(?:之)?(前|后|後|过后|過後)\s*(?:的|那|那个|那個|这个|這個)?\s*(?:一个|一個)?\s*(?:周末|週末)/, match => [match[1], /前/.test(match[2]) ? 'before' : 'after']],
  ['holiday-weekend', /\b(?:the\s+)?weekend\s+(before|after)\s+(thanksgiving|christmas|xmas|halloween|new\s*year['’]?s?(?:\s+day)?|veterans['’]?\s+day)\b/i, match => [match[2], match[1].toLowerCase()]],
  // A whole month, or its first, middle or last third ("12月初"). Not "3月大的宝宝", 月票, 月饼 or a dated day.
  // Review (API-BB-5 round 1): not a month that dates something else in the ask: a move, a birth, a trip or a
  // start ("我们3月搬来湾区", "宝宝3月出生", "我1月要回国", "我12月去日本", "9月刚上幼儿园"), a time before or after
  // it ("12月前"), the band 五月天 or 12月天气.
  ['month', new RegExp(`(?:(20\\d{2})\\s*年\\s*)?(?<![\\d一二三四五六七八九十个個几幾每上下这這本])${ZH_MONTH}\\s*月(?:份)?(?:\\s*(初|上旬|中旬|下旬|底|末))?(?![\\d一二三四五六七八九十]|\\s+\\d|\\s*(?:日|号|號|大|龄|齡|票|卡|租|薪|费|費|供|付|刊|饼|餅|光|亮|球|子|嫂|经|經|天)|\\s*(?:份)?\\s*(?:(?:就|才|要|会|會|将|將|准备|準備|打算|计划|計劃|刚|剛|已经|已經)\\s*)?(?:搬|出生|生的|生了|生日|来的|來的|来湾|來灣|来美|來美|到湾|到灣|到美|开始|開始|那时|那時|的时候|的時候|以前|之前|前|之后|之後|以后|以後|后|後|回国|回國|回去|回来|回來|出国|出國|出发|出發|离开|離開|走|上学|上學|入学|入學|毕业|畢業|上幼|上小|上中|上大|去(?:日本|中国|中國|台湾|台灣|香港|欧洲|歐洲|外地|外州|国外|國外|旅游|旅遊|度假|出差)|出差|旅游|旅遊|度假))`), match => [match[1], zhMonth(match[2]), match[3]]],
  ['month', new RegExp(`\\b(?:in|during|throughout|this|for|all of|all|early|mid|late)[- ]+${EN_MONTH_FULL}\\b(?!\\s*\\d)`, 'i'), match => [null, enMonth(match[1]), /early/i.test(match[0]) ? '初' : /mid/i.test(match[0]) ? '中' : /late/i.test(match[0]) ? '底' : '', match[1]]],
];
/** The span of days an ask names (beyond one day), with the matched text: { start, end, kind, index, length }, or null. */
function askedDateRange(message, today) {
  const text = String(message || '').slice(0, 4000);
  if (!realDay(today)) return null;
  const explicit = dateRangeFor(text, today);
  if (explicit && /(20\d{2}-\d{2}-\d{2})\s*(?:到|至|through|to|[~–])\s*(20\d{2}-\d{2}-\d{2})/i.test(text)) return { ...explicit, kind: 'iso' };
  for (const [kind, pattern, read, options] of RANGE_FORMS) {
    // 这周末 / next weekend outrank a bare month in the same ask ("我1月回国，这周末去哪玩").
    if (kind === 'month' && explicit) return { ...explicit, kind: 'weekend' };
    const match = pattern.exec(text);
    if (!match) continue;
    const at = { index: match.index, length: match[0].length, text: match[0] };
    if (kind === 'days') {
      const [written, startMonth, startDay, endMonth, endDay] = read(match).map((value, index) => index && value !== null && value !== undefined ? Number(value) : value);
      const year = yearOf(startMonth, today, written), start = isoDay(year, startMonth, startDay);
      const end = isoDay(endMonth < startMonth ? year + 1 : year, endMonth, endDay);
      if (!realDay(start) || !realDay(end) || end <= start || Date.parse(end) - Date.parse(start) > 31 * 86400000) continue;
      return { start, end, kind, ...at };
    }
    if (kind === 'weekend-of') {
      const [written, month, day] = read(match);
      const named = isoDay(yearOf(Number(month), today, written), Number(month), Number(day));
      if (!realDay(named) || options?.weekendDay && ![0, 6].includes(weekdayOf(named))) continue;
      return { ...weekendOf(named), kind, ...(options?.weekendDay ? { day: named } : {}), ...at };
    }
    if (kind === 'nth-weekend') {
      const [written, month, nth] = read(match);
      if (!month || !nth) continue;
      const range = nthWeekend(yearOf(month, today, written), month, nth);
      if (range) return { ...range, kind, ...at };
      continue;
    }
    if (kind === 'holiday-weekend') {
      const [name, side] = read(match);
      const holiday = holidayDate(name, today);
      if (!holiday) continue;
      let saturday = plus(holiday, side === 'before' ? -1 : 1);
      while (weekdayOf(saturday) !== 6) saturday = plus(saturday, side === 'before' ? -1 : 1);
      return { start: saturday, end: plus(saturday, 1), kind, ...at };
    }
    if (kind === 'month') {
      const [written, month, part, name] = read(match);
      // "may" in English is a verb as often as a month: only a capitalised "May" counts.
      if (!month || month > 12 || (name && name.toLowerCase() === 'may' && name !== 'May')) continue;
      // Review round 2: the English form skips a month that dates a move, a birth or a trip away, like the zh form
      // ("We moved here in March", "We go back to China in January, … before that?", "In December we fly to Japan").
      if (name) {
        const before = text.slice(0, match.index).split(/[,.;!?，。；]/).pop(), after = text.slice(match.index + match[0].length).split(/[,.;!?，。；]/)[0];
        // Review round 4: only a past arrival or start dates the background ("We arrived in March"); "We arrive in
        // December" and "Winter break starts in December" ask about that month.
        const away = /\b(?:mov(?:e|ed|es|ing)|born|due|arrived|leav(?:e|es|ing)|left|fly(?:ing)?|flew|go(?:es|ing)? (?:back|home)|went (?:back|home)|return\w*|head(?:ing)? (?:back|home)|started)\b/i;
        if (away.test(before) || (/^\s*(?:we|i|they|he|she|my|our|the (?:baby|kids?))\b/i.test(after) && away.test(after))
          || /\b(?:before that|before then|until then)\b/i.test(text)) continue;
      }
      const range = monthRange(yearOf(month, today, written), month, part, today);
      if (range) return { ...range, kind, ...at };
    }
  }
  const relative = /(?:这个|這個|本)月|\bthis month\b|(下个|下個)月|\b(next) month\b/i.exec(text);
  if (relative && !/(?:这个|這個|本|下个|下個)月\s*(?:\d|[一二三四五六七八九十]+\s*(?:日|号|號))/.test(text)) {
    const next = !!(relative[1] || relative[2]);
    const month = Number(today.slice(5, 7)) + (next ? 1 : 0);
    const year = Number(today.slice(0, 4)) + (month > 12 ? 1 : 0);
    const range = monthRange(year, month > 12 ? 1 : month, '', today);
    if (range) return { ...range, kind: 'month', index: relative.index, length: relative[0].length, text: relative[0] };
  }
  return explicit ? { ...explicit, kind: 'weekend' } : null;
}
// ---- BAYBAY_ENGINE=v2 retrieval aliases (API-BB-ENGINE) --------------------
// Colloquial names readers type for things the site already covers. A match
// adds the canonical terms to the retrieval query; it never states a fact.
// Keep entries to names with a real record or guide on the site.
// `subject` marks a how-to topic: an evidence item must then name the topic
// (its subject pattern) to be used, so a shared word such as 预约 or 中文 never
// pads a DMV answer with a yoga class (buildFastEvidence).
const ALIAS_GROUPS = Object.freeze([
  { id: 'fleet-week', match: /fleet\s*week|舰队周|艦隊[週周]|海[军軍](?:周|週|节|節)|[蓝藍]天使|blue\s*angels/i, terms: ['Fleet Week', '舰队周', '蓝天使', 'Blue Angels'] },
  { id: 'glass-pumpkin', match: /玻璃南瓜|glass\s*pumpkins?/i, terms: ['Glass Pumpkin', '玻璃南瓜'] },
  { id: 'social-security', match: /[养養]老金|退休金|社安(?:金|局|卡)?|社[会會]安全(?:局|金)?|social\s*security|\bssa\b/i, terms: ['Social Security', 'my Social Security', '社安', '退休福利'], subject: /[养養]老金|退休|社安|社[会會]安全|social\s*security|\bssa\b|\bssi\b/i },
  { id: 'medi-cal', match: /白卡|medi-?cal|加州[医醫][疗療]补助|加州醫療補助/i, terms: ['Medi-Cal', '白卡'], subject: /白卡|medi-?cal|[医醫][疗療]补助|醫療補助/i },
  { id: 'medicare', match: /[红紅][蓝藍]卡|medicare|[联聯]邦[医醫][疗療]保[险險]/i, terms: ['Medicare'], subject: /medicare|hicap|[红紅][蓝藍]卡|[联聯]邦[医醫][疗療]保[险險]/i },
  { id: 'chinese-doctor', match: /(?:中文|[华華]人|[会會]?[说說]中文的?|[讲講]中文的?|国语|國語|普通[话話]|粤语|粵語)\s*(?:的)?\s*[医醫]生|chinese[- ]speaking\s+doctors?/i, terms: ['医生', '保险网络', '医生名录', 'Provider Directory', '语言'], subject: /[医醫]生|doctor|provider|[诊診]所|clinic|保[险險]网络|保險網絡/i },
  { id: 'library-card', match: /[图圖][书書][馆館]卡|借[书書][证證]|[图圖][书書][证證]|library\s*card|\becard\b/i, terms: ['图书馆卡', 'library card', 'eCard'], subject: /[图圖][书書][馆館]|librar(?:y|ies)|借[书書][证證]|[办辦]卡|ecard|[实實][体體]卡|cards?-by-mail|\b(?:sfpl|sjpl|sccld?|aclibrary|smcl)\b/i },
  { id: 'dmv', match: /[驾駕](?:照|[驶駛][执執]照)|[笔筆][试試]|路考|知[识識]考[试試]|\bdmv\b|driver['’]?s?\s+licen[cs]e|\b(?:knowledge|written|driving|drive|road)\s+test\b|behind[- ]the[- ]wheel/i, terms: ['DMV', '驾照', '知识考试', '路考', 'knowledge test', 'drive test'], subject: /[驾駕]照|\bdmv\b|路考|[笔筆][试試]|driver['’]?s?\s+licen[cs]e|\b(?:knowledge|drive|driving)\s+test\b|\breal\s*id\b/i },
  { id: 'seniors', match: /[长長]者|老人|[长長][辈輩]|老年人|\bseniors?\b|\belderly\b/i, terms: ['长者', '老人', 'senior'] },
  // API-BB-5 (API-SYNC-3c follow-up 3): the four venue names are San Francisco's. They name those museums only for an
  // ask that names San Francisco or no city ("住 San Jose … 美术馆" led with SFMOMA and the Exploratorium).
  { id: 'museums', match: /museums?|博物[馆館]|美[术術][馆館]|[艺藝][术術][馆館]/i, terms: ['museum', 'art', '艺术', '博物馆'], cityTerms: { 'San Francisco': ['SFMOMA', 'Asian Art Museum', 'de Young', 'Exploratorium'] } },
  { id: 'pumpkin-patch', match: /南瓜(?:园|園|田|地|农场|農場)|摘南瓜|pumpkin\s*patch(?:es)?/i, terms: ['pumpkin patch', '南瓜田', '南瓜季', '农场', 'Farm'] },
  { id: 'newcomer', match: /新移民|刚到[湾灣]区|剛到[灣湾]區|刚搬[来到]|剛搬[來到]|新来[湾灣]区|新來[灣湾]區|\bnew(?:ly)? (?:arrived|immigrants?|to the bay area)\b|\bjust (?:moved|arrived)\b/i, terms: ['刚搬来湾区', '前 7 天', '第一周', 'SSN', '社安卡', '银行', '驾照', 'newcomer'] },
  { id: 'scam', match: /[诈詐][骗騙]|防[骗騙]|[骗騙]局|\bscams?\b|\bfraud\b/i, terms: ['诈骗', '防骗', 'scam'], subject: /[诈詐][骗騙]|[骗騙]|冒充|假冒|scam|fraud|phishing/i },
]);

/** The alias groups a question names (ids) and the canonical terms to add to its retrieval query. */
function queryAliases(query) {
  const text = String(query || '').slice(0, 4000);
  const groups = ALIAS_GROUPS.filter(group => group.match.test(text));
  const subjects = groups.filter(group => group.subject);
  const cities = groups.some(group => group.cityTerms) ? mentionedCities(text) : [];
  const local = group => Object.entries(group.cityTerms || {}).filter(([city]) => !cities.length || cities.includes(city)).flatMap(([, terms]) => terms);
  return { ids: groups.map(group => group.id), terms: [...new Set(groups.flatMap(group => [...group.terms, ...local(group)]))],
    // A how-to question: does this evidence text name (one of) its topic(s)?
    onSubject: subjects.length ? value => subjects.some(group => group.subject.test(value)) : null };
}

const GENERIC_SUFFIX = /(?:\s*20\d{2})?\s*(?:艺术节|藝術節|音乐节|音樂節|文化节|文化節|美食节|美食節|嘉年华|嘉年華|节|節|活动|活動|展览|展覽|展|市集|集市|夜市|大会|大會|\bfestival\b|\bfair\b|\bmarket\b|\bevents?\b|\bexhibition\b|\bshow\b)\s*$/i;
const GENERIC_TOKENS = new Set(['the', 'and', 'of', 'at', 'in', 'on', 'for', 'a', 'an', 'to', 'day', 'one', 'free', 'night', 'family', '活动', '活動', '免费', '免費', '周末', '週末', '周日', '週日', '周六', '週六', '一日', '亲子', '親子', '社区', '社區', '公园', '公園']);
const latinWords = text => text.match(/[a-z0-9][a-z0-9'’&-]*/g) || [];
const cjkBigrams = text => (text.match(/[㐀-鿿]+/g) || []).flatMap(run => run.length === 1 ? [] : Array.from({ length: run.length - 1 }, (_, index) => run.slice(index, index + 2)));
const coreOf = alias => { let core = alias; for (let i = 0; i < 2; i++) core = core.replace(GENERIC_SUFFIX, '').trim(); return core; };
/** Token signature of an alias: every Latin word and CJK bigram of its core
 * name. Usable only with at least two tokens and one distinctive token, so a
 * bare city name or "free family day" never names an entity. */
function signature(alias, cityTokens) {
  const core = coreOf(alias);
  const tokens = [...new Set([...latinWords(core), ...cjkBigrams(core)])];
  const distinctive = tokens.filter(token => !GENERIC_TOKENS.has(token) && !cityTokens.has(token));
  return tokens.length >= 2 && distinctive.length >= 1 && core.replace(/\s/g, '').length >= 4 ? tokens : null;
}

const v2Indexes = new WeakMap();
const NO_DISCOVERIES = Object.freeze({ items: [] });
function v2Index(catalog, discoveries, cityTokens) {
  const catalogKey = catalog && typeof catalog === 'object' ? catalog : NO_DISCOVERIES;
  let byDiscovery = v2Indexes.get(catalogKey);
  if (!byDiscovery) { byDiscovery = new WeakMap(); v2Indexes.set(catalogKey, byDiscovery); }
  const discoveryKey = discoveries && typeof discoveries === 'object' ? discoveries : NO_DISCOVERIES;
  let index = byDiscovery.get(discoveryKey);
  if (!index) {
    const rows = [...(catalog?.events || []).map(row => ({ kind: 'event', row })), ...(catalog?.places || []).map(row => ({ kind: 'place', row })),
      ...(Array.isArray(discoveryKey.items) ? discoveryKey.items : []).filter(row => ['offer', 'opening'].includes(row?.kind)).map(row => ({ kind: row.kind, row }))];
    index = rows.map(value => {
      const aliases = aliasesFor(value.row);
      return { ...value, aliases, signatures: aliases.map(alias => signature(alias, cityTokens)).filter(Boolean) };
    });
    byDiscovery.set(discoveryKey, index);
  }
  return index;
}

/** v2 named-entity matcher (events, places, offers and openings): an exact
 * alias as in v1, or every token of an alias's core name ("santana row 玻璃南瓜"
 * for "Santana Row 玻璃南瓜艺术节") appears in the question once colloquial
 * alias groups are added (舰队周 -> Fleet Week). `cityTokens` are words that
 * never make a name distinctive on their own. */
function namedEntitiesV2(query, catalog, { discoveries, cityTokens = new Set() } = {}) {
  const text = normalize([query, ...queryAliases(query).terms].join(' '));
  const words = new Set(latinWords(text)), bigrams = new Set(cjkBigrams(text));
  const has = token => /[㐀-鿿]/.test(token) ? bigrams.has(token) : words.has(token);
  return v2Index(catalog, discoveries, cityTokens).filter(item => item.aliases.some(alias => text.includes(alias)) || item.signatures.some(tokens => tokens.every(has))).slice(0, 8);
}

module.exports = { namedEntities, dateRangeFor, askedDateRange, aliasesFor, namedEntitiesV2, queryAliases, ALIAS_GROUPS };
