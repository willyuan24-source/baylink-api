// Evidence comes only from the user's words. AI questions help the conversation,
// but their dates, times and places must never become supplied facts.
function clocksIn(value) {
  const found = new Set();
  const push = (hour, minute) => {
    if (Number.isInteger(hour) && hour >= 0 && hour < 24 && Number.isInteger(minute) && minute >= 0 && minute < 60) found.add(`${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`);
  };
  const numeral = value => {
    if (/^\d+$/.test(value)) return Number(value);
    const digits = '零一二三四五六七八九', clean = value.replace(/[两兩]/g, '二').replace(/〇/g, '零');
    if (clean.includes('十')) { const [tens, units] = clean.split('十'); return (tens ? digits.indexOf(tens) : 1) * 10 + (units ? digits.indexOf(units) : 0); }
    return digits.indexOf(clean);
  };
  const hourIn = (hour, period) => {
    if (hour < 0 || hour > 23) return NaN;
    if (period === 'am' || period === 'pm') return hour >= 1 && hour <= 12 ? hour % 12 + (period === 'pm' ? 12 : 0) : NaN;
    if (period === '凌晨') return hour === 12 ? 0 : hour < 12 ? hour : NaN;
    if (['早上', '上午'].includes(period)) return hour < 12 ? hour : NaN;
    if (period === '中午') return hour === 12 ? 12 : hour >= 1 && hour <= 2 ? hour + 12 : NaN;
    if (period === '晚上' && hour === 12) return NaN; // Midnight needs an unambiguous date.
    return hour < 12 ? hour + 12 : hour;
  };
  const period = '(凌晨|早上|上午|中午|下午|晚上|傍晚)';
  const number = '[零〇一二两兩三四五六七八九十\\d]{1,3}';
  const token = `(${number})(?::([0-5]\\d)|(?:点|點|时|時)(半|${number}分?)?)`;
  let remaining = String(value).normalize('NFKC');
  const consume = (pattern, visit) => { remaining = remaining.replace(pattern, (...args) => { visit(...args); return ' '.repeat(args[0].length); }); };
  const minuteOf = (colon, words) => colon !== undefined ? Number(colon) : words === '半' ? 30 : words ? numeral(words.replace(/分$/, '')) : 0;
  // Consume the entire contextual range before looking for unqualified clocks.
  consume(new RegExp(`${period}\\s*${token}\\s*(?:到|至|[—–-])\\s*${period}?\\s*${token}`, 'g'), (_all, p1, h1, m1, w1, p2, h2, m2, w2) => {
    push(hourIn(numeral(h1), p1), minuteOf(m1, w1));
    push(hourIn(numeral(h2), p2 || p1), minuteOf(m2, w2));
  });
  consume(new RegExp(`${period}\\s*${token}`, 'g'), (_all, p, h, m, w) => push(hourIn(numeral(h), p), minuteOf(m, w)));
  consume(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:[—–-]|to)\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/gi, (_all, h1, m1, p1, h2, m2, p2) => {
    if (p1 || Number(h1) < Number(h2)) push(hourIn(Number(h1), (p1 || p2).toLowerCase()), Number(m1 || 0));
    push(hourIn(Number(h2), p2.toLowerCase()), Number(m2 || 0));
  });
  consume(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/gi, (_all, h, m, p) => push(hourIn(Number(h), p.toLowerCase()), Number(m || 0)));
  for (const match of remaining.matchAll(/\b([01]?\d|2[0-3]):([0-5]\d)\b/g)) push(Number(match[1]), Number(match[2]));
  for (const match of remaining.matchAll(new RegExp(`${token}`, 'g'))) {
    const hour = numeral(match[1]);
    if (hour === 0 || hour >= 13) push(hour, minuteOf(match[2], match[3]));
  }
  return found;
}

const dateHint = /20\d{2}-\d{2}-\d{2}|\d{1,2}\s*(?:月|\/)\s*\d{1,2}|(?:周|週|星期)[日天一二三四五六]|今天|明天|后天|後天|\b(?:today|tomorrow|sun(?:day)?|mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b/i;
function replacesClockEvidence(answer) {
  const correction = /改|更正|调整|調整|instead|change|actually|correction|switch|move/i.test(answer);
  const dayPart = /凌晨|早上|上午|中午|下午|晚上|傍晚|\b(?:morning|afternoon|evening|night|noon|midnight)\b/i.test(answer);
  const unchanged = /(?:时间|時間|时段|時段)\s*(?:不变|不變|照旧|照舊)|\b(?:same|unchanged)\s+(?:(?:morning|afternoon|evening|night)\s+)?(?:time|hours?)\b|\b(?:keep|retain)\s+(?:the\s+)?(?:same\s+)?(?:(?:morning|afternoon|evening|night)\s+)?(?:time|hours?)\b/i.test(answer);
  // An explicitly undecided clock withdraws the previous appointment even
  // without a replacement HH:mm. A date-only correction keeps its times.
  const undecided = /(?:时间|時間|时刻|時刻|几点|幾點)[^,，;；.。!?！？\n]{0,16}(?:待定|未定|没定|沒定|不定|不确定|不確定|没决定|沒決定|没有决定|沒有決定)|(?:(?:还没|還沒|尚未|没有|沒有)(?:决定|決定|确定|確定|想好)|不确定|不確定)[^,，;；.。!?！？\n]{0,12}(?:时间|時間|时刻|時刻|几点|幾點)|\b(?:time|hours?)\b[^,;.?!\n]{0,35}\b(?:tbd|undecided|unknown|not\s+(?:yet\s+)?(?:set|decided|confirmed)|to be (?:decided|confirmed))\b|\b(?:(?:haven[’']t|hasn[’']t|not)\s+(?:yet\s+)?(?:decided|set|confirmed)|undecided|unknown|not sure)\b[^,;.?!\n]{0,35}\b(?:time|hours?)\b/i.test(answer);
  return undecided || correction && (clocksIn(answer).size > 0 || dayPart && !unchanged);
}
function draftContext(intent, answers, today, locale, resolveDate) {
  let calendar = resolveDate(intent, today, locale);
  let clockEvidence = intent;
  for (const entry of answers) {
    if (dateHint.test(entry.answer)) calendar = resolveDate(entry.answer, today, locale);
    // A correction supersedes earlier clock evidence rather than validating
    // both the discarded time and the replacement as equally current.
    if (replacesClockEvidence(entry.answer)) clockEvidence = entry.answer;
    else clockEvidence += `\n${entry.answer}`;
  }
  return { calendar, clockEvidence, intent: [intent, ...answers.map(entry => entry.answer)].join('\n'), originalIntent: intent, answers };
}

function cityIsOnlyOrigin(intent, city) {
  const value = intent.toLowerCase(), needle = city.toLowerCase();
  let offset = 0, found = false;
  while ((offset = value.indexOf(needle, offset)) !== -1) {
    found = true;
    const before = value.slice(Math.max(0, offset - 45), offset), after = value.slice(offset + needle.length, offset + needle.length + 18);
    if (!/(?:从|從|住在|家在|出发地[：:]?|出發地[：:]?|\bfrom|\bleaving|\bdeparting|\blive in|\bbased in)\s*$/i.test(before) && !/^\s*(?:出发|出發|to\b|→)/i.test(after)) return false;
    offset += needle.length;
  }
  return found;
}

module.exports = { clocksIn, draftContext, cityIsOnlyOrigin };
