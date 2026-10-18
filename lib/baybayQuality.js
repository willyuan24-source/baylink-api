// BayBay v2 answer quality (overhaul API-BB-QUALITY). Deterministic helpers the v2
// engine applies around its one model call; v1 never calls this module.
//
//   cardInLocale        entity cards in the reader's language (I18N-SEO-01, BBL-13)
//   nearbyClarifier     "附近有什么好吃的" with no known place: one short question (C11)
//   turnRules           this turn's conditional rules: follow-up carry and choices
//                       (BBL-07), every free option (BBL-06), newcomer checklist (B8)
//   leadConsistency     the lead must not contradict the points (count, choice)
const CJK = /[㐀-鿿]/;
const LOCALE_INDEX = locale => locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;
// Characters whose Traditional form differs, to recognise the zh-Hant alias of an event.
const TRADITIONAL = /[這們說時會麼為過還進動問發對開關題東車門長區優費買賣帶讓個從後來實際應該處圖書館農場飯點給須選擇網線話證據經歷記錄雖然樣鐘頭義務辦寧灣節驗藝術兒親園課]/;

let englishGuides;
/** Pure English guide records by slug (the search catalog merges both languages into one title). */
function englishGuide(slug) {
  englishGuides ||= new Map(require('../data/guide-catalog.en.json').filter(row => row?.slug).map(row => [row.slug, row]));
  return englishGuides.get(slug) || null;
}
const english = value => typeof value === 'string' && value.trim() && !CJK.test(value) ? value.trim() : '';
/** The English name of a catalog event or place: an alias without Chinese characters
 * (the longest for places, whose first English alias is often just the landmark). */
function englishAlias(row, kind) {
  const names = (Array.isArray(row?.aliases) ? row.aliases : []).filter(value => english(value) && /[A-Za-z]{3}/.test(value));
  if (!names.length) return '';
  return kind === 'place' ? names.reduce((best, value) => value.length > best.length ? value : best) : names[0];
}
const traditionalAlias = row => (Array.isArray(row?.aliases) ? row.aliases : []).find(value => typeof value === 'string' && TRADITIONAL.test(value)) || '';

/**
 * A card in the reader's locale. `row` is the catalog record behind the card (event,
 * place, offer or opening; offers and openings already arrive translated for en).
 * en: an English title (alias, or the guide's English title for a place shown as its
 * guide) and an English summary, or none: a Chinese summary is dropped, never shown
 * to an English reader. zh-Hant: an event's Traditional alias when it has one.
 */
function cardInLocale(card, { locale = 'zh-Hans', row = null, kind = card?.kind } = {}) {
  if (!card || locale === 'zh-Hans') return card;
  if (locale === 'zh-Hant') {
    const title = kind === 'event' ? traditionalAlias(row) : '';
    return title ? { ...card, title } : card;
  }
  const guide = card.kind === 'guide' ? englishGuide(card.id) : row?.guideSlug ? englishGuide(row.guideSlug) : null;
  const title = english(card.title) || (kind === 'event' || kind === 'place' ? englishAlias(row, kind) : '') || english(guide?.title) || card.title;
  const neutral = [row?.dateLabel, row?.venue].map(english).filter(Boolean).join(' · ');
  const summary = english(card.summary) || english(guide?.summary) || (kind === 'event' ? neutral : '');
  return { ...card, title, summary };
}

// ---- C11: "nearby" with no place known --------------------------------------------
// 附近 with no anchor of its own: at the start of a clause, or after 我/我家/这里 only.
// "斯坦福附近" or "near Stanford" names the place, so it is never asked again.
// One whitespace run per gap between required tokens keeps the match linear (no ReDoS).
const NEARBY = /(?:^|[，,。！？!?；;])\s*(?:(?:请问|請問|问一下|問一下)\s*)?(?:(?:我们|我們|我)?(?:家|这里|這裡|这边|這邊|这|這)\s*|(?:我们|我們|我)\s*)?(?:附近|周边|周邊|这一带|這一帶)|\b(?:near me|nearby|near here|around here|close by)\b/i;
const FIND_PLACE = /吃|喝|餐|饭|飯|咖啡|奶茶|早餐|早茶|超市|商店|店|买|買|玩|逛|公园|公園|景点|景點|去处|去處|地方|活动|活動|图书馆|圖書館|厕所|廁所|停车|停車|加油|\b(?:eat|food|restaurants?|caf[eé]s?|coffee|boba|groceries|grocery|shops?|stores?|parks?|things to do|places?|library|parking)\b/i;
/** One short question when the user asks for something 附近 and BayBay knows no city,
 * area, origin or page (C11): a list of far-apart places is not an answer. */
function nearbyClarifier(message, { state = {}, hasPage = false, locale = 'zh-Hans' } = {}) {
  if (hasPage || state.city || (state.region && state.region !== 'all') || state.origin || state.originCandidateId) return null;
  const text = String(message || '');
  if (!NEARBY.test(text) || !FIND_PLACE.test(text)) return null;
  return ['你现在在湾区哪个城市，或哪个地标附近？告诉我后，我只推荐那附近的，比如回复：Cupertino 图书馆附近。',
    '你現在在灣區哪個城市，或哪個地標附近？告訴我後，我只推薦那附近的，比如回覆：Cupertino 圖書館附近。',
    'Which Bay Area city or landmark are you near? Tell me and I will only suggest places close by, for example: near the Cupertino library.'][LOCALE_INDEX(locale)];
}

// ---- conditional rules for this turn (sent after the user turn, never in block 1) ---
const CHOOSE = /哪个更|哪個更|哪个最|哪個最|哪(?:一)?个好|哪(?:一)?個好|选哪|選哪|只挑|挑一个|挑一個|更合适|更合適|最适合|最適合|最轻松|最輕鬆|\bwhich (?:one )?(?:is )?(?:better|best|easiest|closer|closest)\b|\bpick one\b/i;
const NEWCOMER_SETUP = /(?:新移民|刚移民|剛移民|移民来|移民來|刚来美国|剛來美國|刚到美国|剛到美國|刚来湾区|剛來灣區|刚到湾区|剛到灣區|刚搬来|剛搬來|新来|新來|落地)[^。？?！!]{0,24}(?:办|辦|做|准备|準備|清单|清單|事情|事)|(?:第一(?:周|週|个月|個月)|頭一個月|头一个月)[^。？?！!]{0,12}(?:办|辦|做|准备|準備|清单|清單)|\b(?:new (?:immigrant|arrival)s?|just (?:moved|arrived))\b[^.?!]{0,60}\b(?:do|set up|checklist|first)\b/i;
const CREATIVE = /(?:写|寫|作)(?:一)?(?:首|段|句)[^。？?！!]{0,12}(?:诗|詩|词|詞|祝福|文案|对联|對聯)|\b(?:write|compose) (?:me )?(?:a |an )?(?:short )?(?:poem|haiku|limerick|greeting)\b/i;
/**
 * This turn's conditional rules for the v2 model call (role:'system' after the user
 * turn, so system block 1 stays cached). Plain-language, no data from the request.
 */
function turnRules({ message = '', state = {}, followup = false, locale = 'zh-Hans' } = {}) {
  const rules = [];
  const text = String(message || '');
  if (followup) rules.push('This is a follow-up turn. state holds every condition the user has given so far (child ages, party size, budget and whether it is per person or total, date, part of the day in preferences, transport, free-only, area). Apply all of them to this answer and say the ones that shape it (for example 两个孩子 4 岁和 7 岁, 两人 $60 以内, 坐 Caltrain); never ask for any of them again and never drop one the user did not change.');
  if (followup && CHOOSE.test(text)) rules.push('The user asks you to choose. Pick exactly one option from the records (or from the options in recentConversation that the records support), put it in the lead, and give the reason in the points. Never write that you cannot judge or compare after choosing; if a fact is unknown, still choose on what is known and name the one detail to check.');
  if (state.travelMode === 'transit') rules.push('Transport is public transit. Name the system the user named (BART, Caltrain, VTA, Muni, ferry). When a record names a station, stop or the walk from it, say it; otherwise say plainly which last leg needs checking in the transit planner, and prefer options a record places near a station. Never invent station names, distances or travel times.');
  // Only when looking for things to do: "这个活动免费吗？" about one item is not a list request.
  if (state.freeOnly || (['discover', 'day-plan'].includes(state.goal) && /免[费費]|\bfree\b/i.test(text))) rules.push('Free options: name every record in evidence that is free (cost or text says free or 免费) and fits the asked date and area, up to five, best fit first (family and child-friendly first when children come). Never say only one, or none, is free unless every record in evidence was checked and the others clearly cost money; a paid or unknown-cost record is not a reason to say the rest are not free.');
  if (state.goal === 'newcomer' || NEWCOMER_SETUP.test(text)) rules.push('Newcomer setup checklist: answer with up to five points, one official step each, in this order of urgency: (1) a Social Security number from SSA (free; an immigrant who asked for it on the immigrant visa application usually gets the card by mail, otherwise apply at an SSA office); (2) a phone number and a bank account; (3) a California driver license or state ID from the DMV; (4) health coverage (Medi-Cal through the county or BenefitsCal, Covered California, or work insurance); (5) school enrollment for children with the school district, or a library card. The first point is always the Social Security number. This checklist is the one exception to the site-only scope: these are general official steps you state even when the records do not mention them; cite a record wherever it supports a step (the BAYLINK newcomer, bank and DMV guides). Do not decide anyone\'s eligibility; never ask for ID or Social Security numbers.');
  // H73 (audit 10-13, BB-1013-10; API-BB-4B): where the asker is. From a stated home or starting city
  // with no destination, nearest first (the evidence is already ordered so); with no area at all on
  // an outing ask, a spread across the Bay Area and one short question about their area.
  const area = state.region && state.region !== 'all';
  if (['discover', 'day-plan'].includes(state.goal) && state.origin && !state.city && !area) rules.push(`The user starts from "${String(state.origin).replace(/["\n\r]/g, ' ').slice(0, 60)}" and named no destination. Recommend the records nearest to it first (the same city, then its county, then neighbouring areas) and name each one's city; include a far one only when nothing nearer fits, and say it is farther away.`);
  else if (state.goal === 'discover' && !state.city && !state.region && !state.origin) rules.push('No area is known (no city, region or starting point). Give options from at least two different parts of the Bay Area, name each one\'s city, and use gap to ask in one short question which area they will start from.');
  if (CREATIVE.test(text)) rules.push('The user asked for a piece of writing (a poem, a short message or a greeting). Put the whole piece in lead and points as its lines, complete and in the user\'s language; no citations, no reminders to check official pages, and gap "".');
  return rules;
}

// ---- (e) the lead must not contradict the points ----------------------------------
// API-BB-5 (captain decision 10-15): the rule of api main 74f5b50 again, narrowed. Five review rounds of the
// always-strip rule (every stated count of 2-6 options went) each found zh count phrasings it damaged, and the
// table in tests/baybay-lead-counts.test.js still failed 11 of its first 117 leads on 3fe0801, 10 of them damaged
// ("有两场或更多" -> "有或更多", "有两场" at the end -> "有", "兩個鐘", "坐两站 BART", a Saturday and a Sunday count,
// "There is one free event" -> "There is free event"). A lead's count of the options is removed only when it
// differs from the number of options listed, and only a plain count: '<2-6><measure word>' (zh) or 'two'-'six'
// (en) right before an option noun, with at most two short modifiers between ("两场免费活动", "3 场适合孩子的活动",
// "这两个地方", "two free South Bay family events"), the lead's only count, and no other word in the lead refers
// back to it ("Both are in Oakland", "the third is paid", 二选一, 第三场). Ranges ("两三场", "2-3个", "两个到三个"),
// approximations ("三个左右", "两个以上", "两个及以上", "两场或更多"), qualified counts ("其中两个", "一共有两场",
// "only two"), counts without an option noun ("两场都免费", "活动有两场"), "one" / "一", English digits, a lead
// with two counts and numbers that are not counts (dates, times, ages, prices, lines, people, durations, stops)
// are never touched. The count is read on the lead without its citation markers, as the reader sees it. While
// the lead streams, the draft writer holds the lead from such a count until the points are known (leadDraftText,
// createDraftWriter's end({ points })), so the streamed lead ends exactly as the result (live L04).
const ZH_NUMBER = { 两: 2, 兩: 2, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6 };
const EN_NUMBER = { two: 2, three: 3, four: 4, five: 5, six: 6 };
const ZH_UNIT = '(?:场|場|项|項|个|個|家|处|處|种|種|条|條|站|段)';
const ZH_UNIT_CHAR = /[场場项項个個家处處种種条條站段]/;
// What follows a measure word and is never an option: people, ages, durations and periods ("两个孩子", "一家三口",
// "两个半小时", "兩個鐘", "两个周末").
const ZH_NOT_OPTION = '(?:孩子|小孩|小朋友|朋友|宝宝|寶寶|儿子|兒子|女儿|女兒|学生|學生|大人|成人|老人|长辈|長輩|娃|人|岁|歲|半|小时|小時|钟|鐘|分钟|分鐘|月|星期|礼拜|禮拜|晚|(?:周|週)(?:末|[一二三四五六日天])|[三四五六]口)';
const ZH_NOT_OPTION_AHEAD = new RegExp(`^${ZH_NOT_OPTION}`);
const ZH_NUMERAL = '[一二三四五六七八九十百千两兩几幾零〇\\d]';
const ZH_JOIN = '[到至或及~～\\-–—－、/／]';
const ZH_APPROX_AHEAD = new RegExp(`^[ \\t]{0,3}(?:${ZH_JOIN}|左右|以上|以下|以内|以內|上下|多|余|餘|来|來)`);
// Every count-like phrase, a numeral and a measure word that is not people or a duration (not after 第): a lead
// with two of them ("周六两场、周日三场免费活动") is left whole.
const ZH_PHRASE_BEFORE = new RegExp(`(?<!第[ \\t]{0,3}${ZH_NUMERAL}{0,6})${ZH_NUMERAL}[ \\t]{0,3}$`);
const ZH_MODIFIER_WORDS = ['免费', '免費', '亲子', '親子', '室内', '室內', '户外', '戶外', '好玩', '不错', '不錯', '热门', '熱門', '小型', '大型', '中文', '华人', '華人', '社区', '社區', '家庭', '本地'];
const ZH_OPTION_WORDS = ['活动', '活動', '选择', '選擇', '选项', '選項', '地方', '去处', '去處', '农夫市集', '農夫市集', '图书馆', '圖書館', '美术馆', '美術館', '市集', '集市', '展览', '展覽', '电影', '電影', '博物馆', '博物館', '公园', '公園', '景点', '景點', '节目', '節目', '演出', '表演', '讲座', '講座', '故事会', '故事會', '推荐', '推薦'];
const ZH_MODIFIER = `(?:(?:${ZH_MODIFIER_WORDS.join('|')})的?|(?:适合|適合)[^，。；,;：:！？!?\\n]{1,8}?的|[好新])`;
const ZH_SIMPLE = new RegExp(`[两兩二三四五六2-6][ \\t]{0,3}${ZH_UNIT}(?![ \\t]{0,3}(?:${ZH_JOIN}|左右|以上|以下|以内|以內|上下|多|余|餘|来|來))(?!${ZH_NOT_OPTION})((?:${ZH_MODIFIER}){0,2})(${ZH_OPTION_WORDS.join('|')})`, 'y');
// The first character of a modifier or an option noun: anything else after the measure word settles a streamed count.
const ZH_SIMPLE_NEXT = new Set([...ZH_MODIFIER_WORDS, ...ZH_OPTION_WORDS, '适合', '適合', '好', '新'].map(word => word[0]));
const ZH_BARE = new Set(['地方', '去处', '去處', '选择', '選擇', '选项', '選項', '推荐', '推薦']);
// A plain count is never the second number of a range ("两三场", "这周两三场", "2-3个", "十二个"; only the 一-六 of
// 周六 / 星期六 / 礼拜六 is a day), never after 第 and never after a qualifier: a part of the options, an estimate, a
// total or a rate ("其中两个", "大约三场", "一共有两场", "每周两场").
const ZH_NOT_COUNT_BEFORE = new RegExp(`(?:第[ \\t]{0,3}|(?<!周|週|星期|礼拜|禮拜)${ZH_NUMERAL}|(?<=周|週|星期|礼拜|禮拜)[七八九十百千两兩几幾零〇\\d]|${ZH_JOIN}[ \\t]{0,3}|(?:其中|前|头|頭|后|後|另|另外|其他|其它|其余|其餘|剩下|只有|仅有|僅有|只|仅|僅|至少|最多|约|約|大约|大約|大概|超过|超過|不到|将近|將近|接近|差不多|共|共有|一共|一共有|总共|總共|总共有|總共有|每|每周|每週|每天|每日|每月|每次)[ \\t]{0,3})$`);
const ZH_STOP = /[，。；,;：:！？!?\n]/;
// English counts are number words only: a digit is a day, an age or a time far more often ("December 5", "aged 3
// to 5"). Not after a qualifier or a range word ("about three", "only two", "the first two", "two or three").
const EN_BEFORE_WORDS = 'to|and|or|aged?|ages|between|from|under|over|than|of|about|around|roughly|approximately|nearly|almost|least|most|only|just|another|other|first|last|top';
const EN_NOT_COUNT_BEFORE = new RegExp(`(?:\\b(?:${EN_BEFORE_WORDS})\\s+|[-–—]\\s*)$`, 'i');
const EN_NOT_AFTER = '(?:to|or|and|of|out|more|plus|hours?|hrs?|minutes?|mins?|days?|nights?|weeks?|weekends?|months?|years?|yrs?|kids?(?![\\w-])|children|adults?|people|persons?|grown-?ups|seniors|times|blocks?|miles?|stops?|dollars?|bucks)\\b';
const EN_NOT_AFTER_AHEAD = new RegExp(`^[ \\t]+${EN_NOT_AFTER}`, 'i');
const EN_FILLER = '(?:to|for|at|in|on|of|from|near|with|by|and|or|but|than|per|each|is|are|was|were|will|can|have|has|that|which)\\b';
// API-BB-8 (live 10-17, L08 "Yes, two East Bay farmers markets run on Saturday mornings"): markets, museums, libraries,
// parks, storytimes, programmes, shows and fairs are options too.
const EN_SIMPLE = new RegExp(`(two|three|four|five|six)[ \\t]+(?!${EN_NOT_AFTER})(?:(?!${EN_FILLER})[a-z][a-z'’-]*[ \\t]+){0,4}?(?:events|options|places|choices|activities|festivals|ideas|picks|markets|museums|libraries|parks|venues|spots|storytimes|programs|programmes|classes|workshops|shows|concerts|exhibits|exhibitions|fairs|parades)\\b`, 'iy');
// Review of API-BB-8: "The festival has two shows" counts what one record contains, not the options. A count of shows,
// concerts, classes … right after has / have / includes / features / offers / hosts / with is no count of the options.
const EN_CONTENT_NOUN = /\b(?:storytimes|programs|programmes|classes|workshops|shows|concerts|exhibits|exhibitions|parades)$/i;
const EN_CONTAINS_BEFORE = /\b(?:has|have|had|includes?|including|features?|featuring|offers?|hosts?|with)[ \t]+$/i;
const EN_WORD = /\b(?:one|two|three|four|five|six)\b/gi;
const DASH = /[-–—]/;
const WIDE = /[㐀-鿿　-〿＀-￯]/;

// A streamed zh count digit at p that is not a plain count yet: true once later characters cannot make it one.
function zhSettled(text, p) {
  let index = p + 1;
  while (index < text.length && index - p <= 3 && (text[index] === ' ' || text[index] === '\t')) index++;
  if (index >= text.length) return false; // "有两" / "有 2 ": the measure word may still come
  if (!ZH_UNIT_CHAR.test(text[index])) return true; // "两点", "2岁", "两三"
  const tail = text.slice(index + 1, index + 41);
  if (!tail) return false;
  if (ZH_NOT_OPTION_AHEAD.test(tail) || ZH_APPROX_AHEAD.test(tail) || !ZH_SIMPLE_NEXT.has(tail[0])) return true;
  return ZH_STOP.test(tail) || tail.length >= 26;
}
// A streamed English number word that is not a plain count yet: true once later words cannot make it one (six
// words follow, or anything that is not a word). EN_SIX_WORDS is the short way to the first answer.
const EN_SIX_WORDS = /(?:[\s'’-]*[a-z][a-z'’-]*(?![a-z'’-])){6}/iy;
function enSettled(text, end) {
  const window = text.slice(end, end + 200);
  if (!window.trim()) return false;
  if (DASH.test(window[0]) || EN_NOT_AFTER_AHEAD.test(window)) return true;
  EN_SIX_WORDS.lastIndex = 0;
  if (EN_SIX_WORDS.test(window) || /[^a-z'’\-\s]/i.test(window)) return true;
  return (window.match(/[a-z][a-z'’-]*/gi) || []).length >= 6;
}
/**
 * The counts in a lead: `phrases` (every count-like phrase, zh and English), `simple` (the plain counts of options:
 * { start, end, value, replacement, en }) and, while the lead streams (`streaming`), `cut`: the first count whose
 * reading later characters could still change (the draft shows the text before it). A streamed lead is held from
 * its first plain or unsettled count, so while streaming the scan stops there and `phrases` is not counted (the
 * draft writer calls this on every flush).
 */
function countsIn(text, locale, streaming) {
  let phrases = 0, cut = text.length, held = text.length;
  const simple = [];
  if (locale !== 'en') {
    if (!streaming) {
      for (let index = 0; index < text.length; index++) {
        if (ZH_UNIT_CHAR.test(text[index]) && ZH_PHRASE_BEFORE.test(text.slice(Math.max(0, index - 16), index)) && !ZH_NOT_OPTION_AHEAD.test(text.slice(index + 1, index + 5))) phrases++;
      }
    }
    for (const match of text.matchAll(/[两兩二三四五六2-6]/g)) {
      const p = match.index;
      const before = text.slice(Math.max(0, p - 12), p);
      if (ZH_NOT_COUNT_BEFORE.test(before)) continue;
      ZH_SIMPLE.lastIndex = p;
      const found = ZH_SIMPLE.exec(text);
      if (found) {
        const end = p + found[0].length - found[1].length - found[2].length;
        const prefix = /[这這那][ \t]*$/.test(before);
        // 这两个地方 -> 这些地方, 去两个地方 -> 去这些地方, 下面两个活动 -> 下面的活动.
        const replacement = prefix ? '些' : !found[1] && ZH_BARE.has(found[2]) ? (locale === 'zh-Hant' ? '這些' : '这些') : /(?:下面|上面)[ \t]*$/.test(before) ? '的' : '';
        simple.push({ start: p, end, value: ZH_NUMBER[text[p]], replacement, nounEnd: p + found[0].length });
        if (streaming) { held = p; break; }
      } else if (streaming && !zhSettled(text, p)) { cut = held = p; break; }
    }
  }
  for (const match of text.matchAll(EN_WORD)) {
    const p = match.index, end = p + match[0].length;
    if (p >= held) break;
    // A hyphenated word ("two-year-old", "two-day") is not a count; while streaming, "two" at the end may still become one.
    if (DASH.test(text[p - 1] || '') || DASH.test(text[end] || '')) continue;
    phrases++;
    if (/^one$/i.test(match[0]) || EN_NOT_COUNT_BEFORE.test(text.slice(Math.max(0, p - 16), p))) continue;
    EN_SIMPLE.lastIndex = p;
    if (EN_SIMPLE.test(text)) {
      if (EN_CONTENT_NOUN.test(text.slice(p, EN_SIMPLE.lastIndex)) && EN_CONTAINS_BEFORE.test(text.slice(Math.max(0, p - 16), p))) continue;
      simple.push({ start: p, end, value: EN_NUMBER[match[0].toLowerCase()], replacement: '', en: true, nounEnd: EN_SIMPLE.lastIndex });
      if (streaming) break;
    } else if (streaming && !enSettled(text, end)) { cut = p; break; }
  }
  return { phrases, simple: simple.filter(count => count.start < cut).sort((a, b) => a.start - b.start), cut };
}
function stripCount(text, count) {
  let before = text.slice(0, count.start), after = text.slice(count.end);
  if (count.en) {
    after = after.replace(/^[ \t]+/, '');
    // A sentence start, also inside an opening quote or bracket ('"Two free events" fit' -> '"Free events" fit').
    const head = before.replace(/[ \t"'“‘(]+$/, '');
    if (!head || /[.!?]["'’”)]?$/.test(head)) after = after.replace(/^[a-z]/, letter => letter.toUpperCase());
  } else {
    // "有 2 场免费活动" loses the space with the count; "Oakland 两场活动" keeps the space after the name.
    let trim = before.length;
    while (trim > 0 && (before[trim - 1] === ' ' || before[trim - 1] === '\t')) trim--;
    if (trim < before.length && (!trim || WIDE.test(before[trim - 1]))) before = before.slice(0, trim);
  }
  return before + count.replacement + (count.keep || '') + after;
}
// A count beside "the rest" / "each" / 其余 / 各 is a part of the options or a rate ("Two events need tickets; the
// rest are free", "周六和周日各有两场"), never their number. A count that other words in the lead refer back to
// ("Both are in Oakland", "the third is paid", 二选一, 二者, 第三场, 另一场) stays too: without it they read wrong.
const PARTS = new RegExp([
  '其余|其餘|剩下|其他的|其它的|另外的|各|分别|分別|每',
  '[二两兩三四五六][选選]一|任[选選]|[二两兩]者|第[ \\t]*[三四五六3-6]|另一|另外一',
  '\\b(?:the rest|the others|others|remaining|each|per|apiece|both|either|neither|another|the (?:third|fourth|fifth|sixth|other))\\b',
].join('|'), 'i');
/** The lead's plain count of the options (its only count, a plain form, not beside "the rest" / 各), or null. */
function plainCount(text, locale) {
  const { phrases, simple } = countsIn(text, locale, false);
  return phrases === 1 && simple.length === 1 && !PARTS.test(text) ? simple[0] : null;
}
const optionCount = points => points.filter(point => (point?.cardIds || []).length).length || points.length;
// Citation markers the reader never sees; the draft writer's sanitizeDraft drops the same ones.
const MARKER = /(?<!\s)\s*\[\[[^\]]{0,100}\]\]|\[\d+\]/g;
/** The lead with a plain count of the options removed when it differs from the listed options; otherwise the lead.
 * The count is read on the lead without its citation markers, as the streamed lead shows it ("两场[[e1]]免费活动"
 * is a plain count), and removed from the lead itself; a marker inside the count keeps the lead whole. */
function countRepaired(lead, locale, points, siteListed = true) {
  if (!Array.isArray(points) || points.length < 2) return lead;
  const at = [];
  let visible = '', last = 0;
  for (const marker of lead.matchAll(MARKER)) {
    for (let index = last; index < marker.index; index++) at.push(index);
    visible += lead.slice(last, marker.index); last = marker.index + marker[0].length;
  }
  if (!last) visible = lead;
  else { for (let index = last; index < lead.length; index++) at.push(index); visible += lead.slice(last); }
  const count = plainCount(visible, locale);
  if (!count) return lead;
  if (count.value === optionCount(points)) return siteListed ? scopeAttributed(lead, visible, count, last ? at : null, locale) : lead;
  if (!last) return stripCount(lead, count);
  // A marker inside the count ("两 [[e1]] 场") stays where the count was.
  const start = at[count.start], end = at[count.end - 1] + 1, shown = new Set(at.slice(count.start, count.end));
  let keep = '';
  for (let index = start; index < end; index++) if (!shown.has(index)) keep += lead[index];
  return stripCount(lead, { ...count, start, end, keep: keep.trim() });
}
// API-BB-8 (live 10-17, L08 "Yes, two East Bay farmers markets run on Saturday mornings"): a count that matches the
// listed options and says that many exist (zh after 有, en as the subject, after "Yes," / "There are" / "has") reads
// as every market in the East Bay, when it is the ones BAYLINK lists. It says so: zh "有 BAYLINK 收录的两个农夫市集"
// (inserted where the count starts), en "two East Bay farmers markets listed on BAYLINK run …" (after the option
// noun). Both are at or after the point where the streamed lead is held (leadDraftText), so the streamed lead stays a
// prefix of the result. A lead that already names its scope (BAYLINK, 收录, listed) and a count that refers back
// ("这两个地方", "两场…都", "Here are three ideas") are left as they are. Review of API-BB-8: only when the options are
// BAYLINK's (siteListed: no point cites a web search result or names a web candidate). A count of what one record
// contains ("The festival has two shows") is no count of the options (EN_CONTENT_NOUN in countsIn). A digit after the
// inserted words is spaced as the engine spaces numbers ("收录的 5 个").
const SCOPE_NAMED = /BAYLINK|收录|收錄|列出|站内|站內|\blist(?:s|ed|ing)?\b|\bon (?:the )?site\b/i;
const ZH_EXISTS_BEFORE = /(?<![我你您他她它们們])有[ \t]*$/;
const EN_EXISTS_BEFORE = /(?:^|[.!?:;—–]\s*)(?:(?:yes|no|yep)\s*[,!—–-]?\s*)?$|\bthere\s+(?:are|were|is|will\s+be)\s+$|\b(?:has|have|had)\s+$/i;
function scopeAttributed(lead, visible, count, at, locale) {
  if (SCOPE_NAMED.test(visible)) return lead;
  const before = visible.slice(0, count.start);
  if (count.en ? !EN_EXISTS_BEFORE.test(before) : !ZH_EXISTS_BEFORE.test(before)) return lead;
  // Positions in the lead itself (its citation markers are not in `visible`).
  const position = index => !at ? index : index < at.length ? at[index] : lead.length;
  if (count.en) {
    const insert = at ? at[count.nounEnd - 1] + 1 : count.nounEnd;
    return `${lead.slice(0, insert)} listed on BAYLINK${lead.slice(insert)}`;
  }
  const insert = position(count.start);
  const traditional = locale === 'zh-Hant';
  const lead0 = lead.slice(0, insert), rest = lead.slice(insert).replace(/^(\d+)(?=[㐀-鿿])/, '$1 ');
  const space = /[ \t]$/.test(lead0) || !lead0 ? '' : ' ';
  const after = /^\d/.test(rest) ? ' ' : '';
  return `${lead0}${space}BAYLINK ${traditional ? '收錄' : '收录'}的${after}${rest}`;
}
/** The lead text a draft may show while it streams. Until the points are known (`points`, from the finished
 * answer), it stops before a plain count of the options and before a count whose reading later characters could
 * still change ("周六带两个" … "孩子" or "活动"; "There are two" … "free options"); with the points it is the
 * result's lead, so the streamed lead is always a prefix of the result and ends as it. */
function leadDraftText(text, { done = false, locale = 'zh-Hans', points, siteListed = true } = {}) {
  const value = String(text || '');
  if (done) {
    if (Array.isArray(points)) return countRepaired(value, locale, points, siteListed);
    const count = plainCount(value, locale);
    return count ? value.slice(0, count.start).trimEnd() : value;
  }
  const { simple, cut } = countsIn(value, locale, true);
  const hold = simple.reduce((least, count) => Math.min(least, count.start), cut);
  return value.slice(0, hold).trimEnd();
}
const CANNOT_TELL = /(?:不能|无法|無法|没法|沒法)(?:判断|判斷|比较|比較|确定|確定)(?:哪|是否更)|\b(?:can(?:no|')t|cannot|unable to) (?:tell|say|judge|compare) which\b/i;
const CHOICE_LEAD = /更|最|选|選|建议|建議|推荐|推薦|\b(?:better|best|easiest|go with|pick|choose|recommend)\b/i;
/**
 * Deterministic repair of a lead that contradicts its points (captain item (e)):
 * - a plain count in the lead ("两场免费活动") that differs from the listed options loses the
 *   number ("免费活动"), which reads naturally in Chinese and English;
 * - a lead that chooses, followed by a point that says the options cannot be compared,
 *   loses that point when other points remain.
 * Returns { draft, repairs[] }; the draft is unchanged when nothing contradicts.
 */
function leadConsistency(draft, { locale = 'zh-Hans', siteListed = true } = {}) {
  if (!draft || typeof draft.lead !== 'string' || !Array.isArray(draft.points)) return { draft, repairs: [] };
  const repairs = [];
  let { lead, points } = draft;
  const counted = countRepaired(lead, locale, points, siteListed);
  if (counted !== lead) { repairs.push(counted.length > lead.length ? 'lead_scope' : 'lead_count'); lead = counted; }
  if (CHOICE_LEAD.test(lead) && !CANNOT_TELL.test(lead) && points.length > 1 && points.some(point => CANNOT_TELL.test(point.text))) {
    const kept = points.filter(point => !CANNOT_TELL.test(point.text));
    if (kept.length) { points = kept; repairs.push('lead_choice'); }
  }
  // A gap that repeats what the lead or a point already says ("以官方为准" twice) is dropped.
  let gap = draft.gap;
  if (typeof gap === 'string' && gap && overlap(gap, [lead, ...points.map(point => point.text)].join(' ')) >= 0.5) { gap = ''; repairs.push('gap_repeat'); }
  return { draft: repairs.length ? { ...draft, lead, points, gap } : draft, repairs };
}
// Share of a text's CJK bigrams (or English words of 4+ letters) found in another text.
function overlap(text, other) {
  const units = value => {
    // A citation marker is at most 100 characters inside (the citeRefs bound): unbounded,
    // a run of [[ with no closing ]] in a model-written text was quadratic.
    const plain = String(value).replace(/\[\[[^\]]{0,100}\]\]/g, ''), cjk = plain.replace(/[^㐀-鿿]/g, '');
    return cjk.length >= 4 ? [...new Set(Array.from({ length: cjk.length - 1 }, (_, index) => cjk.slice(index, index + 2)))] : [...new Set(plain.toLowerCase().match(/[a-z]{4,}/g) || [])];
  };
  const mine = units(text);
  if (mine.length < 3) return 0;
  const theirs = new Set(units(other));
  return mine.filter(unit => theirs.has(unit)).length / mine.length;
}
/**
 * Points that recommend only records outside the asked area (a San Francisco museum for an
 * Oakland weekend) are dropped when other points remain. areaOf(ref) is the record's region,
 * or null (guides, named records, unknown region); points without records are kept.
 */
// API-BB-6 (live 10-15, L06 and L08): a weekly market's listed dates are BAYLINK's calendar, not its season. The model
// no longer sees the listing window (lib/baybayEvidence.js weeklyListing); this is the net when an answer still says
// "starting Sat, Oct 17", "from Oct 17 through Dec 12" or 从10月18日（周日）开始 about the weekly record itself.
// Review (10-16): only a point that cites the record (or, citing nothing, names it), or a lead / gap sentence that
// does, is repaired; another record's "from Oct 24 through Dec 12" or 10月17日起 is its own date and stays. A range is
// one window's own pair (first or next listed date to the last), never two dates of the union, and a range inside the
// asked dates is the asked day or weekend itself. Each pattern starts at its keyword or digit (no leading \s*): a
// whitespace-padded draft was cubic at the fast draft's own field bounds.
const EN_MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const EN_DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
function dateForms(iso) {
  const [, month, day] = iso.split('-').map(Number);
  const weekday = new Date(`${iso}T12:00:00Z`).getUTCDay();
  const zhDay = `(?:[（(]\\s*(?:周|週|星期|礼拜|禮拜)[日天一二三四五六]\\s*[)）])?`;
  const enDay = `(?:(?:${EN_DAYS[weekday]}|${EN_DAYS[weekday].slice(0, 3)})\\.?,?\\s+)?`;
  const en = `${enDay}(?:${EN_MONTHS[month - 1]}|${EN_MONTHS[month - 1].slice(0, 3)})\\.?\\s+${day}(?:st|nd|rd|th)?\\b`;
  return { zh: `(?:${month}\\s*月\\s*${day}\\s*[日号號]?${zhDay}|${month}/${day}(?!\\d)${zhDay})`, en: `(?:${en}|${month}/${day}(?!\\d))` };
}
const LISTING_MARKET = /农夫市集|農夫市集|市集|farmers['’]?\s?markets?/i;
const LISTING_STOP = new Set(['farmers', 'market', 'markets', 'certified', 'weekly', 'every', 'saturday', 'sunday', 'year', 'round']);
const LISTING_CITE = /\[\[([^\]]{0,100})\]\]/g;
// Review round 2 (10-16): a segment that cites nothing is about every market once it says 农夫市集 / farmers market, so
// "先逛农夫市集，再去 OMCA 看10月17日起开放的新展" lost the exhibit's own date. In such a segment a phrase belongs to the
// nearest subject before it (with none before, the first one after it): the market (its name words or the market noun)
// or another subject: an evidence record that is not a weekly market, named by a distinctive title word; an exhibit /
// festival / show noun; in Chinese prose, any other Latin name that is not a city, a weekday or month, or a market.
// Only a phrase whose nearest subject is the market is removed. A sentence that calls the dates the listed dates
// (列出的日期, "listed dates") is honest and stays.
const LISTING_MARKET_ALL = new RegExp(LISTING_MARKET.source, 'gi');
const LISTING_OTHER_NOUN = /展览|展覽|新展|特展|展出|博物馆|博物館|美术馆|美術館|图书馆|圖書館|故事时间|故事時間|南瓜|游行|遊行|音乐会|音樂會|演出|庆典|慶典|嘉年华|嘉年華|丰收节|豐收節|亡灵节|亡靈節|灯光节|燈光節|\b(?:exhibits?|exhibitions?|museums?|library|storytimes?|pumpkins?|parade|concerts?|performances?|festival|show|class(?:es)?|workshops?|fair)\b/gi;
const LISTING_HONEST = /列出的日期|列出日期|listed (?:dates?|on)\b/i;
const LISTING_CJK = /[㐀-鿿]/;
const CITY_NAMES = Object.entries(require('../data/city-search-aliases.json')).flatMap(([city, names]) => [city, ...names]).map(String);
const LISTING_CITY_WORDS = new Set(CITY_NAMES.flatMap(name => name.toLowerCase().match(/[a-z]+/g) || []));
const LISTING_CITY_CJK = CITY_NAMES.filter(name => LISTING_CJK.test(name));
const LISTING_GENERIC = new Set([...EN_MONTHS, ...EN_DAYS].flatMap(word => [word.toLowerCase(), word.slice(0, 3).toLowerCase()]).concat(['sept', 'tues', 'thur', 'thurs',
  'bart', 'muni', 'caltrain', 'ferry', 'california', 'family', 'families', 'kids', 'children', 'free', 'community', 'center', 'centre', 'park', 'downtown',
  'morning', 'afternoon', 'evening', 'night', 'with', 'from', 'this', 'that', 'and', 'the', 'for', 'you', 'are']));
const LISTING_CJK_GENERIC = /[周週末日月天年]|亲子|親子|活动|活動|免费|免費|孩子|儿童|兒童|家庭|市集|农夫|農夫/;
const spansOf = (lower, words) => words.flatMap(word => {
  const found = [];
  for (let at = lower.indexOf(word); at !== -1; at = lower.indexOf(word, at + word.length)) found.push([at, at + word.length]);
  return found;
});
const regexSpans = (text, pattern) => [...text.matchAll(pattern)].map(match => [match.index, match.index + match[0].length]);
// API-BB-7 (live 10-16, L08): an English answer writes 12-hour times, as the cards do ("9am–2pm"), not "9:00-14:00".
// A time already followed by am / pm (or a.m. / p.m., with or without the final dot), a ratio or a score inside other digits, and a [[ref]] are left alone.
const CLOCK_RANGE = /(?<![\d:.])([01]?\d|2[0-3]):([0-5]\d)\s*(?:-|–|—|to)\s*([01]?\d|2[0-3]):([0-5]\d)(?![\d:]|\s*(?:(?:am|pm)\b|a\.m\b|p\.m\b))/gi;
const CLOCK_ONE = /(?<![\d:.])([01]?\d|2[0-3]):([0-5]\d)(?![\d:]|\s*(?:(?:am|pm)\b|a\.m\b|p\.m\b)|\s*[-–—]\s*\d)/gi;
const twelve = (hour, minute) => `${Number(hour) % 12 || 12}${minute !== '00' ? `:${minute}` : ''}${Number(hour) < 12 ? 'am' : 'pm'}`;
function englishClock(text) {
  return String(text).replace(CLOCK_RANGE, (match, h1, m1, h2, m2) => {
    const [from, to] = [twelve(h1, m1), twelve(h2, m2)];
    return from.slice(-2) === to.slice(-2) ? `${from.slice(0, -2)}–${to}` : `${from}–${to}`;
  }).replace(CLOCK_ONE, (match, hour, minute) => twelve(hour, minute));
}
function englishClockRepair(draft, { locale } = {}) {
  if (locale !== 'en' || !draft) return { draft, repaired: false };
  const fix = value => (typeof value === 'string' ? englishClock(value) : value);
  const next = { ...draft, lead: fix(draft.lead), gap: fix(draft.gap), points: Array.isArray(draft.points) ? draft.points.map(point => ({ ...point, text: fix(point.text) })) : draft.points };
  return { draft: next, repaired: JSON.stringify(next) !== JSON.stringify(draft) };
}
function listingWindowRepair(draft, { windows = [], asked = null, others = [] } = {}) {
  if (!draft || !windows.length) return { draft, repaired: false };
  const alternation = (dates, key) => [...new Set(dates.filter(Boolean))].map(iso => dateForms(iso)[key]).join('|');
  const rows = windows.filter(row => row.end && (row.start || row.next)).map(row => {
    const starts = [row.start, row.next], ends = [row.end];
    const en = alternation(starts, 'en'), enEnd = alternation(ends, 'en'), zh = alternation(starts, 'zh'), zhEnd = alternation(ends, 'zh');
    // The record's name: its title before the colon, without the market noun or the weekday.
    const words = [...new Set((row.titles || []).flatMap(title => String(title || '').split(/[：:]/)[0].replace(/农夫市集|農夫市集|市集|(?:周|週|星期)[一二三四五六日天]/g, ' ').toLowerCase().match(/[a-z]{4,}|[㐀-鿿]{2,}/g) || []))]
      .filter(word => !LISTING_STOP.has(word));
    return { refs: row.refs || [], words, titleText: (row.titles || []).join(' ').toLowerCase(), market: (row.titles || []).some(title => LISTING_MARKET.test(title || '')), patterns: [
      new RegExp(`\\b(?:starting|beginning|from|as of)\\s+(?:on\\s+)?(?:${en})(?:\\s*(?:through|to|until|till|–|—|-)\\s*(?:${enEnd}))?`, 'gi'),
      new RegExp(`\\b(?:through|until|till)\\s+(?:${enEnd})`, 'gi'),
      new RegExp(`(?:从|從|自)\\s*(?:${zh})\\s*(?:起|开始|開始)(?:\\s*(?:至|到|–|—|-|～|~)\\s*(?:${zhEnd}))?`, 'g'),
      new RegExp(`(?:${zh})\\s*(?:起|开始|開始)`, 'g'),
      new RegExp(`(?:(?:从|從|自)\\s*)?(?:${zh})\\s*(?:至|到|–|—|-|～|~)\\s*(?:${zhEnd})(?:\\s*(?:期间|期間|之间|之間))?`, 'g'),
    ], dates: [...new Set([...starts, ...ends].filter(Boolean))] };
  });
  const range = asked?.start ? { start: asked.start, end: asked.end || asked.start } : null;
  const dateTests = [...new Set(rows.flatMap(row => row.dates))].map(iso => { const form = dateForms(iso); return [iso, new RegExp(`${form.zh}|${form.en}`, 'i')]; });
  // A range whose dates all fall on the asked day or weekend is that day or weekend, not a season.
  const askedOnly = phrase => {
    if (!range) return false;
    const hit = dateTests.filter(([, pattern]) => pattern.test(phrase)).map(([iso]) => iso);
    return hit.length >= 2 && hit.every(iso => iso >= range.start && iso <= range.end);
  };
  const names = (row, lower) => {
    if (row.market && LISTING_MARKET.test(lower)) return true;
    return row.words.length > 0 && row.words.filter(word => lower.includes(word)).length >= Math.min(2, row.words.length);
  };
  // A segment is about the record when it cites it, or cites nothing and names it.
  const about = (row, text, cardIds) => {
    const refs = [...[...text.matchAll(LISTING_CITE)].map(match => match[1].trim()), ...cardIds].filter(Boolean);
    return refs.length ? refs.some(ref => row.refs.includes(ref)) : names(row, text.toLowerCase());
  };
  // The other subjects an uncited segment can name (see LISTING_OTHER_NOUN above).
  const marketWords = new Set(rows.flatMap(row => row.words));
  const plainWord = word => !LISTING_STOP.has(word) && !LISTING_GENERIC.has(word) && !LISTING_CITY_WORDS.has(word) && !marketWords.has(word);
  const otherWords = [...new Set(others.flatMap(other => (other.titles || []).flatMap(title => {
    const head = String(title || '').split(/[：:—–|·]/)[0].toLowerCase();
    const cjk = (head.match(/[㐀-鿿]{2,}/g) || []).flatMap(run => (run.length <= 2 ? [run] : Array.from({ length: run.length - 2 }, (_, at) => run.slice(at, at + 3))));
    return [...(head.match(/[a-z]{4,}/g) || []).filter(plainWord), ...cjk.filter(word => !LISTING_CJK_GENERIC.test(word) && !LISTING_CITY_CJK.some(city => city.includes(word) || word.includes(city)))];
  })))];
  // One replace call sees one string: its subjects are found once, not once per matched phrase.
  let found = { row: null, whole: null };
  const subjects = (row, whole) => {
    if (found.row === row && found.whole === whole) return found;
    const lower = whole.toLowerCase();
    const own = [...(row.market ? regexSpans(whole, LISTING_MARKET_ALL) : []), ...spansOf(lower, row.words)];
    const latin = LISTING_CJK.test(whole) ? regexSpans(whole, /[A-Za-z]{3,}/g).filter(([from, to]) => plainWord(lower.slice(from, to)) && !row.titleText.includes(lower.slice(from, to))) : [];
    const other = [...regexSpans(whole, LISTING_OTHER_NOUN).filter(([from, to]) => !row.titleText.includes(lower.slice(from, to))), ...spansOf(lower, otherWords), ...latin];
    // By start; at the same start the other subject sorts last, so it wins the tie and the phrase stays.
    const marks = [...own.map(([from, to]) => [from, to, true]), ...other.map(([from, to]) => [from, to, false])].sort((a, b) => a[0] - b[0] || b[2] - a[2]);
    found = { row, whole, marks };
    return found;
  };
  const marketNearest = (row, whole, start, end) => {
    const { marks } = subjects(row, whole);
    let low = 0, high = marks.length;
    while (low < high) { const mid = (low + high) >> 1; if (marks[mid][0] < start) low = mid + 1; else high = mid; }
    for (let at = low - 1; at >= 0; at--) if (marks[at][1] <= start) return marks[at][2];
    for (let at = low; at < marks.length; at++) if (marks[at][0] >= end) return marks[at][2];
    return true;
  };
  let repaired = false;
  const fixSegment = (segment, cardIds) => {
    if (LISTING_HONEST.test(segment)) return segment;
    const cited = cardIds.length > 0 || /\[\[[^\]]{0,100}\]\]/.test(segment);
    let text = segment;
    for (const row of rows) {
      if (!about(row, segment, cardIds)) continue;
      for (const pattern of row.patterns) {
        text = text.replace(pattern, (phrase, offset, whole) => (askedOnly(phrase) || (!cited && !marketNearest(row, whole, offset, offset + phrase.length)) ? phrase : ''));
      }
    }
    if (text === segment) return segment;
    repaired = true;
    // The removed phrase's own padding goes; the space before the next sentence stays.
    const indent = /^\s/.test(segment) ? ' ' : '';
    return indent + text.replace(/(?<!\s)\s+(?=[,，。.;；!！?？])/g, '').replace(/([，,])\s*([，,。.])/g, '$2').replace(/^[\s，,]+/, '').replace(/ {2,}/g, ' ').trim();
  };
  // The lead and the gap sentence by sentence (each delimiter stays with its sentence); a point as a whole. A period
  // after a month or weekday abbreviation ("Oct. 17", "Sat. Oct 17") does not end the sentence.
  const fixProse = value => (typeof value !== 'string' || !value ? value : value.split(/(?<=[。！？!?；;])|(?<=\.)(?<!\b(?:Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|Mon|Tue|Tues|Wed|Thu|Thur|Thurs|Fri|Sat|Sun)\.)(?=\s)/i).map(part => fixSegment(part, [])).join('').trim());
  const lead = fixProse(draft.lead), gap = fixProse(draft.gap);
  const points = (draft.points || []).map(point => {
    if (typeof point?.text !== 'string' || !point.text) return point;
    const text = fixSegment(point.text, Array.isArray(point.cardIds) ? point.cardIds : []);
    return text === point.text ? point : { ...point, text: text.trim() };
  });
  return repaired ? { draft: { ...draft, lead, gap, points }, repaired } : { draft, repaired };
}

function dropOffArea(draft, { region, areaOf } = {}) {
  if (!draft || !region || region === 'all' || !Array.isArray(draft.points) || draft.points.length < 2) return { draft, dropped: 0 };
  // The ref is trimmed after matching, as in citeRefs: padding inside the pattern (\s*, lazy
  // ref, \s*) backtracked cubically on [[ and a long run of spaces in a model-written point.
  const refsOf = point => [...new Set([...(point.cardIds || []), ...[...String(point.text || '').matchAll(/\[\[([^\]]{0,100})\]\]/g)].map(match => match[1].trim()).filter(Boolean)])];
  const off = point => { const regions = refsOf(point).map(areaOf); return regions.length > 0 && regions.every(value => value && value !== region); };
  const kept = draft.points.filter(point => !off(point));
  // Only padding is dropped: at least one in-area recommendation must remain.
  if (!kept.some(point => refsOf(point).length) || kept.length === draft.points.length) return { draft, dropped: 0 };
  const keptRefs = new Set(kept.flatMap(refsOf));
  const droppedRefs = new Set(draft.points.filter(point => off(point)).flatMap(refsOf));
  return { draft: { ...draft, points: kept, candidateIds: (draft.candidateIds || []).filter(ref => !droppedRefs.has(ref) || keptRefs.has(ref)) }, dropped: draft.points.length - kept.length };
}

// H73 (audit 10-13, BB-1013-10; API-BB-4B): a point that rules its own record out ("Randall Museum is
// closed Sundays, so it won't work" on a Sunday ask) keeps its words but not its card: the excluded
// place is not shown as an option. Only a self-exclusion counts (review 10-14): a clause whose
// subject is the record (it, this one, 这里, 它, its title) and that ends the recommendation ("so it
// won't work", "so it is not an option", 所以这天去不了), or "closed <the asked weekday>" said of the
// record itself. Never a conditional sentence (如果, 的话, if, unless), a remark about a part of the
// visit ("Strollers won't work on the upper trail", "Parking is not an option on Sundays",
// "the boat rental is closed Mondays"), "can't go wrong", or a closed day that is qualified
// ("in winter only") or sits beside an open or free statement.
const CONDITIONAL = /如果|假如|若是|要是|的话|的話|万一|萬一|\b(?:if|unless|in case|otherwise)\b/i;
// The English self-exclusion ends its clause (review round 3), optionally with the day or "for
// you": "so it won't be open late", "so it won't fit a full day" and "It is not an option for
// strollers" are remarks about one part of the visit, as is any exclusion followed by but / though.
const EXCLUSION_TAIL_EN = String.raw`(?:\s+(?:this (?:weekend|week|time|sunday|monday|tuesday|wednesday|thursday|friday|saturday)|that day|on (?:that day|the day|sundays?|mondays?|tuesdays?|wednesdays?|thursdays?|fridays?|saturdays?)|today|tonight|tomorrow|for (?:you|us|your family|this trip|this plan|today|this weekend)))?(?=\s*(?:[,.;:!?)—–]|\s-\s|$))`;
const SELF_EXCLUDED_EN = new RegExp(String.raw`\b(?:so|which means|meaning|that means|therefore|hence)\s+(?:it|this(?: one| place| museum| event| option)?|that(?: one| place)?|the (?:museum|event|park|library|place|venue|festival|show))\s+(?:won['’]?t|will not|doesn['’]?t|does not|isn['’]?t|is not|can['’]?t|cannot)\s+(?:work|be an option|fit|suit (?:you|your (?:family|plans?|schedule|day))|be open)${EXCLUSION_TAIL_EN}|\b(?:it|this one|this place|that one)\s+(?:is|['’]s)\s+(?:not an option|ruled out|off the list)${EXCLUSION_TAIL_EN}|\brul(?:e|es|ed|ing) (?:it|this one|that one) out${EXCLUSION_TAIL_EN}`, 'i');
const EXCLUSION_TURN_EN = /\b(?:but|though|although|however|yet)\b/i;
const selfExcludedEn = sentence => {
  const match = sentence.match(SELF_EXCLUDED_EN);
  return !!match && !EXCLUSION_TURN_EN.test(sentence.slice(match.index + match[0].length));
};
const CLAUSE_END = '(?=[，,。；;！!？?\\s\\[]|$)';
const SELF_EXCLUDED_ZH = new RegExp(`(?:所以|因此|它|这里|這裡|该馆|該館|这家|這家|这场|這場|这个地方|這個地方)[^，,。；;！!？?]{0,6}(?:去不了|不能去|不行|不合适|不合適|不适合|不適合|不推荐|不推薦)${CLAUSE_END}|(?:这天|這天|那天|当天|當天|(?:周|週|星期)[一二三四五六日天])就?(?:去不了|不能去)${CLAUSE_END}|不(?:推荐|推薦)(?:这|這|它)(?:里|裡|个|個|家|场|場)?${CLAUSE_END}|排除(?:这|這|它)`);
const CLOSED_ZH = /(?:周|週|星期)([一二三四五六日天])([^。；;，,]{0,6}?)(闭馆|閉館|休馆|休館|不开放|不開放|关门|關門|不营业|不營業)/;
const CLOSED_EN = /\b(?:is |are |['’]s )?(?:always |usually |normally )?closed (?:on |this )?(sun|mon|tue|wed|thu|fri|sat)[a-z]*/i;
const CLOSED_QUALIFIED = /只|仅|僅|冬季|夏季|淡季|除了|以外|之外|(?<!不)开放|(?<!不)開放|(?<!不)营业|(?<!不)營業|免费|免費|\b(?:only|except|in (?:winter|summer|the off-season)|seasonal(?:ly)?|until|through|but|opens?|open(?:ed)? (?:this|on|today|tomorrow)|free)\b/i;
const RECORD_SUBJECT_EN = /(?:^|\b)(?:it|this(?: one| place| museum| library)?|that(?: one| place)?|the (?:museum|library|venue|center|centre|gallery|zoo|place|branch))\s*$/i;
const RECORD_SUBJECT_ZH = /(?:它|这里|這裡|该馆|該館|本馆|本館|博物馆|博物館|图书馆|圖書館)\s*$/;
const sentencesOf = text => String(text || '').replace(/\[\[[^\]]+\]\]/g, ' ').split(/[。；;！!？?]|\.(?=\s|$)/).map(part => part.trim()).filter(Boolean);
function dropExcludedCards(draft, { date, titleOf } = {}) {
  if (!draft || !Array.isArray(draft.points)) return { draft, refs: [] };
  const weekday = typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date) ? new Date(`${date}T12:00:00Z`).getUTCDay() : null;
  // The words before "closed" name the record: nothing (the sentence starts with it), it / this
  // museum / 该馆, or words of the record's own title.
  const namesRecord = (before, titles) => {
    const subject = before.replace(/\s*(?:is|are|['’]s)?\s*(?:always|usually|normally)?\s*$/i, '').trim();
    if (!subject || RECORD_SUBJECT_EN.test(subject) || RECORD_SUBJECT_ZH.test(subject)) return true;
    return titles.some(title => {
      const words = String(title).toLowerCase().match(/[a-z0-9]{3,}|[㐀-鿿]{2,}/g) || [];
      const lower = subject.toLowerCase();
      return words.length > 0 && words.filter(word => lower.includes(word)).length >= Math.min(2, words.length);
    });
  };
  const closedThatDay = (sentence, titles) => {
    if (weekday === null || Number.isNaN(weekday) || CLOSED_QUALIFIED.test(sentence)) return false;
    const zh = sentence.match(CLOSED_ZH);
    // 闭馆 / 休馆 is the venue itself; 不开放 / 关门 / 不营业 may be one part of it (周一游船不开放): the
    // words between the day and the verb, or else before the day, must name the record.
    const middle = zh ? zh[2].replace(/^[\s都也均是会會就]+|[\s都也均是会會就]+$/g, '') : '';
    if (zh && '日一二三四五六'.indexOf(zh[1] === '天' ? '日' : zh[1]) === weekday && (/闭馆|閉館|休馆|休館/.test(zh[3]) || namesRecord(middle || sentence.slice(0, zh.index), titles))) return true;
    const en = sentence.match(CLOSED_EN);
    return !!en && ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].indexOf(en[1].toLowerCase()) === weekday && namesRecord(sentence.slice(0, en.index), titles);
  };
  const excludes = point => {
    const titles = (point.cardIds || []).map(ref => titleOf?.(ref)).filter(Boolean);
    // A closed-day remark beside an open or free statement in the same point is a note, not an exclusion.
    const pointQualified = CLOSED_QUALIFIED.test(String(point.text || '').replace(/\[\[[^\]]+\]\]/g, ' '));
    return sentencesOf(point.text).some(sentence => !CONDITIONAL.test(sentence)
      && (selfExcludedEn(sentence) || SELF_EXCLUDED_ZH.test(sentence) || (!pointQualified && closedThatDay(sentence, titles))));
  };
  const refs = new Set();
  const points = draft.points.map(point => {
    if (!(point.cardIds || []).length || !excludes(point)) return point;
    point.cardIds.forEach(ref => refs.add(ref));
    return { ...point, cardIds: [] };
  });
  if (!refs.size) return { draft, refs: [] };
  const kept = new Set(points.flatMap(point => point.cardIds || []));
  const excluded = [...refs].filter(ref => !kept.has(ref));
  return { draft: { ...draft, points, candidateIds: (draft.candidateIds || []).filter(ref => !excluded.includes(ref)) }, refs: excluded };
}

// ---- (f) why a provider call failed: a fixed vocabulary, never provider text ----------
const FAILURE_CODES = new Set(['AI_DAILY_LIMIT', 'AI_DAILY_BUDGET', 'AI_WEB_BUDGET', 'AI_QUOTA_UNAVAILABLE', 'AI_CALL_LIMIT', 'AI_PROVIDER_TIMEOUT', 'REQUEST_CANCELLED']);
const QUOTA_CODES = new Set(['AI_DAILY_LIMIT', 'AI_DAILY_BUDGET', 'AI_WEB_BUDGET', 'AI_QUOTA_UNAVAILABLE']);
const SOCKET_CODES = new Set(['UND_ERR_SOCKET', 'UND_ERR_CLOSED', 'ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN']);
/** {kind, status?, code?} for a failed provider call: quota, timeout, cancelled, http (with
 * the HTTP status), stream or other. Safe to log and to return in research.modelResponses. */
function failureReason(error) {
  const message = String(error?.message || '');
  const code = FAILURE_CODES.has(error?.code) ? error.code : undefined;
  const http = Number(message.match(/\bHTTP (\d{3})\b/)?.[1]);
  const status = Number.isInteger(http) && http >= 100 && http < 600 ? http : Number.isInteger(error?.status) && error.status >= 100 && error.status < 600 ? error.status : undefined;
  // API-BB-5: "fetch failed" (a socket closed or reset below HTTP) is 'connection', with its socket code when the
  // code is one of a fixed set; before, it was 'other' (live 10-15, L07).
  const socket = String(error?.cause?.code || error?.code || '');
  const connection = !http && error?.name === 'TypeError' && /fetch failed/i.test(message);
  const kind = QUOTA_CODES.has(code) ? 'quota' : code === 'AI_PROVIDER_TIMEOUT' || /timed out/i.test(message) ? 'timeout'
    : code === 'REQUEST_CANCELLED' || error?.name === 'AbortError' ? 'cancelled' : http ? 'http' : connection ? 'connection' : /stream|event|json/i.test(message) ? 'stream' : 'other';
  return { kind, ...(status ? { status } : {}), ...(code ? { code } : {}), ...(connection && SOCKET_CODES.has(socket) ? { socket } : {}) };
}

// ---- B8: a newcomer's setup answer always names the SSN step -----------------------
// The model keeps to the site's newcomer guides, which never mention it (live eval: the
// rule alone did not hold), so a setup answer without it gets the step appended as its
// last point, in the wording of the SSA professional template.
const SSN_MENTION = /SSN|社安|社会安全|社會安全|社会保障号|社會保障號|Social Security/i;
const SSN_POINT = ['社安号（SSN）：向 SSA 免费申请；申请移民签证时勾选过的，入境后一般会把卡寄到你填的美国地址，没收到可打 1-800-772-1213（可要求中文口译）。',
  '社安號（SSN）：向 SSA 免費申請；申請移民簽證時勾選過的，入境後一般會把卡寄到你填的美國地址，沒收到可撥 1-800-772-1213（可要求中文口譯）。',
  'Social Security number (SSN): free from SSA; if you asked for it on your immigrant visa application, the card is usually mailed to your U.S. address after you arrive. If it does not come, call 1-800-772-1213 (interpreters available).'];
/** Appends the SSN step to a newcomer setup answer that leaves it out. */
function ensureNewcomerSsn(draft, { message = '', state = {}, locale = 'zh-Hans' } = {}) {
  if (!draft || !Array.isArray(draft.points) || !(state.goal === 'newcomer' || NEWCOMER_SETUP.test(String(message || '')))) return { draft, added: false };
  if (SSN_MENTION.test([draft.lead, ...draft.points.map(point => point.text), draft.gap].join(' '))) return { draft, added: false };
  const points = [...draft.points.slice(0, 4), { text: SSN_POINT[LOCALE_INDEX(locale)], cardIds: [] }];
  return { draft: { ...draft, points }, added: true };
}

// ---- API-BB-8: a point keeps its source; a plan's points and lead follow its stops ----
// Live 10-17 (api bc0ee27): L08 ("Any farmers markets in the East Bay on Saturday morning?") came back with 0 sources.
// The model's output (698 characters) was its draft without one [[ref]]: both points named their market in cardIds and
// cited nothing, so no repair step had dropped anything and nothing put a source back. In L07 the market stop's point
// cited nothing either (its only ref was a store id, s-…, not an evidence ref). And L07's lead named Ferry Building
// before the market although the plan visits the market first, and no point gave a stop's clock time or card.
const CITED = /\[\[[^\]]{0,100}\]\]/;
// The Chinese name of a Latin venue name, and back, as plan answers write them ("渡轮大厦" for Ferry Building).
const STOP_NAME_PAIRS = [
  [/\bferry building\b|渡轮大厦|渡輪大廈/i, ['ferry building', '渡轮大厦', '渡輪大廈']],
  [/\bchinatown\b|唐人街|华埠|華埠/i, ['chinatown', '唐人街', '华埠', '華埠']],
  [/\bfisherman['’]?s wharf\b|渔人码头|漁人碼頭/i, ['fisherman\'s wharf', '渔人码头', '漁人碼頭']],
  [/\bgolden gate park\b|金门公园|金門公園/i, ['golden gate park', '金门公园', '金門公園']],
  [/\bgolden gate bridge\b|金门大桥|金門大橋/i, ['golden gate bridge', '金门大桥', '金門大橋']],
  [/\bunion square\b|联合广场|聯合廣場/i, ['union square', '联合广场', '聯合廣場']],
  [/\bpalace of fine arts\b|艺术宫|藝術宮/i, ['palace of fine arts', '艺术宫', '藝術宮']],
  [/\bpier 39\b|39\s*号码头|39\s*號碼頭/i, ['pier 39', '39号码头', '39號碼頭']],
];
const STOP_CJK_GENERIC = new Set(['一日', '半天', '半日', '一圈', '安排', '行程', '指南', '活动', '活動', '公园', '公園', '图书馆', '圖書館', '博物馆', '博物館', '市集', '中心', '分馆', '分館', '周六', '週六', '周日', '週日']);
const STOP_LATIN_GENERIC = new Set(['the', 'a', 'an', 'and', 'of', 'at', 'in', 'park', 'museum', 'library', 'market', 'markets', 'center', 'centre', 'downtown', 'visit', 'day', 'tour', 'walk', 'guide', 'free', 'family', 'saturday', 'sunday']);
/** The names a stop goes by in prose: its title's and aliases' parts, the Latin names inside them, their pairs. */
function stopNames(stop) {
  const names = new Set();
  for (const name of [stop?.title, ...(Array.isArray(stop?.aliases) ? stop.aliases : [])].filter(value => typeof value === 'string' && value)) {
    for (const [pattern, pair] of STOP_NAME_PAIRS) if (pattern.test(name)) pair.forEach(value => names.add(value));
    for (const part of name.split(/[·•：:|｜—–()（）/,，、;；]+|\s-\s/)) {
      for (const run of part.match(/[A-Za-z][A-Za-z0-9'’.]*(?:[ \t]+[A-Za-z0-9][A-Za-z0-9'’.]*)*/g) || []) {
        const words = run.toLowerCase().split(/[ \t]+/);
        if (run.replace(/[^A-Za-z]/g, '').length >= 4 && !words.every(word => STOP_LATIN_GENERIC.has(word) || LISTING_CITY_WORDS.has(word))) names.add(words.join(' '));
      }
      for (const run of part.match(/[㐀-鿿]{2,}/g) || []) for (const piece of run.split(/[与與和及]/)) if (piece.length >= 2 && !STOP_CJK_GENERIC.has(piece)) names.add(piece);
    }
  }
  return [...names];
}
/** Each stop's names, without a name two stops share (it names neither). */
function stopNameSets(stops) {
  const sets = stops.map(stopNames);
  const count = new Map();
  for (const set of sets) for (const name of set) count.set(name, (count.get(name) || 0) + 1);
  return sets.map(set => set.filter(name => count.get(name) === 1));
}
const LATIN_EDGE = /[a-z0-9]/i;
/** Where a stop's names occur in a text: merged spans (a gap of spaces joins two names: "Ferry Plaza 农夫市集"). */
function stopSpans(text, names) {
  const lower = String(text || '').toLowerCase(), spans = [];
  for (const name of names) {
    const latin = /^[a-z]/.test(name);
    for (let at = lower.indexOf(name); at !== -1; at = lower.indexOf(name, at + name.length)) {
      if (latin && (LATIN_EDGE.test(lower[at - 1] || '') || LATIN_EDGE.test(lower[at + name.length] || ''))) continue;
      spans.push([at, at + name.length]);
    }
  }
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged = [];
  for (const span of spans) {
    const last = merged.at(-1);
    if (last && (span[0] <= last[1] || /^[ \t]+$/.test(lower.slice(last[1], span[0])))) last[1] = Math.max(last[1], span[1]);
    else merged.push([...span]);
  }
  return merged;
}
/** The stops a sentence names, in the order it first names them. */
function namedStops(text, nameSets) {
  return nameSets.map((names, index) => ({ index, span: stopSpans(text, names)[0] })).filter(entry => entry.span).sort((a, b) => a.span[0] - b.span[0]).map(entry => entry.index);
}
// Review of API-BB-8: moving only the names is safe only in a plain list of stops. Between two mentions there may be
// nothing but list connectors: zh 、，, 和 与 與 及 跟, then optionally 然后/接着/最后 or 再 (+ 去/到/逛); en ", " / "and" /
// "then". Anything else ("渡轮大厦的农夫市集", "渡轮大厦前的", "从渡轮大厦出发，逛…", "唐人街离…", "from the Ferry Building to
// …", "Chinatown for dim sum, then browse …") describes one stop, and would move to the wrong stop with its name.
const ZH_LIST_GAP = /^[、，,]?(?:和|与|與|及|跟)?(?:(?:然后|然後|接着|接著|最后|最後)再?(?:去|到|逛)?|再(?:去|到|逛)?)?$/;
const EN_LIST_GAP = /^(?:,|(?:,[ \t]*)?(?:and|then|and then))$/i;
// Nothing locative or possessive before the first mention, and only punctuation (or the end) after the last one:
// "海边的 Ferry Building", "from the Ferry Building", "the city's Chinatown", "唐人街吃点心" keep their stop.
const ZH_BEFORE_LIST = /[的从從到离離]$/;
const EN_BEFORE_LIST = /(?:\b(?:from|to|into|toward|towards|near|outside|at|in|of|by|around|behind|beside|past|across|off)|['’]s)$/i;
const AFTER_LIST = /^[ \t]*(?:$|[，。,.;；:：!！?？)）—–])/;
// Second review of API-BB-8: and the sentence's words before the first mention say only when and that one goes there:
// day or part-of-day words, then optionally 先/可以/可, then a generic visit verb (zh 逛/去/游/走走/看看/参观; en visit/see/
// explore/tour/start with/stop by). "午饭去…", "早茶：…", "先吃…", "Dim sum: …" tie an activity to the first stop.
const ZH_TIME = '(?:(?:这个?|這個?|本|下个?|下個?)?(?:周|週|星期|礼拜|禮拜)[一二三四五六日天末]|今天|明天|后天|後天|上午|下午|中午|早上|早晨|清晨|傍晚|晚上|午后|午後|半天|一天|全天|整天|当天|當天)';
const ZH_LIST_OPENING = new RegExp(`^(?:${ZH_TIME}[，,：:、]?){0,4}(?:可以先|可先|可以|可|先|就)?(?:逛逛|逛|去|到|游|遊|走走|看看|参观|參觀)?$`);
const EN_TIME = '(?:(?:on|this|next)[ \\t]+)?(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|weekend|today|tomorrow)(?:[ \\t]+(?:morning|afternoon|evening))?|(?:in[ \\t]+the[ \\t]+)?(?:morning|afternoon|evening)';
const EN_LIST_OPENING = new RegExp(`^(?:(?:${EN_TIME})[ \\t]*[,:]?[ \\t]*){0,3}(?:(?:you[ \\t]+can|you[ \\t]+could|first)[ \\t]+)?(?:visit|see|explore|tour|start[ \\t]+with|stop[ \\t]+by)?$`, 'i');
const CJK_CHAR = /[㐀-鿿]/, LATIN_CHAR = /[A-Za-z0-9]/;
/**
 * A lead that names the plan's stops out of visiting order as a plain list ("逛渡轮大厦、农夫市集，再去唐人街" for market
 * → Ferry Building → Chinatown) names them in order: each stop's one mention moves into the slots the mentions take, in
 * stop order ("逛农夫市集、渡轮大厦，再去唐人街"); an English mention takes its "the" with it. A lead that names a stop
 * twice or fewer than two stops is left alone, and so is one whose mentions are not a plain list (mismatch: true).
 */
function leadStopOrder(lead, stops) {
  if (typeof lead !== 'string' || !Array.isArray(stops) || stops.length < 2) return { lead, repaired: false };
  const sets = stopNameSets(stops);
  const mentions = [];
  for (let index = 0; index < sets.length; index++) {
    const spans = stopSpans(lead, sets[index]);
    if (spans.length > 1) return { lead, repaired: false };
    if (spans.length) mentions.push({ index, span: [...spans[0]] });
  }
  if (mentions.length < 2) return { lead, repaired: false };
  const byPlace = [...mentions].sort((a, b) => a.span[0] - b.span[0]);
  if (byPlace.some((entry, at) => at && entry.span[0] < byPlace[at - 1].span[1])) return { lead, repaired: false };
  if (byPlace.every((entry, at) => !at || entry.index > byPlace[at - 1].index)) return { lead, repaired: false };
  // A Latin mention's article is part of it ("the Ferry Building").
  for (const [at, entry] of byPlace.entries()) {
    const article = /\bthe[ \t]+$/i.exec(lead.slice(at ? byPlace[at - 1].span[1] : 0, entry.span[0]));
    if (article && LATIN_CHAR.test(lead[entry.span[0]])) entry.span[0] -= article[0].length;
  }
  const zh = CJK_CHAR.test(lead);
  const unchanged = { lead, repaired: false, mismatch: true };
  const before = lead.slice(0, byPlace[0].span[0]).trimEnd(), after = lead.slice(byPlace.at(-1).span[1]);
  if ((zh && ZH_BEFORE_LIST.test(before)) || EN_BEFORE_LIST.test(before) || !AFTER_LIST.test(after)) return unchanged;
  const opening = before.slice(Math.max(...[...(zh ? '。！？!?；;' : '.!?;')].map(mark => before.lastIndexOf(mark))) + 1);
  if (zh ? !ZH_LIST_OPENING.test(opening.replace(/[ \t]+/g, '')) : !EN_LIST_OPENING.test(opening.trim())) return unchanged;
  const gaps = byPlace.slice(1).map((entry, at) => lead.slice(byPlace[at].span[1], entry.span[0]));
  if (!gaps.every(gap => zh ? ZH_LIST_GAP.test(gap.replace(/[ \t]+/g, '')) && gap.trim() : EN_LIST_GAP.test(gap.trim().replace(/[ \t]+/g, ' ')))) return unchanged;
  const names = [...mentions].sort((a, b) => a.index - b.index).map(entry => lead.slice(entry.span[0], entry.span[1]));
  if (zh) {
    // Chinese: spaces only where a Latin name meets a Chinese character ("逛 Ferry Building", "农夫市集、渡轮大厦").
    const join = (left, right) => (CJK_CHAR.test(left.at(-1) || '') && LATIN_CHAR.test(right[0] || '')) || (LATIN_CHAR.test(left.at(-1) || '') && CJK_CHAR.test(right[0] || '')) ? ' ' : '';
    const pieces = [before, ...names.flatMap((name, at) => at < gaps.length ? [name, gaps[at].trim()] : [name]), after.replace(/^[ \t]+/, '')];
    return { lead: pieces.reduce((out, piece) => piece ? out + join(out, piece) + piece : out, ''), repaired: true };
  }
  let out = '', cursor = 0;
  byPlace.forEach((entry, at) => {
    const head = lead.slice(cursor, entry.span[0]);
    // A mention at the start of a sentence starts with a capital ("The Ferry Plaza …"); elsewhere its article is "the".
    const start = !(out + head).trim() || /[.!?][ \t]*$/.test(out + head);
    const name = names[at].replace(/^the(?=[ \t])/i, start ? 'The' : 'the');
    out += head + (start ? name[0].toUpperCase() + name.slice(1) : name); cursor = entry.span[1];
  });
  return { lead: out + lead.slice(cursor), repaired: true };
}
const CLOCK_IN_TEXT = /\d{1,2}[:：]\d{2}|\b\d{1,2}\s*(?:am|pm|a\.m\.|p\.m\.)(?![a-z])|\d{1,2}\s*[点點](?!心)|\bnoon\b|中午/i;
// Review of API-BB-8: the note says the time is the record's ("记录的开放时段", "Recorded hours"). It follows the point's own
// last sentence, joined with "，" when that sentence has no end mark yet; a point that already ends in "。" is not
// rewritten, because the streamed point (RC-21) already showed that "。" and must stay a prefix of the result.
const CLOCK_NOTE = { session: ['记录的场次', '記錄的場次', 'Listed time:'], hours: ['记录的开放时段', '記錄的開放時段', 'Recorded hours:'] };
/** A point with a clock note before its trailing citations: zh "…为准。记录的开放时段 8:00–14:00。", en "… Recorded hours: 8am–2pm." */
function withClockNote(text, clock, locale) {
  // The trailing [[ref]] markers, found from the end without a regex (a long run of spaces stays linear).
  let cut = text.trimEnd().length;
  for (;;) {
    const head = text.slice(0, cut);
    if (!head.endsWith(']]')) break;
    const open = head.lastIndexOf('[[');
    if (open < 0 || cut - open > 104 || head.slice(open + 2, cut - 2).includes(']')) break;
    cut = head.slice(0, open).trimEnd().length;
  }
  const tail = text.slice(cut), body = text.slice(0, cut).trimEnd();
  const label = CLOCK_NOTE[clock.kind]?.[LOCALE_INDEX(locale)] || CLOCK_NOTE.hours[LOCALE_INDEX(locale)];
  const note = locale === 'en' ? `${/[.!?]$/.test(body) ? ' ' : '. '}${label} ${clock.text}.` : `${/[。！？!?]$/.test(body) ? '' : '，'}${label} ${clock.text}。`;
  return `${body}${note}${tail}`;
}
/**
 * The stop each plan point is about. Review of API-BB-8: a point that names two stops ("逛完农夫市集后，走进渡轮大厦大厅休
 * 息") is not about the first one it names. A point that names one stop is about that stop. A point that names more is
 * about stop i only when the answer has a point per stop, it is point i, it names stop i, and no one-stop point is
 * about stop i (an opening overview that names every stop is about none); otherwise it is about none, and gets no
 * clock, card or stop ref.
 */
function pointStops(points, sets) {
  const named = points.map(point => typeof point?.text === 'string' && sets.length ? namedStops(point.text, sets) : []);
  const perStop = sets.length > 0 && points.length >= sets.length;
  const claimed = new Set(named.filter(list => list.length === 1).map(list => list[0]));
  return named.map((list, index) => list.length === 1 ? list[0] : perStop && index < sets.length && list.includes(index) && !claimed.has(index) ? index : -1);
}
/**
 * Points that keep their sources, and, in a plan answer, their stops' times and cards. stops: the plan's stops in
 * visiting order, each { title, aliases, refs, clock? } (clock { kind: 'session' | 'hours', text }); citable(ref): the
 * ref is an evidence ref or a store source. A point that cites nothing gets the refs it lists in cardIds, or the first
 * ref of the stop it is about (pointStops); a point about a stop with a clock time that gives none gets it. Both go at
 * the end of the point, so a streamed point stays a prefix of the result; a marker is spaced as the answer's own
 * markers are (always in English). stopOf[i] is the stop point i is about, or -1.
 */
// API-BB-10 (live 10-17, Q5): a point that gives an event's child prices also gives the adult tier its record lists ("0–3 岁免费，
// 4–14 岁 $5" left out the accompanying adult's "18+ $8"), so it never reads as if only the children pay. The tier is copied
// from the cited record's cost line, after the point's last child price.
const PRICE = /\$\s*\d+(?:\.\d{1,2})?/;
const ADULT_TIER = /(?:18\s*\+|1[89]\s*(?:岁|歲)\s*(?:及)?以上|成人|大人|\badults?\b)\s*[:：]?\s*\$\s*\d+(?:\.\d{1,2})?/i;
const CHILD_TIER = /(?:\d+\s*[–-]\s*\d+\s*(?:岁|歲)|\d+\s*(?:岁|歲)(?:及)?以下|儿童|兒童|孩子|小孩|\b(?:kids?|child(?:ren)?|ages?\s*\d+\s*[–-]\s*\d+)\b)[^，,；;。$]*\$\s*\d+(?:\.\d{1,2})?/gi;
const amount = value => value.match(PRICE)[0].replace(/\s/g, '');
function adultTierRepair(draft, { costOf = () => null, locale = 'zh-Hans' } = {}) {
  let repaired = false;
  const points = (draft.points || []).map(point => {
    const text = String(point.text || '');
    for (const [, ref] of text.matchAll(/\[\[([^\]]{1,40})\]\]/g)) {
      const cost = costOf(ref);
      const adult = typeof cost === 'string' ? ADULT_TIER.exec(cost) : null;
      if (!adult || text.replace(/\s/g, '').includes(amount(adult[0]))) continue;
      const childAmounts = new Set([...cost.matchAll(CHILD_TIER)].map(match => amount(match[0])));
      const last = [...text.matchAll(new RegExp(PRICE.source, 'g'))].filter(match => childAmounts.has(amount(match[0]))).at(-1);
      if (!last) continue;
      const at = last.index + last[0].length;
      repaired = true;
      return { ...point, text: `${text.slice(0, at)}${locale === 'en' ? ', ' : '、'}${adult[0].trim()}${text.slice(at)}` };
    }
    return point;
  });
  return { repaired, draft: repaired ? { ...draft, points } : draft };
}

function pointRepairs(draft, { citable = () => false, stops = [], locale = 'zh-Hans' } = {}) {
  if (!draft || !Array.isArray(draft.points)) return { draft, cited: 0, clocked: 0, stopOf: [] };
  const sets = stops.length ? stopNameSets(stops) : [];
  const about = pointStops(draft.points, sets);
  const spaced = locale === 'en' || draft.points.some(point => typeof point?.text === 'string' && /\s\[\[[^\]]{0,100}\]\]/.test(point.text));
  let cited = 0, clocked = 0;
  const stopOf = [];
  const points = draft.points.map((point, index) => {
    const at = about[index];
    stopOf.push(at);
    if (!point || typeof point.text !== 'string' || !point.text.trim()) return point;
    let text = point.text;
    const clock = at >= 0 ? stops[at].clock : null;
    if (clock?.text && !CLOCK_IN_TEXT.test(text)) { text = withClockNote(text, clock, locale); clocked++; }
    if (!CITED.test(text)) {
      const refs = [...new Set((Array.isArray(point.cardIds) ? point.cardIds : []).filter(citable))].slice(0, 2);
      if (!refs.length && at >= 0) refs.push(...(stops[at].refs || []).filter(citable).slice(0, 1));
      if (refs.length) { text = `${text.trimEnd()}${spaced ? ' ' : ''}${refs.map(ref => `[[${ref}]]`).join('')}`; cited++; }
    }
    return text === point.text ? point : { ...point, text };
  });
  return { draft: cited || clocked ? { ...draft, points } : draft, cited, clocked, stopOf };
}

module.exports = { adultTierRepair, cardInLocale, englishAlias, nearbyClarifier, turnRules, leadConsistency, listingWindowRepair, englishClock, englishClockRepair, leadDraftText, dropOffArea, dropExcludedCards, ensureNewcomerSsn, failureReason,
  stopNames, leadStopOrder, pointRepairs };
