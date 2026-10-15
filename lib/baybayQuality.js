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
const ZH_NUMBER = { 一: 1, 两: 2, 兩: 2, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6 };
const EN_NUMBER = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6 };
// What follows a count word and is never an option: people, ages, durations and periods ("两个孩子", "一家三口",
// "两个半小时", "两个周末"). Shared by the mismatch rule (ZH_COUNT) and the never-stated rule (ZH_MANY).
const ZH_UNIT = '(?:场|場|项|項|个|個|家|处|處|种|種|条|條|站|段)';
const ZH_NOT_OPTION = '(?:孩子|小孩|小朋友|朋友|宝宝|寶寶|儿子|兒子|女儿|女兒|学生|學生|大人|成人|老人|长辈|長輩|娃|人|岁|歲|半|小时|小時|钟头|鐘頭|分钟|分鐘|月|星期|礼拜|禮拜|晚|(?:周|週)(?:末|[一二三四五六日天])|[三四五六]口)';
const ZH_OPTION = '(?:活动|活動|选择|選擇|地方|去处|去處|选项|選項|免费|免費|市集|节|節|展|电影|電影|推荐|推薦|安排)';
const ZH_NOT_AFTER_DAY = '(?<![周週十初]|星期|礼拜|禮拜)';
// Review round 5: an approximate count ("两三个", "两到三个", "两、三个", "2-3个", "三五个") is left alone, as the English
// side leaves "two or three": its second number is never stripped or compared on its own ("两三场免费活动" read
// "两免费活动"). The 六 of 周六 is a day, not the first number of a range ("这周六三个地方" is still a count).
const ZH_NOT_RANGE = `(?<!${ZH_NOT_AFTER_DAY}[一两兩二三四五六七八九十几幾][ \\t]{0,3}(?:[到至或~～\\-–、][ \\t]{0,3})?)(?<!\\d[ \\t]{0,3}[到至或~～\\-–][ \\t]{0,3})`;
// "有两场免费活动" / "两项选择" / "two free events": a count of the options listed below. Not "第 2 站" (the site's
// spaced style too) or the "1" of "12个".
const ZH_COUNT = new RegExp(`(?<!第[ \\t]{0,3})(?<!\\d)${ZH_NOT_RANGE}([一两兩二三四五六\\d])[ \\t]{0,3}${ZH_UNIT}(?!${ZH_NOT_OPTION})(?=[^，。；,;]{0,12}(?:${ZH_OPTION}|$))`);
// English counts are number words only: a digit is a day, an age or a time far more often ("December 5", "aged 3 to 5").
const EN_COUNT = /(?<!\b(?:to|and|or|aged?|ages|between|from|under|over|than|of)\s+)(?<![-–])\b(one|two|three|four|five|six)\s+(?!(?:to|or|and|of|out|more|hours?|hrs?|minutes?|mins?|days?|nights?|weeks?|weekends?|months?|years?|yrs?|kids?|children|adults?|people|persons?|grown-?ups|seniors|times|blocks?|miles?|stops?)\b)(?=(?:[a-z'-]+\s+){0,4}(?:events?|options?|places?|choices?|activities|festivals?|ideas?|picks?)\b)/i;
// API-BB-5 (live 10-15, L04): the streamed lead said "two free options are open that weekend" and the result
// then said "free options are open", so the reader saw the lead change. The lead never states how many
// options there are (2-6): the draft writer strips the count while the lead streams (leadDraftText) and
// leadConsistency strips it from the result, so both read the same; "one" / "一" keep the mismatch-only rule below.
// Review (API-BB-5 round 1): the stripping must never damage a correct lead, so a count is only a number before
// an option noun, never a date ("December 5"), an age range ("aged 3 to 5"), a stop ("第 2 站"), people or a
// duration ("two hours"); "这两个地方" reads "这些地方"; a sentence that starts with the count keeps its capital.
// Review round 2: the 六 of 周六 / 星期六 and the 二 of 十二 are a day or a larger number, never a count; holding them while
// streaming froze the lead at 周 once the next flush read 周六两场 (the cut moved back).
// Review round 4: only 二-六 can be a weekday or the tail of a larger number; 两 / 兩 never are, so "这周两场" /
// "這週兩場" is a count and is held and stripped while streaming as the result strips it.
const ZH_MANY_DIGIT = `(?:[两兩]|${ZH_NOT_AFTER_DAY}[二三四五六]|[2-6])`;
const ZH_MANY_HEAD = new RegExp(`(?<!第[ \\t]{0,3})(?<!\\d)${ZH_NOT_RANGE}(这|這|那)?${ZH_MANY_DIGIT}[ \\t]{0,3}${ZH_UNIT}(?!${ZH_NOT_OPTION})`, 'g');
const ZH_OPTION_AHEAD = new RegExp(`^[^，。；,;]{0,12}${ZH_OPTION}`);
const ZH_END_AHEAD = /^[^，。；,;]{0,12}$/;
const ZH_TRAILING_NUMBER = new RegExp(`(?<!第[ \\t]{0,3})(?<!\\d)${ZH_NOT_RANGE}${ZH_MANY_DIGIT}[ \\t]{0,3}$`);
const EN_MANY_HEAD = /\b(?:two|three|four|five|six)\b/gi;
const EN_NOT_BEFORE = /(?:\b(?:to|and|or|aged?|ages|between|from|under|over|than|of)\s+|[-–])$/i;
const EN_NOT_AFTER = /^(?:\s*[-–]|\s+(?:to|or|and|of|out|more|hours?|hrs?|minutes?|mins?|days?|nights?|weeks?|weekends?|months?|years?|yrs?|kids?|children|adults?|people|persons?|grown-?ups|seniors|times|blocks?|miles?|stops?)\b)/i;
const EN_OPTION_AHEAD = /^\s+(?:[a-z'-]+\s+){0,4}(?:events?|options?|places?|choices?|activities|festivals?|ideas?|picks?)\b/i;
/** Where the stated counts are in a lead: { strips: [[start, end, replacement]], cut }. While the lead streams
 * (`streaming`), a count whose reading the next characters could still change sets `cut` (the draft shows the
 * text before it), so the draft is always a prefix of the result. */
function statedCounts(text, locale, streaming) {
  const strips = [];
  let cut = text.length;
  if (locale !== 'en') {
    for (const match of text.matchAll(ZH_MANY_HEAD)) {
      const end = match.index + match[0].length, after = text.slice(end, end + 16);
      const option = ZH_OPTION_AHEAD.test(after);
      // Held from the number, not from 这 / 那 ("这两个地方" may still read "这些地方").
      if (streaming && !option && after.length < 14 && !/[，。；,;]/.test(after)) { cut = Math.min(cut, match.index + (match[1] ? match[1].length : 0)); break; }
      if (!option && (streaming || !ZH_END_AHEAD.test(text.slice(end, end + 13)))) continue;
      // "去两个地方" reads "去这些地方", not "去地方".
      const bare = !match[1] && /^(?:地方|去处|去處|选择|選擇|选项|選項)/.test(after);
      strips.push([match.index, end, match[1] ? `${match[1]}些` : bare ? (locale === 'zh-Hant' ? '這些' : '这些') : '']);
    }
    if (streaming) {
      const trailing = text.slice(0, cut).match(ZH_TRAILING_NUMBER);
      if (trailing) cut = trailing.index;
    }
  }
  for (const match of text.matchAll(EN_MANY_HEAD)) {
    if (match.index >= cut) break;
    if (EN_NOT_BEFORE.test(text.slice(Math.max(0, match.index - 12), match.index))) continue;
    const end = match.index + match[0].length, window = text.slice(end, end + 200);
    const option = EN_OPTION_AHEAD.exec(window);
    const settled = (option && option[0].length < window.length) || /[^a-z'\-\s]/i.test(window) || (window.match(/[a-z'-]+(?=\s)/gi) || []).length >= 5;
    if (streaming && !settled) { cut = Math.min(cut, match.index); break; }
    if (!option || EN_NOT_AFTER.test(window)) continue;
    strips.push([match.index, end + window.match(/^\s*/)[0].length, '']);
  }
  return { strips: strips.filter(([start]) => start < cut).sort((a, b) => a[0] - b[0]), cut };
}
const WIDE = /[㐀-鿿　-〿＀-￯]/;
function removeCounts(text, locale, streaming) {
  const { strips, cut } = statedCounts(text, locale, streaming);
  // A streamed draft never ends in the space before a held count ("有 3 场" may become "有适合…").
  if (!strips.length) return streaming ? text.slice(0, cut).trimEnd() : text;
  let out = '', last = 0, upper = false, started = false;
  for (const [start, end, replacement] of strips) {
    let kept = text.slice(last, start);
    if (upper) kept = kept.replace(/^(\s*)([a-z])/, (all, space, letter) => space + letter.toUpperCase());
    // "有 3 场适合孩子的活动" loses the space with the count; "Oakland 两场活动" keeps the space after the name.
    // (Plain loops over the tail: a lead of thousands of spaces or counts stays linear.)
    if (!replacement) {
      let trim = kept.length;
      while (trim > 0 && (kept[trim - 1] === ' ' || kept[trim - 1] === '\t')) trim--;
      if (trim < kept.length && (trim ? WIDE.test(kept[trim - 1]) : !out || WIDE.test(out.at(-1)))) kept = kept.slice(0, trim);
    }
    out += kept + replacement;
    started ||= /\S/.test(kept + replacement);
    upper = !replacement && (!started || /[.!?]\s*$/.test(out.slice(-8))) && !WIDE.test(text[end] || '');
    last = end;
    if (!replacement && (!out || WIDE.test(out.at(-1)))) while (last < cut && (text[last] === ' ' || text[last] === '\t')) last++;
  }
  let rest = text.slice(last, cut);
  if (upper) rest = rest.replace(/^(\s*)([a-z])/, (all, space, letter) => space + letter.toUpperCase());
  const value = (out + rest).replace(/[ \t]{2,}/g, ' ').replace(/^[ \t]+/, '');
  return streaming ? value.trimEnd() : value;
}
/** A lead without a stated count of options ("有两场免费活动" -> "有免费活动", "two free options" -> "free options"). */
function withoutStatedCount(lead, locale = 'zh-Hans') {
  const text = String(lead || '');
  return removeCounts(text, locale, false);
}
/** The lead text a draft may show while it streams: no stated count, and a count whose reading later
 * characters could still change ("周六带两个" … "孩子" or "活动"; "There are two" … "free options") held back. */
function leadDraftText(text, { done = false, locale = 'zh-Hans' } = {}) {
  return removeCounts(String(text || ''), locale, !done);
}
const CANNOT_TELL = /(?:不能|无法|無法|没法|沒法)(?:判断|判斷|比较|比較|确定|確定)(?:哪|是否更)|\b(?:can(?:no|')t|cannot|unable to) (?:tell|say|judge|compare) which\b/i;
const CHOICE_LEAD = /更|最|选|選|建议|建議|推荐|推薦|\b(?:better|best|easiest|go with|pick|choose|recommend)\b/i;
/**
 * Deterministic repair of a lead that contradicts its points (captain item (e)):
 * - a count in the lead ("两场免费活动") that differs from the listed options loses the
 *   number ("免费活动"), which reads naturally in Chinese and English;
 * - a lead that chooses, followed by a point that says the options cannot be compared,
 *   loses that point when other points remain.
 * Returns { draft, repairs[] }; the draft is unchanged when nothing contradicts.
 */
function leadConsistency(draft, { locale = 'zh-Hans' } = {}) {
  if (!draft || typeof draft.lead !== 'string' || !Array.isArray(draft.points)) return { draft, repairs: [] };
  const repairs = [];
  let { lead, points } = draft;
  // API-BB-5: a count of 2-6 options is never stated, matching or not (what the streamed draft showed).
  const uncounted = withoutStatedCount(lead, locale);
  if (uncounted !== lead) { lead = uncounted; repairs.push('lead_count'); }
  const options = points.filter(point => (point.cardIds || []).length).length || points.length;
  const zh = locale !== 'en' ? lead.match(ZH_COUNT) : null;
  const en = !zh ? lead.match(EN_COUNT) : null;
  const stated = zh ? (/\d/.test(zh[1]) ? Number(zh[1]) : ZH_NUMBER[zh[1]]) : en ? (/\d/.test(en[1]) ? Number(en[1]) : EN_NUMBER[en[1].toLowerCase()]) : null;
  if (stated && stated !== options && points.length > 1 && !repairs.includes('lead_count')) {
    lead = zh ? lead.replace(zh[0], '') : lead.replace(en[0], '');
    lead = lead.replace(/\s{2,}/g, ' ').replace(/^\s+/, '').replace(/^[a-z]/, letter => letter.toUpperCase());
    repairs.push('lead_count');
  }
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

module.exports = { cardInLocale, englishAlias, nearbyClarifier, turnRules, leadConsistency, withoutStatedCount, leadDraftText, dropOffArea, dropExcludedCards, ensureNewcomerSsn, failureReason };
