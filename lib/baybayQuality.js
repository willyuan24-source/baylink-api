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
const NEARBY = /附近|周边|周邊|旁边|旁邊|这一带|這一帶|\b(?:near(?:by| me| here)|around here|close by)\b/i;
const FIND_PLACE = /吃|喝|餐|饭|飯|咖啡|奶茶|早餐|早茶|超市|商店|店|买|買|玩|逛|公园|公園|景点|景點|去处|去處|地方|活动|活動|图书馆|圖書館|厕所|廁所|停车|停車|加油|\b(?:eat|food|restaurants?|caf[eé]s?|coffee|boba|groceries|grocery|shops?|stores?|parks?|things to do|places?|library|parking)\b/i;
/** One short question when the user asks for something 附近 and BayBay knows no city,
 * area, origin or page (C11): a list of far-apart places is not an answer. */
function nearbyClarifier(message, { state = {}, hasPage = false, locale = 'zh-Hans' } = {}) {
  if (hasPage || state.city || (state.region && state.region !== 'all') || state.origin || state.originCandidateId) return null;
  const text = String(message || '');
  if (!NEARBY.test(text) || !FIND_PLACE.test(text)) return null;
  return ['你现在在湾区哪个城市，或哪个地标附近？告诉我后，我只推荐那附近的。例如：“我在 Cupertino 图书馆附近”。',
    '你現在在灣區哪個城市，或哪個地標附近？告訴我後，我只推薦那附近的。例如：「我在 Cupertino 圖書館附近」。',
    'Which Bay Area city or landmark are you near? Tell me and I will only suggest places close by, for example "near Cupertino Library".'][LOCALE_INDEX(locale)];
}

// ---- conditional rules for this turn (sent after the user turn, never in block 1) ---
const CHOOSE = /哪个更|哪個更|哪个最|哪個最|哪(?:一)?个好|哪(?:一)?個好|选哪|選哪|只挑|挑一个|挑一個|更合适|更合適|最适合|最適合|最轻松|最輕鬆|\bwhich (?:one )?(?:is )?(?:better|best|easiest|closer|closest)\b|\bpick one\b/i;
const NEWCOMER_SETUP = /(?:新移民|刚移民|剛移民|移民来|移民來|刚来美国|剛來美國|刚到美国|剛到美國|刚来湾区|剛來灣區|刚到湾区|剛到灣區|刚搬来|剛搬來|新来|新來|落地)[^。？?！!]{0,24}(?:办|辦|做|准备|準備|清单|清單|事情|事)|(?:第一(?:周|週|个月|個月)|頭一個月|头一个月)[^。？?！!]{0,12}(?:办|辦|做|准备|準備|清单|清單)|\b(?:new (?:immigrant|arrival)s?|just (?:moved|arrived))\b[^.?!]{0,60}\b(?:do|set up|checklist|first)\b/i;
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
  if (state.freeOnly || /免[费費]|\bfree\b/i.test(text)) rules.push('Free options: name every record in evidence that is free (cost or text says free or 免费) and fits the asked date and area, up to five, best fit first (family and child-friendly first when children come). Never say only one, or none, is free unless every record in evidence was checked and the others clearly cost money; a paid or unknown-cost record is not a reason to say the rest are not free.');
  if (state.goal === 'newcomer' || NEWCOMER_SETUP.test(text)) rules.push('Newcomer setup checklist: cover the core official steps in order of urgency, one short point each, citing evidence where it exists: a Social Security number from SSA (free; an immigrant who asked for it on the immigrant visa application usually gets the card by mail); a phone number and a bank account; a California driver license or state ID from the DMV; health coverage (Medi-Cal through the county or BenefitsCal, Covered California, or work insurance); school enrollment for children with the school district; a library card. Do not decide anyone\'s eligibility; never ask for ID or Social Security numbers.');
  return rules;
}

// ---- (e) the lead must not contradict the points ----------------------------------
const ZH_NUMBER = { 一: 1, 两: 2, 兩: 2, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6 };
const EN_NUMBER = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6 };
// "有两场免费活动" / "两项选择" / "two free events": a count of the options listed below.
const ZH_COUNT = /([一两兩二三四五六\d])\s*(?:场|場|项|項|个|個|家|处|處|种|種|条|條|站|段)(?!孩子|小孩|大人|成人|老人|长辈|長輩|娃|人|岁|歲)(?=[^，。；,;]{0,12}(?:活动|活動|选择|選擇|地方|去处|去處|选项|選項|免费|免費|市集|节|節|展|电影|電影|推荐|推薦|安排|$))/;
const EN_COUNT = /\b(one|two|three|four|five|six|[1-6])\s+(?=(?:[a-z'-]+\s+){0,4}(?:events?|options?|places?|choices?|activities|festivals?|ideas?|picks?)\b)/i;
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
  const options = points.filter(point => (point.cardIds || []).length).length || points.length;
  const zh = locale !== 'en' ? lead.match(ZH_COUNT) : null;
  const en = !zh ? lead.match(EN_COUNT) : null;
  const stated = zh ? (/\d/.test(zh[1]) ? Number(zh[1]) : ZH_NUMBER[zh[1]]) : en ? (/\d/.test(en[1]) ? Number(en[1]) : EN_NUMBER[en[1].toLowerCase()]) : null;
  if (stated && stated !== options && points.length > 1) {
    lead = zh ? lead.replace(zh[0], '') : lead.replace(en[0], '');
    lead = lead.replace(/\s{2,}/g, ' ').replace(/^\s+/, '');
    repairs.push('lead_count');
  }
  if (CHOICE_LEAD.test(lead) && !CANNOT_TELL.test(lead) && points.length > 1 && points.some(point => CANNOT_TELL.test(point.text))) {
    const kept = points.filter(point => !CANNOT_TELL.test(point.text));
    if (kept.length) { points = kept; repairs.push('lead_choice'); }
  }
  return { draft: repairs.length ? { ...draft, lead, points } : draft, repairs };
}

module.exports = { cardInLocale, englishAlias, nearbyClarifier, turnRules, leadConsistency };
