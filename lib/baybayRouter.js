// Deterministic BayBay router for BAYBAY_ENGINE=v2 (overhaul API-BB-ENGINE;
// baybay.md §3.1). Decided before any model call, from facts the server already
// computed for the turn; no I/O and no model.
//
//   emergency    the 911-first card (lib/safetyRouting.js), no model
//   outing       deterministic squad search (server.js runs it before BayBay)
//   agent        the research loop with tools: day plans, plan edits and
//                follow-ups on a published plan, two or more named stops, and
//                members who asked for (or need) a live web lookup
//   fast         one call, no tools, structured lead-first answer
//                (lib/baybayFastPath.js); guarded professional topics take this
//                path on the baybay_professional route (never Haiku, RC-20)
//
// v1 (the default) never calls this module.

const PLAN_EDITS = new Set(['replace', 'remove', 'select', 'invalid']);

/**
 * @param {object} turn
 * @param {boolean} [turn.emergency]        emergencyResponse() matched
 * @param {boolean} [turn.outing]           the deterministic outing search answered
 * @param {object|null} [turn.professional] the professional guard (safetyRouting)
 * @param {object} turn.state               resolved task state (goal, city, date, …)
 * @param {object|null} [turn.edit]         preparePlanEdit() result
 * @param {string[]} [turn.explicitCandidateIds] stops the user named this turn
 * @param {boolean} [turn.planFollowup]     a published plan is in scope (same city/date/goal)
 * @param {boolean} [turn.planRequest]      asksForPlan(): a plan-shaped ask the task state did not classify
 * @param {string} [turn.searchMode]        'site' | 'smart' | 'web' after access rules
 * @param {boolean} [turn.timely]           the question needs a current fact
 * @returns {{path: 'emergency'|'outing'|'agent'|'fast', route?: string, reason: string}}
 */
function routeBayBay({ emergency = false, outing = false, professional = null, state = {}, edit = null, explicitCandidateIds = [], planFollowup = false, planRequest = false, searchMode = 'site', timely = false } = {}) {
  if (emergency) return { path: 'emergency', reason: 'emergency_lexicon' };
  if (outing) return { path: 'outing', reason: 'outing_intent' };
  if (state.goal === 'day-plan') return { path: 'agent', route: 'baybay_agent', reason: 'day_plan' };
  if (edit && PLAN_EDITS.has(edit.kind)) return { path: 'agent', route: 'baybay_agent', reason: 'plan_edit' };
  if (explicitCandidateIds.length >= 2) return { path: 'agent', route: 'baybay_agent', reason: 'named_stops' };
  if (planFollowup) return { path: 'agent', route: 'baybay_agent', reason: 'plan_followup' };
  // v1 runs every turn through the tool loop, so a plan the task state does not
  // classify (幫我排行程, "Plan a Saturday …", 帮我排一下顺序) can still get create_plan
  // there; v2 keeps that parity by sending it to the agent too.
  if (planRequest && !professional) return { path: 'agent', route: 'baybay_agent', reason: 'plan_request' };
  // Guests are site-only; a member's Web mode, or Smart mode on a time-sensitive
  // question, keeps the server pre-search and the research loop.
  if (searchMode === 'web' || (searchMode === 'smart' && timely)) return { path: 'agent', route: professional ? 'baybay_professional' : 'baybay_agent', reason: 'live_web' };
  if (professional) return { path: 'fast', route: 'baybay_professional', reason: 'professional_topic' };
  return { path: 'fast', route: 'baybay_fast', reason: 'site_answer' };
}

/** BAYBAY_ENGINE: 'v2' turns the router, fast path, v2 retrieval and the cache layout on. */
const baybayEngine = (config = {}) => String(config.BAYBAY_ENGINE || '').trim().toLowerCase() === 'v2' ? 'v2' : 'v1';

// "帮我订机票 / Can you book a flight": a request addressed to BayBay to book, reserve
// or buy something, which it cannot do. The verb must open a clause, after at most a
// polite address (请你 / 你能不能 / 让你), so "老公说要给我买包" or "我想给我买个蛋糕"
// is a shopping question, not a request. A clause that asks where, which or what to
// buy, or that books a plan or itinerary, is not a booking request either.
const CLAUSE = String.raw`(?:^|[。！？!?，,；;：:\s])`;
const ADDRESS = String.raw`(?:(?:我想|我要|想)?(?:让|讓|请|請|叫)(?:你|您)|(?:请|請|麻烦|麻煩)?\s*(?:你|您|baybay)?)\s*(?:能不能|能否|可不可以|可以|可否|能|直接|马上|馬上)?\s*`;
const HELP = String.raw`(?:帮我|幫我|替我|帮忙|幫忙|给我|給我|帮|幫)\s*(?:直接|马上|馬上)?\s*(?:订|訂|预订|預訂|预定|預定|买|買|购买|購買|抢|搶)`;
const NOT_A_PURCHASE_ZH = String.raw`(?![^。！？!?，,；;]{0,30}(?:行程|计划|計劃|路线|路線|安排|一日游|一日遊|哪里|哪裡|哪儿|哪兒|哪家|哪个|哪個|哪种|哪種|什么|什麼|推荐|推薦|建议|建議))`;
const BOOKING_ZH = new RegExp(`${CLAUSE}${ADDRESS}${HELP}${NOT_A_PURCHASE_ZH}`, 'i');
// English: "can you / please / help me" + book…; "Can you buy tickets at the door?" uses
// a generic "you" and asks how, so a door, on-site, online or walk-up clause is excluded.
const BOOKING_EN = /\b(?:can you|could you|would you|please|help me|i want you to)\s+(?:book|reserve|buy|purchase|order)\b(?![^.?!,;]{0,40}\b(?:plan|itinerary|schedule|what|which|where|recommend|suggest|ideas?|at the (?:door|gate|box office|entrance)|on ?site|online|in person|walk-?up)\b)/i;
/** True when the message asks BayBay itself to book, reserve or buy something. */
const isBookingRequest = (message = '') => BOOKING_ZH.test(String(message)) || BOOKING_EN.test(String(message));

// A request to arrange an outing, its order or its stops: 帮我排行程 / 幫我排行程 / 排一下顺序 /
// 顺便排一下 / "Plan a Saturday in SF" / "in what order should we visit". Negated asks
// (不要排行程) and questions about the word itself are not requests.
const PLAN_ASK_ZH = /(?:排|安排|规划|規劃)(?:个|個|一个|一個|一下|好)?(?:行程|[游遊]程|顺序|順序|路线|路線|一天|半天|一日|半日)|(?:顺便|順便|再|帮我|幫我|请|請)(?:排|安排)一下(?:吧|吗|嗎)?(?=$|[。！？!?，,；;\s])/;
const PLAN_ASK_EN = /\bplan (?:a|an|my|our|the)?\s*(?:saturday|sunday|weekend|day|morning|afternoon|evening|half[- ]day|full[- ]day|visit|trip|outing|route)\b|\b(?:put together|map out|work out) (?:a|an|our|my|the) (?:day|plan|itinerary|route|schedule)\b|\b(?:in )?(?:what|which|the best) order (?:should|to|do|can)\b/i;
const PLAN_ASK_NOT = /(?:不要|不用|不必|别|別|无需|無需|暂时不|暫時不)(?:再)?(?:帮我|幫我)?(?:排|安排|规划|規劃)|\b(?:don['’]t|do not|no need to|stop)\s+plan|翻译|翻譯|什么意思|什麼意思|\b(?:translate|meaning of|what does\b[^?.!]{0,40}\bmean)\b/i;
/** True when the message asks BayBay to arrange a day, its stops or their order. */
const asksForPlan = (message = '') => { const text = String(message); return !PLAN_ASK_NOT.test(text) && (PLAN_ASK_ZH.test(text) || PLAN_ASK_EN.test(text)); };

module.exports = { routeBayBay, baybayEngine, isBookingRequest, asksForPlan };
