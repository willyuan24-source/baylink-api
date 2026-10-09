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
 * @param {string} [turn.searchMode]        'site' | 'smart' | 'web' after access rules
 * @param {boolean} [turn.timely]           the question needs a current fact
 * @returns {{path: 'emergency'|'outing'|'agent'|'fast', route?: string, reason: string}}
 */
function routeBayBay({ emergency = false, outing = false, professional = null, state = {}, edit = null, explicitCandidateIds = [], planFollowup = false, searchMode = 'site', timely = false } = {}) {
  if (emergency) return { path: 'emergency', reason: 'emergency_lexicon' };
  if (outing) return { path: 'outing', reason: 'outing_intent' };
  if (state.goal === 'day-plan') return { path: 'agent', route: 'baybay_agent', reason: 'day_plan' };
  if (edit && PLAN_EDITS.has(edit.kind)) return { path: 'agent', route: 'baybay_agent', reason: 'plan_edit' };
  if (explicitCandidateIds.length >= 2) return { path: 'agent', route: 'baybay_agent', reason: 'named_stops' };
  if (planFollowup) return { path: 'agent', route: 'baybay_agent', reason: 'plan_followup' };
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

module.exports = { routeBayBay, baybayEngine, isBookingRequest };
