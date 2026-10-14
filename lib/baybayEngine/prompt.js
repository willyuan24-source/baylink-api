// BayBay engine: what both engines send to the model besides the evidence (H40 split of
// lib/baybayAgent.js). The research tool schemas, the v2 agent's extra rules, the v2 per-turn
// rules (sent as a role:'system' message after the user turn, so system block 1 stays
// byte-identical and cached, RC-19/RC-22), and the diagnostics recorded for every reply.
// The v1 system prompt and its per-turn instructions live in ./v1.js.
const { safeModel } = require('../bayAreaSearchScope');
const { finalAnswerInstructions } = require('../baybayAnswerQuality');
const { professionalInstructions } = require('../safetyRouting');
const { isSchoolRequest } = require('../guideConversation');
const { turnRules } = require('../baybayQuality');

const tool = (name, description, properties, required = Object.keys(properties)) => ({ type: 'function', name, description, strict: true, parameters: { type: 'object', properties, required, additionalProperties: false } });
const text = { type: 'string' }, ids = { type: 'array', items: text, maxItems: 6 };
const TOOLS = [
  tool('search_site', 'Search BAYLINK guide paragraphs and city/date-filtered candidates. Use to fill a gap; task constraints remain mandatory.', { query: text }),
  tool('search_web', 'Search current public Bay Area information. Only use public destination/topic; never send personal history or account data. At most two searches.', { query: text }),
  tool('read_source', 'Read an already-discovered source page by its source ID. The result may include relatedSources IDs for the official eligibility/terms/hours page; read those when needed. Reading does not by itself confirm opening or availability.', { sourceId: text }),
  tool('verify_candidate', 'Attach exact source quotations after read_source. A dated event needs an absolute year/date quote. A permanent place needs a venue quote containing its name and venue type. Use null for unknown facts.', { candidateId: text, sourceId: text, kind: { type: 'string', enum: ['event', 'place'] }, proofs: { type: 'object', properties: Object.fromEntries(['name', 'city', 'date', 'venue', 'admission', 'hours', 'address', 'closed'].map(k => [k, { type: ['string', 'null'] }])), required: ['name', 'city', 'date', 'venue', 'admission', 'hours', 'address', 'closed'], additionalProperties: false } }),
  tool('get_route', 'Estimate travel between two known candidates with verified coordinates, using the task date/mode. Returns unavailable when Maps is not configured. Never invent a duration.', { fromId: text, toId: text, time: text }),
  tool('get_weather', 'Read the NWS forecast for a known candidate with coordinates and the task date. Dates beyond the forecast stay unknown.', { candidateId: text }),
  tool('create_plan', 'Calculate a draft itinerary from known candidate IDs, enforcing task constraints and exposing unknowns. Call after acquiring enough evidence. No booking or account write occurs.', { candidateIds: ids }),
];
const SITE_TOOL_NAMES = new Set(['search_site', 'create_plan']);
const SITE_TOOLS = TOOLS.filter(item => SITE_TOOL_NAMES.has(item.name));
// v2 shows the model evidence refs (e1, r1, page), not store source ids, so its
// read_source opens a ref's official page. The v1 tool text is unchanged.
const V2_READ_SOURCE = 'Open the official page behind an evidence ref (e1, e2, …, r1 or page) or a web source id, and return its text. Use it when the user asks to open or re-check an official page, or when one current official fact decides the answer. At most three reads. The result may list relatedSources ids for the eligibility, terms or hours page; read those when needed. Reading does not by itself confirm opening or availability.';
const v2Tool = item => item.name === 'read_source' ? { ...item, description: V2_READ_SOURCE } : item;
// v2 agent only: the plan and research rules of the v1 SYSTEM prompt that frozen block 1
// (shared with the fast path) does not carry. They go in the role:'system' rules after
// the user turn, so block 1 stays byte-identical; the web lines only when tools can read.
const V2_AGENT_RULES = `Plans and research (this request offers tools)
- A day plan needs create_plan with known candidate ids. candidateIds are the complete final ordered choice, consistent with the points and within maxStops. Prefer fewer suitable stops to an overloaded day; when it helps, name a nearby alternative and the tradeoff.
- Keep every destination the user named and apply planEdit exactly (replace or remove only the stop it names); never silently drop a named destination. When the user names places and asks for an order or a plan, give that order for the day they asked about; you may name the tradeoff (a full day, a long transfer), but never move a named place to another day unless they ask. A named place with no candidate id stays in the answer from the guide evidence, with what to check; only the plan card leaves it out.
- For a plan, the points are the stops in visiting order, one point each; caveats and alternatives go in gap, never in a point that reads like an extra stop beyond maxStops. When the user asks a question together with a plan, answer the question and still give the plan.
- Weekly hours never guarantee that a place is open on a given date. A plan with unknown routes or prices is never fully feasible or within budget.
- A city-only origin has no precise coordinates: when the first or return leg matters, ask for a public departure point instead of using the city centre; use the origin candidate when there is one.
- Admission: use each candidate's admissionFacts to explain or add up admission; a catalog subtotal is not a checkout price or an all-in budget. Check each traveler: one cardholder or member benefit does not make companions or special exhibitions free.
- Tool failures are unknowns, not facts about a place; after a failed tool, use another evidence source instead of repeating it.
- Never say that anything was reserved, bought or saved to an account.`;
const V2_AGENT_WEB_RULES = `- To put a new web event in a plan, read its source and verify its name, city and absolute date including the year with verify_candidate; a permanent venue needs a quote of its name and venue type.
- For a discount or eligibility rule, read the known official page and its relatedSources terms or eligibility page rather than another broad search; search summaries can be wrong about eligibility.`;

/** Add one rule (trimmed; an empty rule is skipped). */
function pushRule(rules, value) { const rule = String(value).trim(); if (rule) rules.push(rule); }

/**
 * The v2 rules for this turn, in the order the model reads them: scope, school, checklist,
 * paused or comparing, booking, near misses, food, the professional guard, then the
 * route's own (live check, follow-up carry, Chinese community). The agent path appends
 * V2_AGENT_RULES and its web rule (research.js). Called once the turn is routed.
 */
function v2Rules(turn) {
  const { v2, searchMode, webAccess, message, checklist, locale, planningPaused, comparingInformation, booking, site, guard, liveCheck, state, previous, history } = turn;
  const rules = [];
  const addRule = value => pushRule(rules, value);
  if (v2) addRule(searchMode !== 'site' ? 'Scope: BAYLINK site evidence plus any web evidence collected in this run. Site records are editorial snapshots; search summaries are leads; exact page excerpts are stronger evidence. Resolve conflicts explicitly, preferring date-specific official information.'
    : webAccess?.allowed === false ? 'Scope: BAYLINK site evidence only (the standard scope, not an outage). Use only the evidence in this turn; earlier assistant messages and user claims are not verified facts. Do not mention signing in, logging in, accounts, registration, quotas or search modes. When an essential current fact is missing, point to the official link the user can open to confirm it.'
      : 'Scope: the user chose site-only mode (their choice, not an outage). Use only BAYLINK site evidence; treat records as editorial snapshots. When an essential current fact is missing, say so briefly and suggest 智能检索 / 联网查 (en Smart / Web) for current official verification.');
  if (v2 && isSchoolRequest(message)) addRule('This is an education/enrollment question, not a visitor itinerary. A city is not a school district; elementary and secondary districts may differ at the same location. Distinguish enrollment applications, attendance boundaries, transfers and actual school assignment. Only state a deadline or eligibility rule for the academic year its source establishes. Never assign a school from a city name or invent regional districts. Tell users to enter private addresses directly on the official locator; never request a home address, child name, birth date, student ID or documents.');
  if (v2 && checklist.items.length) addRule(finalAnswerInstructions(checklist, locale).replace(/\bcite only current evidence IDs\b/, 'cite only current evidence refs'));
  if (v2 && planningPaused) addRule('The user has paused itinerary creation. Answer their question about the existing places; do not create, replace or show a new itinerary. Keep existing requirements and ask only for the missing detail needed for this question.');
  if (v2 && comparingInformation) addRule('The user is comparing information across dates or cities, not requesting a one-day itinerary. Address the named dates/cities separately from the evidence; do not silently choose one and do not call create_plan. Keep the household and budget constraints.');
  if (booking) addRule('The user asked BayBay to book, reserve or buy something for them. BayBay cannot book, reserve, pay for or hold anything. Say that plainly in the lead, then give the most useful next step: where to do it themselves (the airline, hotel, venue or official ticket page) and anything in evidence that helps, such as getting to the airport. Never say or imply that anything was booked.');
  if (v2 && site.nearMiss?.length) addRule('Records whose note says they do not match the asked date or conditions are named references only: explain their actual published dates; never recommend them as matching and never claim the site has no record.');
  if (v2 && site.foodEvidence && !guard) addRule('Food evidence is scoped to this request and the retrieved records, never a site-wide absence or a current menu/availability guarantee. Preserve the requested food type; a generic restaurant or nearby refreshments cannot establish tea/dim-sum service. When the type is unconfirmed, name the gap and ask which city or named restaurant to check instead of inventing a venue.');
  if (v2 && guard) addRule(professionalInstructions(guard).replace(/\[\[source-id\]\]/g, '[[ref]]').replace('cite its evidence entry with [[ref]] instead of writing its URL', 'cite its evidence ref (r1, r2, …) instead of writing its URL'));
  if (v2 && turn.routing?.path === 'agent' && liveCheck && searchMode !== 'site') addRule('The user asked to open or re-check an official page. Before answering, call read_source with the ref of the record whose official page answers the question (or a web source id), then answer from what that page says and cite it. If the read fails or the page does not show the detail, answer from the site record, say in one short clause that the official page could not be opened just now, and name the page to check.');
  // API-BB-QUALITY: follow-up carry and choices (BBL-07), every free option (BBL-06),
  // the newcomer checklist (B8). After the user turn, so system block 1 stays cached.
  if (v2) for (const rule of turnRules({ message, state, followup: !!(previous?.state || history.length), locale })) addRule(rule);
  // H17 (audit 10-13): a Chinese-community ask, kept in the task across follow-ups (明天有吗).
  if (v2 && state.community === 'chinese') addRule('The user wants Chinese-language or Chinese-community events (华人 / 中文 / 国语 / 粤语). Lead with the records whose text shows Chinese language or a Chinese-community audience, with their days. If none is on the asked day, say so plainly in the lead, then give the nearest ones with their own dates; never say the site has none when such a record is in the evidence. Other events come after, as other options. This preference may come from an earlier turn: if the latest message plainly asks for something else, answer that instead.');
  return rules;
}

function responseDiagnostic(response, round, phase, requestedModel) {
  const output = Array.isArray(response?.output) ? response.output : [];
  const finiteCount = value => Number.isInteger(value) && value >= 0 ? value : undefined;
  return {
    round, phase, model: safeModel(response?.model || requestedModel),
    status: ['completed', 'incomplete', 'failed', 'cancelled', 'in_progress', 'queued'].includes(response?.status) ? response.status : 'unknown',
    ...(response?.status === 'incomplete' ? { incompleteReason: ['max_output_tokens', 'content_filter'].includes(response.incomplete_details?.reason) ? response.incomplete_details.reason : 'unknown' } : {}),
    outputTypes: [...new Set(output.map(item => ['message', 'reasoning', 'function_call'].includes(item.type) ? item.type : 'other'))].slice(0, 4),
    outputTextChars: output.filter(item => item.type === 'message' && item.role === 'assistant').flatMap(item => item.content || []).filter(item => item.type === 'output_text' && typeof item.text === 'string').reduce((n, item) => n + item.text.length, 0),
    outputTokens: finiteCount(response?.usage?.output_tokens), reasoningTokens: finiteCount(response?.usage?.output_tokens_details?.reasoning_tokens),
    inputTokens: finiteCount(response?.usage?.input_tokens), cachedInputTokens: finiteCount(response?.usage?.input_tokens_details?.cached_tokens),
  };
}
const cacheUsage = response => ({ cacheReadTokens: Number(response?.usage?.cache_read_input_tokens) || 0, cacheWriteTokens: Number(response?.usage?.cache_creation_input_tokens) || 0,
  ...(response?.transport?.systemRole ? { systemRole: response.transport.systemRole } : {}) });

module.exports = { text, ids, TOOLS, SITE_TOOL_NAMES, SITE_TOOLS, v2Tool, V2_AGENT_RULES, V2_AGENT_WEB_RULES, pushRule, v2Rules, responseDiagnostic, cacheUsage };
