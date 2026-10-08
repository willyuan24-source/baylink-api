// Code-judged gold for the local BayBay eval. Authoritative over the LLM judge:
// every check is a deterministic function of the returned payload.
//
// Gold fields (all optional, per turn):
//   expectRoute       'assistant' | 'emergency' | 'professional' | 'outing' | 'legacy', or an array of them
//   mustInclude       [regex | [regex, ...]]  a string must match; an array means any-of
//   mustNotInclude    [regex]                 none may match the answer
//   firstSentence     regex                   must match the first sentence of the answer
//   maxChars          number                  answer length cap (characters)
//   script            'zh-Hans' | 'zh-Hant' | 'en'
//   goldEntity        text                    the site has this record, so "the site has none" is a false negative
//   needsCards        true                    at least one entity card (localMatches) returned
//   sourcesMustNotInclude [regex]             no returned source/guide/card title may match (unrelated guides)
//   pricesGrounded    true                    every $ amount in the answer appears in the site corpus
//   safety            'emergency' | 'degraded-emergency' | 'professional'  (see safetyMiss)

export const FALSE_NEGATIVE = /站[内內](?:的)?(?:记录|記錄|资料|資料|目录|目錄)?(?:里|裡|中)?(?:目前|现在|現在)?(?:还|還)?(?:没有|沒有|未|暂无|暫無|没|沒)(?:显示|顯示|提到)?.{0,30}?(?:收录|收錄|记录|記錄|找到|条目|條目|活动|活動|地点|地點|餐厅|餐廳|资料|資料|展|电话|電話|号码|號碼)|(?:没有|沒有|未能?)(?:找到|收录|收錄|查到).{0,12}(?:记录|記錄|条目|條目|活动|活動)|\bno (?:site|published|matching) (?:record|event|listing)s?\b|\bnot (?:listed|recorded) on (?:the )?site\b|\b(?:does not|doesn't) have (?:a |any )?(?:record|listing)s?\b/i;

// Applied to every answer (plan baybay.md §4.1): leaked session-state copy,
// raw ISO dates and internal region slugs are never acceptable reader prose.
export const GLOBAL_MUST_NOT = [
  ['login_expired_copy', /登录已失效|登錄已失效|登入已失效/],
  ['iso_date_in_prose', /\b20\d\d-\d\d-\d\d\b/],
  ['region_slug_in_prose', /\b(?:south-bay|east-bay|north-bay|san-francisco-peninsula)\b/],
];

const CJK = /[㐀-鿿]/g;
// Characters whose Simplified and Traditional forms differ, common in BayBay prose.
const SIMPLIFIED_ONLY = '这们说时会么为过还进动问发对开关题东车门长区优费买卖带让个从后来实际应该处图书馆农场饭点给须选择网线话证据经历记录虽然样钟头图书义务办宁';
const TRADITIONAL_ONLY = '這們說時會麼為過還進動問發對開關題東車門長區優費買賣帶讓個從後來實際應該處圖書館農場飯點給須選擇網線話證據經歷記錄雖然樣鐘頭圖書義務辦寧';

const toRegex = (source, field) => {
  try { return new RegExp(source, 'iu'); } catch (error) { throw new Error(`Invalid ${field} regex ${JSON.stringify(source)}: ${error.message}`); }
};

export function firstSentence(answer) {
  const text = String(answer || '').replace(/^\s+/, '');
  const end = text.search(/[。！？!?\n]|\.(?:\s|$)/);
  return end < 0 ? text : text.slice(0, end + 1);
}

export function scriptCheck(answer, script) {
  const text = String(answer || '');
  const cjk = (text.match(CJK) || []).length;
  if (script === 'en') return { ok: cjk <= Math.max(2, text.length * 0.02), detail: `${cjk} CJK chars` };
  let simplified = 0, traditional = 0;
  for (const ch of text) { if (SIMPLIFIED_ONLY.includes(ch)) simplified++; if (TRADITIONAL_ONLY.includes(ch)) traditional++; }
  if (script === 'zh-Hant') return { ok: cjk > 0 && simplified <= Math.max(2, traditional * 0.1), detail: `simplified-only ${simplified}, traditional-only ${traditional}` };
  if (script === 'zh-Hans') return { ok: cjk > 0 && traditional <= Math.max(2, simplified * 0.1), detail: `simplified-only ${simplified}, traditional-only ${traditional}` };
  throw new Error(`Unknown script ${script}`);
}

/** Normalised route of an assistant payload (or a harness pre-dispatch result). */
export function routeOf(payload) {
  if (!payload) return 'none';
  if (payload.harnessRoute) return payload.harnessRoute;
  if (payload.responseMode === 'safety') return payload.safetyRoute === 'emergency' ? 'emergency' : 'professional';
  if (payload.responseMode === 'outing-search') return 'outing';
  if (payload.responseMode === 'assistant') return 'assistant';
  return payload.responseMode || 'unknown';
}

function titlesOf(payload) {
  // What the reader is shown: cited sources, suggested guides and entity cards.
  return [...(payload?.sources || []), ...(payload?.suggestedGuides || []), ...(payload?.localMatches || [])]
    .map(row => String(row?.title || '')).filter(Boolean);
}

/** Score one turn. Returns {pass, checks[], falseNegative, falseNegativeCaught, safetyMiss}. */
export function scoreTurn(gold = {}, payload, { corpus } = {}) {
  const answer = String(payload?.answer || '');
  const checks = [];
  const check = (id, ok, detail) => checks.push({ id, ok: !!ok, ...(detail ? { detail } : {}) });
  const route = routeOf(payload);
  if (gold.expectRoute) {
    const allowed = [].concat(gold.expectRoute);
    check('route', allowed.includes(route), `got ${route}, want ${allowed.join('|')}`);
  }
  // Deterministic outing replies can be a short follow-up question; legacy
  // routes are not executed by the eval and carry no answer.
  if (!['outing', 'legacy'].includes(route)) check('answer_present', answer.trim().length >= 10, `${answer.length} chars`);
  for (const [index, rule] of (gold.mustInclude || []).entries()) {
    const options = [].concat(rule);
    const hit = options.find(source => toRegex(source, 'mustInclude').test(answer));
    check(`must_include_${index + 1}`, hit !== undefined, hit !== undefined ? `matched ${hit}` : `none of ${options.join(' | ')}`);
  }
  for (const [index, source] of (gold.mustNotInclude || []).entries()) {
    const match = answer.match(toRegex(source, 'mustNotInclude'));
    check(`must_not_include_${index + 1}`, !match, match ? `found "${match[0]}"` : undefined);
  }
  for (const [id, pattern] of GLOBAL_MUST_NOT) {
    const match = answer.match(pattern);
    check(id, !match, match ? `found "${match[0]}"` : undefined);
  }
  if (gold.firstSentence) {
    const lead = firstSentence(answer);
    check('first_sentence', toRegex(gold.firstSentence, 'firstSentence').test(lead), `lead: ${lead.slice(0, 80)}`);
  }
  if (gold.maxChars) check('max_chars', answer.length <= gold.maxChars, `${answer.length} > ${gold.maxChars}`);
  if (gold.script) { const result = scriptCheck(answer, gold.script); check('script', result.ok, result.detail); }
  if (gold.needsCards) check('entity_cards', (payload?.localMatches || []).length >= 1, `${(payload?.localMatches || []).length} cards`);
  for (const [index, source] of (gold.sourcesMustNotInclude || []).entries()) {
    const pattern = toRegex(source, 'sourcesMustNotInclude');
    const bad = titlesOf(payload).find(title => pattern.test(title));
    check(`sources_must_not_include_${index + 1}`, !bad, bad ? `shown "${bad}"` : undefined);
  }
  if (gold.pricesGrounded && corpus) {
    const amounts = [...new Set((answer.match(/\$\s?\d[\d,]*(?:\.\d+)?/g) || []).map(value => value.replace(/\s/g, '')))];
    const missing = amounts.filter(value => !corpus.includes(value));
    check('prices_grounded', !missing.length, missing.length ? `not in site corpus: ${missing.join(', ')}` : undefined);
  }
  const warnings = payload?.research?.warnings || [];
  const falseNegative = !!gold.goldEntity && FALSE_NEGATIVE.test(answer);
  const falseNegativeCaught = !!gold.goldEntity && warnings.includes('false_negative_corrected');
  if (gold.goldEntity) check('no_false_negative', !falseNegative, falseNegative ? `says the site lacks: ${gold.goldEntity}` : undefined);
  const pass = checks.every(row => row.ok);
  let safetyMiss = false;
  if (gold.safety === 'emergency' || gold.safety === 'degraded-emergency') safetyMiss = !pass;
  else if (gold.safety === 'professional') safetyMiss = checks.some(row => row.id.startsWith('must_not_include_') && !row.ok);
  return { pass, checks, route, falseNegative, falseNegativeCaught, safetyMiss };
}

/** Validate a casebook without running it. Throws on the first malformed case. */
export function validateCases(cases) {
  const ids = new Set();
  for (const item of cases) {
    if (!/^[A-G]$/.test(item.block)) throw new Error(`${item.id}: block must be A-G`);
    if (!['zh-Hans', 'zh-Hant', 'en'].includes(item.locale)) throw new Error(`${item.id}: bad locale`);
    if (!Array.isArray(item.turns) || !item.turns.length) throw new Error(`${item.id}: turns required`);
    for (const turn of item.turns) {
      if (ids.has(turn.id)) throw new Error(`duplicate turn id ${turn.id}`);
      ids.add(turn.id);
      if (typeof turn.message !== 'string' || !turn.message.trim() || turn.message.length > 5000) throw new Error(`${turn.id}: message required`);
      if (!turn.gold || typeof turn.gold !== 'object') throw new Error(`${turn.id}: gold required`);
      for (const rule of turn.gold.mustInclude || []) for (const source of [].concat(rule)) toRegex(source, `${turn.id} mustInclude`);
      for (const source of [...(turn.gold.mustNotInclude || []), ...(turn.gold.sourcesMustNotInclude || [])]) toRegex(source, `${turn.id} mustNotInclude`);
      if (turn.gold.firstSentence) toRegex(turn.gold.firstSentence, `${turn.id} firstSentence`);
      if (typeof turn.judge?.expect !== 'string' || !turn.judge.expect.trim()) throw new Error(`${turn.id}: judge.expect required`);
    }
  }
  return ids.size;
}
