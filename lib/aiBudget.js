// API-BB-CUTOVER: the daily $ caps and the BayBay pause mode, as readers see them.
// lib/aiGovernance.js enforces the caps; lib/baybayAgent.js attaches these notices to
// answers and to GET /api/ai/baybay-capabilities (WEB-BB-UI shows them as a banner,
// with the 911/211 card first). No dollar amounts are ever shown to readers.
const { bayAreaDate } = require('./eventEngagement');

const LOCALES = Object.freeze(['zh-Hans', 'zh-Hant', 'en']);
const localeIndex = locale => locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;

const NOTICES = Object.freeze({
  // Hard cap (AI_SPEND_HARD_DAILY_USD, $10) or the daily BayBay run limit: no model
  // call until Pacific midnight; answers come from site records only.
  ai_daily_budget: ['今日 AI 名额已满，以下为站内资料；明天会恢复。', '今日 AI 名額已滿，以下為站內資料；明天會恢復。',
    "Today's AI answers are used up. Here is information from the site; BayBay is back tomorrow."],
  // Paused: BAYBAY_PAUSED=true, the assistant switched off, or no usable provider
  // (key missing, ANTHROPIC_USE_UNTIL passed).
  ai_paused: ['AI 助手暂停，以下为站内资料。', 'AI 助手暫停，以下為站內資料。', 'The AI assistant is paused. Here is information from the site.'],
  // Soft cap (AI_SPEND_SOFT_DAILY_USD, $6): site evidence and the fast path only.
  ai_budget_reduced: ['今天 AI 用量较高：先用站内资料快速回答，暂不联网查询。', '今天 AI 用量較高：先用站內資料快速回答，暫不聯網查詢。',
    'BayBay is busy today, so answers use site information only, without web lookups.'],
});

const ERRORS = Object.freeze({
  AI_DAILY_BUDGET: ['今日 AI 名额已满，明天会恢复；站内资料仍可浏览。', '今日 AI 名額已滿，明天會恢復；站內資料仍可瀏覽。',
    "Today's AI capacity is used up and resets tomorrow. Site information is still available."],
  AI_WEB_BUDGET: ['今天 AI 用量较高，暂停联网查询；站内资料仍可使用。', '今天 AI 用量較高，暫停聯網查詢；站內資料仍可使用。',
    'Web lookups are paused for today because AI use is high. Site information is still available.'],
});

/** `{kind, text}` in the reader's locale (plus any extra fields), or null for an unknown kind. */
function budgetNotice(kind, locale, extra = {}) {
  const copy = NOTICES[kind];
  return copy ? { kind, text: copy[localeIndex(locale)], ...extra } : null;
}

/** The notice text in every locale, for the capabilities endpoint (no locale in that request). */
function noticeBanners(kind) {
  const copy = NOTICES[kind];
  return copy ? Object.fromEntries(LOCALES.map((locale, index) => [locale, copy[index]])) : null;
}

/** A 429 the governed routes already pass through as `{error: message}`. */
function budgetError(code, locale) {
  const copy = ERRORS[code] || ERRORS.AI_DAILY_BUDGET;
  return Object.assign(new Error(copy[localeIndex(locale)]), { status: 429, code });
}

/** ISO time of the Pacific midnight that ends Bay Area day `day` (YYYY-MM-DD); quotas and caps reset then. */
function pacificResetAt(day) {
  const tomorrow = new Date(Date.parse(`${day}T12:00:00Z`) + 86400000).toISOString().slice(0, 10);
  // Pacific midnight is UTC 07:00 in DST and UTC 08:00 otherwise.
  const seven = Date.parse(`${tomorrow}T07:00:00Z`);
  return new Date(bayAreaDate(seven) === tomorrow ? seven : seven + 3600000).toISOString();
}

/** Whether the $ caps are enforced. `AI_SPEND_CAPS=off` keeps them report-only (rollback). */
const spendCapsEnforced = (config = {}) => String(config.AI_SPEND_CAPS ?? '').trim().toLowerCase() !== 'off';

module.exports = { LOCALES, NOTICES, budgetNotice, noticeBanners, budgetError, pacificResetAt, spendCapsEnforced };
