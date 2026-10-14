// API-OPS: the AI credit burn-down for the owner (GET /api/admin/ai-metrics `credit`, and one
// owner e-mail in lib/aiSpendAlerts.js).
//
// Optional env, both needed for the burn-down:
//   AI_CREDIT_TOTAL_USD  the credit on the Claude key, in USD (e.g. 1000)
//   AI_CREDIT_START      the Pacific day the credit started to be used, YYYY-MM-DD
//                        (a full ISO time with Z or an offset counts as its Pacific day)
// Spend comes from the in-app ledger (lib/aiGovernance.js: integer micro-USD per Pacific day
// and month for every Claude call, at list prices). It is an estimate; the Console Usage page
// is the bill. The averages are over the last 7 and 30 full Pacific days (the site's burn
// rate, whichever key paid for it; shorter while the ledger is younger than the window). The
// projected run-out date uses the faster of the two, so it is the earlier, cautious date.
// Neither value is secret, but like ANTHROPIC_USE_UNTIL they are only shown to admins.
const { readUseUntil } = require('./anthropicUseUntil');
const { bayAreaDate } = require('./eventEngagement');
const { pacificResetAt } = require('./aiBudget');

const DAY_MS = 86400000;
const WINDOWS = Object.freeze([7, 30]);
// One owner e-mail when the projected run-out comes more than this many days before
// ANTHROPIC_USE_UNTIL.
const CREDIT_ALERT_LEAD_DAYS = 14;
const MAX_CREDIT_USD = 1000000;
// The ledger keeps day rows 400 days (lib/aiGovernance.js); a start older than that is read
// from the oldest day still kept.
const MAX_LOOKBACK_DAYS = 400;

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const noon = day => Date.parse(`${day}T12:00:00Z`);
const realDay = value => typeof value === 'string' && DAY.test(value) && Number.isFinite(noon(value)) && new Date(noon(value)).toISOString().slice(0, 10) === value;
const addDays = (day, count) => new Date(noon(day) + count * DAY_MS).toISOString().slice(0, 10);
const dayDiff = (from, to) => Math.round((noon(to) - noon(from)) / DAY_MS);
const nextMonth = month => { const [year, number] = month.split('-').map(Number); return number === 12 ? `${year + 1}-01` : `${year}-${String(number + 1).padStart(2, '0')}`; };
const usd = micro => Math.round(micro / 1e4) / 100;
const oneDecimal = value => Math.round(value * 10) / 10;
const amount = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const text = value => value == null ? '' : String(value).trim();

/** AI_CREDIT_TOTAL_USD: { set, valid, problem, microUsd }. Plain number, up to 2 decimals, > 0. */
function readCreditTotal(value) {
  const raw = text(value);
  if (!raw) return { set: false, valid: true, problem: null, microUsd: null };
  if (!/^\d+(?:\.\d{1,2})?$/.test(raw)) return { set: true, valid: false, problem: 'format', microUsd: null };
  const number = Number(raw);
  if (!(number > 0 && number <= MAX_CREDIT_USD)) return { set: true, valid: false, problem: 'range', microUsd: null };
  return { set: true, valid: true, problem: null, microUsd: Math.round(number * 1e6) };
}

/** AI_CREDIT_START: { set, valid, problem, day } with `day` the Pacific YYYY-MM-DD. */
function readCreditStart(value) {
  const raw = text(value);
  if (!raw) return { set: false, valid: true, problem: null, day: null };
  if (DAY.test(raw)) return realDay(raw) ? { set: true, valid: true, problem: null, day: raw } : { set: true, valid: false, problem: 'invalid_date', day: null };
  const instant = readUseUntil(raw);
  return instant.valid ? { set: true, valid: true, problem: null, day: bayAreaDate(instant.at) } : { set: true, valid: false, problem: instant.problem, day: null };
}

/** Both values read together; `configured` only when both are set and valid. */
function creditConfig(config = {}) {
  const total = readCreditTotal(config.AI_CREDIT_TOTAL_USD), start = readCreditStart(config.AI_CREDIT_START);
  const problem = (own, other) => own.problem || (!own.set && other.set ? 'missing' : null);
  return { total, start, configured: total.set && total.valid && start.set && start.valid, problems: { total: problem(total, start), start: problem(start, total) } };
}

/** The earliest Pacific day the burn-down reads from the ledger. */
function creditLedgerFrom(config = {}, today) {
  const { start, configured } = creditConfig(config);
  const window = addDays(today, -Math.max(...WINDOWS));
  const from = configured && start.day < window ? start.day : window;
  const oldest = addDays(today, -MAX_LOOKBACK_DAYS);
  return from < oldest ? oldest : from;
}

/**
 * The burn-down. `ledger` = { days: { 'YYYY-MM-DD': microUsd }, months: { 'YYYY-MM': microUsd } }
 * from creditLedgerFrom() to today. Pure: same input, same answer.
 */
function creditBurnDown({ config = {}, ledger = {}, now }) {
  const today = bayAreaDate(now);
  const days = ledger.days || {}, months = ledger.months || {};
  const { total, start, configured, problems } = creditConfig(config);

  // Average per full Pacific day (today is still running), over 7 and 30 days, or over the
  // days since the oldest ledger day when the ledger is younger than the window.
  const ledgerDays = Object.keys(days).filter(day => realDay(day) && day < today).sort();
  const known = ledgerDays.length ? dayDiff(ledgerDays[0], today) : 0;
  const rates = {}, perDay = {};
  for (const window of WINDOWS) {
    const count = Math.min(window, known);
    let sum = 0;
    for (let index = 1; index <= count; index++) sum += amount(days[addDays(today, -index)]);
    rates[window] = count ? sum / count : null;
    perDay[`last${window}`] = { days: count, usd: count ? usd(sum / count) : null };
  }
  const credit = { configured, totalUsd: total.valid && total.set ? usd(total.microUsd) : null, start: start.valid ? start.day : null, problems, perDay };
  if (!configured) return credit;

  // Spend since the start: the start month from its day rows (the month row also holds the
  // days before the start), every later month from its month row (or its day rows, if the
  // two disagree, the larger: a lost write never hides spend).
  const started = start.day <= today;
  let spent = 0;
  if (started) {
    const startMonth = start.day.slice(0, 7), thisMonth = today.slice(0, 7);
    for (let month = startMonth; month <= thisMonth; month = nextMonth(month)) {
      const daySum = Object.entries(days).filter(([day]) => realDay(day) && day.startsWith(`${month}-`) && day >= start.day && day <= today).reduce((sum, [, value]) => sum + amount(value), 0);
      spent += month === startMonth && !start.day.endsWith('-01') ? daySum : Math.max(amount(months[month]), daySum);
    }
  }
  const remaining = Math.max(0, total.microUsd - spent);
  // Before the start day the projection counts from the start (Pacific midnight).
  const base = started ? now : Date.parse(pacificResetAt(addDays(start.day, -1)));
  const runOut = {};
  for (const window of WINDOWS) {
    const rate = rates[window];
    if (!(rate > 0)) { runOut[`last${window}`] = null; continue; }
    const at = base + remaining / rate * DAY_MS;
    runOut[`last${window}`] = { day: bayAreaDate(at), at: new Date(at).toISOString(), daysLeft: oneDecimal((at - now) / DAY_MS) };
  }
  const exhausted = started && spent >= total.microUsd;
  const projected = exhausted ? { basis: 'spent', day: today, at: new Date(now).toISOString(), daysLeft: 0 }
    : WINDOWS.map(window => runOut[`last${window}`] && { basis: `last${window}`, ...runOut[`last${window}`] }).filter(Boolean).sort((a, b) => Date.parse(a.at) - Date.parse(b.at))[0] || null;
  const until = readUseUntil(config.ANTHROPIC_USE_UNTIL);
  const cutoff = until.set && until.valid ? until.at : null;
  const daysEarly = cutoff !== null && projected ? oneDecimal((cutoff - Date.parse(projected.at)) / DAY_MS) : null;
  return {
    ...credit, started, daysSinceStart: started ? dayDiff(start.day, today) + 1 : 0,
    spentUsd: usd(spent), remainingUsd: usd(remaining), exhausted, runOut, projected,
    // daysEarly: how many days before ANTHROPIC_USE_UNTIL the credit is projected to run out
    // (negative: after it). alert: more than CREDIT_ALERT_LEAD_DAYS early, cutoff still ahead.
    useUntil: { at: cutoff !== null ? new Date(cutoff).toISOString() : null, daysEarly },
    alert: daysEarly !== null && daysEarly > CREDIT_ALERT_LEAD_DAYS && now < cutoff,
    estimate: 'in-app ledger at list prices; the Console Usage page is the bill',
  };
}

module.exports = { readCreditTotal, readCreditStart, creditConfig, creditLedgerFrom, creditBurnDown, CREDIT_ALERT_LEAD_DAYS, WINDOWS, MAX_LOOKBACK_DAYS };
