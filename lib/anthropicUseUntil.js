// API-OPS-KEY: ANTHROPIC_USE_UNTIL, the instant new Claude calls stop (the credit cutoff).
//
// One reading of the value for every check: anthropicAvailable (lib/anthropicBaybay.js),
// the startup warning (server.js), GET /api/admin/ai-metrics `useUntil` and
// `scripts/check-ai-readiness.mjs --check-value`. Accepted, with no spaces:
//   YYYY-MM-DD                          (00:00 UTC that day)
//   YYYY-MM-DDTHH:MM:SS[.mmm]Z          or with an offset instead of Z, e.g. -07:00
// Unset or empty means no cutoff. Any other value fails closed: Claude is unavailable at
// once, with no advance banner (the 7-day banner needs a valid instant). That is why a
// malformed value is logged once at startup and shown to admins. The raw value is never
// logged or returned, in case a secret was pasted into the wrong variable.

const USE_UNTIL_FORMAT = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?$/;
const USE_UNTIL_EXAMPLES = '2027-04-19, 2027-04-19T00:00:00Z or 2027-04-18T17:00:00-07:00';
/** Why a nonempty value is not accepted (names only; the value itself is never repeated). */
const USE_UNTIL_PROBLEMS = Object.freeze({
  spaces: 'it contains spaces; delete them, and between the date and the time write T instead of a space',
  missing_zone: 'the time has no Z or ±HH:MM offset',
  invalid_date: 'it is not a real calendar date or time',
  format: 'it is not YYYY-MM-DD or a full ISO time with Z or an offset',
});

// `spaces` only when the spaces are the whole problem: deleting them, or writing T for the
// space between the date and the time, gives an accepted shape (or empty). Otherwise the
// value is named by what is really wrong with it (e.g. 'April 19, 2027' is `format`).
function problemOf(value) {
  if (typeof value !== 'string') return 'format';
  if (/\s/.test(value)) {
    const deleted = value.replace(/\s+/g, '');
    const withT = value.trim().replace(/^(\d{4}-\d{2}-\d{2})\s+(?=\d)/, '$1T').replace(/\s+/g, '');
    if (deleted === '' || USE_UNTIL_FORMAT.test(deleted) || USE_UNTIL_FORMAT.test(withT)) return 'spaces';
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(value)) return 'missing_zone';
  return 'format';
}

/**
 * Read one ANTHROPIC_USE_UNTIL value: { set, valid, problem, at }.
 * `at` is the cutoff in epoch ms when the value is set and valid, else null.
 * Unset (undefined, null or '') is valid and means no cutoff.
 */
function readUseUntil(value) {
  if (value == null || value === '') return { set: false, valid: true, problem: null, at: null };
  if (typeof value !== 'string' || !USE_UNTIL_FORMAT.test(value)) return { set: true, valid: false, problem: problemOf(value), at: null };
  const day = value.slice(0, 10);
  const [year, month, date] = day.split('-').map(Number);
  const validDay = new Date(Date.UTC(year, month - 1, date)).toISOString().slice(0, 10) === day;
  const at = Date.parse(value);
  return validDay && Number.isFinite(at) ? { set: true, valid: true, problem: null, at } : { set: true, valid: false, problem: 'invalid_date', at: null };
}

/** The admin view (GET /api/admin/ai-metrics `useUntil`): { set, valid, problem, at (ISO), passed }. */
function useUntilStatus(config = {}, now = Date.now()) {
  const until = readUseUntil(config.ANTHROPIC_USE_UNTIL);
  const cutoff = until.set && until.valid;
  return { set: until.set, valid: until.valid, problem: until.problem, at: cutoff ? new Date(until.at).toISOString() : null, passed: cutoff ? !(now < until.at) : null };
}

/** The one startup log line for a set but invalid value, or null. */
function useUntilWarning(config = {}) {
  const until = readUseUntil(config.ANTHROPIC_USE_UNTIL);
  if (until.valid) return null;
  return `[ai-config] ANTHROPIC_USE_UNTIL is set but invalid (${until.problem}: ${USE_UNTIL_PROBLEMS[until.problem]}). `
    + 'Claude is treated as unavailable from now on: every feature that uses Claude stops at once (BayBay too while BAYBAY_AI_PROVIDER=anthropic), with no advance banner. '
    + `Use YYYY-MM-DD or a full ISO time with Z or an offset (${USE_UNTIL_EXAMPLES}), or leave it empty for no cutoff. See docs/claude-baybay-rollout.md.`;
}

module.exports = { USE_UNTIL_FORMAT, USE_UNTIL_EXAMPLES, USE_UNTIL_PROBLEMS, readUseUntil, useUntilStatus, useUntilWarning };
