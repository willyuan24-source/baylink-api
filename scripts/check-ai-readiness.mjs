#!/usr/bin/env node
// API-OPS-KEY: is BayBay ready on Claude? Run it after the owner switches the Anthropic key
// and ANTHROPIC_USE_UNTIL on Render (docs/claude-baybay-rollout.md, "换新 key").
//
// Free and read-only: two public GETs, no key, no login, no cookies, no AI call.
//   GET <base>/health                  -> status, commit
//   GET <base>/ai/baybay-capabilities  -> enabled, pause, reduced, aiUntil, pauseScheduled,
//                                         configuredProvider, configuredModel, engine
// These reads prove the configuration, not that the key works (the API reports
// modelAccessVerified: false). The owner-approved 5-question smoke proves the key.
//
// --check-value <value> checks a candidate ANTHROPIC_USE_UNTIL offline (no network), with the
// same reading the API uses (lib/anthropicUseUntil.js), before it is pasted into Render.
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import useUntil from '../lib/anthropicUseUntil.js';

const { readUseUntil, USE_UNTIL_PROBLEMS, USE_UNTIL_EXAMPLES } = useUntil;
export const DEFAULT_BASE = 'https://baylink-api.onrender.com/api';
const TIMEOUT_MS = 60000; // per try: a Render cold start can take most of a minute
const TRIES = 2; // a GET with no answer (timeout or network error) is tried once more
const DAY_MS = 86400000;
const SCHEDULED_PAUSE_DAYS = 7; // lib/aiBudget.js scheduledPause
export const EXIT = Object.freeze({ READY: 0, NOT_READY: 1, USAGE: 2, ERROR: 4 });
export const USAGE = `Usage: node scripts/check-ai-readiness.mjs [--base ${DEFAULT_BASE}]
         [--expect-until <the ANTHROPIC_USE_UNTIL value set on Render> | none] [--expect-commit <sha>] [--json]
       node scripts/check-ai-readiness.mjs --check-value <candidate ANTHROPIC_USE_UNTIL value>
Exit code: 0 READY (or the value is valid), 1 NOT READY (or the value is invalid or already passed),
           2 bad arguments, 4 ERROR (the API could not be read, after a second try; rerun in a minute).`;

const PAUSE_HINTS = {
  provider_unavailable: 'Claude is not usable: ANTHROPIC_API_KEY is missing, ANTHROPIC_USE_UNTIL has passed, or ANTHROPIC_USE_UNTIL is not a valid value (Render log line "[ai-config]"; /api/admin/ai-metrics -> useUntil)',
  paused: 'BAYBAY_PAUSED=true is set on Render',
  daily_budget: "today's hard $ cap or the BayBay daily run limit was reached",
  disabled: 'BAYBAY_AGENT_ENABLED=false is set on Render',
};

/** "Thu, Oct 29, 2026, 5:00 PM PT" */
export function pacific(ms) {
  return `${new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(ms))} PT`;
}

function usageError(message) {
  return Object.assign(new Error(message), { usage: true });
}

export function parseArgs(argv) {
  const options = { base: DEFAULT_BASE, json: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--json') { options.json = true; continue; }
    if (flag === '--help' || flag === '-h') { options.help = true; continue; }
    if (!['--base', '--expect-until', '--expect-commit', '--check-value'].includes(flag) || argv[i + 1] === undefined) throw usageError(`Unknown or incomplete argument: ${flag}`);
    const value = argv[++i];
    if (flag === '--base') options.base = value.replace(/\/+$/, '');
    else if (flag === '--expect-commit') options.expectCommit = value.toLowerCase();
    else if (flag === '--check-value') options.checkValue = value;
    else options.expectUntil = value;
  }
  if (!/^https?:\/\/[^/\s]+(?:\/[^\s]*)?\/api$/.test(options.base)) throw usageError(`--base must be the API base ending in /api, e.g. ${DEFAULT_BASE}`);
  if (options.expectCommit !== undefined && !/^[0-9a-f]{7,40}$/.test(options.expectCommit)) throw usageError('--expect-commit must be 7 to 40 hex characters');
  if (options.expectUntil !== undefined && options.expectUntil !== 'none') {
    const until = readUseUntil(options.expectUntil);
    if (!until.set || !until.valid) throw usageError(`--expect-until is not a value the API accepts (${until.set ? `${until.problem}: ${USE_UNTIL_PROBLEMS[until.problem]}` : 'empty'}); use ${USE_UNTIL_EXAMPLES}, or none`);
  }
  return options;
}

const check = (level, name, detail) => ({ level, name, detail });

/**
 * Judge the two public reads. Returns { result: 'READY' | 'NOT_READY', checks: [{ level, name, detail }] }
 * with level ok | warn | fail | info. Any fail means NOT_READY; warnings do not.
 */
export function assessReadiness({ health, capabilities, now = Date.now(), expectUntil, expectCommit } = {}) {
  const checks = [];
  const commit = typeof health?.commit === 'string' ? health.commit : null;
  if (health?.status !== 'ok') checks.push(check('fail', 'health', `status ${JSON.stringify(health?.status ?? null)}, expected "ok"`));
  else if (expectCommit && !(commit || '').startsWith(expectCommit)) checks.push(check('fail', 'commit', `${commit || 'unknown'}, expected ${expectCommit}`));
  else checks.push(check('ok', expectCommit ? 'commit' : 'health', `ok, commit ${commit ? commit.slice(0, 7) : 'unknown'}`));

  const caps = capabilities || {};
  checks.push(caps.enabled === true ? check('ok', 'enabled', 'true') : check('fail', 'enabled', `${JSON.stringify(caps.enabled ?? null)}${caps.pause ? '' : ` (${PAUSE_HINTS.disabled}, or the API is not BayBay v2)`}`));
  if (caps.pause) {
    const resumes = caps.pause.resumesAt && Number.isFinite(Date.parse(caps.pause.resumesAt)) ? `; resumes ${pacific(Date.parse(caps.pause.resumesAt))}` : '';
    checks.push(check('fail', 'pause', `${caps.pause.reason || 'unknown'}: ${PAUSE_HINTS[caps.pause.reason] || 'unknown reason'}${resumes}`));
  } else checks.push(check('ok', 'pause', 'none'));
  if (caps.reduced) {
    const resumes = caps.reduced.resumesAt && Number.isFinite(Date.parse(caps.reduced.resumesAt)) ? `; resumes ${pacific(Date.parse(caps.reduced.resumesAt))}` : '';
    checks.push(check('warn', 'reduced', `soft daily $ cap reached: site-only fast answers and no web search today${resumes}`));
  } else checks.push(check('ok', 'reduced', 'none'));
  const model = `${caps.configuredModel || 'unknown model'} · engine ${caps.engine || 'unknown'}`;
  checks.push(caps.configuredProvider === 'anthropic' ? check('ok', 'provider', `anthropic · ${model}`)
    : check('fail', 'provider', `${caps.configuredProvider || 'unknown'} · ${model}: BayBay is not on Claude (BAYBAY_AI_PROVIDER)`));

  const expected = expectUntil === undefined ? undefined : expectUntil === 'none' ? null : readUseUntil(expectUntil).at;
  const at = caps.aiUntil == null ? null : Date.parse(caps.aiUntil);
  if (caps.aiUntil != null && !Number.isFinite(at)) checks.push(check('fail', 'aiUntil', `unreadable value ${JSON.stringify(caps.aiUntil)}`));
  else if (at != null) {
    const daysLeft = (at - now) / DAY_MS, when = `${new Date(at).toISOString()} = ${pacific(at)}`;
    if (!(at > now)) checks.push(check('fail', 'aiUntil', `${when}: already passed`));
    else if (expected === null) checks.push(check('fail', 'aiUntil', `${when}, expected no cutoff (ANTHROPIC_USE_UNTIL empty)`));
    else if (expected !== undefined && expected !== at) checks.push(check('fail', 'aiUntil', `${when}, expected ${new Date(expected).toISOString()} = ${pacific(expected)}`));
    else checks.push(check(daysLeft <= SCHEDULED_PAUSE_DAYS ? 'warn' : 'ok', 'aiUntil', `${when} (${daysLeft.toFixed(1)} days left${daysLeft <= SCHEDULED_PAUSE_DAYS ? ': every page shows the pause banner and the 7/3/1-day alerts are due' : ''})`));
  } else if (expected != null) checks.push(check('fail', 'aiUntil', `none reported, expected ${new Date(expected).toISOString()} = ${pacific(expected)} (ANTHROPIC_USE_UNTIL unset or invalid on the API, or BayBay is not on Claude)`));
  else checks.push(check('info', 'aiUntil', 'none: no cutoff, so no pause banner and no 7/3/1-day alerts; watch the Console balance'));
  if (caps.pauseScheduled) {
    const banner = caps.pauseScheduled.banner?.en || caps.pauseScheduled.banner?.['zh-Hans'] || '';
    checks.push(check('warn', 'scheduled', `pause banner on every page: ${banner}`));
  } else checks.push(check('ok', 'scheduled', 'no pause banner'));
  checks.push(check('info', 'key', 'these reads prove the configuration only; the owner-approved 5-question smoke proves the key works'));
  return { result: checks.some(item => item.level === 'fail') ? 'NOT_READY' : 'READY', checks };
}

export function formatReport({ base, checkedAt, result, checks }) {
  const lines = [`BAYLINK AI readiness · ${base} · ${pacific(checkedAt)}`];
  for (const item of checks) lines.push(`  ${item.level.padEnd(5)} ${item.name.padEnd(10)} ${item.detail}`);
  const warnings = checks.filter(item => item.level === 'warn').length;
  lines.push(`RESULT: ${result}${result === 'READY' && warnings ? ` (${warnings} warning${warnings > 1 ? 's' : ''})` : ''}`);
  return lines.join('\n');
}

/** --check-value: the API's own reading of a candidate ANTHROPIC_USE_UNTIL. No network. */
export function checkValue(value, now = Date.now()) {
  const until = readUseUntil(value);
  const lines = [`ANTHROPIC_USE_UNTIL ${JSON.stringify(value)} (offline; the API reads it the same way)`];
  if (!until.set) return { code: EXIT.READY, text: [...lines, '  empty: no cutoff. Claude stays on until the key or its credit runs out; no pause banner and no 7/3/1-day alerts.', 'RESULT: VALID'].join('\n') };
  if (!until.valid) return { code: EXIT.NOT_READY, text: [...lines,
    `  invalid (${until.problem}: ${USE_UNTIL_PROBLEMS[until.problem]}).`,
    '  With this value the API treats Claude as unavailable at once: every feature that uses Claude stops (BayBay too while BAYBAY_AI_PROVIDER=anthropic), with no advance banner.',
    `  Use ${USE_UNTIL_EXAMPLES}.`, 'RESULT: INVALID'].join('\n') };
  const when = `${new Date(until.at).toISOString()} = ${pacific(until.at)}`;
  if (!(now < until.at)) return { code: EXIT.NOT_READY, text: [...lines, `  valid, but ${when} has already passed: Claude would pause at once.`, 'RESULT: PASSED'].join('\n') };
  return { code: EXIT.READY, text: [...lines,
    `  valid: Claude calls stop at ${when}.`,
    `  The pause banner shows from ${pacific(until.at - SCHEDULED_PAUSE_DAYS * DAY_MS)}; alert e-mails 7, 3 and 1 days before (when e-mail delivery is on).`,
    'RESULT: VALID'].join('\n') };
}

async function read(fetchImpl, base, path) {
  let response;
  for (let attempt = 1; !response; attempt++) {
    try {
      response = await fetchImpl(`${base}${path}`, { method: 'GET', headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (error) {
      // No answer at all (a cold start, a dropped connection): one more try. An HTTP error status is not retried.
      if (attempt < TRIES) continue;
      throw new Error(`GET ${path} failed after ${TRIES} tries: ${error?.name === 'TimeoutError' ? `no answer in ${TIMEOUT_MS / 1000} s` : error?.message || 'network error'}`);
    }
  }
  if (!response.ok) throw new Error(`GET ${path} answered HTTP ${response.status}`);
  try { return await response.json(); } catch { throw new Error(`GET ${path} did not answer JSON`); }
}

export async function main(argv, { fetchImpl = globalThis.fetch, now = Date.now, out = console.log } = {}) {
  let options;
  try { options = parseArgs(argv); } catch (error) { out(`${error.message}\n${USAGE}`); return EXIT.USAGE; }
  if (options.help) { out(USAGE); return EXIT.READY; }
  if (options.checkValue !== undefined) { const result = checkValue(options.checkValue, now()); out(result.text); return result.code; }
  let health, capabilities;
  try {
    [health, capabilities] = await Promise.all([read(fetchImpl, options.base, '/health'), read(fetchImpl, options.base, '/ai/baybay-capabilities')]);
  } catch (error) { out(`ERROR: ${error.message}`); return EXIT.ERROR; }
  const checkedAt = now();
  const report = { base: options.base, checkedAt, ...assessReadiness({ health, capabilities, now: checkedAt, expectUntil: options.expectUntil, expectCommit: options.expectCommit }) };
  out(options.json ? JSON.stringify({ ...report, checkedAt: new Date(checkedAt).toISOString(), commit: health?.commit ?? null, aiUntil: capabilities?.aiUntil ?? null }, null, 2) : formatReport(report));
  return report.result === 'READY' ? EXIT.READY : EXIT.NOT_READY;
}

// Run only as a command (`node scripts/check-ai-readiness.mjs`), not when a test imports it.
const entry = (() => { try { return pathToFileURL(realpathSync(process.argv[1] || '')).href; } catch { return null; } })();
if (entry === import.meta.url) process.exitCode = await main(process.argv.slice(2));
