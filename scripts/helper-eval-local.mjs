#!/usr/bin/env node
// Local helper-set eval (API-BB-HELPERS). Runs the 12 cases in
// scripts/eval/helper-set.json through the real helper code (post translation,
// post-assist, outing draft, planner ranking, event screenshot) on one or more
// model arms and judges each provider reply on schema validity: stop_reason
// end_turn, one JSON object, and valid against the output_config.format schema
// the request carried. It also records whether the caller's own validator
// accepted the reply.
//
// Default is a dry run: a synthetic provider, no key, no network, $0.
// A paid run needs --live and --budget-usd (hard stop before any call that could
// cross it). The key is read only from BAYLINK_EVAL_ANTHROPIC_KEY (or
// ANTHROPIC_API_KEY) and is never printed, logged, written or passed on the
// command line. Only https://api.anthropic.com/v1/messages is reachable; post-
// assist runs in-process on memory models. Results are written OUTSIDE the repo.
import { createRequire } from 'node:module';
import { performance } from 'node:perf_hooks';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVAL_DIR = path.join(ROOT, 'scripts', 'eval');
const MESSAGES_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_OUT = process.env.BAYLINK_EVAL_OUT || path.join(os.homedir(), 'opus-qa', 'overhaul', 'eval');
// Arms set only helper-route variables; BayBay routes are untouched.
const ARMS = Object.freeze({
  'haiku-low': { BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5', BAYBAY_EFFORT_HELPERS: 'low' },
  'sonnet-low': { BAYBAY_MODEL_HELPERS: 'claude-sonnet-5-5', BAYBAY_EFFORT_HELPERS: 'low' },
  // Today's production helper setting (ANTHROPIC_BAYBAY_MODEL=claude-opus-5-5, legacy effort medium).
  'opus-medium': { ANTHROPIC_BAYBAY_MODEL: 'claude-opus-5-5' },
});
const USAGE = `Usage: node scripts/helper-eval-local.mjs [--arms haiku-low,sonnet-low,opus-medium] [--items id,id] [--repeat 1-3]
       [--run-id <id>] [--out <dir outside the repo>] [--live --budget-usd <USD up to 5>]
Without --live it is a dry run (synthetic provider, no key, no network).`;

function parseArgs(argv) {
  const options = { arms: ['haiku-low'], repeat: 1, live: false, out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--help' || flag === '-h') { console.log(USAGE); process.exit(0); }
    if (flag === '--live') { options.live = true; continue; }
    const value = argv[++i];
    if (value === undefined) throw new Error(`Missing value for ${flag}\n${USAGE}`);
    if (flag === '--arms' || flag === '--items') options[flag.slice(2)] = value.split(',').map(item => item.trim()).filter(Boolean);
    else if (flag === '--repeat') options.repeat = Number(value);
    else if (flag === '--budget-usd') options.budgetUsd = Number(value);
    else if (flag === '--run-id') options.runId = value;
    else if (flag === '--out') options.out = value;
    else throw new Error(`Unknown argument ${flag}\n${USAGE}`);
  }
  for (const arm of options.arms) if (!Object.hasOwn(ARMS, arm)) throw new Error(`Unknown arm ${arm}; choose from ${Object.keys(ARMS).join(', ')}`);
  if (!Number.isInteger(options.repeat) || options.repeat < 1 || options.repeat > 3) throw new Error('--repeat must be 1, 2 or 3');
  if (options.live && !(options.budgetUsd > 0 && options.budgetUsd <= 5)) throw new Error('--live requires --budget-usd between 0 and 5');
  if (!options.live) options.budgetUsd = 0;
  if (path.resolve(options.out).startsWith(ROOT)) throw new Error('--out must be outside the repository');
  return options;
}

/** Minimal validator for the structured-output subset the helper schemas use. */
export function validateAgainst(schema, value, at = '$') {
  const errors = [];
  const type = schema?.type;
  const is = { object: v => !!v && typeof v === 'object' && !Array.isArray(v), array: Array.isArray, string: v => typeof v === 'string',
    integer: Number.isInteger, number: v => typeof v === 'number' && Number.isFinite(v), boolean: v => typeof v === 'boolean', null: v => v === null };
  if (type && !is[type]?.(value)) return [`${at}: expected ${type}`];
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${at}: not in enum`);
  if (type === 'object') {
    for (const key of schema.required || []) if (!Object.hasOwn(value, key)) errors.push(`${at}.${key}: missing`);
    for (const [key, child] of Object.entries(value)) {
      if (!Object.hasOwn(schema.properties || {}, key)) { if (schema.additionalProperties === false) errors.push(`${at}.${key}: not allowed`); continue; }
      errors.push(...validateAgainst(schema.properties[key], child, `${at}.${key}`));
    }
  }
  if (type === 'array' && schema.items) value.forEach((item, index) => errors.push(...validateAgainst(schema.items, item, `${at}[${index}]`)));
  return errors;
}

// Synthetic provider for dry runs: a schema-shaped reply (echoes a same-shaped user JSON).
function syntheticValue(schema, hint) {
  if (schema.enum) return schema.enum[0];
  if (schema.type === 'object') return Object.fromEntries((schema.required || []).map(key => [key, syntheticValue(schema.properties[key], hint?.[key])]));
  if (schema.type === 'array') return [];
  if (schema.type === 'integer' || schema.type === 'number') return 2;
  if (schema.type === 'boolean') return false;
  return typeof hint === 'string' ? hint : 'synthetic';
}
function syntheticReply(body) {
  const schema = body.output_config?.format?.schema;
  let hint;
  try { hint = JSON.parse(body.messages.at(-1).content.find(part => part.type === 'text')?.text); } catch { /* not JSON */ }
  const value = schema ? syntheticValue(schema, hint) : {};
  return { ok: true, status: 200, headers: new Headers(), json: async () => ({ type: 'message', role: 'assistant', model: body.model, stop_reason: 'end_turn',
    content: [{ type: 'text', text: JSON.stringify(value) }], usage: { input_tokens: 0, output_tokens: 0 } }) };
}

const { claudeCost } = require(path.join(ROOT, 'lib/aiPricing'));
const { estimatePromptTokens } = require(path.join(ROOT, 'lib/aiModels'));
const { translateWithProvider } = require(path.join(ROOT, 'lib/postTranslation'));
const { createOutingDraft, resolveDraftDate } = require(path.join(ROOT, 'lib/outingDraft'));
const { draftContext } = require(path.join(ROOT, 'lib/outingIntent'));
const { recommend, loadPlannerCatalog } = require(path.join(ROOT, 'lib/planner'));
const { extractEvent } = require(path.join(ROOT, 'lib/localAi'));
const { bayAreaDate } = require(path.join(ROOT, 'lib/eventEngagement'));

// Upper bound for one call, used only for the hard budget stop.
const OUT_PRICE = { 'claude-haiku-5-5': [0.5, 2.5], 'claude-sonnet-5-5': [2, 10], 'claude-opus-5-5': [4, 20] };
function reserveUsd(body) {
  const [input, output] = OUT_PRICE[body.model] || [10, 50];
  return (estimatePromptTokens(body) * input + (body.max_tokens || 9000) * output) / 1e6;
}

function gitHead() { try { return execFileSync('git', ['-C', ROOT, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { return null; } }

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const book = JSON.parse(readFileSync(path.join(EVAL_DIR, 'helper-set.json'), 'utf8'));
  const cases = book.cases.filter(item => !options.items || options.items.includes(item.id));
  const now = Date.parse(book.pinnedNow), today = bayAreaDate(now);
  const keyVar = ['BAYLINK_EVAL_ANTHROPIC_KEY', 'ANTHROPIC_API_KEY'].find(name => typeof process.env[name] === 'string' && process.env[name].trim());
  const workspaceVar = ['BAYLINK_EVAL_ANTHROPIC_WORKSPACE_ID', 'ANTHROPIC_WORKSPACE_ID'].find(name => typeof process.env[name] === 'string' && process.env[name].trim());
  if (options.live && !keyVar) throw new Error('--live needs BAYLINK_EVAL_ANTHROPIC_KEY (or ANTHROPIC_API_KEY) in the environment, e.g. node --env-file=<private file>.');
  const apiKey = options.live ? process.env[keyVar].trim() : 'dry-run-placeholder';
  const runId = options.runId || `helpers-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const runDir = path.join(options.out, runId);
  mkdirSync(runDir, { recursive: true });
  const ledger = { spentUsd: 0, calls: 0, exhausted: false };
  let current = null; // the case whose provider calls are being recorded

  async function providerFetch(url, init) {
    if (url !== MESSAGES_URL) throw new Error('Only the Claude Messages API is reachable in this eval');
    const body = JSON.parse(init.body);
    if (options.live && ledger.spentUsd + reserveUsd(body) > options.budgetUsd) { ledger.exhausted = true; throw new Error('Eval budget exhausted'); }
    const started = performance.now();
    const response = options.live ? await fetch(url, init) : syntheticReply(body);
    let data = null;
    try { data = await response.json(); } catch { /* recorded as unparsable */ }
    const latencyMs = Math.round(performance.now() - started);
    const schema = body.output_config?.format?.schema;
    const text = Array.isArray(data?.content) ? data.content.filter(block => block?.type === 'text').map(block => block.text).join('') : '';
    let parsed, errors = [];
    if (!response.ok) errors = [`http ${response.status}`];
    else if (data?.stop_reason !== 'end_turn') errors = [`stop_reason ${data?.stop_reason}`];
    else {
      try { parsed = JSON.parse(text); } catch { errors = ['not JSON']; }
      if (!errors.length) errors = schema ? validateAgainst(schema, parsed) : ['no schema sent'];
    }
    const cost = data?.usage ? claudeCost({ model: data.model || body.model, usage: data.usage, day: today }) : { priced: false };
    const costUsd = cost.priced ? cost.microUsd / 1e6 : 0;
    ledger.spentUsd += costUsd; ledger.calls++;
    current?.calls.push({ requestedModel: body.model, servedModel: data?.model || null, effort: body.output_config?.effort, maxTokens: body.max_tokens, promptEstimate: estimatePromptTokens(body),
      schemaSent: !!schema, sampling: ['temperature', 'top_p', 'top_k'].filter(key => Object.hasOwn(body, key)),
      httpStatus: response.status, stopReason: data?.stop_reason ?? null, schemaValid: !errors.length, errors: errors.slice(0, 5), latencyMs,
      usage: data?.usage ? { input: data.usage.input_tokens, output: data.usage.output_tokens, cacheRead: data.usage.cache_read_input_tokens || 0 } : null,
      costUsd: +costUsd.toFixed(6), output: parsed ?? null });
    return { ok: response.ok, status: response.status, headers: response.headers, json: async () => data };
  }

  const catalog = loadPlannerCatalog();
  if (!catalog) throw new Error('data/planner-catalog.json did not load');
  const { createApplication } = require(path.join(ROOT, 'server.js'));
  const { createMemoryModels } = require(path.join(ROOT, 'tests/support/memory-models.js'));
  const member = require(path.join(ROOT, 'tests/support/member-session.js'));

  async function runCase(item, config) {
    switch (item.helper) {
      case 'translate': {
        const result = await translateWithProvider(item.source, { config, fetchImpl: providerFetch, now: () => now });
        return { accepted: true, result };
      }
      case 'post-assist': {
        const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: member.SECRET, ...config }, models: createMemoryModels({ User: [member.user] }), postAssistFetch: providerFetch });
        await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
        try {
          const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/post-assist`, { method: 'POST',
            headers: { 'Content-Type': 'application/json', ...member.headers() }, body: JSON.stringify(item.body) });
          const data = await response.json();
          return { accepted: response.status === 200 && data.ok === true, result: data.draft || { status: response.status, error: data.error } };
        } finally { await new Promise(resolve => app.io.close(resolve)); }
      }
      case 'outing': {
        const input = { ...draftContext(item.intent, [], today, item.locale, resolveDraftDate), eventId: null, locale: item.locale, today, now };
        const result = await createOutingDraft(input, { config, fetchImpl: providerFetch });
        return { accepted: true, result };
      }
      case 'planner': {
        const result = await recommend({ body: { message: item.message, locale: item.locale }, catalog, config, now: () => now, fetchImpl: providerFetch });
        return { accepted: result.responseMode === 'ai', result: { responseMode: result.responseMode, filters: result.filters,
          suggestions: result.suggestions.map(row => row.eventId), placeSuggestions: result.placeSuggestions.map(row => row.placeId) } };
      }
      case 'screenshot': {
        const image = `data:image/png;base64,${readFileSync(path.join(EVAL_DIR, item.image)).toString('base64')}`;
        const result = await extractEvent({ image, locale: item.locale }, { config, fetchImpl: providerFetch });
        return { accepted: true, result };
      }
      default: throw new Error(`Unknown helper ${item.helper}`);
    }
  }

  const meta = { runId, startedAt: new Date().toISOString(), gitHead: gitHead(), live: options.live, arms: Object.fromEntries(options.arms.map(arm => [arm, ARMS[arm]])),
    pinnedNow: book.pinnedNow, repeat: options.repeat, budgetUsd: options.budgetUsd, cases: cases.map(item => item.id), workspaceVar: workspaceVar || null };
  writeFileSync(path.join(runDir, 'meta.json'), JSON.stringify(meta, null, 1));
  console.log(`${cases.length} cases x ${options.arms.length} arms x ${options.repeat}; ${options.live ? `live, budget $${options.budgetUsd}` : 'dry run ($0)'}; results ${runDir}`);
  const rows = [];
  for (const arm of options.arms) {
    const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: apiKey, ...(workspaceVar ? { ANTHROPIC_WORKSPACE_ID: process.env[workspaceVar].trim() } : {}), ...ARMS[arm] };
    for (let round = 1; round <= options.repeat; round++) {
      for (const item of cases) {
        if (ledger.exhausted) break;
        current = { calls: [] };
        const started = performance.now();
        let outcome;
        try { outcome = await runCase(item, config); } catch (error) { outcome = { accepted: false, result: { status: error.status ?? null, code: error.code ?? null } }; }
        const calls = current.calls; current = null;
        const row = { arm, round, id: item.id, helper: item.helper, calls: calls.length, schemaValid: calls.length > 0 && calls.every(call => call.schemaValid && call.schemaSent),
          callerAccepted: outcome.accepted, servedModels: [...new Set(calls.map(call => call.servedModel))], sampling: calls.flatMap(call => call.sampling),
          completeMs: Math.round(performance.now() - started), costUsd: +calls.reduce((sum, call) => sum + call.costUsd, 0).toFixed(6), result: outcome.result, providerCalls: calls };
        rows.push(row);
        appendFileSync(path.join(runDir, 'results.jsonl'), `${JSON.stringify(row)}\n`);
        console.log(`[${arm} r${round}] ${item.id.padEnd(22)} schema=${row.schemaValid ? 'valid' : 'INVALID'} caller=${row.callerAccepted ? 'accepted' : 'REJECTED'} calls=${row.calls} ${row.servedModels.join('+')} ${(row.completeMs / 1000).toFixed(1)}s $${row.costUsd.toFixed(4)} (spent $${ledger.spentUsd.toFixed(4)})`);
      }
    }
  }
  const summary = options.arms.map(arm => {
    const mine = rows.filter(row => row.arm === arm);
    const sorted = mine.map(row => row.completeMs).sort((a, b) => a - b);
    const pick = q => sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] : null;
    return { arm, items: mine.length, schemaValid: mine.filter(row => row.schemaValid).length, callerAccepted: mine.filter(row => row.callerAccepted).length,
      providerCalls: mine.reduce((sum, row) => sum + row.calls, 0), samplingParams: mine.reduce((sum, row) => sum + row.sampling.length, 0),
      p50Ms: pick(0.5), p90Ms: pick(0.9), costUsd: +mine.reduce((sum, row) => sum + row.costUsd, 0).toFixed(5),
      byHelper: Object.fromEntries([...new Set(mine.map(row => row.helper))].map(helper => [helper, `${mine.filter(row => row.helper === helper && row.schemaValid).length}/${mine.filter(row => row.helper === helper).length}`])) };
  });
  writeFileSync(path.join(runDir, 'summary.json'), JSON.stringify({ ...meta, finishedAt: new Date().toISOString(), spentUsd: +ledger.spentUsd.toFixed(5), budgetExhausted: ledger.exhausted, summary }, null, 1));
  for (const row of summary) console.log(`${row.arm}: schema-valid ${row.schemaValid}/${row.items}, caller-accepted ${row.callerAccepted}/${row.items}, calls ${row.providerCalls}, p50 ${(row.p50Ms / 1000).toFixed(1)}s, p90 ${(row.p90Ms / 1000).toFixed(1)}s, $${row.costUsd}`);
  console.log(`Spent $${ledger.spentUsd.toFixed(4)}${options.live ? ` of $${options.budgetUsd}` : ' (dry run)'}${ledger.exhausted ? ' - BUDGET EXHAUSTED' : ''}. Results: ${runDir}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
