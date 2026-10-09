#!/usr/bin/env node
// Local BayBay eval (docs/baybay-eval.md). Builds the BayBay assistant from this
// checkout with an in-memory quota, a pinned clock and a guarded fetch, runs the
// casebook in scripts/eval/ across model arms, scores code gold, runs the Opus
// judge, and writes everything OUTSIDE the repository.
//
// Default is a dry run: a synthetic provider, no key, no network, $0.
// A paid run needs --live and --budget-usd. The key is read only from
// BAYLINK_EVAL_ANTHROPIC_KEY (or ANTHROPIC_API_KEY) and is never printed,
// logged, written or passed on the command line. No Express, no Mongo, no
// production quota: only https://api.anthropic.com/v1/messages is reachable.
import { createRequire } from 'node:module';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rawUsage, callCostUsd, PRICING_DATE } from './eval/pricing.mjs';
import { scoreTurn, validateCases, routeOf } from './eval/gold.mjs';
import { preDispatch, serverIntentFingerprint, INTENT_MIRROR_FINGERPRINT } from './eval/route.mjs';
import { createJudge, judgeCase, JUDGE_MODEL } from './eval/judge.mjs';
import { writeReport } from './eval/report.mjs';
import { armRoutes } from './eval/arms.mjs';
import { requestShape, responseShape, toolRounds } from './eval/request-shape.mjs';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVAL_DIR = path.join(ROOT, 'scripts', 'eval');
const MESSAGES_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_NOW = '2026-10-08T10:00:00-07:00';
const DEFAULT_OUT = process.env.BAYLINK_EVAL_OUT || path.join(os.homedir(), 'opus-qa', 'overhaul', 'eval');
const PROVIDER_FAILURE_WARNINGS = new Set(['model_unavailable', 'model_unavailable_or_capacity', 'quota_unavailable']);

const { createBayBayAssistant } = require(path.join(ROOT, 'lib/baybayAgent'));
const { createMessageAccumulator, readMessageStream } = require(path.join(ROOT, 'lib/anthropicStream'));
const { createPublicContext } = require(path.join(ROOT, 'lib/publicContext'));
const { bayAreaDate } = require(path.join(ROOT, 'lib/bayAreaSearchScope'));
const { normalizeGuideHistory } = require(path.join(ROOT, 'lib/guideConversation'));
const { validateChatSearchContext } = require(path.join(ROOT, 'lib/guideWebSearch'));
const { baybayWebAccess } = require(path.join(ROOT, 'lib/baybayAccess'));

// A probe replaces the scored casebook with its own file (block T), e.g. the
// tool-round probe that forces a tool_use round before the tool_choice:none synthesis.
const PROBES = Object.freeze({ 'tool-rounds': 'probe-tool-rounds.json', 'agent-path': 'probe-agent-path.json' });
const USAGE = `Usage: node scripts/baybay-eval-local.mjs [--set v0|v1|r0] [--blocks A,C,E,G] [--arms a,b] [--items id,id] [--probe tool-rounds]
       [--run-id <id>] [--out <dir outside the repo>] [--now <ISO>] [--concurrency 1-3] [--max-reruns N]
       [--no-judge] [--no-drafts] [--save-sse N] [--resume] [--live --budget-usd <USD>]
Without --live it is a dry run (synthetic provider, no key, no network).
The harness is a capable client (streamVersion 3) unless --no-drafts: v2 fast-path turns
stream and report draft events; --save-sse N keeps the first N raw provider streams.
Live: node --env-file=<private env file> scripts/baybay-eval-local.mjs --live --budget-usd 20 ...`;

function parseArgs(argv) {
  const options = { set: 'v0', concurrency: 2, maxReruns: 2, judge: true, drafts: true, saveSse: 0, resume: false, live: false, now: DEFAULT_NOW, out: DEFAULT_OUT };
  const values = new Set(['--set', '--blocks', '--arms', '--items', '--run-id', '--out', '--now', '--concurrency', '--max-reruns', '--budget-usd', '--baseline', '--probe', '--save-sse']);
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--help' || flag === '-h') { console.log(USAGE); process.exit(0); }
    if (flag === '--live') { options.live = true; continue; }
    if (flag === '--no-judge') { options.judge = false; continue; }
    if (flag === '--no-drafts') { options.drafts = false; continue; }
    if (flag === '--resume') { options.resume = true; continue; }
    if (!values.has(flag) || argv[i + 1] === undefined) throw new Error(`Unknown or incomplete argument: ${flag}\n${USAGE}`);
    const value = argv[++i];
    if (flag === '--blocks' || flag === '--arms' || flag === '--items') options[flag.slice(2)] = value.split(',').map(item => item.trim()).filter(Boolean);
    else if (flag === '--concurrency' || flag === '--max-reruns' || flag === '--budget-usd' || flag === '--save-sse') options[{ '--concurrency': 'concurrency', '--max-reruns': 'maxReruns', '--budget-usd': 'budgetUsd', '--save-sse': 'saveSse' }[flag]] = Number(value);
    else options[{ '--set': 'set', '--run-id': 'runId', '--out': 'out', '--now': 'now', '--baseline': 'baseline', '--probe': 'probe' }[flag]] = value;
  }
  if (options.probe !== undefined && !Object.hasOwn(PROBES, options.probe)) throw new Error(`--probe must be one of: ${Object.keys(PROBES).join(', ')}`);
  if (!Number.isInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 3) throw new Error('--concurrency must be 1, 2 or 3');
  if (!Number.isInteger(options.maxReruns) || options.maxReruns < 0 || options.maxReruns > 4) throw new Error('--max-reruns must be 0-4');
  if (!Number.isInteger(options.saveSse) || options.saveSse < 0 || options.saveSse > 20) throw new Error('--save-sse must be 0-20');
  if (!Number.isFinite(Date.parse(options.now))) throw new Error('--now must be an ISO date-time');
  if (options.live && !(options.budgetUsd > 0 && options.budgetUsd <= 100)) throw new Error('--live requires --budget-usd between 0 and 100 (hard stop for every provider call, judge included)');
  if (!options.live) options.budgetUsd = 0;
  return options;
}

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) return reject(new Error('aborted'));
  const timer = setTimeout(resolve, ms);
  signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('aborted')); }, { once: true });
});

function loadCasebook(probe) {
  const files = probe ? [PROBES[probe]] : readdirSync(EVAL_DIR).filter(file => /^cases-[A-H]-.+\.json$/.test(file)).sort();
  const books = files.map(file => ({ file, ...JSON.parse(readFileSync(path.join(EVAL_DIR, file), 'utf8')) }));
  const cases = books.flatMap(book => book.cases.map(item => ({ ...item, pinnedNow: book.pinnedNow })));
  validateCases(cases);
  return { books, cases };
}

function loadCatalogs() {
  const guideCatalog = require(path.join(ROOT, 'data/guide-catalog.json'));
  const englishGuides = require(path.join(ROOT, 'data/guide-catalog.en.json'));
  // Same shaping as server.js (GUIDE_CATALOG / ENGLISH_GUIDE_CATALOG / ENGLISH_SEARCH_CATALOG).
  const englishGuideMap = new Map(englishGuides.filter(guide => guideCatalog.some(source => source.slug === guide.slug)).map(guide => [guide.slug, guide]));
  const englishSearchCatalog = guideCatalog.map(guide => {
    const english = englishGuideMap.get(guide.slug);
    return english ? { ...guide, title: `${guide.title} ${english.title}`, summary: `${guide.summary || ''} ${english.summary || ''}`, keywords: [...(guide.keywords || []), ...(english.keywords || [])], content: `${english.content || ''}\n${guide.content || ''}` } : guide;
  });
  const corpus = ['data/guide-catalog.json', 'data/guide-catalog.en.json', 'data/planner-catalog.json', 'data/discoveries.json', 'data/discoveries.en.json']
    .map(file => readFileSync(path.join(ROOT, file), 'utf8')).join('\n');
  return { guideCatalog, englishGuideMap, englishSearchCatalog, corpus };
}

/** The two Quota calls createBayBayAssistant makes, in memory. Never touches Mongo. */
export function createMemoryQuota() {
  const rows = new Map();
  return {
    async updateOne(filter, update, options) { if (!rows.has(filter.id) && options?.upsert) rows.set(filter.id, { ...update.$setOnInsert }); return { acknowledged: true }; },
    async findOneAndUpdate(filter, update) {
      const row = rows.get(filter.id);
      if (!row || !(row.count < filter.count.$lt)) return null;
      row.count += update.$inc.count;
      return { ...row };
    },
  };
}

function gitHead() {
  try { return execFileSync('git', ['-C', ROOT, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { return null; }
}

function syntheticResponse(body) {
  // A v2 request (BAYBAY_ENGINE=v2) asks for the lead-first schema.
  const v2 = !!body.output_config?.format?.schema?.properties?.lead;
  const text = JSON.stringify(v2 ? { lead: 'Dry-run synthetic answer.', points: [{ text: 'No provider was called.', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' }
    : { answer: 'Dry-run synthetic answer. No provider was called.', candidateIds: [], followups: [], coverage: [] });
  const message = { id: 'msg_dry_run', type: 'message', role: 'assistant', model: body.model, stop_reason: 'end_turn',
    content: [{ type: 'text', text }], usage: { input_tokens: Math.ceil(JSON.stringify(body).length / 3), output_tokens: 60, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } };
  if (body.stream === true) return new Response(syntheticSse(message), { status: 200, headers: { 'content-type': 'text/event-stream' } });
  return new Response(JSON.stringify(message), { status: 200, headers: { 'content-type': 'application/json' } });
}

/** A dry-run streamed reply in the Messages SSE wire format: text in 6-character
 * deltas, sent as a few byte chunks so the client's parser and draft path run. */
function syntheticSse(message) {
  const event = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
  const text = message.content[0].text;
  let sse = event('message_start', { type: 'message_start', message: { ...message, content: [], stop_reason: null, usage: { ...message.usage, output_tokens: 1 } } })
    + event('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
  for (let index = 0; index < text.length; index += 6) sse += event('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: text.slice(index, index + 6) } });
  sse += event('content_block_stop', { type: 'content_block_stop', index: 0 })
    + event('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: message.usage.output_tokens } })
    + event('message_stop', { type: 'message_stop' });
  const bytes = Buffer.from(sse, 'utf8'), chunks = [];
  for (let index = 0; index < bytes.length; index += 97) chunks.push(bytes.subarray(index, index + 97));
  return new ReadableStream({ pull(controller) { if (chunks.length) controller.enqueue(chunks.shift()); else controller.close(); } });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const armsBook = JSON.parse(readFileSync(path.join(EVAL_DIR, 'arms.json'), 'utf8'));
  const set = armsBook.sets[options.set];
  if (!set) throw new Error(`Unknown --set ${options.set}`);
  const blocks = options.probe ? ['T'] : options.blocks || set.blocks;
  const armNames = options.arms || set.arms;
  for (const arm of armNames) {
    const def = armsBook.arms[arm];
    if (!def) throw new Error(`Unknown arm ${arm}`);
    if (def.requestOverrides && Object.keys(def.requestOverrides).some(key => key !== 'thinking')) throw new Error(`${arm}: only a thinking override is allowed`);
    // A body override reaches every call of the arm, professional route included.
    if (def.requestOverrides?.thinking && Object.values(armRoutes(def.config)).some(route => !route.model.startsWith('claude-haiku-'))) throw new Error(`${arm}: disabled thinking is only valid on Haiku 5.5; use BAYBAY_THINKING_AGENT instead`);
  }
  const baselineArm = options.baseline || set.baselineArm;
  // Credentials: environment only. Name of the variable is recorded, never the value.
  const keyVar = ['BAYLINK_EVAL_ANTHROPIC_KEY', 'ANTHROPIC_API_KEY'].find(name => typeof process.env[name] === 'string' && process.env[name].trim());
  const workspaceVar = ['BAYLINK_EVAL_ANTHROPIC_WORKSPACE_ID', 'ANTHROPIC_WORKSPACE_ID'].find(name => typeof process.env[name] === 'string' && process.env[name].trim());
  if (options.live && !keyVar) throw new Error('--live needs BAYLINK_EVAL_ANTHROPIC_KEY (or ANTHROPIC_API_KEY) in the environment, e.g. node --env-file=<private file>.');
  const outRoot = path.resolve(options.out);
  if (outRoot === ROOT || outRoot.startsWith(ROOT + path.sep)) throw new Error('--out must be outside the repository; results are never committed');
  const runId = options.runId || `${options.live ? options.set : 'dry'}-${new Date().toISOString().replace(/[-:]/g, '').slice(0, 13)}`;
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(runId)) throw new Error('--run-id may use letters, digits, dot, dash and underscore');
  const runDir = path.join(outRoot, runId);
  if (existsSync(path.join(runDir, 'meta.json')) && !options.resume) throw new Error(`${runDir} already exists; pass --resume to continue it or choose another --run-id`);
  mkdirSync(runDir, { recursive: true });

  const nowMs = Date.parse(options.now), now = () => nowMs;
  const { cases } = loadCasebook(options.probe);
  const selected = cases.filter(item => blocks.includes(item.block) && (!options.items || options.items.includes(item.id) || item.turns.some(turn => options.items.includes(turn.id))));
  if (!selected.length) throw new Error('No cases selected');
  const pinnedMismatch = [...new Set(selected.map(item => item.pinnedNow).filter(value => value && Date.parse(value) !== nowMs))];
  if (pinnedMismatch.length) console.warn(`WARNING: --now ${options.now} differs from the casebook golds (${pinnedMismatch.join(', ')}); re-date the golds before trusting date checks.`);
  const fingerprint = serverIntentFingerprint();
  if (fingerprint !== INTENT_MIRROR_FINGERPRINT) console.warn('WARNING: server.js inferBayBayIntent changed; update scripts/eval/route.mjs so legacy-route detection still matches production.');
  const catalogs = loadCatalogs();

  const apiKey = options.live ? process.env[keyVar].trim() : 'dry-run-synthetic-key';
  const workspaceId = options.live && workspaceVar ? process.env[workspaceVar].trim() : undefined;
  const scrub = text => { if (options.live && apiKey.length >= 8 && text.includes(apiKey)) throw new Error('Refusing to write output that contains the API key'); return text; };
  const writeJsonl = (file, row) => appendFileSync(path.join(runDir, file), scrub(JSON.stringify(row)) + '\n');

  // Ledger and budget. Every provider call is priced from its usage; a call
  // that could cross the hard budget is refused before it is sent.
  const ledgerFile = path.join(runDir, 'ledger.jsonl');
  const ledger = { spentUsd: 0, exhausted: false };
  if (existsSync(ledgerFile)) for (const line of readFileSync(ledgerFile, 'utf8').split('\n').filter(Boolean)) ledger.spentUsd = Math.max(ledger.spentUsd, JSON.parse(line).spentUsd || 0);
  const reserveFor = model => /opus/.test(model) ? 0.5 : /sonnet/.test(model) ? 0.25 : 0.03;
  let cooldownUntil = 0, savedSse = 0;
  const als = new AsyncLocalStorage();

  async function providerFetch(url, init) {
    if (url !== MESSAGES_URL) throw new Error(`eval harness blocks network access to ${(() => { try { return new URL(url).host; } catch { return 'an invalid URL'; } })()}`);
    const ctx = als.getStore() || { kind: 'unattributed', calls: [], t0: performance.now() };
    let body = JSON.parse(init.body);
    if (ctx.requestOverrides) body = { ...body, ...ctx.requestOverrides };
    // The request's shape (no content) shows which calls were tool rounds and that
    // the body kept the model's rules; see scripts/eval/request-shape.mjs.
    const call = { kind: ctx.kind, model: body.model, startMs: Math.round(performance.now() - ctx.t0), retries: 0, request: requestShape(body) };
    ctx.calls.push(call);
    if (options.live && ledger.spentUsd + reserveFor(body.model) > options.budgetUsd) {
      ledger.exhausted = true; call.error = 'budget_exhausted';
      throw new Error('Eval budget exhausted');
    }
    try {
      for (let attempt = 0; ; attempt++) {
        const response = options.live ? await fetch(url, { ...init, body: JSON.stringify(body) }) : syntheticResponse(body);
        call.headersMs = Math.round(performance.now() - ctx.t0); call.status = response.status;
        if ([429, 529].includes(response.status) && attempt < 2 && !init.signal?.aborted) {
          const retryAfter = Number(response.headers.get('retry-after'));
          const wait = Math.min(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 1500 * 2 ** attempt, 4000);
          cooldownUntil = Math.max(cooldownUntil, Date.now() + Math.max(wait, 10000));
          call.retries++; await response.arrayBuffer().catch(() => {});
          await sleep(wait, init.signal); continue;
        }
        // A streamed call (API-BB-STREAM): the caller reads one branch of the body; the
        // ledger reads the other to its end (usage arrives in message_start/message_delta).
        if (body.stream === true && response.ok && response.body) {
          const [mine, theirs] = response.body.tee();
          const raw = options.saveSse && savedSse < options.saveSse ? (savedSse++, []) : null;
          const accumulator = createMessageAccumulator({ onDelta: delta => { if (delta.type === 'text' && call.firstTextMs == null) call.firstTextMs = Math.round(performance.now() - ctx.t0); } });
          async function* tap(stream) { for await (const chunk of stream) { raw?.push(Buffer.from(chunk)); yield chunk; } }
          ctx.pending?.push((async () => {
            try {
              const message = await readMessageStream(tap(mine), accumulator);
              call.endMs = Math.round(performance.now() - ctx.t0);
              call.stopReason = message.stop_reason; call.stopCategory = message.stop_details?.category; call.contentTypes = responseShape(message); call.responseModel = message.model;
              call.usage = rawUsage(message.usage);
              call.costUsd = options.live ? callCostUsd(message.model || body.model, call.usage) : 0;
              ledger.spentUsd += call.costUsd;
              appendFileSync(ledgerFile, scrub(JSON.stringify({ at: new Date().toISOString(), arm: ctx.arm, turnId: ctx.turnId, kind: ctx.kind, model: message.model || body.model, usage: call.usage, costUsd: +call.costUsd.toFixed(6), spentUsd: +ledger.spentUsd.toFixed(6), streamed: true })) + '\n');
            } catch (error) {
              call.endMs ??= Math.round(performance.now() - ctx.t0);
              call.error ??= /abort/i.test(error.name + error.message) ? 'aborted_or_timeout' : String(error.message).slice(0, 160);
              // A cut stream is still billed: price the usage it reported, input at least.
              const partial = accumulator.partial();
              if (partial?.usage && options.live) { call.usage = rawUsage(partial.usage); call.costUsd = callCostUsd(partial.model || body.model, call.usage); ledger.spentUsd += call.costUsd; }
            } finally {
              if (raw) { mkdirSync(path.join(runDir, 'sse'), { recursive: true }); writeFileSync(path.join(runDir, 'sse', `${ctx.arm}-${ctx.turnId}-${ctx.calls.indexOf(call) + 1}.sse`), scrub(Buffer.concat(raw).toString('utf8'))); }
            }
          })());
          call.streamed = true;
          return new Response(theirs, { status: response.status, statusText: response.statusText, headers: { 'content-type': 'text/event-stream' } });
        }
        const text = await response.text();
        call.endMs = Math.round(performance.now() - ctx.t0);
        let data = null; try { data = JSON.parse(text); } catch { /* non-JSON error body */ }
        if (!response.ok) {
          call.error = `${data?.error?.type || 'http_error'}: ${String(data?.error?.message || '').slice(0, 160)}`;
          if ([429, 529].includes(response.status)) cooldownUntil = Math.max(cooldownUntil, Date.now() + 20000);
        }
        call.stopReason = data?.stop_reason; call.stopCategory = data?.stop_details?.category; call.contentTypes = responseShape(data);
        call.responseModel = data?.model;
        if (data?.usage) {
          call.usage = rawUsage(data.usage);
          call.costUsd = options.live ? callCostUsd(data.model || body.model, call.usage) : 0;
          ledger.spentUsd += call.costUsd;
          appendFileSync(ledgerFile, scrub(JSON.stringify({ at: new Date().toISOString(), arm: ctx.arm, turnId: ctx.turnId, kind: ctx.kind, model: data.model || body.model, usage: call.usage, costUsd: +call.costUsd.toFixed(6), spentUsd: +ledger.spentUsd.toFixed(6) })) + '\n');
        }
        return new Response(text, { status: response.status, statusText: response.statusText, headers: { 'content-type': 'application/json' } });
      }
    } catch (error) {
      call.endMs ??= Math.round(performance.now() - ctx.t0);
      call.error ??= /abort/i.test(error.name + error.message) ? 'aborted_or_timeout' : String(error.message).slice(0, 160);
      throw error;
    }
  }

  const armLabels = Object.fromEntries(armNames.map(arm => [arm, armsBook.arms[arm].label]));
  const armConfigs = Object.fromEntries(armNames.map(arm => [arm, { config: armsBook.arms[arm].config, routes: armRoutes(armsBook.arms[arm].config) }]));
  const meta = { runId, mode: options.live ? 'live' : 'dry-run', set: options.set, ...(options.probe ? { probe: options.probe } : {}), blocks, arms: armNames, armLabels, armConfigs, baselineArm, pinnedNow: options.now,
    concurrency: options.concurrency, maxReruns: options.maxReruns, budgetUsd: options.budgetUsd, judge: options.judge ? { model: JUDGE_MODEL, effort: 'low' } : null, drafts: options.drafts,
    gitHead: gitHead(), node: process.version, pricingDate: PRICING_DATE, keyEnvVar: keyVar || null, workspaceHeader: !!workspaceId,
    intentMirror: { expected: INTENT_MIRROR_FINGERPRINT, server: fingerprint, ok: fingerprint === INTENT_MIRROR_FINGERPRINT },
    cases: selected.map(item => item.id), turns: selected.reduce((sum, item) => sum + item.turns.length, 0), startedAt: new Date().toISOString() };
  // A resume keeps the provenance of the answers already on disk (first start,
  // code head, budget) and appends this session, e.g. a judge-only pass.
  const metaPath = path.join(runDir, 'meta.json');
  if (options.resume && existsSync(metaPath)) {
    const first = JSON.parse(readFileSync(metaPath, 'utf8'));
    Object.assign(meta, { startedAt: first.startedAt, gitHead: first.gitHead, budgetUsd: first.budgetUsd,
      resumes: [...(first.resumes || []), { at: meta.startedAt, gitHead: meta.gitHead, budgetUsd: options.budgetUsd, spentBeforeUsd: +ledger.spentUsd.toFixed(4), arms: armNames, judge: options.judge }] });
  }
  writeFileSync(metaPath, scrub(JSON.stringify(meta, null, 1)));
  console.log(`Run ${runId} (${meta.mode}) -> ${runDir}`);
  console.log(`${selected.length} cases / ${meta.turns} turns x ${armNames.length} arms; pinned now ${options.now}; budget ${options.live ? `$${options.budgetUsd}` : '$0 (dry run)'}; spent so far $${ledger.spentUsd.toFixed(3)}`);

  const publicContext = createPublicContext({ guideCatalog: catalogs.guideCatalog, englishGuideCatalog: catalogs.englishGuideMap });
  const secret = randomBytes(32).toString('hex');

  async function runTurn({ arm, assistant, item, turn, history, sessionToken }) {
    const ctx = { arm, turnId: turn.id, kind: 'assistant', calls: [], requestOverrides: armsBook.arms[arm].requestOverrides, t0: performance.now(), progress: [], pending: [], drafts: [] };
    return als.run(ctx, async () => {
      let payload, error;
      try {
        const searchContext = validateChatSearchContext(turn.searchContext);
        const normalized = normalizeGuideHistory(history.length ? history : undefined);
        if (!normalized.ok) throw new Error(normalized.error);
        const pre = preDispatch({ message: turn.message, history: normalized.history, locale: item.locale, nowMs, secret, guideCatalog: catalogs.guideCatalog, englishGuideCatalog: catalogs.englishGuideMap });
        if (pre) payload = pre;
        else {
          const webAccess = baybayWebAccess(item.member ? 'eval-member' : null);
          const searchMode = webAccess.allowed ? item.searchMode || 'smart' : 'site';
          const pageContext = publicContext.resolve({ context: { currentPath: item.currentPath }, currentPath: item.currentPath, today: bayAreaDate(now), locale: item.locale });
          payload = await assistant.run({ message: turn.message, history: normalized.history, searchContext, sessionToken, searchMode, locale: item.locale, currentPath: item.currentPath,
            webAccess, pageContext, ip: 'local-eval',
            onProgress: event => { ctx.progress.push([Math.round(performance.now() - ctx.t0), event.phase, event.status]); },
            onQuickCard: cards => { if (cards?.length && ctx.firstCardMs == null) ctx.firstCardMs = Math.round(performance.now() - ctx.t0); },
            // A capable client (streamVersion 3): the draft events guide-chat would write.
            // Lead TTFT = the first `lead` draft, exactly what the reader would see first.
            ...(options.drafts ? { onDraft: event => {
              const ms = Math.round(performance.now() - ctx.t0);
              ctx.drafts.push({ ms, seq: event.seq, field: event.field, chars: event.text.length });
              if (event.field === 'lead' && ctx.firstDraftMs == null) ctx.firstDraftMs = ms;
            } } : {}) });
        }
      } catch (caught) { error = String(caught?.message || caught).slice(0, 300); }
      const completeMs = Math.round(performance.now() - ctx.t0);
      await Promise.allSettled(ctx.pending);
      return { payload, error, ctx, completeMs };
    });
  }

  function resultRow({ arm, item, turn, outcome, attempts }) {
    const { payload, error, ctx, completeMs } = outcome;
    const route = error ? 'error' : routeOf(payload);
    const warnings = payload?.research?.warnings || [];
    const usage = ctx.calls.reduce((sum, call) => { for (const key of Object.keys(sum)) sum[key] += call.usage?.[key] || 0; return sum; }, { inputTokens: 0, cacheWriteTokens: 0, cacheReadTokens: 0, outputTokens: 0, webSearches: 0 });
    const model = route === 'assistant';
    return {
      runId, arm, model: armConfigs[arm].routes.agent.model, effort: armConfigs[arm].routes.agent.effort, professionalModel: armConfigs[arm].routes.professional.model, fastModel: armConfigs[arm].routes.fast.model,
      caseId: item.id, turnId: turn.id, block: item.block, locale: item.locale, currentPath: item.currentPath, tags: [...new Set([...(item.tags || []), ...(turn.tags || [])])], message: turn.message,
      route, responseMode: payload?.responseMode, safetyRoute: payload?.safetyRoute, legacyReason: payload?.legacyReason,
      engine: payload?.engine || 'v1', routePath: payload?.route?.path || (route === 'assistant' ? 'agent' : route), routeReason: payload?.route?.reason, lead: payload?.lead || null, points: payload?.points || null,
      degraded: !!payload?.degraded, degradedReplay: !!item.degradedReplay, voidedAttempts: attempts - 1, voidFinal: !!outcome.voidFinal, budgetStopped: !!outcome.budgetStopped, error,
      answer: payload?.answer || '', answerChars: String(payload?.answer || '').length,
      sources: (payload?.sources || []).map(({ title, url }) => ({ title, url })),
      localMatches: (payload?.localMatches || []).map(({ kind, id, title }) => ({ kind, id, title })),
      suggestedGuides: (payload?.suggestedGuides || []).map(({ title, url }) => ({ title, url })),
      followups: payload?.followups || [], warnings, plan: payload?.assistantPlan ? { status: payload.assistantPlan.status, stops: (payload.assistantPlan.stops || []).map(stop => stop.title) } : null,
      modelResponses: payload?.research?.modelResponses || [], steps: (payload?.research?.steps || []).map(step => ({ tool: step.tool, status: step.status })),
      calls: ctx.calls, toolRounds: toolRounds(ctx.calls), usage, costUsd: +ctx.calls.reduce((sum, call) => sum + (call.costUsd || 0), 0).toFixed(6),
      timings: { firstCardMs: ctx.firstCardMs ?? null, ttftMs: model ? ctx.calls.find(call => call.headersMs != null)?.headersMs ?? null : completeMs,
        leadMs: ctx.firstDraftMs ?? completeMs, leadSource: ctx.firstDraftMs != null ? 'draft-event' : 'answer-complete', completeMs, progress: ctx.progress, stages: payload?.research?.timings || null,
        firstTextMs: ctx.calls.find(call => call.firstTextMs != null)?.firstTextMs ?? null },
      // API-BB-STREAM: the draft events this turn produced and whether the result corrected them.
      drafts: ctx.drafts.length ? { events: ctx.drafts.length, chars: ctx.drafts.reduce((sum, row) => sum + row.chars, 0), firstLeadMs: ctx.firstDraftMs ?? null,
        lastMs: ctx.drafts.at(-1).ms, corrected: payload?.corrected ?? null } : null,
      gold: error ? { pass: false, checks: [{ id: 'run_error', ok: false, detail: error }], route, falseNegative: false, falseNegativeCaught: false, safetyMiss: !!turn.gold.safety } : scoreTurn(turn.gold, payload, { corpus: `${catalogs.corpus}\n${turn.message}` }),
    };
  }

  function isVoid(item, outcome) {
    if (item.degradedReplay) return false;
    if (outcome.error) return true;
    const { payload, ctx } = outcome;
    if (routeOf(payload) !== 'assistant' || !payload?.degraded) return false;
    const warnings = payload.research?.warnings || [];
    return warnings.some(warning => PROVIDER_FAILURE_WARNINGS.has(warning)) || ctx.calls.some(call => call.error);
  }

  async function runConversation(arm, assistant, item, resultsFile) {
    const history = [];
    let sessionToken;
    for (const turn of item.turns) {
      if (item.requires === 'web') {
        writeJsonl(resultsFile, { runId, arm, caseId: item.id, turnId: turn.id, block: item.block, skipped: 'requires_web', gold: null });
        console.log(`[${arm}] ${turn.id} skipped (needs web search wiring, v1)`);
        continue;
      }
      let outcome, attempts = 0;
      for (;;) {
        while (Date.now() < cooldownUntil) await sleep(Math.min(1000, cooldownUntil - Date.now()));
        if (ledger.exhausted) { outcome = { payload: null, error: 'budget_exhausted', ctx: { calls: [], progress: [] }, completeMs: 0, budgetStopped: true }; break; }
        attempts++;
        // A case may cap the model rounds (validated: no model or effort keys) and use the web stub.
        const armConfig = { ...baseConfig, ...armsBook.arms[arm].config, ...(item.config || {}), ...(item.degradedReplay ? { ANTHROPIC_USE_UNTIL: '2026-10-01T00:00:00Z' } : {}) };
        const runner = item.degradedReplay || item.config || item.webStub ? buildAssistant(armConfig, { webStub: item.webStub }) : assistant;
        outcome = await runTurn({ arm, assistant: runner, item, turn, history, sessionToken });
        if (ledger.exhausted && isVoid(item, outcome)) { outcome.budgetStopped = true; break; }
        if (!isVoid(item, outcome)) break;
        if (attempts > options.maxReruns) { outcome.voidFinal = true; break; }
        const backoff = 10000 * 2 ** (attempts - 1);
        console.log(`[${arm}] ${turn.id} degraded by provider/transport (${(outcome.error || outcome.payload?.research?.warnings?.join(',') || '').slice(0, 80)}); rerun ${attempts}/${options.maxReruns} in ${backoff / 1000}s`);
        cooldownUntil = Math.max(cooldownUntil, Date.now() + backoff);
      }
      const row = resultRow({ arm, item, turn, outcome, attempts: Math.max(1, attempts) });
      writeJsonl(resultsFile, row);
      console.log(`[${arm}] ${turn.id} ${row.budgetStopped ? 'BUDGET-STOP' : row.gold.pass ? 'pass' : 'FAIL'} route=${row.route}${row.toolRounds.length ? ` tool-rounds=${row.toolRounds.map(round => `${round.toolUse.status} tool_use -> ${round.next ? `${round.next.status} ${round.next.stopReason} (tool_choice ${round.next.toolChoice}, ${round.next.toolResults} tool_result)` : 'no next call'}`).join('; ')}` : ''} ${(row.timings.completeMs / 1000).toFixed(1)}s $${row.costUsd.toFixed(4)} (spent $${ledger.spentUsd.toFixed(3)})${row.voidFinal ? ' still-degraded' : ''}`);
      if (row.budgetStopped) return;
      const answer = String(outcome.payload?.answer || '').trim();
      if (answer) {
        history.push({ role: 'user', content: turn.message.trim().slice(0, 500) }, { role: 'assistant', content: answer.slice(0, 1200) });
        history.splice(0, Math.max(0, history.length - 8));
      }
      sessionToken = outcome.payload?.assistantSessionToken || sessionToken;
    }
  }

  const baseConfig = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: apiKey, ...(workspaceId ? { ANTHROPIC_WORKSPACE_ID: workspaceId } : {}),
    BAYBAY_STATE_SECRET: secret, BAYBAY_DAILY_RUN_LIMIT: '100000', BAYBAY_AGENT_ENABLED: 'true' };
  // A probe case's web search is a local stub: no network, one fixed lead without sources.
  const stubWebSearch = async () => ({ answer: 'Eval probe stub: no live web result is available in the local eval.', sources: [], candidates: [], checkedAt: new Date(nowMs).toISOString(), cached: false, model: 'eval-stub' });
  // read_source has its own page reader (lib/sourceMonitor), not fetchImpl: block it
  // too, so a member-mode read fails closed instead of fetching the page.
  const blockedSourceFetch = async source => {
    throw new Error(`eval harness blocks network access to ${(() => { try { return new URL(source?.url).host; } catch { return 'an invalid URL'; } })()}`);
  };
  const buildAssistant = (config, { webStub } = {}) => createBayBayAssistant({ config, guideCatalog: catalogs.guideCatalog, englishGuideCatalog: catalogs.englishSearchCatalog,
    isTest: false, Quota: createMemoryQuota(), now, fetchImpl: providerFetch, sourceFetch: blockedSourceFetch, ...(webStub ? { webSearch: stubWebSearch } : {}) });

  // Preflight: one tiny Haiku request proves the key, workspace header and
  // credit before any arm starts (a bad key would otherwise burn reruns).
  if (options.live) {
    const ctx = { arm: 'preflight', turnId: 'preflight', kind: 'preflight', calls: [], t0: performance.now() };
    const response = await als.run(ctx, () => providerFetch(MESSAGES_URL, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}`, 'anthropic-version': '2023-06-01', ...(workspaceId ? { 'anthropic-workspace-id': workspaceId } : {}) },
      body: JSON.stringify({ model: 'claude-haiku-5-5', max_tokens: 64, output_config: { effort: 'low' }, messages: [{ role: 'user', content: 'Reply with OK.' }] }) }));
    if (!response.ok) throw new Error(`Preflight failed: HTTP ${response.status} ${ctx.calls[0]?.error || ''}. Check the key, workspace id and credit; nothing else was sent.`);
    console.log(`Preflight ok (${ctx.calls[0]?.endMs} ms).`);
  }

  // Phase 1: answers. Cheap arms first so a budget stop never loses them.
  for (const arm of armNames) {
    if (ledger.exhausted) break;
    const resultsFile = `results-${arm}.jsonl`;
    const done = new Set(options.resume && existsSync(path.join(runDir, resultsFile))
      ? readFileSync(path.join(runDir, resultsFile), 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(row => !row.budgetStopped).map(row => row.turnId) : []);
    const pending = selected.filter(item => !item.turns.every(turn => done.has(turn.id)));
    if (!pending.length) { console.log(`[${arm}] already complete`); continue; }
    const assistant = buildAssistant({ ...baseConfig, ...armsBook.arms[arm].config });
    console.log(`\n== ${arm}: ${armsBook.arms[arm].label} (${pending.length} cases)`);
    // One conversation first (warms any cacheable prefix), then fan out.
    await runConversation(arm, assistant, pending[0], resultsFile);
    let next = 1;
    await Promise.all(Array.from({ length: options.concurrency }, async () => {
      while (next < pending.length && !ledger.exhausted) await runConversation(arm, assistant, pending[next++], resultsFile);
    }));
  }

  // Phase 2: judge model-answered turns (Opus 5.5, effort low), budget permitting.
  if (options.judge) {
    const judge = createJudge({ apiKey, workspaceId, fetchImpl: providerFetch, dryRun: !options.live });
    // Baseline first: if the budget runs out mid-judge, the comparison point is complete.
    for (const arm of [...armNames].sort((a, b) => Number(b === baselineArm) - Number(a === baselineArm))) {
      const resultsPath = path.join(runDir, `results-${arm}.jsonl`), judgeFile = `judge-${arm}.jsonl`;
      if (!existsSync(resultsPath)) continue;
      const rows = [...new Map(readFileSync(resultsPath, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).map(row => [row.turnId, row])).values()];
      const judged = new Set(existsSync(path.join(runDir, judgeFile)) ? readFileSync(path.join(runDir, judgeFile), 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(row => row.scores).map(row => row.turnId) : []);
      const todo = rows.filter(row => row.route === 'assistant' && row.answer && !row.voidFinal && !row.budgetStopped && !judged.has(row.turnId));
      let next = 0;
      await Promise.all(Array.from({ length: options.concurrency }, async () => {
        while (next < todo.length && !ledger.exhausted) {
          const row = todo[next++];
          const item = selected.find(entry => entry.id === row.caseId), turn = item?.turns.find(entry => entry.id === row.turnId);
          if (!turn) continue;
          const ctx = { arm, turnId: row.turnId, kind: 'judge', calls: [], t0: performance.now() };
          try {
            const scores = await als.run(ctx, () => judge(judgeCase({ turn, item, payload: row, completeMs: row.timings.completeMs, pinnedNow: options.now })));
            writeJsonl(judgeFile, { arm, turnId: row.turnId, scores, costUsd: +ctx.calls.reduce((sum, call) => sum + (call.costUsd || 0), 0).toFixed(6) });
          } catch (error) {
            writeJsonl(judgeFile, { arm, turnId: row.turnId, error: String(error.message).slice(0, 200), costUsd: +ctx.calls.reduce((sum, call) => sum + (call.costUsd || 0), 0).toFixed(6) });
          }
        }
      }));
      console.log(`[judge] ${arm}: ${todo.length} turns (spent $${ledger.spentUsd.toFixed(3)})`);
    }
  }

  writeFileSync(metaPath, scrub(JSON.stringify({ ...meta, finishedAt: new Date().toISOString(), spentUsd: +ledger.spentUsd.toFixed(4), budgetExhausted: ledger.exhausted }, null, 1)));
  const { markdown } = writeReport(runDir, baselineArm);
  console.log(`\n${markdown}`);
  console.log(`Spent $${ledger.spentUsd.toFixed(3)}${options.live ? ` of $${options.budgetUsd}` : ' (dry run)'}${ledger.exhausted ? ' - BUDGET EXHAUSTED, run stopped early' : ''}. Results: ${runDir}`);
}

main().catch(error => { console.error(error.message); process.exit(1); });
