#!/usr/bin/env node
// Source-triage dry run (docs/source-monitor.md, "Change triage"). Classifies
// pending source changes with the production triage code against an IN-MEMORY
// store: no MongoDB, no production writes, no email. Output goes OUTSIDE the
// repository.
//
//   node scripts/source-triage-dry-run.mjs --snapshots <file.json> [--out <dir>]
//        [--live --budget-usd 0.10] [--thinking adaptive|disabled] [--limit 200]
//        [--now 2026-10-08T20:00:00-07:00]
//
// <file.json> is either the admin export (GET /api/admin/source-monitor, saved
// by an administrator) or an array of rows shaped like it:
//   { id | sourceId, hash, reviewStatus: 'pending', pendingChange: { removed[], added[], summary, detectedAt, before?, after? } }
// Rows whose id is not in data/source-registry.json are skipped. When a stored diff was
// cut off at 12 lines and the row carries the page texts (pendingChange.before/after, as
// the admin export does), triage rebuilds it with up to 40 lines per side, as in production. `--now` (or a
// top-level `now` in the file, as in the casebook) fixes the clock, so sources that
// have ended since the file was written are still classified.
//
// Without --live a synthetic provider answers "material" for every change ($0).
// --live reads ANTHROPIC_API_KEY (and optional ANTHROPIC_WORKSPACE_ID) from the
// environment only; the key is never printed, logged or written. The only
// reachable URL is https://api.anthropic.com/v1/messages, and the run stops
// before a call that could exceed --budget-usd.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { createSourceTriage, createItemIndex, buildDigest, freshnessFields, triageMessages } = require(path.join(ROOT, 'lib/sourceTriage'));
const registry = require(path.join(ROOT, 'data/source-registry.json'));
const MESSAGES_URL = 'https://api.anthropic.com/v1/messages';

const args = process.argv.slice(2);
const flag = name => args.includes(name);
const option = (name, fallback) => { const at = args.indexOf(name); return at >= 0 && args[at + 1] ? args[at + 1] : fallback; };
const snapshotsPath = option('--snapshots');
if (!snapshotsPath) { console.error('Usage: --snapshots <file.json> [--out <dir>] [--live --budget-usd N] [--thinking disabled] [--limit N]'); process.exit(2); }
const live = flag('--live');
const budgetUsd = Number(option('--budget-usd', '0'));
if (live && !(budgetUsd > 0 && budgetUsd <= 5)) { console.error('--live needs --budget-usd between 0 and 5.'); process.exit(2); }
if (live && !process.env.ANTHROPIC_API_KEY) { console.error('--live needs ANTHROPIC_API_KEY in the environment.'); process.exit(2); }
const thinking = option('--thinking', 'adaptive');
const limit = Math.min(Math.max(Number(option('--limit', '400')) || 400, 1), 2000);
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = path.resolve(option('--out', path.join(os.homedir(), 'opus-qa', 'overhaul', 'eval', `triage-${stamp}`)));
if (outDir.startsWith(ROOT)) { console.error('Write results outside the repository.'); process.exit(2); }

const raw = JSON.parse(readFileSync(snapshotsPath, 'utf8'));
const fixedNow = option('--now') || (!Array.isArray(raw) && typeof raw.now === 'string' ? raw.now : '');
const clock = fixedNow ? Date.parse(fixedNow) : null;
if (fixedNow && !Number.isFinite(clock)) { console.error('--now needs an ISO date-time.'); process.exit(2); }
const now = () => clock ?? Date.now();
const exported = Array.isArray(raw) ? raw : raw.sources;
const known = new Map(registry.map(row => [row.id, row]));
const rows = new Map();
const expected = new Map();
for (const row of exported || []) {
  const sourceId = row.sourceId || row.id;
  if (!known.has(sourceId) || row.reviewStatus !== 'pending' || !row.pendingChange) continue;
  const hash = /^[a-f0-9]{64}$/.test(row.hash || '') ? row.hash : createHash('sha256').update(JSON.stringify(row.pendingChange)).digest('hex');
  rows.set(sourceId, { sourceId, hash, status: row.status || 'changed', reviewStatus: 'pending', pendingChange: row.pendingChange });
  // Casebook rows (scripts/eval/source-triage-cases.json) carry the expected decision.
  if (row.expect) expected.set(sourceId, { expect: row.expect, note: row.note || '' });
}

// In-memory store with the production compare-and-set semantics.
const store = {
  pendingForTriage: async () => [...rows.values()].filter(row => row.reviewStatus === 'pending').map(row => ({ ...row })),
  get: async sourceId => rows.has(sourceId) ? { ...rows.get(sourceId) } : null,
  list: async () => [...rows.values()].map(row => ({ ...row })),
  triage: async (sourceId, expectedHash, patch) => { const row = rows.get(sourceId); if (!row || row.hash !== expectedHash || row.reviewStatus !== 'pending') return null; Object.assign(row, patch); return row; },
};

let spentMicroUsd = 0, calls = 0;
const ESTIMATE_MICRO_USD = 2000; // generous per-call ceiling for Haiku 5.5 (~5k in / 2k out)
const synthetic = async (_url, init) => {
  const body = JSON.parse(init.body);
  return { ok: true, status: 200, json: async () => ({ type: 'message', model: body.model, stop_reason: 'end_turn', usage: { input_tokens: 0, output_tokens: 0 },
    content: [{ type: 'text', text: JSON.stringify({ material: true, fields: ['other'], summary_zh: '合成答案（未调用模型）' }) }] }) };
};
const guarded = async (url, init) => {
  if (String(url) !== MESSAGES_URL) throw new Error('Blocked URL');
  if ((spentMicroUsd + ESTIMATE_MICRO_USD) / 1e6 > budgetUsd) throw Object.assign(new Error('Budget reached'), { code: 'BUDGET' });
  calls++;
  return fetch(url, init);
};
const config = { SOURCE_TRIAGE: 'on', BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: live ? process.env.ANTHROPIC_API_KEY : 'synthetic',
  ...(process.env.ANTHROPIC_WORKSPACE_ID ? { ANTHROPIC_WORKSPACE_ID: process.env.ANTHROPIC_WORKSPACE_ID } : {}),
  ...(thinking === 'disabled' ? { BAYBAY_THINKING_TRIAGE: 'disabled' } : {}) };
const items = createItemIndex();
const perCall = [];
const triage = createSourceTriage({ store, registry, config, items, now, dailyLimit: 2000, batchLimit: limit, batchMaxMs: 60 * 60 * 1000,
  logger: { info() {}, warn() {}, error() {} }, fetchImpl: live ? guarded : synthetic,
  recordSpend: billing => { if (billing?.priced) { spentMicroUsd += billing.microUsd; perCall.push(billing.microUsd); } } });

function casebookScore(list) {
  const scored = list.filter(row => row.expect);
  const missed = scored.filter(row => row.expect.material && row.decision?.material === false);
  const extra = scored.filter(row => !row.expect.material && row.decision?.material === true);
  const fieldHits = scored.filter(row => row.expect.material && row.expect.fields && row.decision?.material && row.expect.fields.every(field => row.decision.fields.includes(field)));
  return { cases: scored.length, correct: scored.filter(row => row.correct).length, materialMissed: missed.map(row => row.sourceId), cosmeticKeptPending: extra.map(row => row.sourceId),
    undecided: scored.filter(row => typeof row.decision?.material !== 'boolean').map(row => row.sourceId),
    fieldsMatched: `${fieldHits.length}/${scored.filter(row => row.expect.material && row.expect.fields).length}` };
}

const started = Date.now();
const report = await triage.run();
const elapsedMs = Date.now() - started;
const results = await Promise.all([...rows.values()].map(async row => {
  const source = known.get(row.sourceId);
  // The lines triage judged: the stored diff, or the rebuilt one when it was cut off.
  const seen = await triage.changeFor({ ...row, triage: undefined });
  return { sourceId: row.sourceId, kind: source.kind, title: source.title, url: source.url, contentIds: source.contentIds,
    listings: items.items(source.contentIds).slice(0, 3).map(item => ({ title: item.title, dateLabel: item.dateLabel, costLabel: item.costLabel })),
    removed: seen.removed, added: seen.added, summary: row.pendingChange.summary, cutOff: seen.truncated, linesPerSide: seen.lineCap,
    decision: row.triage ? { material: row.triage.material ?? null, fields: row.triage.fields || [], summaryZh: row.triage.summaryZh || '', decidedBy: row.triage.decidedBy || null, guards: row.triage.guards || [], failures: row.triage.failures || 0, error: row.triage.lastError || null } : null,
    autoDismissed: row.reviewedBy === 'auto-triage', freshness: freshnessFields(row),
    ...(expected.has(row.sourceId) ? { ...expected.get(row.sourceId), correct: row.triage?.material === expected.get(row.sourceId).expect.material } : {}) };
}));
mkdirSync(outDir, { recursive: true });
writeFileSync(path.join(outDir, 'results.json'), JSON.stringify(results, null, 1));
const digest = buildDigest({ rows: [...rows.values()], registry, items, now: now() });
writeFileSync(path.join(outDir, 'digest-preview.txt'), digest ? `${digest.subject}\n\n${digest.text}\n` : '(nothing to send)\n');
writeFileSync(path.join(outDir, 'prompt-sample.txt'), results[0] ? triageMessages(known.get(results[0].sourceId), { removed: results[0].removed, added: results[0].added, summary: results[0].summary, truncated: results[0].cutOff, lineCap: results[0].linesPerSide }, items.items(known.get(results[0].sourceId).contentIds)).map(m => `## ${m.role}\n${m.content}`).join('\n\n') : '');
const summary = {
  live, thinking, now: new Date(now()).toISOString(), pending: rows.size, triaged: report.triaged ?? 0, material: report.material ?? 0, dismissed: report.dismissed ?? 0, failed: report.failed ?? 0,
  // Without --live every answer is synthetic ("material"): a pipeline smoke test, not a measure of accuracy.
  ...(live ? {} : { note: 'synthetic provider: every model answer is "material"; this checks the pipeline, not accuracy' }),
  modelCalls: calls, usd: Number((spentMicroUsd / 1e6).toFixed(5)), meanUsdPerCall: perCall.length ? Number((spentMicroUsd / perCall.length / 1e6).toFixed(6)) : 0, elapsedMs,
  ...(expected.size ? { casebook: casebookScore(results) } : {}),
};
writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 1));
console.log(JSON.stringify(summary));
console.log(`Results: ${outDir}`);
