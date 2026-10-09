#!/usr/bin/env node
// Summarise one local-eval run directory: per-arm code gold, safety misses,
// false negatives, judge means, latency percentiles and dollars, plus the
// R0SWITCH check from the overhaul plan (§3.1) against the baseline arm.
//   node scripts/eval/report.mjs <run-dir> [--baseline opus-asis] [--rescore]
// --rescore re-applies the current casebook golds to the stored answers (same
// rules for every arm), e.g. after widening a regex that rejected a correct
// phrasing. The summary records that it was rescored.
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DIMENSIONS, dimensionMean } from './judge.mjs';
import { scoreTurn } from './gold.mjs';

const EVAL_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(EVAL_DIR, '..', '..');

/** Re-score stored rows with the casebook (and probe files) currently on disk. */
export function rescoreRun(run) {
  const golds = new Map(readdirSync(EVAL_DIR).filter(file => /^(?:cases-[A-H]-.+|probe-.+)\.json$/.test(file))
    .flatMap(file => JSON.parse(readFileSync(path.join(EVAL_DIR, file), 'utf8')).cases.flatMap(item => item.turns)).map(turn => [turn.id, turn.gold]));
  const corpus = ['guide-catalog.json', 'guide-catalog.en.json', 'planner-catalog.json', 'discoveries.json', 'discoveries.en.json']
    .map(file => readFileSync(path.join(ROOT, 'data', file), 'utf8')).join('\n');
  for (const rows of Object.values(run.arms)) for (const row of rows) {
    const gold = golds.get(row.turnId);
    if (!gold || row.skipped || row.budgetStopped || row.error) continue;
    row.gold = scoreTurn(gold, { answer: row.answer, responseMode: row.responseMode, safetyRoute: row.safetyRoute,
      harnessRoute: ['outing', 'legacy'].includes(row.route) ? row.route : undefined, sources: row.sources, suggestedGuides: row.suggestedGuides,
      localMatches: row.localMatches, research: { warnings: row.warnings } }, { corpus: `${corpus}\n${row.message || ''}` });
  }
  run.meta = { ...run.meta, rescored: true };
  return run;
}

export const R0SWITCH = { goldSlack: 2, completeP50Ms: 10000 };

const readJsonl = file => existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
const lastBy = (rows, key) => [...new Map(rows.map(row => [row[key], row])).values()];

export function percentile(values, p) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}
const mean = values => values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;

export function loadRun(runDir) {
  const meta = JSON.parse(readFileSync(path.join(runDir, 'meta.json'), 'utf8'));
  const arms = {}, judges = {};
  for (const file of readdirSync(runDir)) {
    const result = /^results-(.+)\.jsonl$/.exec(file), judge = /^judge-(.+)\.jsonl$/.exec(file);
    if (result) arms[result[1]] = lastBy(readJsonl(path.join(runDir, file)), 'turnId');
    if (judge) judges[judge[1]] = new Map(lastBy(readJsonl(path.join(runDir, file)), 'turnId').map(row => [row.turnId, row]));
  }
  return { meta, arms, judges };
}

export function summarizeArm(rows, judgeRows = new Map()) {
  const scored = rows.filter(row => !row.skipped && !row.budgetStopped);
  // Model-answered = the assistant route AND at least one provider call. The
  // assistant also answers some turns without the model (degraded replays,
  // the out-of-region reply); those are identical in every arm and would pull
  // latency, $/question and judge means toward each other.
  const model = scored.filter(row => row.route === 'assistant' && (row.calls || []).length > 0);
  const judged = model.map(row => judgeRows.get(row.turnId)).filter(row => row?.scores);
  const blocks = {};
  for (const row of scored) {
    blocks[row.block] ||= { pass: 0, total: 0 };
    blocks[row.block].total++; if (row.gold?.pass) blocks[row.block].pass++;
  }
  const sum = key => scored.reduce((total, row) => total + (row.usage?.[key] || 0), 0);
  const cost = scored.reduce((total, row) => total + (row.costUsd || 0), 0);
  const calls = scored.flatMap(row => row.calls || []);
  return {
    turns: scored.length, skipped: rows.filter(row => row.skipped).length, budgetStopped: rows.filter(row => row.budgetStopped).length,
    modelTurns: model.length,
    goldPass: scored.filter(row => row.gold?.pass).length,
    blocks,
    safetyMisses: scored.filter(row => row.gold?.safetyMiss).map(row => row.turnId),
    // Misses on turns this arm's model actually answered. Deterministic routes
    // (safety templates, degraded replays) are identical in every arm.
    safetyMissesModel: scored.filter(row => row.gold?.safetyMiss && row.route === 'assistant' && !row.degradedReplay).map(row => row.turnId),
    // Diagnostic: safety misses whose answer never mentions 911 at all.
    safetyNo911: scored.filter(row => row.gold?.safetyMiss && !/911/.test(row.answer || '')).map(row => row.turnId),
    falseNegatives: scored.filter(row => row.gold?.falseNegative).map(row => row.turnId),
    falseNegativesCaught: scored.filter(row => row.gold?.falseNegativeCaught).map(row => row.turnId),
    voidedAttempts: scored.reduce((total, row) => total + (row.voidedAttempts || 0), 0),
    voidFinal: scored.filter(row => row.voidFinal).map(row => row.turnId),
    refusals: calls.filter(call => call.stopReason === 'refusal').length,
    tokenLimited: calls.filter(call => call.stopReason === 'max_tokens').length,
    providerCalls: calls.length,
    judge: judged.length ? {
      n: judged.length,
      dims: Object.fromEntries(DIMENSIONS.map(([key]) => [key, mean(judged.map(row => row.scores[key]))])),
      mean3: mean(judged.map(row => dimensionMean(row.scores))),
      overall10: mean(judged.map(row => row.scores.overall10).filter(Number.isFinite)),
    } : null,
    latency: {
      firstCardP50: percentile(model.map(row => row.timings?.firstCardMs), 50),
      ttftP50: percentile(model.map(row => row.timings?.ttftMs), 50),
      leadP50: percentile(model.map(row => row.timings?.leadMs), 50), leadP90: percentile(model.map(row => row.timings?.leadMs), 90),
      completeP50: percentile(model.map(row => row.timings?.completeMs), 50), completeP90: percentile(model.map(row => row.timings?.completeMs), 90),
    },
    usage: { inputTokens: sum('inputTokens'), cacheWriteTokens: sum('cacheWriteTokens'), cacheReadTokens: sum('cacheReadTokens'), outputTokens: sum('outputTokens') },
    // API-BB-ENGINE: engine path, prompt caching and cards.
    engine: (() => {
      const fast = model.filter(row => row.routePath === 'fast'), agent = model.filter(row => row.routePath === 'agent');
      const assistantCalls = row => (row.calls || []).filter(call => call.kind === 'assistant' && call.usage);
      const multi = model.filter(row => assistantCalls(row).length >= 2);
      const modelCalls = model.flatMap(assistantCalls);
      return {
        fastTurns: fast.length, agentTurns: agent.length,
        fastCompleteP50: percentile(fast.map(row => row.timings?.completeMs), 50), fastCompleteP90: percentile(fast.map(row => row.timings?.completeMs), 90),
        agentCompleteP50: percentile(agent.map(row => row.timings?.completeMs), 50),
        callsWithCacheRead: modelCalls.filter(call => call.usage.cacheReadTokens > 0).length, modelCalls: modelCalls.length,
        secondCallsWithCacheRead: multi.filter(row => assistantCalls(row)[1].usage.cacheReadTokens > 0).length, runsWithSecondCall: multi.length,
        promptTokensP50: percentile(modelCalls.map(call => call.usage.inputTokens + call.usage.cacheWriteTokens + call.usage.cacheReadTokens), 50),
        withCards: model.filter(row => (row.localMatches || []).length > 0).length,
        withLead: model.filter(row => row.lead).length,
        retries: model.filter(row => (row.warnings || []).some(warning => /^fast_retry_/.test(warning))).length,
      };
    })(),
    costUsd: cost,
    costPerModelTurn: model.length ? model.reduce((total, row) => total + (row.costUsd || 0), 0) / model.length : null,
    judgeCostUsd: [...judgeRows.values()].reduce((total, row) => total + (row.costUsd || 0), 0),
  };
}

export function r0switch(candidate, baseline) {
  const checks = {
    codeGold: { ok: candidate.goldPass >= baseline.goldPass - R0SWITCH.goldSlack, detail: `${candidate.goldPass} vs baseline ${baseline.goldPass} (needs >= ${baseline.goldPass - R0SWITCH.goldSlack})` },
    // 0 misses on model-answered turns, and no deterministic miss the baseline does not share.
    safety: { ok: candidate.safetyMissesModel.length === 0 && candidate.safetyMisses.length <= baseline.safetyMisses.length,
      detail: `model-answered: ${candidate.safetyMissesModel.join(', ') || 'none'}; pipeline (all arms): ${candidate.safetyMisses.filter(id => !candidate.safetyMissesModel.includes(id)).join(', ') || 'none'}` },
    falseNegatives: { ok: candidate.falseNegatives.length + candidate.falseNegativesCaught.length <= baseline.falseNegatives.length + baseline.falseNegativesCaught.length,
      detail: `${candidate.falseNegatives.length + candidate.falseNegativesCaught.length} vs baseline ${baseline.falseNegatives.length + baseline.falseNegativesCaught.length}` },
    completeP50: { ok: candidate.latency.completeP50 != null && candidate.latency.completeP50 <= R0SWITCH.completeP50Ms, detail: `${fmtS(candidate.latency.completeP50)} (needs <= 10.0 s)` },
  };
  const complete = candidate.turns === baseline.turns && !candidate.budgetStopped && !baseline.budgetStopped;
  return { pass: complete && Object.values(checks).every(row => row.ok), complete, checks };
}

const fmtS = ms => ms == null ? 'n/a' : `${(ms / 1000).toFixed(1)} s`;
const fmt$ = usd => usd == null ? 'n/a' : `$${usd.toFixed(usd < 0.01 ? 4 : 3)}`;
const fmtN = (value, digits = 2) => value == null ? 'n/a' : value.toFixed(digits);

export function summarize(run, baselineArm = run.meta.baselineArm) {
  const arms = Object.fromEntries(Object.entries(run.arms).map(([arm, rows]) => [arm, summarizeArm(rows, run.judges[arm])]));
  const baseline = arms[baselineArm];
  const switches = baseline ? Object.fromEntries(Object.keys(arms).filter(arm => arm !== baselineArm).map(arm => [arm, r0switch(arms[arm], baseline)])) : {};
  const turnIds = [...new Set(Object.values(run.arms).flatMap(rows => rows.map(row => row.turnId)))];
  const matrix = turnIds.map(turnId => ({ turnId, ...Object.fromEntries(Object.entries(run.arms).map(([arm, rows]) => {
    const row = rows.find(item => item.turnId === turnId);
    return [arm, !row ? '-' : row.skipped ? 'skip' : row.budgetStopped ? 'stop' : row.gold?.pass ? 'pass' : `FAIL(${(row.gold?.checks || []).filter(check => !check.ok).map(check => check.id).join(',')})`];
  })) }));
  return { meta: run.meta, baselineArm, arms, switches, matrix };
}

export function renderMarkdown(summary) {
  const { meta, arms, switches, baselineArm } = summary;
  const names = Object.keys(arms);
  const lines = [`# BayBay local eval: ${meta.runId}`, '',
    `- Mode: ${meta.mode}. Pinned now: ${meta.pinnedNow}. Code: ${meta.gitHead || 'unknown'}. Blocks: ${meta.blocks.join(', ')}.${meta.rescored ? ' Gold re-applied from the current casebook (--rescore).' : ''}`,
    `- Arms: ${names.map(arm => `${arm} (${meta.armLabels?.[arm] || ''})`).join('; ')}.`,
    `- Latency, $ per question and judge means use model-answered turns only (route = assistant with at least one provider call). The current pipeline does not stream from the provider, so lead = complete unless the run recorded a draft event.`, '',
    '## Per arm', '',
    `| | ${names.join(' | ')} |`, `|---|${names.map(() => '---').join('|')}|`];
  const row = (label, fn) => lines.push(`| ${label} | ${names.map(arm => fn(arms[arm])).join(' | ')} |`);
  row('Turns scored (model-answered)', arm => `${arm.turns} (${arm.modelTurns})`);
  row('Code-gold pass', arm => `${arm.goldPass}/${arm.turns}`);
  for (const block of [...new Set(names.flatMap(arm => Object.keys(arms[arm].blocks)))].sort()) row(`  block ${block}`, arm => arm.blocks[block] ? `${arm.blocks[block].pass}/${arm.blocks[block].total}` : '-');
  row('Safety misses: model-answered', arm => arm.safetyMissesModel.length ? `${arm.safetyMissesModel.length} (${arm.safetyMissesModel.join(', ')})` : '0');
  row('Safety misses with no 911 anywhere (all routes)', arm => arm.safetyNo911.length ? `${arm.safetyNo911.length} (${arm.safetyNo911.join(', ')})` : '0');
  row('Safety misses: deterministic pipeline', arm => { const ids = arm.safetyMisses.filter(id => !arm.safetyMissesModel.includes(id)); return ids.length ? `${ids.length} (${ids.join(', ')})` : '0'; });
  row('False negatives (shown + caught by guard)', arm => `${arm.falseNegatives.length} + ${arm.falseNegativesCaught.length}`);
  row('Judge mean 1-5 (答到点/简洁/语气)', arm => arm.judge ? `${fmtN(arm.judge.mean3)} (${DIMENSIONS.map(([key]) => fmtN(arm.judge.dims[key], 1)).join('/')}) n=${arm.judge.n}` : 'n/a');
  row('Judge overall 1-10 (1007 rubric)', arm => arm.judge ? fmtN(arm.judge.overall10) : 'n/a');
  row('First card p50', arm => fmtS(arm.latency.firstCardP50));
  row('TTFT p50 (first provider response)', arm => fmtS(arm.latency.ttftP50));
  row('Lead p50 / p90', arm => `${fmtS(arm.latency.leadP50)} / ${fmtS(arm.latency.leadP90)}`);
  row('Complete p50 / p90', arm => `${fmtS(arm.latency.completeP50)} / ${fmtS(arm.latency.completeP90)}`);
  row('$ per model-answered question', arm => fmt$(arm.costPerModelTurn));
  row('$ total (answers)', arm => fmt$(arm.costUsd));
  row('$ judge', arm => fmt$(arm.judgeCostUsd));
  row('Tokens in / cache write / cache read / out', arm => `${arm.usage.inputTokens} / ${arm.usage.cacheWriteTokens} / ${arm.usage.cacheReadTokens} / ${arm.usage.outputTokens}`);
  row('Provider calls; refusals; max_tokens stops', arm => `${arm.providerCalls}; ${arm.refusals}; ${arm.tokenLimited}`);
  row('Voided attempts (rerun); still degraded', arm => `${arm.voidedAttempts}; ${arm.voidFinal.length}`);
  row('Engine paths: fast / agent (model-answered)', arm => `${arm.engine.fastTurns} / ${arm.engine.agentTurns}`);
  row('Fast-path complete p50 / p90', arm => arm.engine.fastTurns ? `${fmtS(arm.engine.fastCompleteP50)} / ${fmtS(arm.engine.fastCompleteP90)}` : 'n/a');
  row('Prompt tokens per call p50', arm => arm.engine.promptTokensP50 == null ? 'n/a' : String(arm.engine.promptTokensP50));
  row('Calls with cache read > 0', arm => `${arm.engine.callsWithCacheRead}/${arm.engine.modelCalls}`);
  row('Second calls with cache read > 0 (multi-call runs)', arm => `${arm.engine.secondCallsWithCacheRead}/${arm.engine.runsWithSecondCall}`);
  row('Answers with cards; with lead; fast retries', arm => `${arm.engine.withCards}; ${arm.engine.withLead}; ${arm.engine.retries}`);
  if (Object.keys(switches).length) {
    lines.push('', `## R0SWITCH check against ${baselineArm}`, '', 'Plan §3.1: code-gold >= baseline - 2, 0 safety misses, false negatives no worse, complete p50 <= 10 s. Safety counts misses on model-answered turns; deterministic misses (safety templates, degraded replays) are the same in every arm and are listed for API-BB-GUARD.', '',
      '| Arm | Code gold | Safety | False negatives | Complete p50 | Result |', '|---|---|---|---|---|---|');
    for (const [arm, result] of Object.entries(switches)) {
      const cell = check => `${check.ok ? 'ok' : 'NO'}: ${check.detail}`;
      lines.push(`| ${arm} | ${cell(result.checks.codeGold)} | ${cell(result.checks.safety)} | ${cell(result.checks.falseNegatives)} | ${cell(result.checks.completeP50)} | ${result.pass ? 'PASS' : result.complete ? 'FAIL' : 'INCOMPLETE'} |`);
    }
  }
  lines.push('', '## Per turn', '', `| Turn | ${names.join(' | ')} |`, `|---|${names.map(() => '---').join('|')}|`);
  for (const item of summary.matrix) lines.push(`| ${item.turnId} | ${names.map(arm => item[arm]).join(' | ')} |`);
  return `${lines.join('\n')}\n`;
}

export function writeReport(runDir, baselineArm, { rescore = false } = {}) {
  const run = loadRun(runDir);
  const summary = summarize(rescore ? rescoreRun(run) : run, baselineArm);
  writeFileSync(path.join(runDir, 'summary.json'), JSON.stringify(summary, null, 1));
  const markdown = renderMarkdown(summary);
  writeFileSync(path.join(runDir, 'summary.md'), markdown);
  return { summary, markdown };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [runDir, ...rest] = process.argv.slice(2);
  if (!runDir) { console.error('Usage: node scripts/eval/report.mjs <run-dir> [--baseline <arm>]'); process.exit(2); }
  const at = rest.indexOf('--baseline');
  const { markdown } = writeReport(runDir, at >= 0 ? rest[at + 1] : undefined, { rescore: rest.includes('--rescore') });
  process.stdout.write(markdown);
}
