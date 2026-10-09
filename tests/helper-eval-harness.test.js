// The local helper-set eval (scripts/helper-eval-local.mjs): casebook quotas,
// the schema validator it judges with, and a $0 dry run end to end.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { validateImage } = require('../lib/localAi');
const helperSchemas = require('../lib/helperSchemas');

const ROOT = path.join(__dirname, '..');
const EVAL = path.join(ROOT, 'scripts', 'eval');
const book = () => JSON.parse(fs.readFileSync(path.join(EVAL, 'helper-set.json'), 'utf8'));

test('the helper set has 12 cases: translate 3, post-assist 3, outing 2, planner 2, screenshot 2', () => {
  const { cases, pinnedNow } = book();
  assert.equal(cases.length, 12);
  assert.equal(new Set(cases.map(item => item.id)).size, 12);
  const count = {};
  for (const item of cases) count[item.helper] = (count[item.helper] || 0) + 1;
  assert.deepEqual(count, { translate: 3, 'post-assist': 3, outing: 2, planner: 2, screenshot: 2 });
  assert.equal(pinnedNow, '2026-10-08T10:00:00-07:00');
  for (const item of cases.filter(entry => entry.helper === 'screenshot')) {
    const file = path.join(EVAL, item.image);
    assert.ok(fs.statSync(file).size < 3 * 1024 * 1024);
    assert.doesNotThrow(() => validateImage(`data:image/png;base64,${fs.readFileSync(file).toString('base64')}`), item.id);
  }
});

test('the eval judges replies with a validator for the helper schema subset', async () => {
  const { validateAgainst } = await import(pathToFileURL(path.join(ROOT, 'scripts', 'helper-eval-local.mjs')).href);
  const schema = helperSchemas.OUTING_DRAFT_SCHEMA;
  assert.deepEqual(validateAgainst(schema, { answer: 'ok', questions: [], draft: {} }), []);
  assert.deepEqual(validateAgainst(schema, { answer: 'ok', questions: ['q'], draft: { capacity: 4, transport: 'walk' } }), []);
  assert.ok(validateAgainst(schema, { answer: 'ok', questions: [] }).some(error => /draft: missing/.test(error)));
  assert.ok(validateAgainst(schema, { answer: 'ok', questions: [], draft: { extra: 'x' } }).some(error => /not allowed/.test(error)));
  assert.ok(validateAgainst(schema, { answer: 'ok', questions: [], draft: { capacity: 2.5 } }).some(error => /expected integer/.test(error)));
  assert.ok(validateAgainst(schema, { answer: 'ok', questions: [], draft: { transport: 'car' } }).some(error => /enum/.test(error)));
  assert.ok(validateAgainst(schema, []).length > 0);
  assert.ok(validateAgainst(helperSchemas.CONVERSATION_TEXT_SCHEMA, { text: 1 }).length > 0);
});

test('a dry run calls every helper once with a schema and spends nothing', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'helper-eval-'));
  try {
    const run = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'helper-eval-local.mjs'), '--run-id', 'dry', '--out', out], {
      encoding: 'utf8', env: { ...process.env, ANTHROPIC_API_KEY: '', BAYLINK_EVAL_ANTHROPIC_KEY: '' }, timeout: 120000 });
    assert.equal(run.status, 0, run.stderr);
    const rows = fs.readFileSync(path.join(out, 'dry', 'results.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(rows.length, 12);
    for (const row of rows) {
      assert.equal(row.calls, 1, row.id); assert.equal(row.schemaValid, true, row.id); assert.deepEqual(row.sampling, [], row.id);
      assert.equal(row.providerCalls[0].requestedModel, 'claude-haiku-5-5'); assert.equal(row.providerCalls[0].effort, 'low');
    }
    const summary = JSON.parse(fs.readFileSync(path.join(out, 'dry', 'summary.json'), 'utf8'));
    assert.equal(summary.live, false); assert.equal(summary.spentUsd, 0);
    assert.doesNotMatch(fs.readFileSync(path.join(out, 'dry', 'results.jsonl'), 'utf8'), /dry-run-placeholder|Bearer/);
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});

test('a live run without a key or a budget is refused before any call', () => {
  for (const args of [['--live'], ['--live', '--budget-usd', '9']]) {
    const run = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'helper-eval-local.mjs'), ...args, '--out', os.tmpdir()], {
      encoding: 'utf8', env: { ...process.env, ANTHROPIC_API_KEY: '', BAYLINK_EVAL_ANTHROPIC_KEY: '' }, timeout: 60000 });
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /budget-usd/);
  }
  const keyless = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'helper-eval-local.mjs'), '--live', '--budget-usd', '0.5', '--out', os.tmpdir()], {
    encoding: 'utf8', env: { ...process.env, ANTHROPIC_API_KEY: '', BAYLINK_EVAL_ANTHROPIC_KEY: '' }, timeout: 60000 });
  assert.notEqual(keyless.status, 0); assert.match(keyless.stderr, /needs BAYLINK_EVAL_ANTHROPIC_KEY/);
});
