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

test('a dry run calls every helper once per default arm (haiku-low and opus-medium) with a schema and spends nothing', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'helper-eval-'));
  try {
    const script = path.join(ROOT, 'scripts', 'helper-eval-local.mjs');
    const env = { ...process.env, ANTHROPIC_API_KEY: '', BAYLINK_EVAL_ANTHROPIC_KEY: '' };
    const run = spawnSync(process.execPath, [script, '--run-id', 'dry', '--out', out], { encoding: 'utf8', env, timeout: 120000 });
    assert.equal(run.status, 0, run.stderr);
    const rows = fs.readFileSync(path.join(out, 'dry', 'results.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(rows.length, 24);
    const expected = { 'haiku-low': ['claude-haiku-5-5', 'low'], 'opus-medium': ['claude-opus-5-5', 'medium'] };
    for (const row of rows) {
      assert.equal(row.calls, 1, row.id); assert.equal(row.schemaValid, true, row.id); assert.deepEqual(row.sampling, [], row.id);
      assert.deepEqual([row.providerCalls[0].requestedModel, row.providerCalls[0].effort], expected[row.arm], `${row.arm} ${row.id}`);
      assert.equal(row.providerCalls[0].providerError, null);
    }
    assert.deepEqual(rows.map(row => row.arm).filter((arm, index, all) => all.indexOf(arm) === index), ['haiku-low', 'opus-medium']);
    const summary = JSON.parse(fs.readFileSync(path.join(out, 'dry', 'summary.json'), 'utf8'));
    assert.equal(summary.live, false); assert.equal(summary.spentUsd, 0);
    assert.deepEqual(summary.gates, { merge: { arm: 'opus-medium', verdict: 'PASS', failures: [] }, cutover: { arm: 'haiku-low', verdict: 'PASS', failures: [] } });
    for (const arm of summary.summary) assert.deepEqual([arm.items, arm.expectedItems, arm.schemaValid, arm.http400, arm.schemaTooComplex], [12, 12, 12, 0, 0], arm.arm);
    assert.match(run.stdout, /MERGE GATE \(opus-medium, no HTTP 400 on any arm\): PASS \(dry run: not evidence\)/);
    const review = fs.readFileSync(path.join(out, 'dry', 'review.md'), 'utf8');
    for (const id of ['P1-room-seeker-zh', 'P2-movers-en', 'P3-desk-bilingual', 'L1-sf-kid-zh', 'L2-weekend-broad-en']) assert.match(review, new RegExp(`### ${id}`));
    assert.match(review, /\| opus-medium \| 1 \| valid \|/);
    for (const file of ['results.jsonl', 'summary.json', 'review.md']) assert.doesNotMatch(fs.readFileSync(path.join(out, 'dry', file), 'utf8'), /dry-run-placeholder|Bearer/);
    // A run id that already holds results is never appended to or overwritten.
    const again = spawnSync(process.execPath, [script, '--run-id', 'dry', '--out', out], { encoding: 'utf8', env, timeout: 60000 });
    assert.notEqual(again.status, 0); assert.match(again.stderr, /already has results/);
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});

test('the gates fail on an HTTP 400, "Schema is too complex", a short run or an invalid final reply', async () => {
  const { rowSchemaValid, summarizeArm, gateVerdicts } = await import(pathToFileURL(path.join(ROOT, 'scripts', 'helper-eval-local.mjs')).href);
  const call = (extra = {}) => ({ schemaSent: true, schemaValid: true, httpStatus: 200, providerError: null, sampling: [], ...extra });
  const row = (arm, id, calls) => ({ arm, id, helper: 'translate', round: 1, calls: calls.length, schemaValid: rowSchemaValid(calls), callerAccepted: true,
    sampling: [], completeMs: 10, costUsd: 0, providerCalls: calls });
  // A 429 retried into a valid reply passes; the final reply is what counts.
  assert.equal(rowSchemaValid([call({ httpStatus: 429, schemaValid: false }), call()]), true);
  assert.equal(rowSchemaValid([call(), call({ schemaValid: false })]), false);
  assert.equal(rowSchemaValid([call({ schemaSent: false }), call()]), false);
  assert.equal(rowSchemaValid([]), false);

  const clean = arm => [row(arm, 'a', [call()]), row(arm, 'b', [call({ httpStatus: 429, schemaValid: false }), call()])];
  const pass = gateVerdicts(['haiku-low', 'opus-medium'].map(arm => summarizeArm(clean(arm), arm, 2)));
  assert.equal(pass.merge.verdict, 'PASS'); assert.equal(pass.cutover.verdict, 'PASS');

  const tooComplex = call({ httpStatus: 400, schemaValid: false, providerError: { type: 'invalid_request_error', message: 'Schema is too complex for compilation.' } });
  const badHaiku = [row('haiku-low', 'a', [call()]), row('haiku-low', 'b', [tooComplex])];
  const gates = gateVerdicts([summarizeArm(badHaiku, 'haiku-low', 2), summarizeArm(clean('opus-medium'), 'opus-medium', 2)]);
  assert.equal(gates.cutover.verdict, 'FAIL');
  assert.deepEqual(gates.cutover.failures, ['schema-valid 1/2', '1 HTTP 400', '1 "Schema is too complex"']);
  assert.equal(gates.merge.verdict, 'FAIL', 'a 400 on any arm blocks the merge');
  assert.deepEqual(gates.merge.failures, ['HTTP 400 on haiku-low']);

  const short = gateVerdicts([summarizeArm(clean('opus-medium').slice(0, 1), 'opus-medium', 2)]);
  assert.equal(short.merge.verdict, 'FAIL'); assert.deepEqual(short.merge.failures, ['ran 1/2 items']);
  assert.equal(short.cutover.verdict, 'NOT RUN');
  assert.equal(gateVerdicts([summarizeArm(clean('haiku-low'), 'haiku-low', 2)]).merge.verdict, 'NOT RUN');
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
