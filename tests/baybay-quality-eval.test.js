const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitize, quotaStop, structuralChecks, selectCases, runEvaluation, MIN_SPACING_MS } = require('../scripts/baybay-quality-eval');
const cases = require('../scripts/baybay-quality-cases.json');
const COMMIT = 'a'.repeat(40), NOW = Date.parse('2026-10-04T19:00:00Z');
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => null }, json: async () => body });
const item = (id, extra = {}) => ({ id, request: { message: `Synthetic ${id}`, searchMode: 'site', locale: 'en' }, assertions: {}, manualReview: ['Verify factual applicability against the displayed official evidence.'], ...extra });
const result = extra => ({ ok: true, responseMode: 'assistant', degraded: false, answer: 'A substantive synthetic response still needs a human factual review.', sources: [], evidence: [], answerCoverage: { status: 'unassessed', items: [] }, research: { timings: Object.fromEntries(['stateMs', 'siteMs', 'monitorMs', 'quotaMs', 'searchMs', 'readMs', 'modelMs', 'finalMs', 'routeMs', 'totalMs'].map(key => [key, 0])), warnings: [], steps: [] }, ...extra });

test('casebook is synthetic, bounded and selects a followup together with its parent', () => {
  assert.equal(cases.cases.length, 7);
  assert.deepEqual(selectCases(cases, ['strict-sf-child-followup']).map(row => row.id), ['strict-sf-family-plan', 'strict-sf-child-followup']);
  assert.ok(cases.cases.every(row => row.manualReview.length && ['site', 'smart', 'web'].includes(row.request.searchMode)));
  assert.throws(() => selectCases(cases, ['nonexistent']), /Unknown case/);
  assert.equal(MIN_SPACING_MS, 65000);
});

test('live runner refuses wrong or absent release SHA before the first assistant request', async () => {
  const book = { validUntil: '2026-10-10', cases: [item('one')] };
  await assert.rejects(runEvaluation({ casebook: book, expectedCommit: 'short', now: () => NOW }), /40-character/);
  let probes = 0;
  const report = await runEvaluation({ casebook: book, expectedCommit: COMMIT, now: () => NOW, fetchImpl: async url => { probes++; assert.match(String(url), /api\/health$/); return response({ status: 'ok', commit: 'b'.repeat(40) }); } });
  assert.equal(probes, 1); assert.equal(report.cases.length, 0); assert.equal(report.status, 'stopped_release_mismatch');
});

test('natural conversation retests include every ancestor in order and reject broken chains', () => {
  const book = { cases: [item('correction', { follows: 'question' }), item('question', { follows: 'opening' }), item('opening')] };
  assert.deepEqual(selectCases(book, ['correction']).map(row => row.id), ['opening', 'question', 'correction']);
  assert.throws(() => selectCases({ cases: [item('question', { follows: 'missing' })] }), /Unknown case: missing/);
  assert.throws(() => selectCases({ cases: [item('one', { follows: 'two' }), item('two', { follows: 'one' })] }), /Cyclic followup/);
});

test('requests start at least 65 seconds apart, continuation remains only in memory, and HTTP 200 is not factual success', async () => {
  let clock = NOW; const starts = [], saved = [];
  const book = { validUntil: '2026-10-10', cases: [item('one'), item('two', { follows: 'one' })] };
  const report = await runEvaluation({ casebook: book, expectedCommit: COMMIT, spacingMs: 1, now: () => clock,
    sleep: async ms => { clock += ms; }, persist: async value => saved.push(structuredClone(value)),
    fetchImpl: async (url, options) => {
      if (String(url).endsWith('/health')) return response({ status: 'ok', commit: COMMIT });
      starts.push(clock); const request = JSON.parse(options.body);
      if (starts.length === 1) assert.equal(request.assistantSessionToken, undefined);
      else {
        assert.equal(request.assistantSessionToken, 'fixture-continuation-secret');
        assert.deepEqual(request.history, [{ role: 'user', content: 'Synthetic one' }, { role: 'assistant', content: result().answer }]);
      }
      clock += 1200;
      return response(result({ assistantSessionToken: 'fixture-continuation-secret' }));
    },
  });
  assert.equal(starts.length, 2); assert.ok(starts[1] - starts[0] >= 65000);
  assert.equal(report.automated.passed, 2); assert.equal(report.status, 'pending_manual_review');
  assert.equal(report.factReview, 'pending'); assert.ok(report.cases.every(row => row.manualReview.status === 'pending'));
  assert.doesNotMatch(JSON.stringify(saved), /fixture-continuation-secret|assistantSessionToken/);
});

test('429 and embedded quota failures stop immediately without a retry or next request', async () => {
  for (const failure of [{ status: 429, body: { code: 'RATE_LIMIT' } }, { status: 200, body: result({ research: { warnings: [], steps: [{ tool: 'search_web', status: 'unavailable', code: 'web_daily_limit' }] } }) }]) {
    let assistantRequests = 0;
    const report = await runEvaluation({ casebook: { validUntil: '2026-10-10', cases: [item('one'), item('two')] }, expectedCommit: COMMIT, now: () => NOW,
      fetchImpl: async url => String(url).endsWith('/health') ? response({ status: 'ok', commit: COMMIT }) : (assistantRequests++, response(failure.body, failure.status)),
      sleep: async () => { throw new Error('Should stop before waiting'); },
    });
    assert.equal(assistantRequests, 1); assert.equal(report.status, 'stopped_quota_or_rate_limit');
  }
  assert.equal(quotaStop(200, result()), null);
});

test('release is rechecked before each assistant call and invalid factual structure fails independently of transport', async () => {
  let healthCalls = 0, requests = 0, clock = NOW;
  const report = await runEvaluation({ casebook: { validUntil: '2026-10-10', cases: [item('one'), item('two')] }, expectedCommit: COMMIT, now: () => clock, sleep: async ms => { clock += ms; },
    fetchImpl: async url => String(url).endsWith('/health') ? response({ status: 'ok', commit: ++healthCalls === 1 ? COMMIT : 'b'.repeat(40) }) : (requests++, response(result())),
  });
  assert.equal(requests, 1); assert.equal(healthCalls, 2); assert.equal(report.status, 'stopped_release_mismatch');
  const checked = structuralChecks(item('broken', { assertions: { coverageIds: ['printing'] } }), 200, result({ answer: 'Answer with unresolved fake reference [5].', answerCoverage: { status: 'complete', items: [{ id: 'other', sourceIds: ['fake'] }] } }));
  assert.equal(checked.status, 'fail');
  assert.ok(checked.checks.some(row => row.id === 'transport_success' && row.status === 'pass'));
  assert.ok(checked.checks.some(row => row.id === 'coverage_printing' && row.status === 'fail'));
  assert.ok(checked.checks.some(row => row.id === 'citation_indices_resolve' && row.status === 'fail'));
});

test('sanitizer retains full public answer and provenance while removing credentials recursively', () => {
  const clean = sanitize({ answer: 'Public answer with conditions.', evidence: [{ url: 'https://example.org/rules?token=private&lang=en' }], nested: { authorization: 'Bearer private', assistantSessionToken: 'secret', OPENAI_API_KEY: 'sk-aaaaaaaaaaaaaaaa' } });
  assert.equal(clean.answer, 'Public answer with conditions.'); assert.match(clean.evidence[0].url, /lang=en/);
  assert.doesNotMatch(JSON.stringify(clean), /private|Bearer|secret|sk-/);
});

test('site-only regression is explicitly labelled and cannot silently pass as the original Smart evaluation', async () => {
  const original = item('smart', { request: { message: 'Synthetic smart request.', searchMode: 'smart' } });
  const report = await runEvaluation({ casebook: { validUntil: '2026-10-10', cases: [original] }, expectedCommit: COMMIT, siteOnly: true, now: () => NOW,
    fetchImpl: async (url, options) => {
      if (String(url).endsWith('/health')) return response({ status: 'ok', commit: COMMIT });
      assert.equal(JSON.parse(options.body).searchMode, 'site');
      return response(result({ retrieval: { webStatus: 'not_requested' } }));
    },
  });
  assert.equal(original.request.searchMode, 'smart');
  assert.equal(report.verificationScope, 'site-only-regression');
  assert.equal(report.cases[0].request.searchMode, 'site');
  assert.ok(report.cases[0].automated.checks.some(check => check.id === 'chosen_search_scope' && check.status === 'pass'));
  assert.ok(report.cases[0].automated.checks.some(check => check.id === 'no_read_source' && check.status === 'pass'));
});

test('factual plans cannot pass with no citations or a citation unrelated to the plan', () => {
  const plan = { stops: [{ id: 'museum', sourceIds: ['official'] }] };
  const common = { assistantPlan: plan, evidence: [{ id: 'official', url: 'https://example.org/museum' }, { id: 'unrelated', url: 'https://example.org/other' }] };
  for (const sourceUrl of [null, 'https://example.org/other', 'https://example.org/museum']) {
    const checked = structuralChecks(item('plan'), 200, result({ ...common, answer: `Museum admission is recorded at $20.${sourceUrl ? ' [1]' : ''}`, sources: sourceUrl ? [{ title: 'Source', url: sourceUrl }] : [] }));
    assert.equal(checked.checks.find(row => row.id === 'factual_plan_has_citation').status, sourceUrl === 'https://example.org/museum' ? 'pass' : 'fail');
  }
  const safelyDegraded = structuralChecks(item('plan'), 200, result({ ...common, degraded: true, answer: 'A sourced snapshot still has incomplete current-date verification. [1]', sources: [{ title: 'Museum', url: 'https://example.org/museum' }] }));
  assert.equal(safelyDegraded.checks.find(row => row.id === 'factual_plan_has_citation').status, 'pass');
  assert.equal(safelyDegraded.checks.find(row => row.id === 'not_degraded').status, 'fail');
});
