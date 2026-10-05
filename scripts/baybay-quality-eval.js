#!/usr/bin/env node
// Default is a dry run. Live execution requires an exact deployed commit and
// uses synthetic casebook data only. Never persist continuation credentials.
const fs = require('node:fs/promises');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const DEFAULT_CASEBOOK = path.join(__dirname, 'baybay-quality-cases.json');
const MIN_SPACING_MS = 65000;
const LIMIT_CODES = /^(?:web_rate_limit|web_daily_limit|rate_limit|quota_unavailable|model_unavailable_or_capacity|route_daily_limit|DAILY_LIMIT|RATE_LIMIT|TOO_MANY_REQUESTS)$/i;

function sanitize(value, depth = 0) {
  if (depth > 25) return '[depth omitted]';
  if (Array.isArray(value)) return value.map(item => sanitize(item, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !/token|secret|password|authorization|cookie|api.?key|session/i.test(key))
    .map(([key, item]) => [key, sanitize(item, depth + 1)]));
  if (typeof value === 'string') return value
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[credential omitted]')
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, '[credential omitted]')
    .replace(/([?&](?:token|key|secret|signature|auth|access_token)=)[^&\s]*/gi, '$1[omitted]');
  return value;
}

function quotaStop(status, body) {
  if (status === 429) return 'http_429';
  const values = [body?.code, body?.retrieval?.failureCode, ...(body?.research?.warnings || []), ...(body?.research?.steps || []).map(step => step.code)];
  return values.find(value => typeof value === 'string' && LIMIT_CODES.test(value)) || null;
}

function structuralChecks(item, status, body, previous) {
  const checks = [];
  const check = (id, passed, detail) => checks.push({ id, status: passed ? 'pass' : 'fail', ...(detail ? { detail } : {}) });
  check('transport_success', status === 200 && body?.ok === true);
  const allowedModes = item.assertions?.responseModes || ['assistant'];
  check('expected_response_mode', allowedModes.includes(body?.responseMode));
  check('substantive_answer_present', typeof body?.answer === 'string' && body.answer.trim().length >= 20);
  check('not_degraded', body?.degraded === false);
  const sources = Array.isArray(body?.sources) ? body.sources : [];
  const citations = [...String(body?.answer || '').matchAll(/\[(\d+)\]/g)].map(match => Number(match[1]));
  check('citation_indices_resolve', citations.every(index => index > 0 && index <= sources.length));
  if (body?.assistantPlan?.stops?.length || item.assertions?.planIds?.length) {
    const planRefs = new Set((body?.assistantPlan?.stops || []).flatMap(stop => [...(stop.sourceIds || []), ...(stop.admissionFacts?.sourceIds || [])]));
    const planUrls = new Set((body?.evidence || []).filter(source => planRefs.has(source.id)).map(source => source.url));
    check('factual_plan_has_citation', citations.some(index => index > 0 && planUrls.has(sources[index - 1]?.url)), 'A factual plan needs at least one visible citation to its own evidence; an empty citation list cannot pass.');
  }
  const evidenceIds = new Set((body?.evidence || []).map(source => source.id));
  const coverage = body?.answerCoverage;
  if (body?.responseMode === 'assistant' || item.assertions?.coverageIds?.length) {
    check('coverage_contract', ['complete', 'partial', 'unassessed'].includes(coverage?.status) && Array.isArray(coverage?.items) && coverage.items.length <= 8);
    check('coverage_sources_resolve', (coverage?.items || []).every(row => Array.isArray(row.sourceIds) && row.sourceIds.every(id => evidenceIds.has(id))));
  } else {
    check('specialized_retrieval_scope', ['site', 'site+web', 'web', 'none'].includes(body?.retrieval?.scope));
    if (body?.responseMode === 'search') check('post_results_contract', Array.isArray(body.matchingPosts));
    if (body?.responseMode === 'outing-search') check('outing_results_contract', ['ready', 'needs_clarification'].includes(body.outingSearch?.state));
  }
  for (const id of item.assertions?.coverageIds || []) check(`coverage_${id}`, (coverage?.items || []).some(row => row.id === id && typeof row.summary === 'string' && row.summary.trim()));
  const timings = body?.research?.timings;
  if (body?.responseMode === 'assistant') check('numeric_stage_timings', timings && ['stateMs', 'siteMs', 'monitorMs', 'quotaMs', 'searchMs', 'readMs', 'modelMs', 'finalMs', 'routeMs', 'totalMs'].every(key => Number.isFinite(timings[key]) && timings[key] >= 0 && timings[key] <= 180000));
  if (item.assertions?.noPlan) check('no_unrequested_itinerary', !body?.assistantPlan);
  if (item.assertions?.webCompleted) check('web_research_completed', body?.retrieval?.webStatus === 'completed' && sources.length > 0);
  for (const [key, value] of Object.entries(item.assertions?.state || {})) check(`state_${key}`, isDeepStrictEqual(body?.taskState?.[key], value));
  if (item.assertions?.webStatus) {
    const scopedSiteFlow = item.request?.searchMode === 'site' && body?.responseMode !== 'assistant'
      && item.assertions.webStatus === 'not_requested' && body?.retrieval?.webStatus === 'not_applicable';
    check('chosen_search_scope', body?.retrieval?.webStatus === item.assertions.webStatus || scopedSiteFlow);
  }
  for (const name of item.assertions?.forbiddenTools || []) check(`no_${name}`, !(body?.research?.steps || []).some(step => step.tool === name && step.status === 'completed'));
  const planIds = plan => (plan?.stops || []).map(stop => stop.entityId || stop.id);
  if (item.assertions?.planIds) {
    const plan = body?.assistantPlan, ids = item.assertions.planIds;
    check('exact_plan_order', isDeepStrictEqual(planIds(plan), ids));
    check('handoff_same_order', isDeepStrictEqual((plan?.handoff?.stops || []).map(stop => stop.id), ids));
    if (item.assertions.exactAlternatives) check('no_changed_alternatives', (plan?.alternatives || []).every(alternative => isDeepStrictEqual(planIds(alternative), ids)
      && (!alternative.handoff || isDeepStrictEqual(alternative.handoff.stops.map(stop => stop.id), ids))));
    if (item.assertions.state?.returnToOrigin === false) check('no_return_leg', !plan?.returnTime && !(plan?.travelLegs || []).some(leg => leg.toId === 'origin'));
  }
  if (item.assertions?.samePlanAs) check('followup_preserves_plan', !!previous && isDeepStrictEqual(planIds(body?.assistantPlan), planIds(previous.assistantPlan)));
  return { status: checks.every(row => row.status === 'pass') ? 'pass' : 'fail', checks, note: 'Structural checks do not establish factual accuracy; human review remains required.' };
}

function selectCases(casebook, selectedIds = []) {
  const all = new Map(casebook.cases.map(item => [item.id, item]));
  const wanted = new Set(), visiting = new Set();
  const include = id => {
    if (!all.has(id)) throw new Error(`Unknown case: ${id}`);
    if (visiting.has(id)) throw new Error(`Cyclic followup: ${id}`);
    if (wanted.has(id)) return;
    visiting.add(id);
    const parent = all.get(id).follows;
    if (parent) include(parent);
    visiting.delete(id);
    wanted.add(id);
  };
  for (const id of selectedIds.length ? selectedIds : all.keys()) include(id);
  return [...wanted].map(id => all.get(id));
}

async function runEvaluation({ casebook, expectedCommit, baseUrl = 'https://baylink-api.onrender.com', selectedIds = [], siteOnly = false, spacingMs = MIN_SPACING_MS, fetchImpl = fetch, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), now = Date.now, persist = async () => {}, log = () => {} }) {
  if (!/^[a-f0-9]{40}$/i.test(expectedCommit || '')) throw new Error('A full 40-character expected deployed commit is required.');
  const endpoint = new URL(baseUrl);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || (endpoint.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname))) throw new Error('Use an HTTPS public base URL or an explicit localhost test endpoint, without credentials.');
  const date = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Los_Angeles', dateStyle: 'short' }).format(new Date(now()));
  if (casebook.validUntil && date > casebook.validUntil) throw new Error('The dated casebook has expired. Review and update its prompts before live evaluation.');
  const cases = selectCases(casebook, selectedIds).map(item => siteOnly ? { ...item, request: { ...item.request, searchMode: 'site' }, assertions: { ...item.assertions, webStatus: 'not_requested', forbiddenTools: ['search_web', 'read_source', 'get_route', 'get_weather'] } } : item);
  const report = { version: 1, kind: 'synthetic-baybay-quality-evaluation', verificationScope: siteOnly ? 'site-only-regression' : 'casebook-requested-modes', expectedCommit: expectedCommit.toLowerCase(), endpoint: endpoint.origin, startedAt: new Date(now()).toISOString(), spacingMs: Math.max(MIN_SPACING_MS, Number(spacingMs) || MIN_SPACING_MS), status: 'running', cases: [], factReview: 'pending' };
  const tokens = new Map(), responses = new Map(), conversations = new Map();
  let lastStart = null;
  for (const item of cases) {
    if (lastStart !== null) { const delay = report.spacingMs - (now() - lastStart); if (delay > 0) { log(`Waiting ${Math.ceil(delay / 1000)} seconds before ${item.id}.`); await sleep(delay); } }
    let health;
    try {
      const probe = await fetchImpl(new URL('/api/health', endpoint), { signal: AbortSignal.timeout(15000), headers: { Accept: 'application/json' } });
      health = await probe.json();
      if (!probe.ok || health?.status !== 'ok' || health?.commit !== expectedCommit.toLowerCase()) { report.status = 'stopped_release_mismatch'; report.health = sanitize({ status: health?.status, commit: health?.commit }); break; }
    } catch { report.status = 'stopped_health_unavailable'; break; }
    const continuation = item.follows ? tokens.get(item.follows) || {} : {};
    const parentMode = item.follows ? responses.get(item.follows)?.responseMode : null;
    if (item.follows && (parentMode === 'assistant' && !continuation.assistantSessionToken || parentMode === 'outing-search' && !continuation.outingSearchToken)) { report.status = 'stopped_missing_continuation'; report.stoppedBeforeCase = item.id; break; }
    const history = item.follows ? conversations.get(item.follows) || [] : [];
    const request = { ...item.request, assistantVersion: 2, context: { currentPath: '/' }, ...(history.length ? { history } : {}), ...continuation };
    lastStart = now(); log(`Running ${item.id}; deployed commit verified.`);
    let response, body;
    try {
      response = await fetchImpl(new URL('/api/ai/guide-chat', endpoint), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(request), signal: AbortSignal.timeout(100000) });
      body = await response.json();
    } catch {
      report.cases.push({ id: item.id, request: sanitize(request), elapsedMs: Math.max(0, now() - lastStart), transport: 'unavailable', automated: { status: 'fail' }, manualReview: { status: 'pending', rubric: item.manualReview } });
      report.status = 'stopped_transport_unavailable'; await persist(sanitize(report)); break;
    }
    const elapsedMs = Math.max(0, now() - lastStart);
    tokens.set(item.id, {
      ...(typeof body?.assistantSessionToken === 'string' ? { assistantSessionToken: body.assistantSessionToken } : {}),
      ...(typeof body?.outingSearch?.continuationToken === 'string' ? { outingSearchToken: body.outingSearch.continuationToken } : {}),
    });
    const clean = sanitize(body); responses.set(item.id, clean);
    if (typeof clean.answer === 'string') conversations.set(item.id, [...history, { role: 'user', content: item.request.message.slice(0, 500) }, { role: 'assistant', content: clean.answer.slice(0, 1200) }].slice(-8));
    report.cases.push({ id: item.id, startedAt: new Date(lastStart).toISOString(), httpStatus: response.status, elapsedMs, serverTiming: response.headers?.get?.('server-timing') || null,
      request: sanitize(request), response: clean, automated: structuralChecks(item, response.status, clean, item.assertions?.samePlanAs ? responses.get(item.assertions.samePlanAs) : null),
      manualReview: { status: 'pending', rubric: item.manualReview, findings: [] } });
    const stopCode = quotaStop(response.status, body);
    if (stopCode) { report.status = 'stopped_quota_or_rate_limit'; report.stopCode = stopCode; }
    else if (!response.ok) report.status = 'stopped_http_error';
    await persist(sanitize(report));
    if (report.status !== 'running') break;
  }
  if (report.status === 'running') report.status = 'pending_manual_review';
  report.finishedAt = new Date(now()).toISOString();
  report.automated = { passed: report.cases.filter(item => item.automated.status === 'pass').length, failed: report.cases.filter(item => item.automated.status !== 'pass').length };
  await persist(sanitize(report));
  return sanitize(report);
}

async function main(argv) {
  const args = {}; for (let index = 0; index < argv.length; index++) { const key = argv[index]; if (!key.startsWith('--')) throw new Error(`Unexpected argument: ${key}`); args[key] = ['--live', '--help', '--site-only'].includes(key) ? true : argv[++index]; }
  if (args['--help']) { console.log('Dry run: node scripts/baybay-quality-eval.js\nLive: node scripts/baybay-quality-eval.js --live --expected-commit <full SHA> [--cases id,id] [--output path.json] [--site-only]\n--site-only runs a separately labelled site-only regression, never a Smart/Web verification.\nLive requests are sequential, >=65s apart, stop on quota/429, and never retry. Results always require human factual review.'); return; }
  const casebook = JSON.parse(await fs.readFile(args['--casebook'] ? path.resolve(args['--casebook']) : DEFAULT_CASEBOOK, 'utf8'));
  const selectedIds = String(args['--cases'] || '').split(',').filter(Boolean);
  const selected = selectCases(casebook, selectedIds);
  if (!args['--live']) { console.log(JSON.stringify({ mode: 'dry-run', networkRequests: 0, verificationScope: args['--site-only'] ? 'site-only-regression' : 'casebook-requested-modes', cases: selected.map(item => ({ id: item.id, searchMode: args['--site-only'] ? 'site' : item.request.searchMode, follows: item.follows || null, manualReview: item.manualReview })), validUntil: casebook.validUntil }, null, 2)); return; }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const output = path.resolve(args['--output'] || path.join(__dirname, '..', 'docs', `baybay-quality-eval-${stamp}.json`));
  await fs.mkdir(path.dirname(output), { recursive: true });
  const result = await runEvaluation({ casebook, expectedCommit: args['--expected-commit'], baseUrl: args['--base-url'], selectedIds, siteOnly: !!args['--site-only'],
    persist: report => fs.writeFile(output, JSON.stringify(report, null, 2) + '\n', 'utf8'), log: message => console.log(message) });
  console.log(JSON.stringify({ output, status: result.status, automated: result.automated, factReview: result.factReview }));
  if (result.status !== 'pending_manual_review' || result.automated.failed) process.exitCode = 1;
}
if (require.main === module) main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { sanitize, quotaStop, structuralChecks, selectCases, runEvaluation, MIN_SPACING_MS };
