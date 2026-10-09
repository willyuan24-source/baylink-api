const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { requestSearch, extractSearchResult, registerPlannerWebSearch } = require('../lib/plannerWebSearch');
const { normalizeAnthropicSearch } = require('../lib/anthropicWebSearch');
const { createAiGovernance } = require('../lib/aiGovernance');
const { createMemoryModels } = require('./support/memory-models');

const NOW = Date.parse('2026-10-07T20:00:00Z');
const config = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'isolated-claude-placeholder', OPENAI_API_KEY: 'isolated-openai-placeholder' };
const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
const input = { query: 'SF arts and gardens', locale: 'en' };
const source = { url: 'https://museum.org/visit', title: 'Example Museum' };
const citation = (fields = {}) => ({ type: 'web_search_result_location', ...source, encrypted_index: 'opaque-citation-index', cited_text: 'A real source excerpt that is never displayed as generated evidence.', ...fields });
function native(text = 'Public local options require confirmation.', fields = {}) {
  return { type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_reason: 'end_turn',
    usage: { input_tokens: 20, output_tokens: 15, server_tool_use: { web_search_requests: 1 } },
    content: [
      { type: 'thinking', thinking: 'Private intermediate reasoning', signature: 'opaque' },
      { type: 'text', text: 'I will search for public sources.' },
      { type: 'server_tool_use', id: 'srvtoolu_search', name: 'web_search', input: { query: 'SF arts' } },
      { type: 'web_search_tool_result', tool_use_id: 'srvtoolu_search', content: [{ type: 'web_search_result', ...source, encrypted_content: 'opaque-source-content' }] },
      { type: 'text', text, citations: [citation()] },
    ], ...fields };
}
const options = extra => ({ config, ai: async () => native(), isTest: true, lookup, now: () => NOW, ...extra });
function service(extra = {}) {
  const models = extra.models || createMemoryModels();
  let route;
  const result = registerPlannerWebSearch({ post: (_path, callback) => { route = callback; } }, {
    Quota: models.PostTranslationQuota, checkRateLimit: () => true, ...options(), ...extra,
    config: { ...config, ...extra.config },
  });
  return { ...result, models, route };
}

test('Claude search uses current direct Messages web tool, scoped query and optional workspace header', async () => {
  const requests = [];
  const result = await requestSearch({ ...input, date: '2026-10-10', city: 'San Francisco' }, {
    config: { ...config, ANTHROPIC_WORKSPACE_ID: 'wrkspc_isolatedtest', ANTHROPIC_BAYBAY_EFFORT: 'low' }, lookup, now: () => NOW,
    extractAi: async () => assert.fail('Claude must not invoke OpenAI extraction'),
    fetchImpl: async (url, request) => { requests.push({ url, ...request, body: JSON.parse(request.body) }); return { ok: true, json: async () => native() }; },
  });
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(request.headers.Authorization, `Bearer ${config.ANTHROPIC_API_KEY}`);
  assert.equal(request.headers['anthropic-version'], '2023-06-01');
  assert.equal(request.headers['anthropic-workspace-id'], 'wrkspc_isolatedtest');
  assert.equal(request.headers['x-api-key'], undefined);
  assert.ok(request.signal instanceof AbortSignal);
  assert.equal(request.body.model, 'claude-opus-5-5');
  assert.equal(request.body.max_tokens, 8000);
  assert.deepEqual(request.body.output_config, { effort: 'low' });
  assert.deepEqual(request.body.tool_choice, { type: 'auto' });
  assert.deepEqual(request.body.tools, [{ type: 'web_search_20260318', name: 'web_search', allowed_callers: ['direct'], response_inclusion: 'full', max_uses: 2,
    user_location: { type: 'approximate', country: 'US', region: 'California', city: 'San Francisco', timezone: 'America/Los_Angeles' } }]);
  for (const field of ['input', 'instructions', 'store', 'thinking', 'temperature', 'max_output_tokens', 'response_format']) assert.equal(request.body[field], undefined);
  assert.deepEqual(request.body.messages, [{ role: 'user', content: JSON.stringify({ ...input, date: '2026-10-10', city: 'San Francisco' }) }]);
  assert.match(request.body.system, /2026-10-07/);
  assert.match(request.body.system, /regular weekday hours, not confirmed hours for the requested date/);
  assert.match(request.body.system, /native web_search tool before answering/);
  assert.doesNotMatch(request.body.system, /BAYLINK_CANDIDATES_V1/);
  assert.equal(result.configuredModel, 'claude-opus-5-5'); assert.equal(result.model, 'claude-opus-5-5');
  assert.equal(result.candidateStatus, 'unavailable');
  assert.match(result.answer, /BAYLINK verification reminder/);
  assert.doesNotMatch(JSON.stringify(result), /isolated-|opaque-|Private intermediate|will search|source excerpt/);
});

test('native max_uses shares the existing bounded tool-call setting and supports model override', async () => {
  for (const [value, expected] of [['1', 1], ['9', 2], ['0', 2], ['-1', 2], ['bad', 2]]) {
    let payload;
    const result = await requestSearch(input, options({ config: { ...config, ANTHROPIC_BAYBAY_MODEL: 'claude-opus-5-5-custom', OPENAI_WEB_SEARCH_MAX_TOOL_CALLS: value },
      ai: async body => { payload = body; return native(); } }));
    assert.equal(payload.tools[0].max_uses, expected);
    assert.equal(payload.model, 'claude-opus-5-5-custom');
    assert.deepEqual(payload.output_config, { effort: 'medium' });
    assert.equal(result.configuredModel, payload.model);
  }
});

test('OpenAI is still the default and an Anthropic key never configures OpenAI or vice versa', async () => {
  const response = { status: 'completed', output: [
    { type: 'web_search_call', status: 'completed', action: { type: 'search' } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Public options [source]', annotations: [{ type: 'url_citation', ...source, start_index: 15, end_index: 23 }] }] },
  ] };
  let url;
  await requestSearch(input, { config: { OPENAI_API_KEY: config.OPENAI_API_KEY, ANTHROPIC_API_KEY: config.ANTHROPIC_API_KEY }, lookup,
    extractAi: async () => ({ candidates: [] }), fetchImpl: async (target, request) => { url = target; assert.equal(JSON.parse(request.body).model, 'gpt-4.1-mini'); return { ok: true, json: async () => response }; } });
  assert.equal(url, 'https://api.openai.com/v1/responses');
  for (const missing of [{ BAYBAY_AI_PROVIDER: 'anthropic', OPENAI_API_KEY: config.OPENAI_API_KEY }, { ANTHROPIC_API_KEY: config.ANTHROPIC_API_KEY }]) {
    await assert.rejects(requestSearch(input, { config: missing, fetchImpl: async () => assert.fail('unconfigured provider must not be called') }), { code: 'web_not_configured' });
  }
});

test('unknown web providers fail before calls, rate limits or quota reservations', async () => {
  const unsupported = { ...config, BAYBAY_AI_PROVIDER: 'anthropi' };
  const forbidden = async () => assert.fail('unknown provider must not invoke AI');
  await assert.rejects(requestSearch(input, { config: unsupported, fetchImpl: forbidden }), { code: 'web_not_configured' });
  await assert.rejects(requestSearch(input, options({ config: unsupported, ai: forbidden })), { code: 'web_not_configured' });
  const blocked = service({ config: unsupported, ai: forbidden,
    checkRateLimit: () => assert.fail('unknown provider must fail before rate limits') });
  await assert.rejects(blocked.search(input), { code: 'web_not_configured' });
  assert.equal(blocked.models.PostTranslationQuota.rows.length, 0);
});

test('Claude search uses a longer production deadline while OpenAI and explicit test deadlines stay unchanged', async t => {
  const scheduled = [];
  const originalSetTimeout = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => {
    scheduled.push(delay);
    return originalSetTimeout(callback, delay, ...args);
  });
  const failImmediately = async () => { throw Error('isolated deadline fixture'); };
  for (const [provider, expected] of [['anthropic', 35000], ['openai', 20000]]) {
    const selected = { ...config, BAYBAY_AI_PROVIDER: provider };
    scheduled.length = 0;
    await assert.rejects(requestSearch(input, { config: selected, ai: failImmediately }), { code: 'web_provider_unavailable' });
    assert.deepEqual(scheduled, [expected]);
    scheduled.length = 0;
    await assert.rejects(service({ config: selected, isTest: false, ai: failImmediately }).search(input), { code: 'web_provider_unavailable' });
    assert.deepEqual(scheduled, [expected]);
  }
  scheduled.length = 0;
  await assert.rejects(requestSearch(input, { config, ai: failImmediately, timeoutMs: 17 }), { code: 'web_provider_unavailable' });
  assert.deepEqual(scheduled, [17]);
  scheduled.length = 0;
  await assert.rejects(service({ config: { PLANNER_WEB_SEARCH_TEST_TIMEOUT_MS: '17' }, ai: failImmediately }).search(input), { code: 'web_provider_unavailable' });
  assert.deepEqual(scheduled, [17]);
});

test('native citations preserve source numbering while removing hand-written links, numbers and private reasoning', async () => {
  const response = native('Published visitor information [42] [uncited](https://forged.org/) https://forged.org/free.');
  response.content[4].citations.push(citation());
  response.content.push({ type: 'text', text: '\n\nCheck the official page.', citations: [citation({ title: 'A generated title must not replace the tool source title' })] });
  const result = await extractSearchResult(normalizeAnthropicSearch(response), { lookup, now: () => NOW });
  assert.deepEqual(result.sources, [source]);
  assert.equal(result.checkedAt, '2026-10-07T20:00:00.000Z');
  assert.match(result.answer, /\[1\].*\[1\]/);
  assert.doesNotMatch(result.answer, /\[42\]|https:|Private|will search|opaque/);
  assert.equal('candidates' in result, false);
});

test('cites require native locations, opaque index and matching returned sources; unsafe DNS is rejected', async () => {
  for (const invalid of [{ type: 'url_citation' }, { encrypted_index: '' }, { url: 'https://forged.org/' }]) {
    const response = native(); response.content[4].citations = [citation(invalid)];
    await assert.rejects(extractSearchResult(normalizeAnthropicSearch(response), { lookup }), { code: 'web_no_cited_sources' });
  }
  for (const url of ['http://127.0.0.1/', 'https://metadata.google.internal/', 'https://user:pass@museum.org/', 'https://museum.org:8443/']) {
    const response = native(); response.content[3].content[0].url = url; response.content[4].citations[0].url = url;
    await assert.rejects(extractSearchResult(normalizeAnthropicSearch(response), { lookup }), { code: 'web_no_cited_sources' });
  }
  await assert.rejects(extractSearchResult(normalizeAnthropicSearch(native()), { lookup: async () => [{ address: '10.0.0.1', family: 4 }] }), { code: 'web_no_cited_sources' });
});

test('truncated, refused, mixed-client-tool or unexecuted searches fail without continuation spend; a turn still paused after two resumes fails', async () => {
  for (const stop_reason of ['pause_turn', 'max_tokens', 'refusal', 'tool_use', 'stop_sequence', null]) {
    let calls = 0;
    await assert.rejects(requestSearch(input, options({ ai: async () => { calls++; return native('The venue does not exist.', { stop_reason }); } })), { code: 'web_incomplete_response' });
    // pause_turn is resumed at most twice (lib/anthropicWebSearch.js MAX_CONTINUATIONS); nothing else is.
    assert.equal(calls, stop_reason === 'pause_turn' ? 3 : 1);
  }
  for (const content of [
    [{ type: 'text', text: 'Unsearched claim.', citations: [citation()] }],
    [...native().content, { type: 'refusal', refusal: 'Refused' }],
    [...native().content, { type: 'tool_use', name: 'other', id: 'client-1', input: {} }],
  ]) await assert.rejects(requestSearch(input, options({ ai: async () => native('', { content }) })), { code: 'web_incomplete_response' });
});

test('native search errors fail closed even when HTTP succeeded and the model generated an absence claim', async () => {
  for (const [error_code, code] of [['too_many_requests', 'web_provider_rate_limit'], ['unavailable', 'web_provider_unavailable'], ['new_unknown_error', 'web_provider_unavailable'], ['max_uses_exceeded', 'web_incomplete_response'], ['invalid_tool_input', 'web_provider_request']]) {
    const response = native('The venue is closed and has no events.');
    response.content[3].content = { type: 'web_search_tool_result_error', error_code, message: 'private provider details' };
    await assert.rejects(requestSearch(input, options({ ai: async () => response })), error => error.code === code && !/private|closed|no events/.test(error.message));
  }
  const partial = native();
  partial.content.splice(4, 0, { type: 'server_tool_use', id: 'srvtoolu_failed', name: 'web_search', input: {} },
    { type: 'web_search_tool_result', tool_use_id: 'srvtoolu_failed', content: { type: 'web_search_tool_result_error', error_code: 'unavailable' } });
  await assert.rejects(requestSearch(input, options({ ai: async () => partial })), { code: 'web_provider_unavailable' });
});

test('unpaired results, unfinished searches, empty results and excess native search calls cannot establish facts', async () => {
  const unpaired = native(); unpaired.content[3].tool_use_id = 'forged';
  const unfinished = native(); unfinished.content.splice(4, 0, { type: 'server_tool_use', id: 'srvtoolu_unfinished', name: 'web_search', input: {} });
  const excess = native(); excess.content.splice(4, 0, { type: 'server_tool_use', id: 'srvtoolu_extra', name: 'web_search', input: {} }, { type: 'web_search_tool_result', tool_use_id: 'srvtoolu_extra', content: [] });
  for (const response of [unpaired, unfinished, excess]) {
    await assert.rejects(requestSearch(input, options({ config: { ...config, OPENAI_WEB_SEARCH_MAX_TOOL_CALLS: '1' }, ai: async () => response })), { code: 'web_incomplete_response' });
  }
  const empty = native(); empty.content[3].content = [];
  await assert.rejects(requestSearch(input, options({ ai: async () => empty })), { code: 'web_no_cited_sources' });
});

test('Claude can use conservative local name cards but never spends on OpenAI candidate extraction', async () => {
  const result = await requestSearch({ query: 'SF cafes', locale: 'en' }, options({
    ai: async () => native('Café Harbor is located at the Ferry Building in San Francisco.'),
    extractAi: async () => assert.fail('No OpenAI extraction in Claude search'),
  }));
  assert.equal(result.candidateStatus, 'ready');
  assert.equal(result.candidates[0].name, 'Café Harbor');
  for (const field of ['city', 'summary', 'timeSummary', 'priceSummary']) assert.equal(result.candidates[0][field], null);
  assert.deepEqual(result.candidates[0].sourceUrls, [source.url]);
});

test('Claude visitor facts use exact fetched source text, retain unknown prices and never call OpenAI', async () => {
  const page = 'Example Museum\nStandard Hours\nWednesday: Closed\nThursday: Noon–8 pm\nLast tickets sold\n7:00 pm\nPlease confirm selected-date changes with the museum before visiting.';
  let providers = 0;
  const result = await requestSearch({ query: 'Example Museum hours', locale: 'en', date: '2026-10-08' }, {
    config, lookup, now: () => NOW,
    fetchImpl: async url => { providers++; assert.equal(url, 'https://api.anthropic.com/v1/messages'); return { ok: true, json: async () => native('Example Museum will definitely be open 24 hours and is free.') }; },
    sourceFetch: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: page }),
    extractAi: async () => assert.fail('No OpenAI fact extraction in Claude search'),
  });
  assert.equal(providers, 1);
  assert.equal(result.factsStatus, 'source-excerpts');
  assert.match(result.answer, /Wednesday: Closed Thursday: Noon–8 pm \[1\]/);
  assert.match(result.answer, /Last tickets sold 7:00 pm/);
  assert.match(result.answer, /Admission details：Not established/);
  assert.match(result.answer, /2026-10-08 opening and ticket availability: not independently confirmed/);
  assert.doesNotMatch(result.answer, /24 hours|definitely|is free/);
});

test('blocked source fetch returns explicit unknowns and no guessed cards or model facts', async () => {
  const result = await requestSearch({ query: 'Example Museum hours', locale: 'en' }, options({
    ai: async () => native('Example Museum is open 24 hours and free for all.'), sourceFetch: async () => { throw Error('blocked source'); },
    extractAi: async () => assert.fail('No extraction for blocked source'),
  }));
  assert.equal(result.factsStatus, 'sources-only'); assert.deepEqual(result.candidates, []);
  assert.match(result.answer, /Not established in this lookup/);
  assert.doesNotMatch(result.answer, /24 hours|free for all/);
});

test('public-policy lookup preserves jurisdiction/date prompt and has no venue cards', async () => {
  let payload;
  const result = await requestSearch({ query: 'San Francisco public school enrollment eligibility', locale: 'en', city: 'San Francisco', date: '2026-10-10' }, options({
    ai: async body => { payload = body; return native('Check the district enrollment eligibility rules.'); },
  }));
  assert.match(payload.system, /Server date: 2026-10-07/);
  assert.match(payload.system, /A supplied trip date is not a policy effective date/);
  assert.match(payload.system, /without collecting or sending a home address or child identity/);
  assert.equal(result.candidateStatus, 'not_applicable'); assert.deepEqual(result.candidates, []);
});

test('Claude retains date/city verification and never upgrades an unsupported absence statement', async () => {
  for (const answer of ['There are no events in San Francisco.', '2026-09-01 is today.']) {
    await assert.rejects(requestSearch({ query: 'San Francisco events today', locale: 'en' }, options({ ai: async () => native(answer) })), { code: 'SEARCH_VERIFICATION_FAILED' });
  }
});

test('shared quota reserves native max uses once, deduplicates in flight, caches and charges failures', async () => {
  let calls = 0;
  const shared = service({ config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '4' }, ai: async () => { calls++; await new Promise(resolve => setTimeout(resolve, 10)); return native(); } });
  const [first, parallel] = await Promise.all([shared.search(input), shared.search(input)]);
  assert.equal(calls, 1); assert.equal(first.cached, false); assert.equal(parallel.cached, false);
  assert.equal(shared.models.PostTranslationQuota.rows[0].count, 2);
  assert.deepEqual(await shared.search(input), { ...first, cached: true });
  const failed = service({ models: shared.models, config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '4' }, ai: async () => { calls++; throw Error('private provider detail'); } });
  await assert.rejects(failed.search({ query: 'Oakland gardens' }), { code: 'web_provider_unavailable' });
  assert.equal(shared.models.PostTranslationQuota.rows[0].count, 4);
  await assert.rejects(shared.search({ query: 'San Jose gardens' }), { code: 'web_daily_limit' });
  await assert.rejects(failed.search({ query: 'Oakland gardens' }), { code: 'web_cooldown' });
  assert.equal(calls, 2);
});

test('authorization, disabled search, rate limits and narrow public inputs still precede Claude spend', async () => {
  let calls = 0;
  const make = extra => service({ ai: async () => { calls++; return native(); }, ...extra });
  await assert.rejects(make({ config: { OPENAI_WEB_SEARCH_ENABLED: 'false' } }).search(input), { code: 'web_disabled' });
  await assert.rejects(make({ checkRateLimit: () => false }).search(input), { code: 'web_rate_limit' });
  await assert.rejects(make({ Quota: undefined }).search(input), { code: 'web_quota_unavailable' });
  for (const field of ['messages', 'history', 'plans', 'account']) await assert.rejects(make({}).search({ ...input, [field]: 'private transcript' }), { code: 'web_invalid_query' });
  const blocked = make({ webAccessForRequest: async () => ({ allowed: false, authenticated: false, reason: 'auth_required' }) });
  const response = { set: () => {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  await blocked.route({ body: input }, response);
  assert.equal(response.code, 401); assert.equal(response.body.code, 'auth_required'); assert.equal(calls, 0);
  assert.equal(blocked.models.PostTranslationQuota.rows.length, 0);
});

test('Claude HTTP failure details are sanitized without switching provider', async () => {
  for (const [status, code] of [[401, 'web_provider_access'], [403, 'web_provider_access'], [400, 'web_provider_request'], [429, 'web_provider_rate_limit'], [500, 'web_provider_unavailable']]) {
    let calls = 0;
    await assert.rejects(requestSearch(input, { config, lookup, fetchImpl: async () => { calls++; return { ok: false, status, json: async () => { throw Error('private provider details'); } }; } }), error => error.code === code && !/private|isolated/.test(error.message));
    assert.equal(calls, 1);
  }
});

test('optional Claude expiry blocks new spend without OpenAI fallback but permits an existing cache entry', async () => {
  const expiry = NOW + 60000;
  let time = NOW, calls = 0;
  const limited = service({ config: { ANTHROPIC_USE_UNTIL: new Date(expiry).toISOString() }, now: () => time,
    ai: async () => { calls++; return native(); } });
  const original = await limited.search(input);
  time = expiry;
  assert.deepEqual(await limited.search(input), { ...original, cached: true });
  await assert.rejects(limited.search({ query: 'Oakland gardens' }), { code: 'web_not_configured' });
  assert.equal(calls, 1); assert.equal(limited.models.PostTranslationQuota.rows[0].count, 2);
  for (const until of [new Date(NOW).toISOString(), 'invalid-date', '2026-02-30T00:00:00Z']) {
    await assert.rejects(requestSearch(input, options({ config: { ...config, ANTHROPIC_USE_UNTIL: until }, ai: async () => assert.fail('expired Claude must not be called') })), { code: 'web_not_configured' });
  }
});

test('web expiry reached during quota reservation prohibits native transport without refund or fallback', async t => {
  const expiry = Date.parse('2099-10-30T00:00:00Z');
  let clock = expiry - 1, calls = 0;
  t.mock.method(Date, 'now', () => clock);
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'isolated-web-expiry-test' }, now: () => clock });
  const req = new EventEmitter(); req.path = '/api/planner/web-search'; req.ip = 'fixture';
  const res = new EventEmitter(); res.writableEnded = false;
  await new Promise((resolve, reject) => {
    governance.middleware(async () => { await Promise.resolve(); clock = expiry; return 'fixture-user'; })(req, res, async () => {
      try {
        await assert.rejects(requestSearch(input, { config: { ...config, ANTHROPIC_USE_UNTIL: new Date(expiry).toISOString() }, lookup,
          fetchImpl: async () => { calls++; return { ok: true, json: async () => native() }; },
        }), { code: 'web_not_configured' });
        assert.equal(calls, 0);
        assert.equal(models.AiGovernance.rows[0].count, 1);
        assert.equal(models.AiGovernance.rows[0].calls || 0, 0);
        assert.equal(models.AiGovernance.rows[0].failures, 1);
        res.writableEnded = true; res.emit('finish'); resolve();
      } catch (error) { reject(error); }
    }).catch(reject);
  });
});

test('Claude search deadline aborts the actual governed provider request', async () => {
  let signal;
  await assert.rejects(requestSearch(input, { config, lookup, timeoutMs: 25,
    fetchImpl: async (_url, request) => { signal = request.signal; return new Promise(() => {}); },
  }), { code: 'web_timeout' });
  assert.equal(signal.aborted, true);
});

test('governance reserves and records Claude calls and caller disconnect reaches provider signal', async () => {
  const models = createMemoryModels();
  const governance = createAiGovernance({ Model: models.AiGovernance, config: { JWT_SECRET: 'isolated-web-governance-secret' }, now: () => NOW });
  const req = new EventEmitter(); req.path = '/api/planner/web-search'; req.ip = 'isolated-ip';
  const res = new EventEmitter(); res.writableEnded = false;
  let signal;
  await new Promise((resolve, reject) => {
    governance.middleware(async () => 'isolated-user')(req, res, async () => {
      try {
        await requestSearch(input, { config, lookup, now: () => NOW, fetchImpl: async (_url, request) => {
          signal = request.signal; return { ok: true, json: async () => native() };
        } });
        assert.equal(models.AiGovernance.rows[0].count, 1);
        assert.equal(models.AiGovernance.rows[0].calls, 1);
        assert.equal(models.AiGovernance.rows[0].inputTokens, 20);
        await assert.rejects(requestSearch(input, { config, lookup, fetchImpl: async (_url, request) => {
          signal = request.signal; req.emit('aborted'); return new Promise(() => {});
        } }));
        assert.equal(signal.aborted, true);
        res.writableEnded = true; res.emit('finish'); resolve();
      } catch (error) { reject(error); }
    }).catch(reject);
  });
});
