const test = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_MODEL, KNOWN_MODELS, EFFORTS, ROUTES, ROUTE_NAMES, HAIKU_MIN_MAX_TOKENS, SERVER_FALLBACK_BETA,
  aiRoute, routeForFeature, modelFamily, serverFallbacksAllowed, maxTokensFor, timeoutFor, firstByteFor, requestControls,
  anthropicHeaders, estimatePromptTokens, assertPromptWithinCap, logRefusalRetry, describeAiModels,
} = require('../lib/aiModels');
const { FEATURES } = require('../lib/aiRuntimeMetrics');

const LEGACY_DEFAULTS = { baybay_agent: [9000, 28000], baybay_web: [4096, 35000], baybay_legacy: [4096, 28000], helper_translate: [6000, 28000],
  helper_post_assist: [6000, 28000], helper_outing: [6000, 28000], helper_planner: [4000, 28000], helper_event_extract: [6000, 28000],
  helper_conversation: [6000, 28000], helper_other: [6000, 28000] };

test('the plan routes exist and every default equals the pre-route request (legacy model, legacy effort, caller budgets)', () => {
  for (const name of ['baybay_fast', 'baybay_agent', 'baybay_professional', 'baybay_web', 'triage', 'helper_translate', 'helper_planner']) assert.ok(ROUTE_NAMES.includes(name), name);
  for (const config of [{}, { ANTHROPIC_BAYBAY_EFFORT: 'low' }, { ANTHROPIC_BAYBAY_EFFORT: 'high' }, { ANTHROPIC_BAYBAY_MODEL: 'fixture-claude' }]) {
    for (const name of ROUTE_NAMES) {
      const route = aiRoute(name, config);
      assert.equal(route.model, config.ANTHROPIC_BAYBAY_MODEL || 'claude-opus-5-5', name);
      // The legacy variable only ever produced low or medium.
      assert.equal(route.effort, config.ANTHROPIC_BAYBAY_EFFORT === 'low' ? 'low' : 'medium', name);
      assert.equal(route.fallbacks, 'off'); assert.equal(route.firstByteMs, null); assert.equal(route.maxPromptTokens, null);
      assert.deepEqual(route.ignored, []);
      if (LEGACY_DEFAULTS[name]) assert.deepEqual([route.maxTokens, route.totalMs], LEGACY_DEFAULTS[name], name);
    }
  }
  assert.equal(DEFAULT_MODEL, 'claude-opus-5-5');
  assert.throws(() => aiRoute('baybay_unknown', {}), /Unknown AI route/);
  // Caller-supplied budgets pass through unchanged by default (agent research/final, helpers, planner).
  const agent = aiRoute('baybay_agent', {}), helper = aiRoute('helper_other', {});
  assert.deepEqual([6000, 9000].map(value => maxTokensFor(agent, value)), [6000, 9000]);
  assert.deepEqual([4000, 6000, 50000, undefined, 0, 'bad'].map(value => maxTokensFor(helper, value)), [4000, 6000, 9000, 6000, 6000, 6000]);
  assert.deepEqual([18000, 25000, 28000, undefined].map(value => timeoutFor(agent, value)), [18000, 25000, 28000, 28000]);
  assert.equal(timeoutFor(aiRoute('baybay_web', {}), 20000), 20000); assert.equal(timeoutFor(aiRoute('baybay_web', {}), 35000), 35000);
  assert.equal(firstByteFor(agent, 28000), undefined);
});

test('per-route model overrides change one route; the helper group override covers helpers; route-specific wins', () => {
  const config = { BAYBAY_MODEL_AGENT: 'claude-haiku-5-5', BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5', BAYBAY_MODEL_HELPER_PLANNER: 'claude-sonnet-5-5', ANTHROPIC_BAYBAY_MODEL: 'claude-opus-5-5' };
  assert.equal(aiRoute('baybay_agent', config).model, 'claude-haiku-5-5');
  assert.equal(aiRoute('baybay_agent', config).modelSource, 'BAYBAY_MODEL_AGENT');
  assert.equal(aiRoute('baybay_professional', config).model, 'claude-opus-5-5', 'professional is not moved by the agent override');
  assert.equal(aiRoute('helper_translate', config).model, 'claude-haiku-5-5');
  assert.equal(aiRoute('helper_planner', config).model, 'claude-sonnet-5-5');
  assert.equal(aiRoute('baybay_fast', config).model, 'claude-opus-5-5', 'the helper group never applies to BayBay routes');
  // The RC-20 rollback is one variable.
  assert.equal(aiRoute('baybay_agent', { ...config, BAYBAY_MODEL_AGENT: 'claude-opus-5-5' }).model, 'claude-opus-5-5');
  for (const typo of ['claude-haiku', 'haiku', 'claude-haiku-5-5-latest', 'gpt-6.1-sol']) {
    const route = aiRoute('baybay_agent', { BAYBAY_MODEL_AGENT: typo });
    assert.equal(route.model, 'claude-opus-5-5', typo);
    assert.deepEqual(route.ignored, [{ name: 'BAYBAY_MODEL_AGENT', reason: 'unknown_model' }]);
  }
  assert.equal(aiRoute('baybay_agent', { BAYBAY_MODEL_AGENT: '  claude-sonnet-5-5  ' }).model, 'claude-sonnet-5-5');
});

test('native web search never resolves to Haiku 5.5, from its own override or from the legacy all-route variable', () => {
  const own = aiRoute('baybay_web', { BAYBAY_MODEL_WEB: 'claude-haiku-5-5' });
  assert.equal(own.model, 'claude-opus-5-5');
  assert.deepEqual(own.ignored, [{ name: 'BAYBAY_MODEL_WEB', reason: 'haiku_not_verified_for_route' }]);
  const legacy = aiRoute('baybay_web', { ANTHROPIC_BAYBAY_MODEL: 'claude-haiku-5-5' });
  assert.equal(legacy.model, 'claude-opus-5-5');
  assert.equal(aiRoute('baybay_agent', { ANTHROPIC_BAYBAY_MODEL: 'claude-haiku-5-5' }).model, 'claude-haiku-5-5');
  assert.equal(aiRoute('baybay_web', { BAYBAY_MODEL_WEB: 'claude-sonnet-5-5' }).model, 'claude-sonnet-5-5');
});

test('effort is explicit on every route and model; overrides accept only low, medium or high', () => {
  for (const name of ROUTE_NAMES) for (const model of KNOWN_MODELS) {
    const controls = requestControls(aiRoute(name, {}), model, undefined);
    assert.ok(EFFORTS.includes(controls.effort), `${name} ${model}`);
  }
  assert.equal(aiRoute('baybay_fast', { BAYBAY_EFFORT_FAST: 'high' }).effort, 'high');
  assert.equal(aiRoute('helper_outing', { BAYBAY_EFFORT_HELPERS: 'low', ANTHROPIC_BAYBAY_EFFORT: 'medium' }).effort, 'low');
  assert.equal(aiRoute('helper_outing', { BAYBAY_EFFORT_HELPERS: 'low', BAYBAY_EFFORT_HELPER_OUTING: 'high' }).effort, 'high');
  for (const unsupported of ['xhigh', 'max', 'HIGH', 'fast']) {
    const route = aiRoute('baybay_agent', { BAYBAY_EFFORT_AGENT: unsupported });
    assert.equal(route.effort, 'medium');
    assert.deepEqual(route.ignored, [{ name: 'BAYBAY_EFFORT_AGENT', reason: 'unsupported_effort' }]);
  }
});

test('Haiku requests never go below 4,000 max_tokens; overrides win over caller budgets and are range-checked', () => {
  assert.equal(HAIKU_MIN_MAX_TOKENS, 4000);
  const haiku = aiRoute('baybay_fast', { BAYBAY_MODEL_FAST: 'claude-haiku-5-5', BAYBAY_MAX_TOKENS_FAST: '1500' });
  assert.equal(haiku.maxTokens, 1500);
  assert.equal(maxTokensFor(haiku, 9000), 4000, 'override wins over the caller, then the Haiku floor applies');
  assert.equal(requestControls(haiku, 'claude-haiku-5-5', 1500).maxTokens, 4000);
  assert.equal(requestControls(haiku, 'claude-sonnet-5-5', 1500).maxTokens, 1500, 'the floor is Haiku-only');
  assert.equal(maxTokensFor(aiRoute('helper_planner', { BAYBAY_MODEL_HELPER_PLANNER: 'claude-haiku-5-5' }), 1200), 4000);
  assert.equal(maxTokensFor(aiRoute('baybay_agent', { BAYBAY_MAX_TOKENS_AGENT: '12000' }), 6000), 12000);
  for (const value of ['100', '40000', '9000.5', '-1', 'many']) {
    const route = aiRoute('baybay_agent', { BAYBAY_MAX_TOKENS_AGENT: value });
    assert.equal(route.maxTokens, 9000); assert.equal(route.maxTokensOverridden, false);
    assert.deepEqual(route.ignored, [{ name: 'BAYBAY_MAX_TOKENS_AGENT', reason: 'out_of_range' }]);
  }
});

test('deadline overrides can only shorten caller deadlines; first-byte deadline applies only when shorter', () => {
  const route = aiRoute('baybay_agent', { BAYBAY_TOTAL_MS_AGENT: '15000', BAYBAY_FIRST_BYTE_MS_AGENT: '6000' });
  assert.equal(timeoutFor(route, 25000), 15000); assert.equal(timeoutFor(route, 9000), 9000);
  assert.equal(firstByteFor(route, 15000), 6000); assert.equal(firstByteFor(route, 5000), undefined);
  assert.deepEqual(aiRoute('helper_other', { BAYBAY_TOTAL_MS_HELPER_OTHER: '999999' }).ignored, [{ name: 'BAYBAY_TOTAL_MS_HELPER_OTHER', reason: 'out_of_range' }]);
});

test('server-side fallbacks are opt-in and only ever sent for Opus or Sonnet, with their beta header', () => {
  assert.deepEqual(KNOWN_MODELS.map(modelFamily), ['opus', 'sonnet', 'haiku']);
  assert.deepEqual(KNOWN_MODELS.map(serverFallbacksAllowed), [true, true, false]);
  assert.equal(serverFallbacksAllowed('fixture-claude'), false);
  const off = requestControls(aiRoute('baybay_agent', {}), 'claude-opus-5-5', 6000);
  assert.equal(off.fallbacks, undefined); assert.deepEqual(off.betas, []);
  const on = aiRoute('baybay_agent', { BAYBAY_FALLBACKS: 'default' });
  for (const model of ['claude-opus-5-5', 'claude-sonnet-5-5']) {
    const controls = requestControls(on, model, 6000);
    assert.equal(controls.fallbacks, 'default'); assert.deepEqual(controls.betas, [SERVER_FALLBACK_BETA]);
  }
  const haiku = requestControls(on, 'claude-haiku-5-5', 6000);
  assert.equal(haiku.fallbacks, undefined); assert.deepEqual(haiku.betas, []);
  assert.equal(aiRoute('baybay_web', { BAYBAY_FALLBACKS: 'default', BAYBAY_FALLBACKS_WEB: 'off' }).fallbacks, 'off');
  assert.deepEqual(aiRoute('baybay_web', { BAYBAY_FALLBACKS: 'yes' }).ignored, [{ name: 'BAYBAY_FALLBACKS', reason: 'unsupported_fallbacks' }]);
  assert.equal(anthropicHeaders({ ANTHROPIC_API_KEY: 'fixture' }, [SERVER_FALLBACK_BETA])['anthropic-beta'], 'server-side-fallback-2026-07-01');
  assert.equal(anthropicHeaders({ ANTHROPIC_API_KEY: 'fixture' })['anthropic-beta'], undefined);
});

test('disabled thinking is an opt-in eval setting sent to Haiku 5.5 only; Opus and Sonnet never receive it', () => {
  assert.equal(aiRoute('baybay_agent', {}).thinking, 'adaptive');
  assert.equal(requestControls(aiRoute('baybay_agent', {}), 'claude-haiku-5-5').thinking, undefined, 'adaptive thinking omits the field');
  const off = aiRoute('baybay_fast', { BAYBAY_MODEL_FAST: 'claude-haiku-5-5', BAYBAY_EFFORT_FAST: 'low', BAYBAY_THINKING_FAST: 'disabled' });
  assert.deepEqual(requestControls(off, 'claude-haiku-5-5').thinking, { type: 'disabled' });
  assert.equal(requestControls(off, 'claude-sonnet-5-5').thinking, undefined, 'Sonnet 5.5 returns a 400 for disabled thinking');
  assert.equal(requestControls(off, 'claude-opus-5-5').thinking, undefined, 'Opus 5.5 returns a 400 for disabled thinking');
  assert.deepEqual(aiRoute('baybay_fast', { BAYBAY_THINKING_FAST: 'off' }).ignored, [{ name: 'BAYBAY_THINKING_FAST', reason: 'unsupported_thinking' }]);
});

test('governed features map to helper routes; every feature resolves to a known route', () => {
  assert.equal(routeForFeature('post_assist'), 'helper_post_assist');
  assert.equal(routeForFeature('post_translation'), 'helper_translate');
  assert.equal(routeForFeature('event_extract'), 'helper_event_extract');
  assert.equal(routeForFeature(undefined), 'helper_other');
  for (const feature of FEATURES) assert.ok(Object.hasOwn(ROUTES, routeForFeature(feature)), feature);
});

test('Haiku prompts are capped at an estimated 60K tokens; images count as a fixed estimate, not base64 length', () => {
  const route = aiRoute('baybay_agent', { BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' });
  assert.equal(route.maxPromptTokens, 60000);
  const small = { model: 'claude-haiku-5-5', system: 'Rules', messages: [{ role: 'user', content: [{ type: 'text', text: '问'.repeat(1000) }] }] };
  assert.doesNotThrow(() => assertPromptWithinCap(small));
  const large = { ...small, messages: [{ role: 'user', content: [{ type: 'text', text: '问'.repeat(61000) }] }] };
  assert.throws(() => assertPromptWithinCap(large), error => error.code === 'AI_PROMPT_TOO_LARGE' && error.cap === 60000);
  assert.doesNotThrow(() => assertPromptWithinCap({ ...large, model: 'claude-sonnet-5-5' }), 'the Sonnet retry has no Haiku cap');
  assert.doesNotThrow(() => assertPromptWithinCap({ ...large, model: 'claude-opus-5-5' }), 'no cap by default');
  const image = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'A'.repeat(3_000_000) } };
  assert.ok(estimatePromptTokens({ system: '', messages: [{ role: 'user', content: [image] }] }) < 2100);
});

test('refusal logging carries route, models and a sanitized category only', () => {
  const lines = [];
  logRefusalRetry({ route: 'baybay_agent', from: 'claude-haiku-5-5', to: 'claude-sonnet-5-5', response: { stop_details: { category: 'general_harms', explanation: 'private question text' }, content: [{ type: 'text', text: 'private' }] } }, line => lines.push(line));
  logRefusalRetry({ route: 'helper_other', from: 'claude-haiku-5-5', to: 'claude-sonnet-5-5', response: { stop_details: { category: 'Bad category with spaces' } } }, line => lines.push(line));
  logRefusalRetry({ route: 'helper_other', from: 'claude-haiku-5-5', to: 'claude-sonnet-5-5', response: { stop_details: null } }, line => lines.push(line));
  assert.deepEqual(lines.map(line => JSON.parse(line.replace('[ai-refusal] ', '')).category), ['general_harms', 'unrecognized', null]);
  assert.doesNotMatch(lines.join('\n'), /private/);
  assert.doesNotThrow(() => logRefusalRetry({ route: 'x', response: {} }, () => { throw new Error('log sink down'); }));
});

test('route description is complete and secret-free', () => {
  const described = describeAiModels({ ANTHROPIC_API_KEY: 'secret-key-value', ANTHROPIC_WORKSPACE_ID: 'wrkspc_secret', BAYBAY_MODEL_WEB: 'claude-haiku-5-5' });
  assert.deepEqual(described.map(item => item.route), ROUTE_NAMES);
  assert.doesNotMatch(JSON.stringify(described), /secret/);
  assert.deepEqual(described.find(item => item.route === 'baybay_web').ignored, [{ name: 'BAYBAY_MODEL_WEB', reason: 'haiku_not_verified_for_route' }]);
});
