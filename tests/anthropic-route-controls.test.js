const test = require('node:test');
const assert = require('node:assert/strict');
const { createAnthropicBaybay, replayableContent, baybayModel, baybayRoute } = require('../lib/anthropicBaybay');
const { requestAnthropicJson } = require('../lib/anthropicJson');
const { searchPayload, requestAnthropicSearch } = require('../lib/anthropicWebSearch');
const { parseDraft } = require('../lib/baybayAgent');
const { KNOWN_MODELS, EFFORTS, SERVER_FALLBACK_BETA } = require('../lib/aiModels');

const base = { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-key-only' };
const SAMPLING = ['temperature', 'top_p', 'top_k'];
const tool = { type: 'function', name: 'search_site', description: 'Search site', parameters: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'], additionalProperties: false } };
const schema = { type: 'object', properties: { answer: { type: 'string' }, candidateIds: { type: 'array', items: { type: 'string' } } }, required: ['answer', 'candidateIds'], additionalProperties: false };
// The agent builds OpenAI-shaped payloads; OpenAI-only sampling fields must never be forwarded to Claude.
const agentPayload = (model, extra = {}) => ({ ...(model ? { model } : {}), instructions: 'Use verified site evidence.', input: [{ role: 'user', content: 'Question' }], tools: [tool],
  text: { format: { type: 'json_schema', name: 'answer', strict: true, schema } }, max_output_tokens: 6000, temperature: 0.2, top_p: 0.9, top_k: 40, reasoning: { effort: 'low' }, ...extra });
const answer = (model, extra = {}) => ({ type: 'message', id: 'msg', model, role: 'assistant', stop_reason: 'end_turn',
  content: [{ type: 'thinking', thinking: '', signature: `sig-${model}` }, { type: 'text', text: JSON.stringify({ answer: 'Supported answer.', candidateIds: [] }) }],
  usage: { input_tokens: 20, output_tokens: 30 }, ...extra });
const refusal = (model, category = 'general_harms') => ({ type: 'message', id: 'msg-refusal', model, role: 'assistant', stop_reason: 'refusal', stop_details: { type: 'refusal', category }, content: [], usage: { input_tokens: 20, output_tokens: 0 } });
const ok = value => ({ ok: true, json: async () => value });
const capture = (responses, sent) => async (url, init) => {
  sent.push({ url, headers: init.headers, body: JSON.parse(init.body) });
  const next = responses.shift();
  return ok(typeof next === 'function' ? next(JSON.parse(init.body)) : next);
};
function assertClaudeBody(body, { family, fallbacks = false } = {}) {
  for (const field of SAMPLING) assert.equal(body[field], undefined, `${field} must never reach Claude`);
  for (const field of ['thinking', 'reasoning', 'input', 'instructions', 'max_output_tokens', 'store', 'include']) assert.equal(body[field], undefined, field);
  assert.ok(EFFORTS.includes(body.output_config?.effort), 'effort is always explicit');
  assert.ok(Number.isSafeInteger(body.max_tokens) && body.max_tokens > 0);
  if (family === 'haiku') assert.ok(body.max_tokens >= 4000, 'Haiku thinking needs >= 4,000 max_tokens');
  if (fallbacks) assert.equal(body.fallbacks, 'default'); else assert.equal(body.fallbacks, undefined);
}

test('Anthropic payloads never carry temperature/top_p/top_k, always carry effort, and gate fallbacks by model on every adapter', async () => {
  for (const model of KNOWN_MODELS) for (const fallbackSetting of [undefined, 'default']) {
    const family = model.split('-')[1];
    const expectFallbacks = fallbackSetting === 'default' && family !== 'haiku';
    const config = { ...base, BAYBAY_MODEL_AGENT: model, BAYBAY_MODEL_HELPERS: model, BAYBAY_MODEL_WEB: model, ...(fallbackSetting ? { BAYBAY_FALLBACKS: fallbackSetting } : {}) };
    const sent = [];
    // Agent research/final calls, with the agent's OpenAI-only fields present in the payload.
    const agent = createAnthropicBaybay({ config, fetchImpl: capture([answer(model)], sent) });
    assert.equal(parseDraft(await agent(agentPayload(baybayModel(config)), { timeoutMs: 25000 })).answer, 'Supported answer.');
    // JSON helpers (explicit route and inferred route).
    await requestAnthropicJson([{ role: 'system', content: 'Return JSON.' }, { role: 'user', content: 'Sample' }], { config, route: 'helper_planner', maxTokens: 1200, fetchImpl: capture([answer(model)], sent) });
    await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config, schema, fetchImpl: capture([answer(model)], sent) });
    // Native web search: the payload builder plus its transport.
    const web = searchPayload({ query: 'SF museums' }, { config, instructions: 'Search.', scope: { city: 'San Francisco', timezone: 'America/Los_Angeles' } });
    await requestAnthropicSearch(web, { config, timeoutMs: 20000, fetchImpl: capture([answer('claude-opus-5-5')], sent) });
    assert.equal(sent.length, 4);
    sent.slice(0, 3).forEach(({ body, headers }) => {
      assert.equal(body.model, model);
      assertClaudeBody(body, { family, fallbacks: expectFallbacks });
      assert.equal(headers['anthropic-beta'], expectFallbacks ? SERVER_FALLBACK_BETA : undefined);
    });
    // Web search stays off Haiku: its model is Opus whenever Haiku is requested.
    const webFamily = family === 'haiku' ? 'opus' : family;
    assert.equal(sent[3].body.model, family === 'haiku' ? 'claude-opus-5-5' : model);
    assertClaudeBody(sent[3].body, { family: webFamily, fallbacks: fallbackSetting === 'default' });
    assert.equal(sent[3].headers['anthropic-beta'], fallbackSetting === 'default' ? SERVER_FALLBACK_BETA : undefined);
    assert.equal(sent[1].body.max_tokens, family === 'haiku' ? 4000 : 1200, 'the planner helper budget is raised to 4,000 only on Haiku');
  }
});

// Sonnet 5.5 rejects thinking {type: "disabled"}, forced tool_choice (any/tool) and
// sampling parameters, and defaults to effort high; max_tokens must cover thinking too.
function assertSonnet55Body(body, { maxTokens, toolChoice }) {
  assert.deepEqual(Object.keys(body).sort(), ['max_tokens', 'messages', 'model', 'output_config', 'system', 'tool_choice', 'tools']);
  assert.equal(body.model, 'claude-sonnet-5-5');
  assert.deepEqual(Object.keys(body.output_config).sort(), ['effort', 'format']);
  assert.equal(body.output_config.effort, 'low', 'effort is explicit: Sonnet 5.5 would default to high');
  assert.equal(body.output_config.format.type, 'json_schema');
  assert.equal(body.thinking, undefined, 'adaptive thinking: the field is omitted ({type: "disabled"} is a 400 on Sonnet 5.5)');
  for (const field of SAMPLING) assert.equal(body[field], undefined, field);
  assert.equal(body.fallbacks, undefined, 'server-side fallbacks stay opt-in');
  assert.deepEqual(body.tool_choice, { type: toolChoice }, 'only auto or none: forced tool_choice is a 400 on Sonnet 5.5');
  assert.ok(body.tools.every(item => item.strict === true && !item.input_schema.properties?.query?.maxLength));
  assert.equal(body.max_tokens, maxTokens); assert.ok(body.max_tokens >= 4000, 'room for adaptive thinking plus the answer');
}

test('R0 default: agent and professional runs send a valid Sonnet 5.5 request (effort low, no thinking field, no sampling, auto/none tools, >= 4,000 max_tokens)', async () => {
  for (const route of ['baybay_agent', 'baybay_professional']) {
    const sent = [];
    const toolTurn = { ...answer('claude-sonnet-5-5'), stop_reason: 'tool_use', content: [{ type: 'thinking', thinking: '', signature: 'sig-sonnet' }, { type: 'tool_use', id: 'call-1', name: 'search_site', input: { query: 'museums' } }] };
    const agent = createAnthropicBaybay({ config: base, route, fetchImpl: capture([toolTurn, answer('claude-sonnet-5-5')], sent) });
    // The agent asks for baybayModel(config) and 6,000 (research) / 9,000 (final) tokens.
    const payload = agentPayload(baybayModel(base), { tool_choice: 'auto' });
    assert.equal(payload.model, 'claude-sonnet-5-5');
    const first = await agent(payload, { timeoutMs: 25000 });
    payload.input.push(...first.output, { type: 'function_call_output', call_id: 'call-1', output: '{"sources":[]}' }, { role: 'user', content: 'Research is complete.' });
    Object.assign(payload, { tool_choice: 'none', max_output_tokens: 9000 });
    assert.equal(parseDraft(await agent(payload, { timeoutMs: 28000 })).answer, 'Supported answer.');
    assertSonnet55Body(sent[0].body, { maxTokens: 6000, toolChoice: 'auto' });
    assertSonnet55Body(sent[1].body, { maxTokens: 9000, toolChoice: 'none' });
    // Sonnet's own thinking block is replayed unchanged within the run.
    assert.deepEqual(sent[1].body.messages[1].content[0], { type: 'thinking', thinking: '', signature: 'sig-sonnet' });
    for (const { headers } of sent) assert.deepEqual(Object.keys(headers).sort(), ['Authorization', 'Content-Type', 'anthropic-version'], route);
  }
  // Even an override asking for disabled thinking is never sent to Sonnet 5.5.
  const sent = [];
  await createAnthropicBaybay({ config: { ...base, BAYBAY_THINKING_AGENT: 'disabled' }, fetchImpl: capture([answer('claude-sonnet-5-5')], sent) })(agentPayload(baybayModel(base)));
  assert.equal(sent[0].body.thinking, undefined);
});

test('R0 rollback: BAYBAY_MODEL_AGENT=claude-opus-5-5 sends the pre-R0 agent request (Opus 5.5, legacy effort, caller max_tokens)', async () => {
  const sent = [];
  const config = { ...base, BAYBAY_MODEL_AGENT: 'claude-opus-5-5' };
  const agent = createAnthropicBaybay({ config, fetchImpl: capture([answer('claude-opus-5-5')], sent) });
  await agent(agentPayload(baybayModel(config)), { timeoutMs: 25000 });
  const { body, headers } = sent[0];
  assert.deepEqual(Object.keys(body).sort(), ['max_tokens', 'messages', 'model', 'output_config', 'system', 'tool_choice', 'tools']);
  assert.equal(body.model, 'claude-opus-5-5'); assert.equal(body.max_tokens, 6000); assert.deepEqual(Object.keys(body.output_config).sort(), ['effort', 'format']);
  assert.equal(body.output_config.effort, 'medium');
  assert.deepEqual(Object.keys(headers).sort(), ['Authorization', 'Content-Type', 'anthropic-version']);
});

test('a Haiku refusal is retried once on Sonnet 5.5 with the identical request; the run then stays on Sonnet', async () => {
  const sent = [], logs = [];
  const config = { ...base, BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' };
  const toolTurn = model => ({ ...answer(model), stop_reason: 'tool_use', content: [{ type: 'thinking', thinking: '', signature: `sig-${model}` }, { type: 'tool_use', id: 'call-1', name: 'search_site', input: { query: 'museums' } }] });
  const agent = createAnthropicBaybay({ config, log: line => logs.push(line), fetchImpl: capture([refusal('claude-haiku-5-5'), toolTurn('claude-sonnet-5-5'), answer('claude-sonnet-5-5')], sent) });
  const payload = agentPayload(baybayModel(config));
  assert.equal(payload.model, 'claude-haiku-5-5');
  const first = await agent(payload, { timeoutMs: 25000 });
  assert.equal(first.status, 'completed'); assert.equal(first.model, 'claude-sonnet-5-5');
  assert.equal(sent.length, 2);
  assert.equal(sent[0].body.model, 'claude-haiku-5-5'); assert.equal(sent[1].body.model, 'claude-sonnet-5-5');
  const { model: _a, ...haikuRest } = sent[0].body, { model: _b, ...sonnetRest } = sent[1].body;
  assert.deepEqual(sonnetRest, haikuRest, 'only the model changes on the retry');
  assert.equal(sent[1].body.fallbacks, undefined, 'fallbacks stay opt-in on the retry too');
  assert.deepEqual(logs.map(line => JSON.parse(line.replace('[ai-refusal] ', ''))), [{ route: 'baybay_agent', from: 'claude-haiku-5-5', to: 'claude-sonnet-5-5', category: 'general_harms' }]);
  // Next round: the caller still asks for Haiku (its invariant), the adapter keeps Sonnet and replays Sonnet's own blocks.
  payload.input.push(...first.output, { type: 'function_call_output', call_id: 'call-1', output: '{"sources":[]}' });
  const second = await agent(payload, { timeoutMs: 25000 });
  assert.equal(parseDraft(second).answer, 'Supported answer.');
  assert.equal(sent.length, 3); assert.equal(sent[2].body.model, 'claude-sonnet-5-5');
  assert.deepEqual(sent[2].body.messages[1].content[0], { type: 'thinking', thinking: '', signature: 'sig-claude-sonnet-5-5' });
  assert.equal(logs.length, 1);
});

test('a Haiku route with disabled thinking sends it to Haiku and drops it from the Sonnet refusal retry', async () => {
  const sent = [];
  const config = { ...base, BAYBAY_MODEL_AGENT: 'claude-haiku-5-5', BAYBAY_EFFORT_AGENT: 'low', BAYBAY_THINKING_AGENT: 'disabled' };
  const agent = createAnthropicBaybay({ config, log: () => {}, fetchImpl: capture([refusal('claude-haiku-5-5'), answer('claude-sonnet-5-5')], sent) });
  await agent(agentPayload('claude-haiku-5-5'));
  assert.deepEqual(sent[0].body.thinking, { type: 'disabled' }); assert.equal(sent[0].body.output_config.effort, 'low');
  assert.equal(sent[1].body.model, 'claude-sonnet-5-5'); assert.equal(sent[1].body.thinking, undefined);
  for (const field of SAMPLING) assert.equal(sent[1].body[field], undefined);
  const helper = [];
  await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config: { ...base, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5', BAYBAY_THINKING_HELPER_OTHER: 'disabled' }, fetchImpl: capture([answer('claude-haiku-5-5')], helper) });
  assert.deepEqual(helper[0].body.thinking, { type: 'disabled' });
});

test('refusals on Opus or Sonnet, or a second refusal on the retry, are returned as content_filter without further calls', async () => {
  for (const model of ['claude-opus-5-5', 'claude-sonnet-5-5']) {
    const sent = [];
    const agent = createAnthropicBaybay({ config: { ...base, BAYBAY_MODEL_AGENT: model }, log: () => {}, fetchImpl: capture([refusal(model, 'cyber')], sent) });
    const result = await agent(agentPayload(model));
    assert.equal(sent.length, 1); assert.equal(result.status, 'incomplete'); assert.equal(result.incomplete_details.reason, 'content_filter');
  }
  const sent = [];
  const agent = createAnthropicBaybay({ config: { ...base, BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' }, log: () => {}, fetchImpl: capture([refusal('claude-haiku-5-5'), refusal('claude-sonnet-5-5', null)], sent) });
  const result = await agent(agentPayload('claude-haiku-5-5'));
  assert.equal(sent.length, 2); assert.equal(result.status, 'incomplete'); assert.equal(parseDraft(result), null);
});

test('JSON helpers retry a Haiku refusal once on Sonnet and keep their 502 refusal contract otherwise', async () => {
  const messages = [{ role: 'user', content: 'Sample' }];
  const logs = [];
  let sent = [];
  const parsed = await requestAnthropicJson(messages, { config: { ...base, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5' }, route: 'helper_translate', log: line => logs.push(line),
    fetchImpl: capture([refusal('claude-haiku-5-5', 'bio'), answer('claude-sonnet-5-5')], sent) });
  assert.equal(parsed.answer, 'Supported answer.');
  assert.deepEqual(sent.map(item => item.body.model), ['claude-haiku-5-5', 'claude-sonnet-5-5']);
  assert.match(logs[0], /"route":"helper_translate".*"category":"bio"/);
  sent = [];
  await assert.rejects(requestAnthropicJson(messages, { config: { ...base, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5' }, log: () => {},
    fetchImpl: capture([refusal('claude-haiku-5-5'), refusal('claude-sonnet-5-5')], sent) }), { status: 502, code: 'AI_RESPONSE_REFUSED' });
  assert.equal(sent.length, 2);
  sent = [];
  await assert.rejects(requestAnthropicJson(messages, { config: base, fetchImpl: capture([refusal('claude-opus-5-5')], sent) }), { status: 502, code: 'AI_RESPONSE_REFUSED' });
  assert.equal(sent.length, 1);
});

test('an over-cap Haiku prompt is answered by Sonnet 5.5 (sticky for the run) instead of failing or crossing the 100K cliff', async () => {
  const huge = [{ role: 'user', content: '活动'.repeat(40000) }];
  const logs = [];
  let sent = [];
  const parsed = await requestAnthropicJson(huge, { config: { ...base, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5', BAYBAY_THINKING_HELPER_OTHER: 'disabled' }, log: line => logs.push(line),
    fetchImpl: capture([answer('claude-sonnet-5-5')], sent) });
  assert.equal(parsed.answer, 'Supported answer.');
  assert.equal(sent.length, 1); assert.equal(sent[0].body.model, 'claude-sonnet-5-5');
  assert.equal(sent[0].body.thinking, undefined, 'Sonnet never receives disabled thinking');
  assertClaudeBody(sent[0].body, { family: 'sonnet' });
  const line = JSON.parse(logs[0].replace('[ai-prompt-cap] ', ''));
  assert.deepEqual([line.route, line.from, line.to, line.cap], ['helper_other', 'claude-haiku-5-5', 'claude-sonnet-5-5', 60000]);
  assert.ok(line.estimate > 60000); assert.doesNotMatch(logs[0], /活动/);
  // Agent: the over-cap research call goes to Sonnet and the rest of the run stays there,
  // even once a later prompt would fit under the cap again.
  sent = []; logs.length = 0;
  const agent = createAnthropicBaybay({ config: { ...base, BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' }, log: line => logs.push(line),
    fetchImpl: capture([{ ...answer('claude-sonnet-5-5'), stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'call-1', name: 'search_site', input: { query: 'x' } }] }, answer('claude-sonnet-5-5')], sent) });
  const payload = agentPayload('claude-haiku-5-5', { input: huge });
  const first = await agent(payload);
  assert.equal(first.status, 'completed');
  payload.input.push(...first.output, { type: 'function_call_output', call_id: 'call-1', output: '{}' });
  const second = await agent(payload);
  assert.equal(second.status, 'completed');
  assert.deepEqual(sent.map(item => item.body.model), ['claude-sonnet-5-5', 'claude-sonnet-5-5']);
  assert.equal(logs.length, 1); assert.match(logs[0], /^\[ai-prompt-cap\] .*"route":"baybay_agent"/);
  // Under the cap nothing changes: Haiku is called directly and nothing is logged.
  sent = []; logs.length = 0;
  await requestAnthropicJson([{ role: 'user', content: 'Sample' }], { config: { ...base, BAYBAY_MODEL_HELPERS: 'claude-haiku-5-5' }, log: line => logs.push(line), fetchImpl: capture([answer('claude-haiku-5-5')], sent) });
  assert.equal(sent[0].body.model, 'claude-haiku-5-5'); assert.equal(logs.length, 0);
});

test('a non-agent route decides its own model; the agent switch never moves professional answers to Haiku', async () => {
  assert.equal(baybayRoute({ safetyTopic: true }), 'baybay_professional');
  assert.equal(baybayRoute({ safetyTopic: false }), 'baybay_agent'); assert.equal(baybayRoute(), 'baybay_agent');
  const run = async (config, model) => {
    const sent = [];
    const agent = createAnthropicBaybay({ config: { ...base, ...config }, route: 'baybay_professional', log: () => {}, fetchImpl: capture([answer('served')], sent) });
    await agent(agentPayload(model));
    return sent[0].body;
  };
  // baybayAgent sends baybayModel(config, route) on every run; the professional route
  // also accepts the agent route's model and replaces it with its own.
  const r0 = { ...base, BAYBAY_MODEL_AGENT: 'claude-haiku-5-5', BAYBAY_EFFORT_AGENT: 'low' };
  let body = await run(r0, baybayModel(r0));
  assert.equal(body.model, 'claude-sonnet-5-5'); assert.equal(body.output_config.effort, 'low');
  body = await run(base, baybayModel(base, 'baybay_professional'));
  assert.equal(body.model, 'claude-sonnet-5-5'); assert.equal(body.output_config.effort, 'low');
  // Professional rollback: its own variable, effort from the legacy rule.
  const opus = { ...base, BAYBAY_MODEL_PROFESSIONAL: 'claude-opus-5-5' };
  body = await run(opus, baybayModel(opus));
  assert.equal(body.model, 'claude-opus-5-5'); assert.equal(body.output_config.effort, 'medium');
  const sonnetLow = { ...r0, BAYBAY_MODEL_PROFESSIONAL: 'claude-sonnet-5-5', BAYBAY_EFFORT_PROFESSIONAL: 'low' };
  body = await run(sonnetLow, baybayModel(sonnetLow));
  assert.equal(body.model, 'claude-sonnet-5-5'); assert.equal(body.output_config.effort, 'low');
  assert.equal(baybayModel(sonnetLow, 'baybay_professional'), 'claude-sonnet-5-5');
  body = await run(sonnetLow, 'claude-sonnet-5-5');
  assert.equal(body.model, 'claude-sonnet-5-5');
  body = await run(sonnetLow, undefined);
  assert.equal(body.model, 'claude-sonnet-5-5');
  // Any other model is an error, never one route's model mixed with another route's controls.
  const agent = createAnthropicBaybay({ config: { ...sonnetLow, ...base }, route: 'baybay_professional', fetchImpl: async () => assert.fail('no transport') });
  await assert.rejects(agent(agentPayload('claude-opus-4-1')), /must come from the route configuration/);
  // The agent route keeps today's behaviour: the caller's model is sent as given.
  const sent = [];
  await createAnthropicBaybay({ config: base, fetchImpl: capture([answer('fixture')], sent) })(agentPayload('fixture-claude'));
  assert.equal(sent[0].body.model, 'fixture-claude');
});

test('server-side fallback responses replay only the serving model blocks after the last fallback marker', async () => {
  const content = [
    { type: 'thinking', thinking: '', signature: 'declined-model' }, { type: 'text', text: 'Partial ' },
    { type: 'tool_use', id: 'declined-call', name: 'search_site', input: { query: 'x' } },
    { type: 'fallback', from: { model: 'claude-opus-5-5' }, to: { model: 'claude-opus-5' } },
    { type: 'thinking', thinking: '', signature: 'fallback-model' }, { type: 'text', text: 'answer' },
  ];
  assert.deepEqual(replayableContent(content).map(block => block.signature || block.text), ['Partial ', 'fallback-model', 'answer']);
  const plain = [{ type: 'thinking', signature: 'keep' }, { type: 'text', text: 'all' }];
  assert.deepEqual(replayableContent(plain), plain);
  const sent = [];
  const agent = createAnthropicBaybay({ config: { ...base, BAYBAY_FALLBACKS: 'default' }, fetchImpl: capture([{ ...answer('claude-opus-5'), stop_reason: 'tool_use', content: [...content.slice(0, 4), { type: 'tool_use', id: 'served-call', name: 'search_site', input: { query: 'y' } }] }, answer('claude-opus-5')], sent) });
  const payload = agentPayload('claude-opus-5-5');
  const first = await agent(payload);
  // The declining model's tool call before the marker is never executed.
  assert.deepEqual(first.output.map(item => item.call_id).filter(Boolean), ['served-call']);
  payload.input.push(...first.output, { type: 'function_call_output', call_id: 'served-call', output: '{}' });
  await agent(payload);
  assert.equal(sent[0].headers['anthropic-beta'], SERVER_FALLBACK_BETA); assert.equal(sent[0].body.fallbacks, 'default');
  assert.deepEqual(sent[1].body.messages[1].content.map(block => block.type), ['text', 'tool_use']);
  assert.deepEqual(sent[1].body.messages[2].content.map(block => block.tool_use_id), ['served-call']);
});
