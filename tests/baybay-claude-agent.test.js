const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');

const NOW = Date.parse('2026-10-04T19:00:00Z');
const config = { JWT_SECRET: 'private-test-task-secret', BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', OPENAI_API_KEY: 'fixture-openai-must-not-be-used' };
const guide = { slug: 'sf-library', url: '/guides/sf-library', title: 'San Francisco library card', content: 'San Francisco library cards require eligibility checks. Use the official library information for current rules.', keywords: ['San Francisco', 'library'], summary: 'Library card reference', updatedAt: '2026-10-02' };
const options = extra => ({ config, guideCatalog: [guide], now: () => NOW, isTest: false, Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) }, ...extra });
const raw = (content, stop_reason = 'end_turn') => ({ type: 'message', id: 'msg-fixture', model: 'claude-opus-5-5', role: 'assistant', stop_reason, content, usage: { input_tokens: 20, output_tokens: 100, output_tokens_details: { thinking_tokens: 70 } } });
const final = answer => raw([{ type: 'text', text: JSON.stringify({ answer, candidateIds: [], followups: [], coverage: [] }) }]);
const toolResponse = (id, name, input) => raw([{ type: 'thinking', thinking: '', signature: `signed-${id}` }, { type: 'tool_use', id, name, input }], 'tool_use');
const reply = value => ({ ok: true, json: async () => value });
const request = { message: 'San Francisco library card information', locale: 'en', searchMode: 'site' };

test('Claude site research preserves signed tool context through final synthesis and never advertises external tools', async () => {
  const sent = [];
  const assistant = createBayBayAssistant(options({ fetchImpl: async (url, init) => {
    assert.equal(url, 'https://api.anthropic.com/v1/messages');
    const body = JSON.parse(init.body); sent.push(body);
    // R0 default route: Claude Sonnet 5.5 at effort low.
    assert.equal(body.model, 'claude-sonnet-5-5'); assert.equal(body.output_config.effort, 'low');
    assert.ok(body.tools.every(tool => ['search_site', 'create_plan'].includes(tool.name)));
    return reply(sent.length === 1 ? toolResponse('call-site', 'search_site', { query: 'San Francisco library card' }) : final('Use the recorded library reference and verify current eligibility.'));
  } }));
  const result = await assistant.run(request);
  assert.equal(sent.length, 2); assert.equal(result.degraded, false);
  assert.equal(assistant.capabilities().configuredProvider, 'anthropic');
  assert.equal(assistant.capabilities().configuredModel, 'claude-sonnet-5-5');
  assert.equal(sent[1].system, sent[0].system); assert.deepEqual(sent[1].tools, sent[0].tools);
  assert.deepEqual(sent[1].tool_choice, { type: 'none' });
  assert.equal(sent[1].messages[1].content[0].signature, 'signed-call-site');
  assert.equal(sent[1].messages[2].content[0].type, 'tool_result');
  assert.match(sent[1].messages.at(-1).content[0].text, /Research is complete/);
  assert.equal(result.research.usage.outputTokens, 200);
  assert.equal(result.research.modelResponses[0].reasoningTokens, 70);
  assert.doesNotMatch(JSON.stringify(result), /signed-call-site|fixture-anthropic|fixture-openai/);
});

test('Claude token-limit output recovers on the same model without accepting a valid-looking truncated answer', async () => {
  const sent = [];
  const assistant = createBayBayAssistant(options({ config: { ...config, BAYBAY_MAX_MODEL_ROUNDS: 1 }, fetchImpl: async (url, init) => {
    assert.equal(url, 'https://api.anthropic.com/v1/messages'); sent.push(JSON.parse(init.body));
    return reply(sent.length === 1 ? { ...final('UNSAFE TRUNCATED ANSWER'), stop_reason: 'max_tokens' } : final('Recovered from current library evidence.'));
  } }));
  const result = await assistant.run(request);
  assert.equal(sent.length, 2); assert.equal(result.degraded, false);
  assert.ok(sent.every(body => body.model === 'claude-sonnet-5-5'));
  assert.ok(result.research.warnings.includes('model_response_incomplete_max_output_tokens'));
  assert.ok(result.research.warnings.includes('final_synthesis_recovered'));
  assert.doesNotMatch(JSON.stringify(result), /UNSAFE TRUNCATED/);
  assert.doesNotMatch(JSON.stringify(sent[1].messages), /UNSAFE TRUNCATED/);
});

test('Claude refusal stops after one request and never bypasses filtering through OpenAI', async () => {
  let calls = 0;
  const assistant = createBayBayAssistant(options({ fetchImpl: async url => {
    assert.equal(url, 'https://api.anthropic.com/v1/messages'); calls++;
    return reply({ ...final('Do not expose this'), stop_reason: 'refusal' });
  } }));
  const result = await assistant.run(request);
  assert.equal(calls, 1); assert.equal(result.degraded, true);
  assert.ok(result.research.warnings.includes('model_response_incomplete_content_filter'));
  assert.doesNotMatch(result.answer, /Do not expose this/);
});

test('Claude provider failures stay bounded and never use configured OpenAI fallback credentials', async () => {
  for (const status of [400, 401, 403, 429, 500]) {
    const urls = [];
    const assistant = createBayBayAssistant(options({ fetchImpl: async url => { urls.push(url); return { ok: false, status }; } }));
    const result = await assistant.run(request);
    assert.ok(urls.length >= 1 && urls.length <= 2);
    assert.ok(urls.every(url => url === 'https://api.anthropic.com/v1/messages'));
    assert.equal(result.degraded, true); assert.ok(result.research.warnings.includes('model_unavailable'));
  }
});

test('missing selected-provider key and unknown provider fail closed despite an OpenAI key', async () => {
  for (const override of [{ ANTHROPIC_API_KEY: '' }, { BAYBAY_AI_PROVIDER: 'unknown-provider' }, { ANTHROPIC_USE_UNTIL: '2000-01-01T00:00:00Z' }, { ANTHROPIC_USE_UNTIL: 'invalid-date' }]) {
    let calls = 0;
    const assistant = createBayBayAssistant(options({ config: { ...config, ...override }, fetchImpl: async () => { calls++; throw new Error('Must not fetch'); } }));
    const result = await assistant.run(request);
    assert.equal(calls, 0); assert.equal(result.degraded, true);
    assert.ok(result.research.warnings.includes('model_unavailable_or_capacity'));
  }
});

test('Claude run transcripts stay isolated when an assistant instance serves concurrent requests', async () => {
  const contexts = [];
  const assistant = createBayBayAssistant(options({ fetchImpl: async (_url, init) => {
    const body = JSON.parse(init.body); contexts.push(body.messages);
    return reply(final('Use the recorded library reference.'));
  } }));
  await Promise.all([assistant.run(request), assistant.run({ ...request, message: 'San Francisco library card second question' })]);
  assert.equal(contexts.length, 2);
  assert.ok(contexts.every(messages => messages.length === 1));
  assert.notEqual(contexts[0][0].content[0].text, contexts[1][0].content[0].text);
});

test('exhausted research tools remain declared for thinking replay while synthesis disables their use', async () => {
  const sent = []; let sourceId;
  const assistant = createBayBayAssistant(options({
    sourceFetch: async () => ({ text: 'Official library card eligibility. Check current rules with the library.' }),
    webSearch: async () => ({ answer: 'Official library information.', sources: [{ title: 'Library', url: 'https://www.sfpl.org/' }], candidates: [] }),
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body); sent.push(body);
      sourceId ||= JSON.parse(body.messages[0].content[0].text).evidence[0].id;
      return reply(sent.length <= 3 ? toolResponse(`read-${sent.length}`, 'read_source', { sourceId }) : final('Use the current official library eligibility rules.'));
    },
  }));
  const result = await assistant.run({ ...request, searchMode: 'smart' });
  assert.equal(sent.length, 4); assert.equal(result.degraded, false);
  assert.ok(sent[0].tools.some(tool => tool.name === 'read_source'));
  assert.deepEqual(sent[3].tools, sent[0].tools);
  assert.equal(sent[3].tool_choice.type, 'none');
  for (let index = 1; index < sent.length; index++) assert.deepEqual(sent[index].messages.slice(0, sent[index - 1].messages.length), sent[index - 1].messages);
  assert.equal(result.research.steps.filter(step => step.tool === 'read_source').length, 3);
});

test('itinerary citation repair appends its directive without changing the system or prior signed final content', async () => {
  const sent = [];
  const assistant = createBayBayAssistant(options({ fetchImpl: async (_url, init) => {
    const body = JSON.parse(init.body); sent.push(body);
    if (sent.length === 1) return reply({ ...final('The two chosen stops are in the plan.'), content: [{ type: 'thinking', thinking: '', signature: 'signed-final' }, ...final('The two chosen stops are in the plan.').content] });
    const context = body.messages.filter(message => message.role === 'user').flatMap(message => message.content).filter(block => block.type === 'text').map(block => { try { return JSON.parse(block.text); } catch { return null; } }).filter(value => value?.currentPlan).at(-1);
    const source = context.currentPlan.stops[0].sourceIds[0];
    return reply(final(`The two chosen stops are retained in the plan. [[${source}]]`));
  } }));
  const result = await assistant.run({ message: '2026-10-10 San Jose 安排一天，想去 King Library 和 San José Museum of Art', searchMode: 'site' });
  assert.equal(sent.length, 2);
  assert.ok(result.research.warnings.includes('answer_plan_citation_retry'));
  assert.equal(sent[1].system, sent[0].system);
  assert.deepEqual(sent[1].messages.slice(0, sent[0].messages.length), sent[0].messages);
  assert.equal(sent[1].messages[sent[0].messages.length].content[0].signature, 'signed-final');
  assert.match(sent[1].messages.at(-1).content[0].text, /previous final answer did not cite/);
  assert.doesNotMatch(JSON.stringify(result), /signed-final/);
});

test('the expiry guard also blocks an injected provider callback', async () => {
  let calls = 0;
  const assistant = createBayBayAssistant(options({ config: { ...config, ANTHROPIC_USE_UNTIL: '2000-01-01T00:00:00Z' }, ai: async () => { calls++; return {}; } }));
  const result = await assistant.run(request);
  assert.equal(calls, 0); assert.equal(result.degraded, true);
});

test('R0 routing: an ordinary run uses baybay_agent, a professional topic uses baybay_professional (never Haiku), and env overrides roll either back', async () => {
  const medicareGuide = { slug: 'bay-area-medicare-hicap-medi-cal-guide', url: '/guides/bay-area-medicare-hicap-medi-cal-guide', title: 'Medicare 与 HICAP 咨询准备', content: 'HICAP 提供免费 Medicare 咨询，电话 1-800-434-0222。', keywords: ['Medicare', 'HICAP'], summary: 'Medicare 咨询', updatedAt: '2026-10-02' };
  const ask = async (extra, message) => {
    const sent = [];
    const assistant = createBayBayAssistant(options({ config: { ...config, ...extra }, guideCatalog: [guide, medicareGuide], fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body); sent.push(body);
      return reply(final('Part A 是住院保险，Part B 是门诊和医生；多数人两部分都有，个人选择请找 HICAP。'));
    } }));
    const result = await assistant.run({ message, locale: 'zh-Hans', searchMode: 'site' });
    return { sent, result };
  };
  const medicare = 'Medicare A 部分和 B 部分有什么区别？我该选哪个？';
  // Defaults: both routes on Sonnet 5.5 low.
  let run = await ask({}, medicare);
  assert.equal(run.result.safetyRoute, 'professional');
  assert.ok(run.sent.length >= 1 && run.sent.every(body => body.model === 'claude-sonnet-5-5' && body.output_config.effort === 'low'));
  assert.match(run.sent[0].system, /Professional-topic guard \(medicare\)/);
  // A Haiku agent switch moves ordinary questions only; professional answers stay on Sonnet (RC-20).
  run = await ask({ BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' }, medicare);
  assert.ok(run.sent.every(body => body.model === 'claude-sonnet-5-5'), 'professional answers never run on Haiku');
  run = await ask({ BAYBAY_MODEL_AGENT: 'claude-haiku-5-5' }, 'San Francisco library card information');
  assert.ok(run.sent.every(body => body.model === 'claude-haiku-5-5'));
  assert.equal(run.result.safetyRoute, undefined);
  // Rollback variables restore Opus with the legacy effort.
  run = await ask({ BAYBAY_MODEL_AGENT: 'claude-opus-5-5', BAYBAY_MODEL_PROFESSIONAL: 'claude-opus-5-5' }, medicare);
  assert.ok(run.sent.every(body => body.model === 'claude-opus-5-5' && body.output_config.effort === 'medium'));
  run = await ask({ BAYBAY_MODEL_AGENT: 'claude-opus-5-5' }, 'San Francisco library card information');
  assert.ok(run.sent.every(body => body.model === 'claude-opus-5-5' && body.output_config.effort === 'medium'));
  assert.equal(run.result.retrieval.configuredModel, 'claude-opus-5-5');
});
