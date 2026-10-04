const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant, parseDraft } = require('../lib/baybayAgent');
const { resolveTaskSecret, encodeTaskToken, decodeTaskToken } = require('../lib/baybayState');
const jwt = require('jsonwebtoken');

const NOW = Date.parse('2026-10-04T19:00:00Z');
const config = { JWT_SECRET: 'private-recovery-test-key' };
const answer = value => ({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: value, candidateIds: [], followups: [] }) }] }] });
const call = (name, args, id = name) => ({ status: 'completed', output: [{ type: 'function_call', name, call_id: id, arguments: JSON.stringify(args) }] });
const options = extra => ({ config, isTest: true, now: () => NOW, ...extra });
const precisePrompt = '2026-10-10 从 The Tech Interactive 出发，早上9点开车，两位成人，想去 San Jose 的 King Library 和 San José Museum of Art，17点前回出发点，总预算100美元。请安排并核算车程。';

test('dedicated task secret enables signed follow-ups without changing account authentication', async () => {
  const dedicated = 'a-separate-random-test-task-signing-key';
  const authConfig = { JWT_SECRET: 'legacy-auth', BAYBAY_STATE_SECRET: dedicated };
  const authToken = jwt.sign({ id: 'fixture-account' }, authConfig.JWT_SECRET, { algorithm: 'HS256' });
  const assistant = createBayBayAssistant(options({ config: authConfig, ai: async () => answer('已按你提供的条件核对。') }));
  assert.equal(assistant.capabilities().taskMemory, true);
  assert.doesNotMatch(JSON.stringify(assistant.capabilities()), /legacy-auth|random-test-task-signing/);
  const first = await assistant.run({ message: precisePrompt, searchMode: 'site' });
  assert.ok(first.assistantSessionToken);
  assert.equal(decodeTaskToken(first.assistantSessionToken, { secret: dedicated, now: NOW }).state.origin, 'The Tech Interactive');
  assert.equal(decodeTaskToken(first.assistantSessionToken, { secret: 'a-different-valid-auth-key', now: NOW }), null);
  assert.equal(first.research.warnings.includes('task_memory_unavailable'), false);
  const second = await assistant.run({ message: '检查这份安排费用', searchMode: 'site', sessionToken: first.assistantSessionToken });
  assert.deepEqual(second.assistantPlan.stops.map(stop => stop.entityId), ['venue-sj-king-library', 'venue-sjma']);
  assert.equal(jwt.verify(authToken, authConfig.JWT_SECRET, { algorithms: ['HS256'] }).id, 'fixture-account');
  assert.equal(authConfig.JWT_SECRET, 'legacy-auth');
});

test('task memory preserves strong JWT compatibility but never accepts a weak key or silently omits its warning', async () => {
  assert.equal(resolveTaskSecret({ BAYBAY_STATE_SECRET: 'dedicated-test-secret-long', JWT_SECRET: config.JWT_SECRET }), 'dedicated-test-secret-long');
  assert.equal(resolveTaskSecret(config), config.JWT_SECRET);
  assert.equal(resolveTaskSecret({ BAYBAY_STATE_SECRET: 'short', JWT_SECRET: config.JWT_SECRET }), config.JWT_SECRET);
  assert.equal(resolveTaskSecret({ BAYBAY_STATE_SECRET: 'short', JWT_SECRET: 'tiny' }), null);
  assert.equal(encodeTaskToken({ state: {} }, { secret: null, now: NOW }), null, 'an explicitly disabled key cannot fall back to another environment key');
  for (const unusable of [{}, { JWT_SECRET: 'short' }, { BAYBAY_STATE_SECRET: 'tiny', JWT_SECRET: 'short' }]) {
    const assistant = createBayBayAssistant(options({ config: unusable, ai: async () => answer('这轮只核对当前资料。') }));
    assert.equal(assistant.capabilities().taskMemory, false);
    const result = await assistant.run({ message: 'San Jose 博物馆资料', searchMode: 'site' });
    assert.equal(result.assistantSessionToken, null); assert.equal(result.degraded, false);
    assert.ok(result.research.warnings.includes('task_memory_unavailable'));
  }
});

test('max-token incomplete output is usable only when the entire final JSON is complete', () => {
  const complete = { ...answer('只说明已有事实。'), status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } };
  assert.equal(parseDraft(complete).answer, '只说明已有事实。');
  const truncated = structuredClone(complete);
  truncated.output[0].content[0].text = '{"answer":"这个不完整';
  assert.equal(parseDraft(truncated), null);
  assert.equal(parseDraft({ ...complete, incomplete_details: { reason: 'content_filter' } }), null);
  assert.equal(parseDraft({ ...complete, status: 'failed' }), null);
});

test('reasoning-only and truncated final outputs recover once with compact grounded context and no tools', async () => {
  for (const broken of [
    { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, output: [{ type: 'reasoning', encrypted_content: 'private-thought-cipher' }], usage: { output_tokens: 2400, output_tokens_details: { reasoning_tokens: 2400 } } },
    { status: 'completed', output: [{ type: 'reasoning' }] },
    { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '{"answer":"Do not leak this broken draft' }] }] },
  ]) {
    const payloads = [];
    const assistant = createBayBayAssistant(options({ config: { ...config, BAYBAY_MAX_MODEL_ROUNDS: 1 }, ai: async payload => {
      payloads.push(structuredClone(payload));
      if (payloads.length === 1) return broken;
      assert.equal(payload.model, 'gpt-4.1-mini'); assert.deepEqual(payload.tools, []); assert.equal(payload.reasoning, undefined);
      assert.equal(payload.text.format.type, 'json_schema'); assert.equal(payload.input.length, 1);
      assert.doesNotMatch(JSON.stringify(payload.input), /private-thought-cipher|Do not leak this broken draft/);
      const context = JSON.parse(payload.input[0].content); assert.ok(context.evidence.length);
      return answer('现有收录可作参考，尚未核实的条件不能保证。');
    } }));
    const result = await assistant.run({ message: 'San Jose 博物馆资料', searchMode: 'site' });
    assert.equal(payloads.length, 2); assert.equal(result.degraded, false);
    assert.ok(result.research.warnings.includes('final_synthesis_recovered'));
    assert.equal(result.research.modelResponses.length, 2);
    assert.equal(result.research.modelResponses[0].status, broken.status);
    assert.equal(result.research.modelResponses[1].phase, 'recovery');
    assert.doesNotMatch(JSON.stringify(result.research.modelResponses), /private-thought-cipher|broken draft|博物馆资料/);
  }
});

test('failed final recovery stays bounded and content filtering is never bypassed', async () => {
  for (const reason of ['max_output_tokens', 'content_filter']) {
    let calls = 0;
    const assistant = createBayBayAssistant(options({ ai: async () => { calls++; return { status: 'incomplete', incomplete_details: { reason }, output: [] }; } }));
    const result = await assistant.run({ message: 'San Jose 博物馆资料', searchMode: 'site' });
    assert.equal(calls, reason === 'content_filter' ? 1 : 2); assert.equal(result.degraded, true);
    assert.ok(result.research.warnings.includes(`model_response_incomplete_${reason}`));
  }
});

test('research deadline forces a final synthesis call before the overall request expires', async t => {
  const start = Date.now(); let elapsed = 0, rounds = 0;
  t.mock.method(Date, 'now', () => start + elapsed);
  const assistant = createBayBayAssistant(options({ ai: async payload => {
    if (++rounds === 1) { elapsed = 59000; return call('search_site', { query: 'San Jose' }); }
    assert.deepEqual(payload.tools, []); assert.match(payload.instructions, /Research is complete/);
    return answer('现有资料可作参考，最新开放情况需核实。');
  } }));
  const result = await assistant.run({ message: 'San Jose 博物馆资料', searchMode: 'site' });
  assert.equal(rounds, 2); assert.equal(result.degraded, false);
  assert.equal(result.research.modelResponses[1].phase, 'final');
});

test('the actual natural trip prompt seeds exactly its named stops and all three precise route legs before synthesis', async () => {
  const routeCalls = []; let webCalls = 0, initial;
  const assistant = createBayBayAssistant(options({
    webSearch: async () => { webCalls++; throw new Error('Broad discovery should not run for named venues.'); },
    routeCompute: async input => { routeCalls.push({ from: input.from.id, to: input.to.id }); return { routes: [{ duration: '600s', distanceMeters: 1000 }] }; },
    ai: async payload => { initial = JSON.parse(payload.input[0].content); return { ...answer('已按指定两站整理；临时闭馆和额外费用仍需核实。'), output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '已按指定两站整理；临时闭馆和额外费用仍需核实。', candidateIds: ['rosicrucian'], followups: [] }) }] }] }; },
  }));
  const result = await assistant.run({ message: precisePrompt, searchMode: 'smart' });
  assert.equal(webCalls, 0);
  assert.deepEqual(result.taskState.selectedCandidateIds, ['venue-sj-king-library', 'venue-sjma']);
  assert.equal(result.taskState.originCandidateId, 'san-jose');
  assert.equal(result.taskState.startTime, '09:00'); assert.equal(result.taskState.finishBy, '17:00');
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['venue-sj-king-library', 'venue-sjma']);
  assert.deepEqual(routeCalls, [{ from: 'origin', to: 'venue-sj-king-library' }, { from: 'venue-sj-king-library', to: 'venue-sjma' }, { from: 'venue-sjma', to: 'origin' }]);
  assert.equal(initial.currentPlan.travelLegs.length, 3); assert.equal(initial.routeEvidence.length, 3);
  assert.ok(initial.currentPlan.returnTime); assert.ok(result.assistantPlan.returnTime);
});

test('a generic signed follow-up cannot replace the established stops with unsolicited model suggestions', async () => {
  let count = 0;
  const assistant = createBayBayAssistant(options({ ai: async () => ({ ...answer('相关费用仍需核实。'), output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: '相关费用仍需核实。', candidateIds: count++ ? ['rosicrucian'] : ['venue-sj-king-library', 'venue-sjma'], followups: [] }) }] }] }) }));
  const first = await assistant.run({ message: precisePrompt, searchMode: 'site' });
  const second = await assistant.run({ message: '检查这份安排费用', searchMode: 'site', sessionToken: first.assistantSessionToken });
  assert.deepEqual(second.assistantPlan.stops.map(stop => stop.entityId), ['venue-sj-king-library', 'venue-sjma']);
});

test('verified closure refreshes a preseeded plan before direct final answer and page reads count as web evidence', async () => {
  let round = 0, museum;
  const place = (id, title) => ({ id, title, city: 'San Jose', region: 'south-bay', officialUrl: `https://example.org/${id}`, cost: 'free', location: { precision: 'venue', lat: 37.33, lng: -121.89 } });
  const assistant = createBayBayAssistant(options({
    catalog: { version: 1, checkedAt: '2026-10-04', events: [], guides: [], places: [place('library', 'King Library'), place('museum', 'Art Museum')] },
    sourceFetch: async () => ({ text: 'Art Museum in San Jose. Art Museum is a museum. Permanently closed.' }),
    webSearch: async () => { throw new Error('No broad discovery expected.'); },
    ai: async payload => {
      if (round++ === 0) {
        const context = JSON.parse(payload.input[0].content); museum = context.candidates.find(c => c.id === 'museum');
        assert.equal(context.currentPlan.stops.length, 2);
        return call('read_source', { sourceId: museum.sourceIds[0] });
      }
      if (round === 2) return call('verify_candidate', { candidateId: museum.id, sourceId: museum.sourceIds[0], kind: 'place', proofs: { name: 'Art Museum', city: 'San Jose', venue: 'Art Museum is a museum', closed: 'Permanently closed' } });
      return answer('已排除官网写明关闭的博物馆，保留图书馆候选。');
    },
  }));
  const result = await assistant.run({ message: '2026-10-10 San Jose 安排一天，想去 King Library 和 Art Museum', searchMode: 'smart' });
  assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['library']);
  assert.equal(result.retrieval.scope, 'site+web'); assert.equal(result.retrieval.webStatus, 'completed');
});
