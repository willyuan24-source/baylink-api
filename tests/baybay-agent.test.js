const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant, parseDraft, renderCitations } = require('../lib/baybayAgent');
const { createEvidenceStore, createResearchTools, verifiedCandidate } = require('../lib/baybayTools');
const NOW = Date.parse('2026-10-04T19:00:00Z');
const guide = { slug: 'sf-museum', url: '/guides/sf-museum', title: '旧金山博物馆攻略', content: '亲子博物馆\n\n旧金山博物馆安排：SFMOMA 适合看艺术。免费区域须在开放时段进入。', keywords: ['旧金山','博物馆','亲子'], summary: '旧金山博物馆参考', updatedAt: '2026-10-02' };
const final = value => ({ model: 'fixture-reasoner', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify(value) }] }] });
const invoke = (name, args, id = 'call-1') => ({ status: 'completed', model: 'fixture-reasoner', output: [{ type: 'function_call', name, call_id: id, arguments: JSON.stringify(args) }] });
const settings = (extra = {}) => ({ config: { JWT_SECRET: 'private-test-baybay-secret-only' }, guideCatalog: [guide], isTest: true, now: () => NOW, webSearch: async () => ({ answer: 'Official current information.', sources: [{ title: 'Official SFMOMA', url: 'https://www.sfmoma.org/visit/' }], candidates: [{ id: 'museum', name: 'SFMOMA', city: 'San Francisco', sourceUrls: ['https://www.sfmoma.org/visit/'] }], checkedAt: new Date(NOW).toISOString() }), ...extra });

test('shared context includes BOTH site paragraphs and actual web sources before synthesis', async () => {
  let input;
  const assistant = createBayBayAssistant(settings({ ai: async payload => { input = JSON.parse(payload.input[0].content); const refs = input.evidence; return final({ answer: `建议先看站内攻略，再按官网核对。 [[${refs[0].id}]] [[${refs.find(s => s.kind === 'web').id}]]`, candidateIds: [] }); } }));
  const result = await assistant.run({ message: '最新旧金山博物馆安排', locale: 'zh-Hans', searchMode: 'web' });
  assert.ok(input.evidence.some(s => s.kind === 'guide')); assert.ok(input.evidence.some(s => s.kind === 'web'));
  assert.equal(input.webResearch[0].answer, 'Official current information.');
  assert.equal(result.responseMode, 'assistant'); assert.equal(result.retrieval.scope, 'site+web'); assert.equal(result.sources.length, 2);
  assert.ok(result.assistantSessionToken); assert.equal(result.research.model, 'fixture-reasoner');
});

test('a failed additional search does not erase the successful initial web research', async () => {
  let calls = 0, rounds = 0;
  const assistant = createBayBayAssistant(settings({ webSearch: async () => {
    if (calls++) throw new Error('Unavailable supplemental search');
    return { answer: 'The initial web result.', sources: [{ title: 'Official SFMOMA', url: 'https://www.sfmoma.org/visit/' }], candidates: [], checkedAt: new Date(NOW).toISOString() };
  }, ai: async () => rounds++ === 0 ? invoke('search_web', { query: 'SFMOMA extra public information' }) : final({ answer: '保留首轮查到的资料；补查未完成。', candidateIds: [] }) }));
  const result = await assistant.run({ message: '最新旧金山博物馆信息', searchMode: 'web' });
  assert.equal(result.retrieval.scope, 'site+web'); assert.equal(result.retrieval.webStatus, 'completed');
  assert.ok(result.research.warnings.includes('additional_web_lookup_unavailable'));
});

test('short follow-ups retain bounded conversational references alongside signed conditions', async () => {
  let input;
  const assistant = createBayBayAssistant(settings({ ai: async payload => { input = JSON.parse(payload.input[0].content); return final({ answer: '需以该馆官网核实。', candidateIds: [] }); } }));
  await assistant.run({ message: '那里需要预约吗？', history: [{ role: 'user', content: '我想去 SFMOMA' }, { role: 'assistant', content: '你可以先核对 SFMOMA 的参观安排。' }], searchMode: 'site' });
  assert.equal(input.recentConversation.length, 2); assert.match(input.recentConversation[0].content, /SFMOMA/);
});

test('assistant can read evidence, resume tool results, and then answer without losing site context', async () => {
  let count = 0;
  const assistant = createBayBayAssistant(settings({ sourceFetch: async () => ({ text: 'SFMOMA visitor information. Wednesday: Closed. Free public spaces whenever we are open.' }), ai: async payload => {
    if (!count++) { const data = JSON.parse(payload.input[0].content); return invoke('read_source', { sourceId: data.evidence.find(s => s.kind === 'web').id }); }
    const output = payload.input.find(x => x.type === 'function_call_output'); assert.ok(output); const source = JSON.parse(output.output); assert.equal(source.verification, 'page-read');
    return final({ answer: `官网常规时间写明周三闭馆。 [[${source.id}]]`, candidateIds: [] });
  } }));
  const result = await assistant.run({ message: 'SFMOMA平常周三开馆吗', searchMode: 'web' });
  assert.equal(count, 2); assert.ok(result.research.steps.some(x => x.tool === 'read_source' && x.status === 'completed'));
  assert.match(result.answer, /周三闭馆/); assert.equal(result.sources[0].url, 'https://www.sfmoma.org/visit');
});

test('site-only prohibits web and page/weather tools even if the model requests them', async () => {
  let external = 0, count = 0;
  const assistant = createBayBayAssistant(settings({ webSearch: async () => { external++; }, sourceFetch: async () => { external++; }, ai: async p => count++ === 0 ? invoke('search_web', { query: 'SFMOMA' }) : final({ answer: '仅参考站内资料。', candidateIds: [] }) }));
  const result = await assistant.run({ message: '旧金山博物馆攻略', searchMode: 'site' });
  assert.equal(external, 0); assert.equal(result.retrieval.webStatus, 'not_requested');
});

test('signed state survives beyond four history turns and clear/reset are authoritative', async () => {
  const assistant = createBayBayAssistant(settings());
  let result = await assistant.run({ message: '周六从Fremont出发，两大一小，孩子6岁，全家预算100美元，安排一天', searchMode: 'site' });
  for (let i = 0; i < 6; i++) result = await assistant.run({ message: '请继续考虑这些条件', searchMode: 'site', sessionToken: result.assistantSessionToken });
  assert.equal(result.taskState.origin, 'Fremont'); assert.equal(result.taskState.partySize, 3); assert.equal(result.taskState.budget, 100);
  const changed = await assistant.run({ message: '预算不限', searchMode: 'site', sessionToken: result.assistantSessionToken });
  assert.equal(changed.taskState.budget, null);
  const cleared = await assistant.run({ message: '重新开始', searchMode: 'site', sessionToken: changed.assistantSessionToken });
  assert.equal(cleared.taskState.origin, null);
  await assert.rejects(assistant.run({ message: '明天呢', sessionToken: result.assistantSessionToken + 'x' }), e => e.code === 'INVALID_ASSISTANT_SESSION');
});

test('model failures keep grounded site material and explicitly degrade', async () => {
  const assistant = createBayBayAssistant(settings({ ai: async () => { throw new Error('unavailable'); } }));
  const result = await assistant.run({ message: '旧金山博物馆攻略', searchMode: 'site' });
  assert.equal(result.degraded, true); assert.ok(result.evidence.length); assert.match(result.answer, /站内资料/);
});

test('unbounded model tool loops stop at the configured limit', async () => {
  let count = 0;
  const assistant = createBayBayAssistant(settings({ config: { JWT_SECRET: 'private-test-baybay-secret-only', BAYBAY_MAX_MODEL_ROUNDS: 2 }, ai: async () => { count++; return invoke('search_site', { query: '博物馆' }, `call-${count}`); } }));
  await assistant.run({ message: '旧金山博物馆攻略', searchMode: 'site' }); assert.equal(count, 2);
});

test('unknown model citations and handwritten external URLs never become clickable sources', () => {
  const store = createEvidenceStore({ sources: [{ title: 'A', url: 'https://www.sfmoma.org/visit/' }] });
  const source = [...store.sources.values()][0];
  const r = renderCitations(`source [[${source.id}]] fake [[made-up]] [8] https://evil.invalid/a`, store);
  assert.equal(r.sources.length, 1); assert.doesNotMatch(r.answer, /made-up|evil|\[8\]/); assert.match(r.answer, /\[1\]/);
  assert.equal(parseDraft({ status: 'incomplete', output: [] })?.answer, undefined);
});

test('web candidates require exact own-page quotations; mere source links are insufficient', () => {
  const candidate = { id: 'web-one', title: 'Art Day', city: 'San Francisco', kind: 'event', origin: 'web', sourceIds: ['s-one'] };
  const source = { id: 's-one', text: 'Art Day in San Francisco on October 10, 2026. Admission $20. Event full.', verification: 'page-read', checkedAt: new Date(NOW).toISOString() };
  assert.ok(verifiedCandidate({ candidate, source: { ...source, verification: 'search-result' }, proofs: {}, state: {}, today: '2026-10-04' }).error);
  const row = verifiedCandidate({ candidate, source, kind: 'event', proofs: { name: 'Art Day', city: 'San Francisco', date: 'October 10, 2026', admission: 'Admission $20', closed: 'Event full' }, state: { date: '2026-10-10' }, today: '2026-10-04' });
  assert.equal(row.verification, 'page-verified'); assert.equal(row.availability, 'unavailable'); assert.deepEqual(row.occurrenceDates, ['2026-10-10']);
  const forged = verifiedCandidate({ candidate, source, proofs: { name: 'Art Day', city: 'San Francisco', date: 'October 11, 2026', admission: 'Free admission' }, state: {}, today: '2026-10-04' });
  assert.equal(forged.verifiedFacts.admission, undefined); assert.equal(forged.verifiedFacts.date, undefined);
});

test('source reader cannot fetch a model-supplied arbitrary URL', async () => {
  let calls = 0;
  const tools = createResearchTools({ store: createEvidenceStore(), state: {}, today: '2026-10-04', locale: 'en', searchMode: 'web', isTest: true, sourceFetch: async () => { calls++; }, deadline: Date.now() + 1000 });
  assert.ok((await tools.readSource('https://127.0.0.1/private')).error); assert.equal(calls, 0);
});

test('an empty computed plan never falls back to recommending the rejected web event', async () => {
  let round = 0;
  const assistant = createBayBayAssistant(settings({
    catalog: { version: 1, checkedAt: '2026-10-04', events: [], places: [], guides: [] },
    webSearch: async () => ({ answer: 'A lead only.', sources: [{ title: 'Official event', url: 'https://example.org/art-day' }], candidates: [{ name: 'Art Day', city: 'San Francisco', sourceUrls: ['https://example.org/art-day'] }], checkedAt: new Date(NOW).toISOString() }),
    sourceFetch: async () => ({ text: 'Art Day in San Francisco on October 10, 2026. Admission $20. Event full.' }),
    ai: async payload => {
      const context = JSON.parse(payload.input[0].content), c = context.candidates.find(c => c.origin === 'web');
      if (round++ === 0) return invoke('read_source', { sourceId: c.sourceIds[0] });
      if (round === 2) return invoke('verify_candidate', { candidateId: c.id, sourceId: c.sourceIds[0], kind: 'event', proofs: { name: 'Art Day', city: 'San Francisco', date: 'October 10, 2026', closed: 'Event full' } }, 'verify');
      if (round === 3) return invoke('create_plan', { candidateIds: [c.id] }, 'plan');
      throw new Error('Model unavailable during final answer');
    },
  }));
  const result = await assistant.run({ message: '2026-10-10 San Francisco 帮我安排一天', searchMode: 'web' });
  assert.deepEqual(result.assistantPlan.stops, []);
  assert.equal(result.degraded, true);
  assert.doesNotMatch(result.answer, /Art Day/);
  assert.match(result.answer, /不能组成/);
});

test('a named catalog origin reaches route tools with precise coordinates and is not an itinerary stop', async () => {
  let round = 0, routeInput;
  const place = (id, title, lat, lng) => ({ id, title, city: 'San Jose', region: 'south-bay', officialUrl: `https://example.org/${id}`, location: { precision: 'venue', lat, lng }, cost: 'free' });
  const assistant = createBayBayAssistant(settings({
    catalog: { version: 1, checkedAt: '2026-10-04', events: [], places: [place('start', 'The Tech Interactive', 37.3316, -121.89), place('finish', 'Family Park', 37.33, -121.87)], guides: [] },
    webSearch: async () => ({ answer: 'No new leads.', sources: [], candidates: [], checkedAt: new Date(NOW).toISOString() }),
    routeCompute: async input => { routeInput = input; return { routes: [{ duration: '1200s', distanceMeters: 2000 }] }; },
    ai: async payload => {
      if (round++ === 0) {
        const context = JSON.parse(payload.input[0].content);
        assert.equal(context.candidates.find(c => c.id === 'origin').location.lat, 37.3316);
        return invoke('get_route', { fromId: 'origin', toId: 'finish', time: '09:00' });
      }
      return final({ answer: '先以公园为候选，开放情况还需核对。', candidateIds: ['finish'] });
    },
  }));
  const result = await assistant.run({ message: '2026-10-10 从 The Tech Interactive 出发，San Jose 开车，9点开始，安排一天', searchMode: 'web' });
  assert.equal(routeInput.from.id, 'origin'); assert.equal(routeInput.to.id, 'finish');
  assert.equal(result.taskState.originCandidateId, 'start');
  assert.ok(result.assistantPlan.stops.every(s => s.entityId !== 'origin'));
  assert.ok(result.research.steps.some(s => s.tool === 'get_route' && s.status === 'completed'));
});

test('a signed follow-up replacing one stop preserves the other stops and rejects an invalid stop index', async () => {
  const catalog = { version: 1, checkedAt: '2026-10-04', events: [], guides: [], places: ['a', 'b', 'c', 'd'].map(id => ({ id, title: `Public Park ${id}`, city: 'San Jose', region: 'south-bay', officialUrl: `https://example.org/${id}`, cost: 'free' })) };
  const assistant = createBayBayAssistant(settings({ catalog, ai: async payload => {
    const data = JSON.parse(payload.input[0].content);
    return final({ answer: '已保留其他站点，具体时间还需核实。', candidateIds: /换掉/.test(data.message) ? ['d'] : ['a', 'b', 'c'] });
  } }));
  const first = await assistant.run({ message: '2026-10-10 San Jose 安排一天', searchMode: 'site' });
  assert.deepEqual(first.assistantPlan.stops.map(s => s.entityId), ['a', 'b', 'c']);
  const second = await assistant.run({ message: '换掉第二站', searchMode: 'site', sessionToken: first.assistantSessionToken });
  assert.deepEqual(second.assistantPlan.stops.map(s => s.entityId), ['a', 'd', 'c']);
  const invalid = await assistant.run({ message: '换掉第六站', searchMode: 'site', sessionToken: second.assistantSessionToken });
  assert.equal(invalid.assistantPlan, undefined); assert.match(invalid.answer, /指定上一份行程/);
});
