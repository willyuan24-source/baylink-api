const test = require('node:test');
const assert = require('node:assert/strict');
const { createPublicContext } = require('../lib/publicContext');
const { namedEntities, dateRangeFor } = require('../lib/entityAliases');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { resolveTaskState } = require('../lib/baybayState');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createBayBayProgressStream } = require('../lib/baybayProgress');
const { EventEmitter } = require('node:events');
const TODAY = '2026-10-05', NOW = Date.parse('2026-10-05T19:00:00Z');
const event = { id: 'fleet-week', title: 'San Francisco Fleet Week 2026', aliases: ['舰队周', '艦隊週', '蓝天使'], region: 'sf', city: 'San Francisco', startDate: '2026-10-09', endDate: '2026-10-11', occurrenceDates: ['2026-10-09', '2026-10-11'], officialUrl: 'https://fixture.example/events/fleet-week', summary: 'Published viewing program. Confirm fees and sessions with the organizer.', cost: 'free', audience: [], plan: [] };
const catalog = { version: 1, checkedAt: TODAY, events: [event], places: [], guides: [] };
const final = value => ({ model: 'fixture-only', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify(value) }] }] });

test('aliases resolve catalog identities but a date mismatch remains explicit excluded evidence', () => {
  assert.equal(namedEntities('蓝天使这个周末有吗', catalog)[0].row.id, event.id);
  const evidence = buildSiteEvidence({ query: '舰队周 2026-10-10', state: { city: 'San Francisco', date: '2026-10-10', goal: 'discover' }, today: TODAY, catalog });
  assert.equal(evidence.candidates.length, 0);
  assert.equal(evidence.nearMiss[0].reason, 'date_mismatch');
  assert.deepEqual(evidence.nearMiss[0].occurrenceDates, ['2026-10-09', '2026-10-11']);
  const eligible = buildSiteEvidence({ query: '舰队周是什么', state: { city: 'San Francisco', date: '2026-10-11', goal: 'information' }, today: TODAY, catalog });
  assert.equal(eligible.candidates[0].id, event.id);
});

test('weekend ranges include actual occurrences without turning a gap day into eligibility', () => {
  assert.deepEqual(dateRangeFor('this weekend', TODAY), { start: '2026-10-10', end: '2026-10-11' });
  const state = resolveTaskState({ message: '旧金山这周末有什么活动', today: TODAY, catalog }).state;
  assert.equal(state.date, null); assert.deepEqual(state.dateRange, { start: '2026-10-10', end: '2026-10-11' });
  assert.equal(buildSiteEvidence({ query: '舰队周', state, today: TODAY, catalog }).candidates[0].id, event.id);
  assert.equal(dateRangeFor('2026-02-30 to 2026-03-01', TODAY), null);
  assert.equal(resolveTaskState({ message: '这周末10月10日去', today: TODAY, catalog }).state.date, '2026-10-10');
});

test('page context trusts catalog facts, validates occurrence dates and makes expired items reference only', () => {
  const context = createPublicContext({ catalog, guideCatalog: [{ slug: 'edition-2026-09', title: 'September reference', editionMonth: '2026-09' }], discoveryCatalog: { items: [{ kind: 'opening', id: 'soon', title: 'Announced opening', status: 'coming-soon' }] } });
  const result = context.resolve({ context: { references: [{ kind: 'event', id: event.id, date: '2026-10-10', title: 'Client invented title' }] }, today: TODAY });
  assert.equal(result.contextReferences[0].title, event.title); assert.equal(result.contextReferences[0].date, undefined);
  assert.ok(result.contextUsed.notices.length);
  assert.equal(context.resolve({ context: {}, currentPath: '/guides/edition-2026-09', today: TODAY }).contextReferences[0].temporalStatus, 'past');
  assert.equal(context.resolve({ context: {}, currentPath: '/openings/soon', today: TODAY }).contextReferences[0].temporalStatus, 'upcoming');
  assert.equal(context.resolve({ context: { references: [] }, currentPath: '/events/fleet-week', today: TODAY }).contextReferences.length, 0, 'Explicit cleared selection suppresses inferred page authority');
  assert.throws(() => context.resolve({ context: { preferences: { email: 'private@example.test' } }, today: TODAY }), error => error.status === 400);
});

test('page evidence reaches pronoun synthesis and false absence claims are corrected with real sources', async () => {
  const context = createPublicContext({ catalog }).resolve({ currentPath: '/events/fleet-week', today: TODAY });
  let input;
  const assistant = createBayBayAssistant({ catalog, isTest: true, now: () => NOW, config: { JWT_SECRET: 'isolated-audit-baybay-secret' }, ai: async payload => { input = JSON.parse(payload.input[0].content); return final({ answer: '站内没有收录这个活动。', candidateIds: [] }); } });
  const result = await assistant.run({ message: '这个活动是什么？', searchMode: 'site', pageContext: context });
  assert.ok(input.evidence.some(source => source.text.includes(event.title)));
  assert.match(result.answer, /站内已收录/); assert.match(result.answer, /2026-10-09/);
  assert.ok(result.research.warnings.includes('false_negative_corrected'));
  assert.equal(result.sources[0].url, 'https://www.baylink.us/events/fleet-week');
});

test('quick cards use resolved public identities with catalog provenance and validated deltas only', () => {
  const response = new EventEmitter(); response.output = ''; response.status = () => response; response.set = () => response; response.flushHeaders = () => {}; response.write = text => { response.output += text; }; response.end = () => { response.writableEnded = true; response.emit('close'); };
  const stream = createBayBayProgressStream(response);
  stream.quickCard([{ kind: 'event', id: 'fleet-week', url: '/events/fleet-week', title: event.title, summary: event.summary, privateField: 'secret' }, { kind: 'event', id: 'forged', url: 'https://forged.example/', title: 'Untrusted' }]);
  stream.validatedText('Already validated answer.'); stream.result({ ok: true });
  assert.match(response.output, /"provenance":"site-record"/); assert.match(response.output, /"verifiedLive":false/); assert.match(response.output, /"validated":true/);
  assert.doesNotMatch(response.output, /secret|forged|privateField/);
});

test('a cancelled assistant starts no model or web work', async () => {
  const controller = new AbortController(); controller.abort(); let calls = 0;
  const assistant = createBayBayAssistant({ catalog, isTest: true, config: { JWT_SECRET: 'isolated-audit-baybay-secret' }, ai: async () => { calls++; }, webSearch: async () => { calls++; } });
  await assert.rejects(assistant.run({ message: 'Fleet Week', signal: controller.signal }), error => error.code === 'REQUEST_CANCELLED');
  assert.equal(calls, 0);
});
