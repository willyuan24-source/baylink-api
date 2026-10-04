const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { isPublicTransitRequest, unverifiedTransitTiming } = require('../lib/guideTransit');
const { selectConversationGuides } = require('../lib/guideConversation');
const catalog = require('../data/guide-catalog.json');

test('public transit routing is distinct from hiring drivers, housing and incidental station references', () => {
  for (const query of ['從 SFO 到 San Jose，公共交通怎麼走？', 'BART 到 Caltrain 怎么转乘？', 'Public transit from SFO to San Jose with two suitcases']) assert.ok(isPublicTransitRequest(query), query);
  for (const query of ['找机场接送司机，BART末班之后接我', 'Book a driver after the last BART', 'Rent an apartment near Caltrain', '招聘公交司机', 'Caltrain 青少年票', 'Caltrain youth fare eligibility']) assert.equal(isPublicTransitRequest(query), false, query);
});

test('airport transit questions retrieve transport sources rather than destination sightseeing articles', () => {
  const first = '从 SFO 到 San Jose Downtown，不开车，有两个大行李箱。公共交通怎么走？';
  const selected = selectConversationGuides(catalog, first, 'other', '/', [], '2026-10-04');
  assert.equal(selected[0].slug, 'bay-area-airport-arrival-guide');
  assert.ok(selected.every(g => /commute|without-car|airport/.test(g.slug)), selected.map(g => g.slug).join(','));
  const followup = selectConversationGuides(catalog, 'What about arriving after 11 pm?', 'other', '/', [{ role: 'user', content: first }, { role: 'assistant', content: 'Check the official timetables.' }], '2026-10-04');
  assert.equal(followup[0].slug, 'bay-area-airport-arrival-guide');
});

test('guide-only answers cannot pass off duration or last-train guesses as checked timetable facts', () => {
  for (const value of ['车程30–40分钟', 'about 30-40 minutes', 'Last train is at midnight', 'The train leaves at 23:15', '末班车在午夜']) assert.ok(unverifiedTransitTiming(value), value);
  assert.equal(unverifiedTransitTiming('Transfer at Millbrae and check the timetable for your travel date.'), false);
});

test('API selects transport guides and rejects invented timing without driver service cards', async t => {
  let captured;
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'test-transit-guard' }, models: createMemoryModels(), plannerNow: () => Date.parse('2026-10-04T19:00:00Z'),
    ai: { guideChat: async payload => { captured = payload; return { answer: 'Millbrae to San Jose Diridon takes 30–40 minutes. The last train leaves at midnight.' }; } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'Public transit from SFO to San Jose Downtown with two suitcases?', searchMode: 'site', locale: 'en' }) });
  const data = await response.json();
  assert.equal(response.status, 200); assert.equal(captured.inferredIntent, 'transit');
  assert.equal(captured.guideSources[0].url, '/guides/bay-area-airport-arrival-guide');
  assert.doesNotMatch(data.answer, /30.?40|midnight/); assert.match(data.answer, /not checked a date-specific timetable/);
  assert.deepEqual(data.interactiveCards, []); assert.ok(!data.suggestedActions.some(action => action.category === 'ride'));
});
