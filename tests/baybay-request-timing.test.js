const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

test('the public assistant reports bounded numeric request timing without private request metadata', async t => {
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'timing-fixture-session-secret', OPENAI_API_KEY: 'timing-fixture-api-key' },
    models: createMemoryModels(), plannerNow: () => Date.parse('2026-10-04T19:00:00Z'),
    ai: { baybay: async input => {
      const source = JSON.parse(input.input[0].content).evidence[0];
      return { model: 'fixture-baybay', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer: `请参考馆方说明。${source ? ` [[${source.id}]]` : ''}`, candidateIds: [], followups: [], coverage: [] }) }] }] };
    } },
  });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: '请介绍 Fremont 的图书馆资源。', assistantVersion: 2, searchMode: 'site' }),
  });
  assert.equal(response.status, 200);
  const result = await response.json(), timings = result.research.timings;
  for (const key of ['preparationMs', 'assistantMs', 'requestMs']) assert.ok(Number.isFinite(timings[key]) && timings[key] >= 0, key);
  assert.ok(timings.requestMs >= timings.assistantMs);
  assert.ok(timings.requestMs >= timings.preparationMs);
  assert.match(response.headers.get('server-timing'), /^baybay_prepare;dur=\d+, baybay_assistant;dur=\d+$/);
  assert.ok(Object.values(timings).every(value => Number.isFinite(value) && value >= 0));
  assert.doesNotMatch(JSON.stringify(timings), /Fremont|secret|fixture-api-key|session/i);

  const streamed = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: '请介绍 Fremont 的图书馆资源。', assistantVersion: 2, searchMode: 'site', stream: true }),
  });
  assert.equal(streamed.status, 200);
  assert.match(streamed.headers.get('content-type'), /^text\/event-stream/);
  const events = (await streamed.text()).split('\n\n').filter(frame => frame.startsWith('event:')).map(frame => {
    const [event, data] = frame.split('\n');
    return { event: event.slice(7), data: JSON.parse(data.slice(6)) };
  });
  assert.ok(events.some(event => event.event === 'progress' && event.data.phase === 'site'));
  assert.ok(events.some(event => event.event === 'progress' && ['answer', 'research'].includes(event.data.phase)));
  const results = events.filter(event => event.event === 'result');
  assert.equal(results.length, 1);
  assert.ok(results[0].data.answer);
  assert.equal(results[0].data.degraded, false);
  assert.ok(Number.isFinite(results[0].data.research.timings.requestMs));
  assert.equal(events.at(-1).event, 'result');
  for (const event of events.filter(event => event.event === 'progress')) assert.deepEqual(Object.keys(event.data).sort(), ['phase', 'status']);

  const invalid = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/guide-chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: '明天还有什么选择', assistantVersion: 2, searchMode: 'site', stream: true, assistantSessionToken: 'forged-value' }),
  });
  assert.match(invalid.headers.get('content-type'), /^text\/event-stream/);
  const failedFrame = await invalid.text();
  assert.match(failedFrame, /event: error\ndata: /);
  assert.match(failedFrame, /INVALID_ASSISTANT_SESSION/);
  assert.doesNotMatch(failedFrame, /event: result/);
  const aggregate = app.models.AiRuntimeMetric.rows.find(row => row.feature === 'guide_chat');
  assert.equal(aggregate.requestCompleted, 2, 'JSON and SSE results both reach the aggregate');
  assert.equal(aggregate.requestError, 1, 'an SSE error envelope is not an HTTP 200 success');
  const observations = field => Object.values(aggregate[field] || {}).reduce((total, count) => total + count, 0);
  assert.equal(observations('completeResult'), 2);
  assert.equal(observations('firstValidatedText'), 1, 'JSON answers do not pretend to stream their first text');
  assert.equal(observations('firstQuickCard'), Number(events.some(event => event.event === 'quick_card')));
  assert.doesNotMatch(JSON.stringify(app.models.AiRuntimeMetric.rows), /Fremont|secret|fixture-api-key|session|firstToken/i);
});
