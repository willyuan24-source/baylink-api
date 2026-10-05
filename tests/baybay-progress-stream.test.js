const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createBayBayProgressStream } = require('../lib/baybayProgress');

function fixture() {
  const response = new EventEmitter();
  response.output = ''; response.writableEnded = false;
  response.status = code => { response.code = code; return response; };
  response.set = headers => { response.headers = headers; return response; };
  response.flushHeaders = () => { response.headersSent = true; };
  response.write = value => { response.output += value; };
  response.end = () => { response.writableEnded = true; response.emit('close'); };
  return response;
}
function events(response) {
  return response.output.trim().split('\n\n').filter(Boolean).map(block => {
    const [event, data] = block.split('\n'); return { event: event.slice(7), data: JSON.parse(data.slice(6)) };
  });
}

test('progress whitelists phases and strips private callback metadata before transmitting', () => {
  const response = fixture(), stream = createBayBayProgressStream(response);
  stream.progress({ phase: 'sources', status: 'running', query: 'private address', token: 'private-token' });
  stream.progress({ phase: 'sources', status: 'running' });
  stream.progress({ phase: 'invented', status: 'completed' });
  stream.result({ ok: true, answer: 'Quoted\nanswer', sources: [] });
  assert.equal(response.headers['Content-Type'], 'text/event-stream; charset=utf-8');
  assert.deepEqual(events(response), [
    { event: 'progress', data: { phase: 'sources', status: 'running' } },
    { event: 'result', data: { ok: true, answer: 'Quoted\nanswer', sources: [] } },
  ]);
  assert.doesNotMatch(response.output, /private/);
  const before = response.output;
  stream.progress({ phase: 'answer', status: 'completed' }); stream.error({ error: 'late' });
  assert.equal(response.output, before);
});

test('disconnect stops all writes and stream errors terminate without returning a partial result', () => {
  const response = fixture(), stream = createBayBayProgressStream(response);
  stream.error({ ok: false, code: 'INVALID_ASSISTANT_SESSION', error: 'Start a new conversation.' });
  assert.deepEqual(events(response).map(row => row.event), ['error']);
  assert.equal(response.writableEnded, true);
  const cancelled = fixture(), stopped = createBayBayProgressStream(cancelled);
  cancelled.emit('close'); stopped.result({ ok: true });
  assert.equal(cancelled.output, '');
});
