const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { installProcessHandlers } = require('../lib/processLifecycle');

const LIFECYCLE = path.join(__dirname, '..', 'lib', 'processLifecycle.js');

function fakeApplication({ hangClose = false } = {}) {
  const calls = [];
  const application = {
    sourceMonitor: { stop: () => calls.push('sourceMonitor.stop') },
    notifications: { stop: () => calls.push('notifications.stop') },
    server: { closeAllConnections: () => calls.push('server.closeAllConnections') },
    io: { close: done => { calls.push('io.close'); if (!hangClose) setImmediate(done); } },
  };
  return { application, calls };
}

test('an unhandled rejection is logged as one structured line and does not exit', () => {
  const target = new EventEmitter(), logs = [], exits = [];
  const { application } = fakeApplication();
  const handlers = installProcessHandlers({ application, target, log: line => logs.push(line), exit: code => exits.push(code) });
  target.emit('unhandledRejection', Object.assign(new Error('private-detail@fixture.invalid'), { name: 'MongoServerError', code: 6 }));
  assert.deepEqual(logs, [{ level: 'error', event: 'unhandled_rejection', error: 'MongoServerError', code: 6 }]);
  assert.deepEqual(exits, []);
  handlers.uninstall();
  assert.equal(target.listenerCount('unhandledRejection'), 0); assert.equal(target.listenerCount('SIGTERM'), 0);
});

test('SIGTERM stops workers, closes sockets and the database once, then exits 0', async () => {
  const target = new EventEmitter(), logs = [], exits = [];
  const { application, calls } = fakeApplication();
  const handlers = installProcessHandlers({ application, target, log: line => logs.push(line), exit: code => exits.push(code),
    disconnect: async () => { calls.push('disconnect'); } });
  target.emit('SIGTERM'); target.emit('SIGTERM'); target.emit('SIGINT');
  await handlers.shutdown('SIGTERM');
  assert.deepEqual(calls, ['sourceMonitor.stop', 'notifications.stop', 'io.close', 'disconnect']);
  assert.deepEqual(exits, [0]);
  assert.deepEqual(logs.map(line => line.event), ['shutdown', 'shutdown_complete']);
  handlers.uninstall();
});

test('a shutdown that cannot drain cuts open connections, then forces exit 1', async () => {
  const target = new EventEmitter(), logs = [], exits = [];
  const { application, calls } = fakeApplication({ hangClose: true });
  const handlers = installProcessHandlers({ application, target, log: line => logs.push(line), exit: code => exits.push(code), drainMs: 5, forceMs: 30 });
  target.emit('SIGTERM');
  await new Promise(resolve => setTimeout(resolve, 80));
  assert.ok(calls.includes('server.closeAllConnections'));
  assert.deepEqual(exits, [1]);
  assert.deepEqual(logs.map(line => line.event), ['shutdown', 'shutdown_timeout']);
  handlers.uninstall();
});

// Real processes: Node 24 exits with code 1 on an unhandled rejection unless a handler is installed.
const child = script => spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 15000 });
const rejectThenServe = install => `
  ${install ? `require(${JSON.stringify(LIFECYCLE)}).installProcessHandlers({ application: {} });` : ''}
  Promise.reject(Object.assign(new Error('boom'), { code: 40 }));
  setTimeout(() => { console.log('still serving'); process.exit(0); }, 100);
`;

test('without the handler an unhandled rejection kills the process (control)', () => {
  const result = child(rejectThenServe(false));
  assert.equal(result.status, 1);
  assert.ok(!result.stdout.includes('still serving'));
});

test('with the handler the process logs the rejection and keeps serving', () => {
  const result = child(rejectThenServe(true));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /still serving/);
  const line = JSON.parse(result.stderr.trim().split('\n').find(text => text.includes('unhandled_rejection')));
  assert.deepEqual(line, { level: 'error', event: 'unhandled_rejection', error: 'Error', code: 40 });
});

test('SIGTERM lets an in-flight request finish before the process exits 0', () => {
  // Windows cannot deliver POSIX signals to a child, so the child emits SIGTERM to itself.
  const result = child(`
    const http = require('node:http');
    const { installProcessHandlers } = require(${JSON.stringify(LIFECYCLE)});
    const server = http.createServer((req, res) => {
      res.on('finish', () => console.log('request finished', res.statusCode));
      setTimeout(() => res.end('finished'), 150);
    });
    installProcessHandlers({ application: { server }, disconnect: async () => console.log('db closed') });
    server.listen(0, '127.0.0.1', () => {
      http.get({ host: '127.0.0.1', port: server.address().port, agent: false }, res => res.resume());
      setTimeout(() => process.emit('SIGTERM'), 50);
    });
  `);
  assert.equal(result.status, 0, result.stderr);
  // SIGTERM arrives at ~50 ms; the request still completes (~150 ms) before the database closes.
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.deepEqual(lines, ['request finished 200', 'db closed']);
  assert.deepEqual(result.stderr.trim().split(/\r?\n/).map(text => JSON.parse(text).event), ['shutdown', 'shutdown_complete']);
});
