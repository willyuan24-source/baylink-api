const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

async function probe(t, commit) {
  const application = createApplication({
    config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-health-test-secret', RENDER_GIT_COMMIT: commit, DATABASE_URL: 'must-not-be-returned' },
    models: createMemoryModels(),
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/health`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return response.json();
}

test('release probe exposes only the public revision and process status without authentication', async t => {
  const commit = 'a'.repeat(40);
  assert.deepEqual(await probe(t, commit), { status: 'ok', service: 'baylink-api', commit });
});

test('release probe does not echo malformed or missing deployment metadata', async t => {
  for (const value of [undefined, 'untrusted-metadata']) {
    assert.deepEqual(await probe(t, value), { status: 'ok', service: 'baylink-api', commit: null });
  }
});
