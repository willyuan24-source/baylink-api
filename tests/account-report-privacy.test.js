const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { accountMemory } = require('./support/account-memory');

const secret = 'report-privacy-test-secret-at-least-thirty-two-characters';
const password = 'OnlyMockPassword7';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

async function fixture(t) {
  const seed = {
    User: ['admin', 'owner', 'reporter'].map(id => ({ id, email: `${id}@fixture.invalid`, nickname: id,
      role: id === 'admin' ? 'admin' : 'user', password: bcrypt.hashSync(password, 4) })),
    Report: [{ id: 'review-case', targetType: 'user', targetId: 'owner', targetUserId: 'owner', reporterId: 'reporter',
      status: 'open', detail: 'private-evidence', evidence: ['private-image'], adminNote: 'private-old-note', createdAt: 1 }],
  };
  const models = createMemoryModels();
  for (const name of ['User', 'Post', 'Message', 'Conversation', 'ContactRequest', 'UserBlock', 'EventInterest',
    'PlannerAccount', 'Outing', 'ServiceBookingAgenda', 'PostTranslation', 'Report', 'ModerationLog', 'AccountAuthChallenge']) {
    models[name] = accountMemory(seed[name] || []);
  }
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: secret },
    accountPrivacyTransaction: work => work() });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const tokens = Object.fromEntries(seed.User.map(user => [user.id, jwt.sign({ id: user.id, purpose: 'session',
    sessionIssuedAt: Date.now(), sessionRevision: 0 }, secret, { expiresIn: '1h' })]));
  const request = async (path, user, method, body) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}${path}`, {
      method, headers: { Authorization: `Bearer ${tokens[user]}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, data: await response.json() };
  };
  const eraseOwner = () => request('/api/users/me/privacy/account', 'owner', 'DELETE', { password, confirmation: 'DELETE MY ACCOUNT' });
  const review = () => request('/api/admin/reports/review-case', 'admin', 'PATCH', { status: 'reviewed', adminNote: 'private-review-note' });
  return { models, eraseOwner, review };
}

test('actual :reportId review route holds target and reporter until delayed review writes settle', { timeout: 8000 }, async t => {
  const f = await fixture(t), saving = deferred(), proceed = deferred();
  const findOne = f.models.Report.findOne;
  f.models.Report.findOne = filter => {
    const query = findOne(filter), then = query.then;
    query.then = (yes, no) => then(async document => {
      // The gate projects ids only. Pause the full document's real route save.
      if (document?.id === 'review-case') {
        const save = document.save;
        document.save = async function() { saving.resolve(); await proceed.promise; return save.call(this); };
      }
      return document;
    }).then(yes, no);
    return query;
  };
  const review = f.review();
  let reviewed;
  try {
    await saving.promise;
    assert.equal(f.models.User.rows.find(row => row.id === 'owner').activeAccountOperations, 1);
    assert.equal(f.models.User.rows.find(row => row.id === 'reporter').activeAccountOperations, 1);
    const blocked = await f.eraseOwner();
    assert.equal(blocked.status, 409);
    assert.equal(blocked.data.code, 'ACCOUNT_OPERATIONS_PENDING');
    assert.ok(f.models.User.rows.some(row => row.id === 'owner'));
  } finally { proceed.resolve(); reviewed = await review; }
  assert.equal(reviewed.status, 200);
  await nextTurn();
  assert.equal((await f.eraseOwner()).status, 200);
  assert.equal(f.models.User.rows.some(row => row.id === 'owner'), false);
  const report = f.models.Report.rows[0];
  assert.match(report.targetUserId, /^deleted_/);
  for (const key of ['detail', 'evidence', 'adminNote']) assert.equal(report[key], undefined, key);
  assert.ok(!JSON.stringify(f.models.ModerationLog.rows).includes('private-review-note'));
});

test('deletion winning between report lookup and target acquisition refuses the late review without restoring evidence', { timeout: 8000 }, async t => {
  const f = await fixture(t), acquiring = deferred(), proceed = deferred();
  const update = f.models.User.findOneAndUpdate;
  f.models.User.findOneAndUpdate = async (filter, changes, options) => {
    if (filter.id === 'owner' && changes.$inc?.activeAccountOperations === 1) {
      acquiring.resolve(); await proceed.promise;
    }
    return update(filter, changes, options);
  };
  const review = f.review();
  try {
    await acquiring.promise;
    assert.equal((await f.eraseOwner()).status, 200);
    assert.equal(f.models.User.rows.some(row => row.id === 'owner'), false);
  } finally { proceed.resolve(); }
  assert.equal((await review).status, 409);
  for (const key of ['detail', 'evidence', 'adminNote']) assert.equal(f.models.Report.rows[0][key], undefined, key);
  assert.equal(f.models.ModerationLog.rows.length, 0);
});
