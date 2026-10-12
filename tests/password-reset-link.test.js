// G78 / ENGSEC-12 (API-SEC): the password-reset token travels in the URL fragment for pages
// that read it, so it never reaches a server log or a Referer header. Old pages keep the
// ?token= form until PASSWORD_RESET_LINK_STYLE=fragment; the token is always POSTed in the body.
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'password-reset-link-secret-0123456789abcdef';
const hash = bcrypt.hashSync('OnlyMockPassword7', 4);

async function start(t, config = {}) {
  const models = createMemoryModels({ User: [{ id: 'owner', email: 'owner@example.test', password: hash, nickname: 'Owner', role: 'user', accountStatus: 'active', isBanned: false }] });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, AUTH_DEV_RETURN_TOKENS: 'true', FRONTEND_URL: 'https://www.example.test', ...config } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const post = async (path, body) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  const owner = () => models.User.rows.find(row => row.id === 'owner');
  // Each request is allowed by the durable 5-minute cooldown only once; move the clock back.
  const ask = async extra => { if (owner().passwordResetRequestedAt) owner().passwordResetRequestedAt -= 300001; return (await post('/auth/forgot-password', { email: 'owner@example.test', ...extra })).data; };
  return { post, ask, owner };
}

test('a page that reads the fragment gets #token=; the token POSTed in the body resets the password', async t => {
  const f = await start(t);
  const { devResetLink } = await f.ask({ resetLinkStyle: 'fragment' });
  assert.match(devResetLink, /^https:\/\/www\.example\.test\/reset-password#token=[0-9a-f]{64}$/);
  const token = new URL(devResetLink).hash.slice('#token='.length);
  const reset = await f.post('/auth/reset-password', { token, newPassword: 'AnotherMock8Pass' });
  assert.equal(reset.status, 200);
  assert.equal((await f.post('/auth/reset-password', { token, newPassword: 'AnotherMock9Pass' })).status, 400, 'used once');
  assert.equal((await f.post('/auth/login', { email: 'owner@example.test', password: 'AnotherMock8Pass' })).status, 200);
});

test('older pages (no resetLinkStyle, or an unknown value) keep the query form they read; the env switch makes the fragment the only form', async t => {
  // One server per case: the in-memory limiter allows 3 reset e-mails per address per hour.
  for (const extra of [{}, { resetLinkStyle: 'query' }, { resetLinkStyle: 'javascript:alert(1)' }, { resetLinkStyle: ['fragment'] }]) {
    assert.match((await (await start(t)).ask(extra)).devResetLink, /\/reset-password\?token=[0-9a-f]{64}$/, JSON.stringify(extra));
  }
  const g = await start(t, { PASSWORD_RESET_LINK_STYLE: 'fragment' });
  assert.match((await g.ask({})).devResetLink, /\/reset-password#token=[0-9a-f]{64}$/);
  assert.match((await g.ask({ resetLinkStyle: 'query' })).devResetLink, /#token=/, 'the switch wins over an old page');
});

test('an unknown address answers exactly like a known one, whichever link form is asked for', async t => {
  const f = await start(t);
  const unknown = await f.post('/auth/forgot-password', { email: 'nobody@example.test', resetLinkStyle: 'fragment' });
  assert.equal(unknown.status, 200);
  assert.deepEqual(Object.keys(unknown.data), ['message']);
});
