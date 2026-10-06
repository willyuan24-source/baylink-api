const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { accountMemory } = require('./support/account-memory');
const { encodeBase32, totpAt, matchingStep, encryptionKey, encryptSecret, decryptSecret, recoveryCodes, createAccountTotp } = require('../lib/accountTotp');

const key = Buffer.alloc(32, 7), password = 'FixturePass123';
const config = { JWT_SECRET: 'mock-only-jwt-key-long-enough-for-tests', ACCOUNT_SECURITY_ENCRYPTION_KEY: key.toString('base64') };
async function fixture(extra = {}, override = {}) {
  let clock = Date.now();
  const User = accountMemory([{ id: 'admin-1', email: 'admin@fixture.invalid', role: 'admin', nickname: 'Test', password: await bcrypt.hash(password, 4), ...extra }]);
  const Challenge = accountMemory(); const disconnected = [], routes = new Map();
  const service = createAccountTotp({ User, Challenge, config: { ...config, ...override }, now: () => clock, getClientIp: () => 'fixture-ip', checkRateLimit: () => true,
    issueToken: (user, options) => jwt.sign({ id: user.id, purpose: 'session', sessionRevision: user.sessionRevision || 0, ...options }, config.JWT_SECRET),
    sanitizeUser: user => ({ id: user.id, email: user.email, nickname: user.nickname, role: user.role }), disconnectUser: id => disconnected.push(id) });
  service.register({ get: (path, ...handlers) => routes.set(path, handlers.at(-1)), post: (path, ...handlers) => routes.set(path, handlers.at(-1)) }, () => {});
  const call = async (path, body = {}) => { let result; await routes.get(path)({ user: { id: 'admin-1' }, body }, { json: value => { result = value; } }); return result; };
  return { User, Challenge, service, disconnected, call, tick: (steps = 1) => { clock += steps * 30000; }, now: () => clock };
}

test('TOTP matches the RFC 6238 SHA1 eight-digit reference vectors', () => {
  const secret = encodeBase32(Buffer.from('12345678901234567890'));
  for (const [time, code] of [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]) assert.equal(totpAt(secret, time * 1000, 8), code);
  assert.equal(matchingStep(secret, '12345', 59000), null);
  assert.equal(matchingStep(secret, totpAt(secret, 59000), 59000), 1);
});

test('secret encryption binds ciphertext to its user and never reuses JWT material', () => {
  assert.equal(encryptionKey({ JWT_SECRET: config.JWT_SECRET }), null);
  assert.equal(encryptionKey({ ACCOUNT_SECURITY_ENCRYPTION_KEY: 'too-short' }), null);
  const secret = encodeBase32(crypto.randomBytes(20)), encrypted = encryptSecret(secret, 'one', key);
  assert.ok(!encrypted.includes(secret)); assert.equal(decryptSecret(encrypted, 'one', key), secret);
  assert.throws(() => decryptSecret(encrypted, 'two', key), { code: 'TOTP_UNAVAILABLE' });
  assert.throws(() => decryptSecret(encrypted, 'one', Buffer.alloc(32, 8)), { code: 'TOTP_UNAVAILABLE' });
});

test('setup is unavailable without a key and leaves password-only accounts usable', async () => {
  const f = await fixture({}, { ACCOUNT_SECURITY_ENCRYPTION_KEY: undefined });
  assert.deepEqual(await f.call('/api/users/me/security'), { totpEnabled: false, setupAvailable: false, recoveryCodesRemaining: 0 });
  await assert.rejects(f.call('/api/users/me/security/totp/setup', { password }), { code: 'TOTP_SETUP_UNAVAILABLE' });
  assert.equal(f.service.enabled(f.User.rows[0]), false); assert.equal(f.User.rows[0].accountSecurity, undefined);
});

test('setup stores only encrypted pending secret and hashed codes until confirmed', async () => {
  const f = await fixture(), setup = await f.call('/api/users/me/security/totp/setup', { password });
  assert.equal(f.service.enabled(f.User.rows[0]), false);
  assert.ok(!JSON.stringify(f.User.rows[0]).includes(setup.secret));
  for (const code of setup.recoveryCodes) assert.ok(!JSON.stringify(f.User.rows[0]).includes(code));
  await assert.rejects(f.call('/api/users/me/security/totp/confirm', { password, totpCode: totpAt(setup.secret, f.now()) }), { code: 'TOTP_SETUP_EXPIRED' });
  const result = await f.call('/api/users/me/security/totp/confirm', { password, recoveryCodesSaved: true, totpCode: totpAt(setup.secret, f.now()) });
  assert.equal(f.service.enabled(f.User.rows[0]), true); assert.equal(f.User.rows[0].sessionRevision, 1);
  assert.equal(f.User.rows[0].accountSecurity.pendingCipher, undefined);
  assert.equal(jwt.verify(result.user.token, config.JWT_SECRET).mfaVerified, true); assert.deepEqual(f.disconnected, ['admin-1']);
});

test('wrong password and expired setup cannot enable MFA; non-admin cannot set it up', async () => {
  const f = await fixture(); await assert.rejects(f.call('/api/users/me/security/totp/setup', { password: 'wrong' }), { code: 'CREDENTIAL_CONFIRMATION_REQUIRED' });
  const setup = await f.call('/api/users/me/security/totp/setup', { password }); f.tick(21);
  await assert.rejects(f.call('/api/users/me/security/totp/confirm', { password, recoveryCodesSaved: true, totpCode: totpAt(setup.secret, f.now()) }), { code: 'TOTP_SETUP_EXPIRED' });
  assert.equal(f.service.enabled(f.User.rows[0]), false);
  const regular = await fixture({ role: 'user' }); await assert.rejects(regular.call('/api/users/me/security/totp/setup', { password }), { code: 'ADMIN_REQUIRED' });
});

test('login challenge is single-use, has no session token, and rejects TOTP replay', async () => {
  const secret = encodeBase32(crypto.randomBytes(20)), f = await fixture({ totpEnabledAt: Date.now(), accountSecurity: { secretCipher: encryptSecret(secret, 'admin-1', key), recoveryHashes: [] } });
  const challenge = await f.service.startLoginChallenge(f.User.rows[0]);
  assert.equal(challenge.token, undefined); assert.equal(jwt.verify(challenge.challengeToken, config.JWT_SECRET).purpose, 'login-totp');
  const user = await f.service.completeLogin({ ...challenge, totpCode: totpAt(secret, f.now()) });
  assert.equal(user.accountSecurity, undefined); assert.equal(jwt.verify(user.token, config.JWT_SECRET).mfaVerified, true);
  await assert.rejects(f.service.completeLogin({ ...challenge, totpCode: totpAt(secret, f.now()) }), { code: 'MFA_CHALLENGE_EXPIRED' });
  const again = await f.service.startLoginChallenge(f.User.rows[0]);
  await assert.rejects(f.service.completeLogin({ ...again, totpCode: totpAt(secret, f.now()) }), { code: 'MFA_REPLAY' });
  f.tick(); assert.ok((await f.service.completeLogin({ ...again, totpCode: totpAt(secret, f.now()) })).token);
});

test('five failed challenge attempts lock that challenge without disabling admin access', async () => {
  const secret = encodeBase32(crypto.randomBytes(20)), f = await fixture({ totpEnabledAt: Date.now(), accountSecurity: { secretCipher: encryptSecret(secret, 'admin-1', key), recoveryHashes: [] } });
  const challenge = await f.service.startLoginChallenge(f.User.rows[0]);
  for (let i = 0; i < 5; i++) await assert.rejects(f.service.completeLogin({ ...challenge, totpCode: 'bad-code' }), { code: 'MFA_INVALID' });
  await assert.rejects(f.service.completeLogin({ ...challenge, totpCode: totpAt(secret, f.now()) }), { code: 'MFA_CHALLENGE_EXPIRED' });
  const fresh = await f.service.startLoginChallenge(f.User.rows[0]); assert.ok((await f.service.completeLogin({ ...fresh, totpCode: totpAt(secret, f.now()) })).token);
});

test('recovery codes are one-use and remain usable when the encryption key is unavailable', async () => {
  const recovery = recoveryCodes(), f = await fixture({ totpEnabledAt: Date.now(), accountSecurity: { secretCipher: 'unreadable', recoveryHashes: recovery.hashes }, securityRevision: 1 }, { ACCOUNT_SECURITY_ENCRYPTION_KEY: undefined });
  const challenge = await f.service.startLoginChallenge(f.User.rows[0]);
  assert.ok((await f.service.completeLogin({ ...challenge, recoveryCode: recovery.codes[0] })).token);
  assert.equal(f.User.rows[0].accountSecurity.recoveryHashes.length, 9);
  const second = await f.service.startLoginChallenge(f.User.rows[0]);
  await assert.rejects(f.service.completeLogin({ ...second, recoveryCode: recovery.codes[0] }), { code: 'MFA_INVALID' });
  const disabled = await f.call('/api/users/me/security/totp/disable', { password, recoveryCode: recovery.codes[1] });
  assert.equal(f.service.enabled(f.User.rows[0]), false); assert.equal(f.User.rows[0].accountSecurity, undefined);
  assert.notEqual(jwt.verify(disabled.user.token, config.JWT_SECRET).mfaVerified, true);
  assert.equal(f.User.rows[0].totpEnabledAt, null); assert.equal(f.User.rows[0].sessionRevision, 1);
});

test('a password/security revision change invalidates outstanding MFA challenges', async () => {
  const recovery = recoveryCodes(), f = await fixture({ totpEnabledAt: Date.now(), accountSecurity: { recoveryHashes: recovery.hashes }, securityRevision: 1 });
  const challenge = await f.service.startLoginChallenge(f.User.rows[0]); f.User.rows[0].securityRevision++;
  await assert.rejects(f.service.completeLogin({ ...challenge, recoveryCode: recovery.codes[0] }), { code: 'MFA_CHALLENGE_EXPIRED' });
  assert.equal(f.User.rows[0].accountSecurity.recoveryHashes.length, 10);
});
