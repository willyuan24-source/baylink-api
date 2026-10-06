const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const PERIOD = 30;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const fail = (message, status = 400, code = 'ACCOUNT_SECURITY_ERROR') => Object.assign(new Error(message), { status, code, publicSafe: true });
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function encodeBase32(bytes) {
  let bits = 0, value = 0, output = '';
  for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { output += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}
function decodeBase32(secret) {
  if (typeof secret !== 'string' || !/^[A-Z2-7]{16,128}$/.test(secret)) throw fail('验证器密钥无效。', 503, 'TOTP_UNAVAILABLE');
  let bits = 0, value = 0; const output = [];
  for (const char of secret) { value = (value << 5) | BASE32.indexOf(char); bits += 5; if (bits >= 8) { output.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(output);
}
function totpAt(secret, timestamp, digits = 6, algorithm = 'sha1') {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 1000 / PERIOD)));
  const hmac = crypto.createHmac(algorithm, decodeBase32(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 15;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits)).padStart(digits, '0');
}
function matchingStep(secret, code, now) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  for (const delta of [0, -1, 1]) {
    const timestamp = now + delta * PERIOD * 1000;
    if (timestamp < 0) continue;
    const expected = totpAt(secret, timestamp);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(code))) return Math.floor(timestamp / 1000 / PERIOD);
  }
  return null;
}
function encryptionKey(config) {
  const value = config.ACCOUNT_SECURITY_ENCRYPTION_KEY;
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 && bytes.toString('base64') === value ? bytes : null;
}
function encryptSecret(secret, userId, key) {
  if (!key) throw fail('验证器设置暂未配置，请保留当前登录方式。', 503, 'TOTP_SETUP_UNAVAILABLE');
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`baylink:totp:${userId}`));
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')].join('.');
}
function decryptSecret(value, userId, key) {
  if (!key || typeof value !== 'string' || value.length > 300) throw fail('验证器服务暂不可用，请使用恢复码或联系支持。', 503, 'TOTP_UNAVAILABLE');
  try {
    const [version, iv, tag, encrypted, extra] = value.split('.');
    if (version !== 'v1' || extra || !iv || !tag || !encrypted) throw new Error('invalid');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
    decipher.setAAD(Buffer.from(`baylink:totp:${userId}`)); decipher.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64')), decipher.final()]).toString('utf8');
  } catch { throw fail('验证器服务暂不可用，请使用恢复码或联系支持。', 503, 'TOTP_UNAVAILABLE'); }
}
const normalizeRecovery = value => typeof value === 'string' ? value.replace(/[\s-]/g, '').toUpperCase() : '';
function recoveryCodes() {
  const codes = Array.from({ length: 10 }, () => crypto.randomBytes(16).toString('hex').toUpperCase().match(/.{4}/g).join('-'));
  return { codes, hashes: codes.map(code => hash(normalizeRecovery(code))) };
}
function createAccountAuthChallengeModel(mongoose, models = {}) {
  if (models.AccountAuthChallenge) return models.AccountAuthChallenge;
  const schema = new mongoose.Schema({
    id: { type: String, required: true, unique: true }, userId: { type: String, required: true, index: true },
    expiresAt: { type: Date, required: true, expires: 0 }, consumedAt: { type: Number, default: null },
    attempts: { type: Number, default: 0 }, securityRevision: Number, passwordChangedAt: Number,
  });
  return mongoose.models.AccountAuthChallenge || mongoose.model('AccountAuthChallenge', schema);
}

function createAccountTotp({ User, Challenge, config, checkRateLimit, getClientIp, issueToken, sanitizeUser, disconnectUser, holdAccount, now = Date.now }) {
  const key = encryptionKey(config);
  const enabled = user => Number.isFinite(user?.totpEnabledAt) && user.totpEnabledAt > 0;
  const privateUser = async id => {
    const user = await User.findOne({ id });
    if (!user) throw fail('账号不可用，请重新登录。', 403, 'ACCOUNT_UNAVAILABLE');
    // Native projection reads the select:false secret without changing any public model query.
    const hidden = typeof User.collection?.findOne === 'function'
      ? await User.collection.findOne({ id }, { projection: { accountSecurity: 1 } }) : user;
    return { ...(typeof user.toObject === 'function' ? user.toObject() : user), accountSecurity: hidden?.accountSecurity };
  };
  const active = user => user && !user.isBanned && user.accountStatus !== 'suspended' && !user.accountDeletionPending;
  const proofFilter = user => ({ id: user.id, password: user.password, accountDeletionPending: { $ne: true },
    ...(user.passwordChangedAt ? { passwordChangedAt: user.passwordChangedAt } : { $or: [{ passwordChangedAt: { $exists: false } }, { passwordChangedAt: null }, { passwordChangedAt: 0 }] }),
  });
  const limit = (req, res, next) => {
    const identity = req.user?.id || getClientIp(req);
    if (!checkRateLimit(`account-security:${identity}`, { windowMs: 15 * 60000, maxRequests: 15 })
      || !checkRateLimit(`account-security-ip:${getClientIp(req)}`, { windowMs: 15 * 60000, maxRequests: 40 })) return res.status(429).json({ error: '验证次数过多，请稍后重试。', code: 'ACCOUNT_RATE_LIMIT' });
    next();
  };
  const verifyFactor = async (user, body) => {
    const recovery = normalizeRecovery(body?.recoveryCode);
    if (recovery) {
      if (!/^[A-F0-9]{32}$/.test(recovery)) throw fail('恢复码无效或已使用。', 403, 'MFA_INVALID');
      const digest = hash(recovery);
      const changed = await User.updateOne({ id: user.id, totpEnabledAt: user.totpEnabledAt, 'accountSecurity.recoveryHashes': digest }, { $pull: { 'accountSecurity.recoveryHashes': digest } });
      if (changed.modifiedCount !== 1) throw fail('恢复码无效或已使用。', 403, 'MFA_INVALID');
      return;
    }
    const security = user.accountSecurity || {};
    const secret = decryptSecret(security.secretCipher, user.id, key);
    const step = matchingStep(secret, body?.totpCode, now());
    if (step === null) throw fail('验证器代码无效，请核对最新六位代码。', 403, 'MFA_INVALID');
    const changed = await User.updateOne({ id: user.id, totpEnabledAt: user.totpEnabledAt,
      'accountSecurity.secretCipher': security.secretCipher,
      $or: [{ 'accountSecurity.lastUsedStep': { $lt: step } }, { 'accountSecurity.lastUsedStep': { $exists: false } }],
    }, { $set: { 'accountSecurity.lastUsedStep': step } });
    if (changed.modifiedCount !== 1) throw fail('这枚代码已使用，请等下一枚代码或使用未使用的恢复码。', 403, 'MFA_REPLAY');
  };
  const confirmCredentials = async req => {
    if (typeof req.body?.password !== 'string' || req.body.password.length > 128) throw fail('请填写当前密码确认操作。', 403, 'CREDENTIAL_CONFIRMATION_REQUIRED');
    const user = await privateUser(req.user.id);
    if (!active(user) || !await bcrypt.compare(req.body.password, user.password)) throw fail('当前密码不正确，请重新确认。', 403, 'CREDENTIAL_CONFIRMATION_REQUIRED');
    if (enabled(user)) await verifyFactor(user, req.body);
    if (!await User.exists(proofFilter(user))) throw fail('账号凭证已变化，请重新登录确认。', 409, 'ACCOUNT_CHANGED');
    return user;
  };
  const startLoginChallenge = async user => {
    const nonce = crypto.randomBytes(32).toString('base64url'), timestamp = now();
    await Challenge.create({ id: hash(nonce), userId: user.id, expiresAt: new Date(timestamp + 5 * 60000), consumedAt: null, attempts: 0,
      securityRevision: user.securityRevision || 0, passwordChangedAt: user.passwordChangedAt || 0 });
    return { mfaRequired: true, challengeToken: jwt.sign({ purpose: 'login-totp', id: user.id, nonce }, config.JWT_SECRET, { algorithm: 'HS256', expiresIn: '5m' }) };
  };
  const completeLogin = async body => {
    let payload;
    try { if (typeof body?.challengeToken !== 'string' || body.challengeToken.length > 1800) throw new Error('invalid'); payload = jwt.verify(body.challengeToken, config.JWT_SECRET, { algorithms: ['HS256'] }); }
    catch { throw fail('登录验证已过期，请重新输入密码。', 401, 'MFA_CHALLENGE_EXPIRED'); }
    if (payload.purpose !== 'login-totp' || typeof payload.id !== 'string' || typeof payload.nonce !== 'string') throw fail('登录验证无效。', 401, 'MFA_CHALLENGE_EXPIRED');
    if (holdAccount) await holdAccount(payload.id);
    const challenge = await Challenge.findOneAndUpdate({ id: hash(payload.nonce), userId: payload.id, consumedAt: null,
      expiresAt: { $gt: new Date(now()) }, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } }, { new: true });
    if (!challenge) throw fail('登录验证已过期或尝试过多，请重新输入密码。', 401, 'MFA_CHALLENGE_EXPIRED');
    const user = await privateUser(payload.id);
    if (!active(user) || !enabled(user) || (user.securityRevision || 0) !== challenge.securityRevision || (user.passwordChangedAt || 0) !== challenge.passwordChangedAt) throw fail('账号状态已变化，请重新登录。', 401, 'MFA_CHALLENGE_EXPIRED');
    await verifyFactor(user, body);
    const consumed = await Challenge.updateOne({ id: challenge.id, consumedAt: null }, { $set: { consumedAt: now() } });
    if (consumed.modifiedCount !== 1) throw fail('登录验证已使用，请重新登录。', 401, 'MFA_CHALLENGE_EXPIRED');
    return { ...sanitizeUser(user), token: issueToken(user, { mfaVerified: true }) };
  };
  const sessionResponse = user => {
    return { user: { ...sanitizeUser(user), token: issueToken(user, { mfaVerified: enabled(user) }) } };
  };
  function register(app, authenticateToken) {
    const privateResponse = (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };
    app.post('/api/auth/login/totp', privateResponse, limit, async (req, res) => res.json(await completeLogin(req.body)));
    app.get('/api/users/me/security', authenticateToken, privateResponse, async (req, res) => {
      const user = await privateUser(req.user.id);
      res.json({ totpEnabled: enabled(user), setupAvailable: user.role === 'admin' && !!key, recoveryCodesRemaining: enabled(user) ? (user.accountSecurity?.recoveryHashes || []).length : 0 });
    });
    app.post('/api/users/me/security/totp/setup', authenticateToken, privateResponse, limit, async (req, res) => {
      const user = await confirmCredentials(req);
      if (user.role !== 'admin') throw fail('此验证器设置目前仅供管理员使用。', 403, 'ADMIN_REQUIRED');
      if (enabled(user)) throw fail('验证器已启用。如需更换，请先通过凭证确认安全停用。', 409, 'TOTP_ALREADY_ENABLED');
      if (!key) throw fail('服务尚未配置独立验证器加密密钥，当前登录方式保持可用。', 503, 'TOTP_SETUP_UNAVAILABLE');
      const secret = encodeBase32(crypto.randomBytes(20)), recovery = recoveryCodes(), expiresAt = now() + 10 * 60000;
      const stored = await User.updateOne({ ...proofFilter(user), totpEnabledAt: { $in: [null, 0] } }, { $set: { accountSecurity: {
        pendingCipher: encryptSecret(secret, user.id, key), pendingRecoveryHashes: recovery.hashes, pendingExpiresAt: expiresAt,
      } } });
      if (stored.modifiedCount !== 1) throw fail('账号状态已变化，请重新开始设置。', 409, 'ACCOUNT_CHANGED');
      res.json({ secret, recoveryCodes: recovery.codes, expiresAt,
        otpauthUri: `otpauth://totp/${encodeURIComponent(`BAYLINK:${user.email}`)}?secret=${secret}&issuer=BAYLINK&algorithm=SHA1&digits=6&period=30` });
    });
    app.post('/api/users/me/security/totp/confirm', authenticateToken, privateResponse, limit, async (req, res) => {
      const user = await confirmCredentials(req);
      if (user.role !== 'admin' || enabled(user)) throw fail('账号状态已变化，请重新开始设置。', 409, 'ACCOUNT_CHANGED');
      const pending = user.accountSecurity || {};
      if (req.body?.recoveryCodesSaved !== true || !pending.pendingExpiresAt || pending.pendingExpiresAt <= now()) throw fail('请先保存恢复码，并在十分钟内确认设置。', 400, 'TOTP_SETUP_EXPIRED');
      const secret = decryptSecret(pending.pendingCipher, user.id, key), step = matchingStep(secret, req.body.totpCode, now());
      if (step === null) throw fail('验证器代码不正确，尚未启用。', 403, 'MFA_INVALID');
      const timestamp = now();
      const changed = await User.findOneAndUpdate({ ...proofFilter(user), role: 'admin', 'accountSecurity.pendingCipher': pending.pendingCipher, 'accountSecurity.pendingExpiresAt': { $gt: timestamp }, totpEnabledAt: { $in: [null, 0] } }, {
        $set: { totpEnabledAt: timestamp, sessionsRevokedAt: timestamp, accountSecurity: { secretCipher: encryptSecret(secret, user.id, key), recoveryHashes: pending.pendingRecoveryHashes, lastUsedStep: step } }, $inc: { securityRevision: 1, sessionRevision: 1 },
      }, { new: true });
      if (!changed) throw fail('设置已变化，请重新开始。', 409, 'ACCOUNT_CHANGED');
      disconnectUser(user.id); res.json(sessionResponse(changed));
    });
    app.post('/api/users/me/security/totp/disable', authenticateToken, privateResponse, limit, async (req, res) => {
      const user = await confirmCredentials(req);
      if (!enabled(user)) throw fail('验证器尚未启用。', 409, 'TOTP_NOT_ENABLED');
      const changed = await User.findOneAndUpdate({ ...proofFilter(user), securityRevision: user.securityRevision || 0 }, { $set: { totpEnabledAt: null, sessionsRevokedAt: now() }, $unset: { accountSecurity: 1 }, $inc: { securityRevision: 1, sessionRevision: 1 } }, { new: true });
      if (!changed) throw fail('账号状态已变化，请重新确认。', 409, 'ACCOUNT_CHANGED');
      disconnectUser(user.id); res.json(sessionResponse(changed));
    });
    app.post('/api/users/me/security/totp/recovery-codes', authenticateToken, privateResponse, limit, async (req, res) => {
      const user = await confirmCredentials(req);
      if (!enabled(user)) throw fail('验证器尚未启用。', 409, 'TOTP_NOT_ENABLED');
      const recovery = recoveryCodes();
      const changed = await User.updateOne({ ...proofFilter(user), totpEnabledAt: user.totpEnabledAt }, { $set: { 'accountSecurity.recoveryHashes': recovery.hashes }, $inc: { securityRevision: 1 } });
      if (changed.modifiedCount !== 1) throw fail('账号状态已变化，请重试。', 409, 'ACCOUNT_CHANGED');
      res.json({ recoveryCodes: recovery.codes });
    });
  }
  return { register, limit, enabled, startLoginChallenge, completeLogin, confirmCredentials };
}
module.exports = { encodeBase32, decodeBase32, totpAt, matchingStep, encryptionKey, encryptSecret, decryptSecret, recoveryCodes, createAccountAuthChallengeModel, createAccountTotp };
