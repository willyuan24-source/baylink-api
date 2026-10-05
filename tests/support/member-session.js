const jwt = require('jsonwebtoken');
const { baybayWebAccess } = require('../../lib/baybayAccess');
const SECRET = 'isolated-member-web-test-session-secret';
const user = { id: 'web-member', accountStatus: 'active', email: 'member@fixture.test' };
const token = secret => jwt.sign({ id: user.id }, secret || SECRET, { expiresIn: '1h' });
const headers = secret => ({ Authorization: `Bearer ${token(secret)}` });
// For isolated register* unit fixtures only. Application regressions below use
// createApplication's full verifySession (expiry, revocation and user status).
const accessForModels = models => async req => {
  try {
    const payload = jwt.verify(String(req.headers.authorization || '').replace(/^Bearer /, ''), SECRET, { algorithms: ['HS256'] });
    const account = await models.User.findOne({ id: payload.id });
    return baybayWebAccess(account && !account.isBanned && account.accountStatus !== 'suspended' ? account.id : null);
  } catch { return baybayWebAccess(null); }
};
module.exports = { SECRET, user, token, headers, accessForModels };
