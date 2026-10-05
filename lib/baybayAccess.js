// Membership comes only from the server's current, verified login session.
// A requested mode, task-memory token or client account flag is not authority.
function baybayWebAccess(userId) {
  return userId ? { authenticated: true, allowed: true } : { authenticated: false, allowed: false, reason: 'auth_required' };
}

function withBaybayAccess(payload, { requestedMode, webAccess }) {
  if (!payload?.retrieval) return payload;
  const effectiveMode = webAccess.allowed ? requestedMode : 'site';
  return { ...payload, retrieval: { ...payload.retrieval, requestedMode, effectiveMode, webAccess,
    ...(!webAccess.allowed && requestedMode !== 'site' ? { webStatus: 'auth_required' } : {}) } };
}

function webSignInMessage(locale) {
  return locale === 'en' ? 'Sign in or create an account to use live web lookup. You can still use BAYLINK site information without signing in.'
    : locale === 'zh-Hant' ? '登入或註冊後可使用聯網查詢；未登入仍可使用 BAYLINK 站內資訊。'
      : '登录或注册后可使用联网查询；未登录仍可使用 BAYLINK 站内信息。';
}

module.exports = { baybayWebAccess, withBaybayAccess, webSignInMessage };
