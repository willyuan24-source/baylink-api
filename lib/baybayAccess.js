// Membership comes only from the server's current, verified login session.
// A requested mode, task-memory token or client account flag is not authority.
function baybayWebAccess(userId) {
  return userId ? { authenticated: true, allowed: true } : { authenticated: false, allowed: false, reason: 'auth_required' };
}

// A visitor who never presented a sign-in and did not ask for live web is not
// "signed out": site-only is simply the guest default. Reporting auth_required
// there made clients print "未登录或登录已失效" under every guest answer. An
// explicit web request, or a presented session that failed verification, still
// reports auth_required so a client can offer to sign in again.
function withBaybayAccess(payload, { requestedMode, webAccess, credentialPresented = true }) {
  if (!payload?.retrieval) return payload;
  const effectiveMode = webAccess.allowed ? requestedMode : 'site';
  const guestDefault = !webAccess.allowed && !credentialPresented && requestedMode !== 'web';
  return { ...payload, retrieval: { ...payload.retrieval, requestedMode, effectiveMode,
    webAccess: guestDefault ? { authenticated: false, allowed: false, reason: 'guest' } : webAccess,
    ...(!webAccess.allowed && requestedMode !== 'site' && !guestDefault ? { webStatus: 'auth_required' } : {}) } };
}

function webSignInMessage(locale) {
  return locale === 'en' ? 'Sign in or create an account to use live web lookup. You can still use BAYLINK site information without signing in.'
    : locale === 'zh-Hant' ? '登入或註冊後可使用聯網查詢；未登入仍可使用 BAYLINK 站內資訊。'
      : '登录或注册后可使用联网查询；未登录仍可使用 BAYLINK 站内信息。';
}

module.exports = { baybayWebAccess, withBaybayAccess, webSignInMessage };
