// G44 / ENGSEC-03: sign every administrator account out everywhere at once.
//
// Used by POST /api/admin/sessions/revoke (server.js) and by
// scripts/revoke-admin-sessions.js (Render shell, for when no admin can sign in).
// It raises each admin account's sessionRevision and stamps sessionsRevokedAt, the two
// fields verifySession already checks, so every session token issued before `at` stops
// working on its next request (HTTP and socket). Passwords, authenticator settings and
// recovery codes are not touched.
async function revokeAdminSessions({ User, now = Date.now }) {
  const at = now();
  const admins = await User.find({ role: 'admin' }).select('id').lean();
  const ids = admins.map(row => row.id).filter(id => typeof id === 'string' && id);
  if (!ids.length) return { at, accounts: 0, ids };
  await User.updateMany({ role: 'admin', id: { $in: ids } }, { $set: { sessionsRevokedAt: at }, $inc: { sessionRevision: 1 } });
  return { at, accounts: ids.length, ids };
}

module.exports = { revokeAdminSessions };
