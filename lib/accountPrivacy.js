const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { reactionKey } = require('./memberSocial');

const MAX_EXPORT_ROWS = 5000;
const pick = (value, fields) => Object.fromEntries(fields.filter(key => value?.[key] !== undefined).map(key => [key, value[key]]));
const plain = value => value?.toObject ? value.toObject() : value;
const error = (message, status = 400, code = 'ACCOUNT_PRIVACY_ERROR') => Object.assign(new Error(message), { status, code, publicSafe: true });
const sessionQuery = (query, session) => session && typeof query?.session === 'function' ? query.session(session) : query;
// All authenticated requests enter this DB-backed gate. Deletion claims it only
// when prior requests have finished, including requests on another API instance.
async function acquireAccountOperation(User, userId) {
  const acquired = await User.findOneAndUpdate({ id: userId, accountDeletionPending: { $ne: true } }, { $inc: { activeAccountOperations: 1 } }, { new: true });
  if (!acquired) throw error('账号正在删除，请稍后重试。', 409, 'ACCOUNT_CHANGED');
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    return User.updateOne({ id: userId, activeAccountOperations: { $gt: 0 } }, { $inc: { activeAccountOperations: -1 } }).catch(() => {});
  };
  return release;
}
const operations = new AsyncLocalStorage();
const releaseFinished = ledger => {
  if (!ledger.ended || ledger.handlers) return;
  for (const release of ledger.releases.splice(0)) release();
};
function runAccountHandler(request, response, handler) {
  let ledger = request.accountOperationLedger;
  if (!ledger) {
    ledger = request.accountOperationLedger = { handlers: 0, ended: false, accounts: new Map(), releases: [] };
    const ended = () => { ledger.ended = true; releaseFinished(ledger); };
    response.once('finish', ended); response.once('close', ended);
  }
  ledger.handlers++;
  return operations.run({ ledger }, () => Promise.resolve().then(handler).finally(() => { ledger.handlers--; releaseFinished(ledger); }));
}
async function holdAccountOperation(User, userId) {
  const context = operations.getStore();
  if (!context) throw error('账号操作缺少安全上下文。', 503, 'ACCOUNT_GATE_UNAVAILABLE');
  const ledger = context.ledger, identity = `user:${userId}`;
  if (!ledger.accounts.has(identity)) ledger.accounts.set(identity, acquireAccountOperation(User, userId).then(release => { ledger.releases.push(release); }));
  await ledger.accounts.get(identity);
}
async function holdPostOperation(Post, postId) {
  const context = operations.getStore();
  if (!context) throw error('信息操作缺少安全上下文。', 503, 'ACCOUNT_GATE_UNAVAILABLE');
  const ledger = context.ledger, key = `post:${postId}`;
  if (!ledger.accounts.has(key)) ledger.accounts.set(key, (async () => {
    const post = await Post.findOneAndUpdate({ id: postId }, { $inc: { activePostOperations: 1 } }, { new: true });
    if (!post) return;
    let released = false;
    ledger.releases.push(() => {
      if (released) return; released = true;
      return Post.updateOne({ id: postId, activePostOperations: { $gt: 0 } }, { $inc: { activePostOperations: -1 } }).catch(() => {});
    });
  })());
  await ledger.accounts.get(key);
}
async function rows(Model, filter, session) {
  const result = await sessionQuery(Model.find(filter).limit(MAX_EXPORT_ROWS + 1).lean(), session);
  if (result.length > MAX_EXPORT_ROWS) throw error('资料数量较大，请联系隐私支持安排完整导出；此次没有生成不完整文件。', 413, 'EXPORT_TOO_LARGE');
  return result;
}

/** Explicit ownership and field lists: never export another person's received messages or contact snapshots. */
function buildAccountExport(data, timestamp = Date.now()) {
  const userId = data.user.id;
  const ownPosts = data.posts.filter(post => post.authorId === userId);
  return {
    formatVersion: 1, exportedAt: new Date(timestamp).toISOString(),
    profile: pick(plain(data.user), ['id', 'email', 'nickname', 'role', 'createdAt', 'bio', 'avatar', 'coverImage', 'contactType', 'contactValue', 'phone', 'isPhoneVerified', 'phoneVerifiedAt', 'area', 'city', 'profileTags', 'interests', 'socialIntents', 'profileVisibility', 'profileTheme', 'statusText', 'website', 'xiaohongshu', 'socialLinks']),
    posts: ownPosts.map(post => ({ ...pick(post, ['id', 'type', 'title', 'city', 'category', 'timeInfo', 'budget', 'description', 'imageUrls', 'createdAt', 'updatedAt', 'status', 'confirmedAt', 'isDeleted']),
      ownContactPreference: pick(post.contactPreference, ['mode', 'methods', 'updatedAt']) })),
    comments: data.commentedPosts.flatMap(post => (post.comments || []).filter(comment => comment.authorId === userId).map(comment => ({ postId: post.id, ...pick(comment, ['id', 'content', 'parentId', 'createdAt', 'updatedAt', 'isDeleted']) }))),
    sentMessages: data.messages.filter(message => message.senderId === userId && (message.messageType || 'text') === 'text' && (!message.type || message.type === 'text')).map(message => pick(message, ['id', 'conversationId', 'content', 'createdAt'])),
    contactRequests: data.contactRequests.filter(request => request.requesterId === userId).map(request => pick(request, ['id', 'postId', 'requestMessage', 'status', 'createdAt', 'respondedAt'])),
    planner: data.planner ? pick(data.planner, ['preferences', 'favorites', 'plans', 'importedEvents', 'webCandidates']) : null,
    eventInterests: data.interests.filter(row => row.userId === userId).map(row => pick(row, ['eventId', 'interested', 'lookingForBuddy', 'createdAt', 'updatedAt'])),
    outings: data.outings.map(row => ({
      ...pick(row, ['id', 'eventId', 'date', 'startTime', 'endTime', 'status']),
      ...(row.hostId === userId ? { hostedByMe: true, ...pick(row, ['title', 'description', 'venue', 'city', 'costNote', 'transport', 'language', 'capacity', 'createdAt']) } : { hostedByMe: false }),
      myMembership: pick((row.members || []).find(member => member.userId === userId), ['role', 'status', 'requestedAt', 'updatedAt', 'note']),
      myMessages: (row.messages || []).filter(message => message.senderId === userId).map(message => pick(message, ['id', 'text', 'createdAt'])),
      myPollAnswers: pick((row.timePoll?.votes || []).find(vote => vote.userId === userId), ['answers', 'updatedAt']),
    })),
    serviceBookings: data.agendas.flatMap(agenda => (agenda.bookings || []).filter(booking => agenda.providerId === userId || booking.customerId === userId).map(booking => ({
      ...pick(booking, ['id', 'postId', 'date', 'startTime', 'endTime', 'status', 'createdAt', 'updatedAt']),
      role: agenda.providerId === userId ? 'provider' : 'customer',
      // A customer's note belongs to that customer; a provider does not get a bulk export of customer notes.
      ...(booking.customerId === userId ? { myNote: booking.note || '' } : {}),
    }))),
    notes: ['Only your authored messages and your own contact details are included. Received messages, other members and contact cards are excluded.', 'Security secrets, tokens, password hashes and internal moderation details are never exported.'],
  };
}

async function loadAccountExport(models, user, now = Date.now()) {
  const id = user.id;
  const [posts, commentedPosts, messages, contactRequests, planners, interests, outings, agendas] = await Promise.all([
    rows(models.Post, { authorId: id }), rows(models.Post, { 'comments.authorId': id }),
    rows(models.Message, { senderId: id }), rows(models.ContactRequest, { requesterId: id }),
    rows(models.PlannerAccount, { userId: id }), rows(models.EventInterest, { userId: id }),
    rows(models.Outing, { $or: [{ hostId: id }, { 'members.userId': id }, { 'messages.senderId': id }] }),
    rows(models.ServiceBookingAgenda, { $or: [{ providerId: id }, { 'bookings.customerId': id }] }),
  ]);
  return buildAccountExport({ user, posts, commentedPosts, messages, contactRequests, planner: planners[0], interests, outings, agendas }, now);
}

/** Remove every stored copy of the post owner's private contact values; preserve opaque ids and status history. */
async function erasePostContacts(models, postIds, { session } = {}) {
  if (!postIds.length) return;
  const cards = await sessionQuery(models.Message.find({ 'contactCard.postId': { $in: postIds } }).select('id').lean(), session);
  await models.Post.updateMany({ id: { $in: postIds } }, { $set: { 'contactPreference.methods': [] } }, { session });
  await models.ContactRequest.updateMany({ postId: { $in: postIds } }, { $set: { contactSnapshot: [] }, $unset: { sharedMethods: 1 } }, { session, strict: false });
  await models.Message.updateMany({ 'contactCard.postId': { $in: postIds } }, { $set: { 'contactCard.methods': [], content: '这条信息的联系方式已移除。' } }, { session });
  if (cards.length) await models.Message.updateMany({ 'replyTo.id': { $in: cards.map(card => card.id) } }, { $unset: { replyTo: 1 } }, { session });
}

async function eraseAccountData(models, user, { session, now = Date.now(), eraseNotifications = async () => {} } = {}) {
  const id = user.id;
  const deletedId = `deleted_${crypto.randomUUID()}`;
  const sharedPosts = await rows(models.Post, { $or: [{ authorId: id }, { likes: id }, { 'comments.authorId': id }, { 'reports.reporterId': id }] }, session);
  if (sharedPosts.some(post => Number(post.activePostOperations) > 0)) throw error('相关信息仍在更新，请稍后重新登录并确认删除。', 409, 'ACCOUNT_OPERATIONS_PENDING');
  const posts = await rows(models.Post, { authorId: id }, session);
  const postIds = posts.map(post => post.id);
  await erasePostContacts(models, postIds, { session });
  await models.Post.updateMany({ authorId: id }, { $set: {
    isDeleted: true, status: 'closed', confirmedAt: null, authorId: deletedId, authorNickname: '已删除账号', authorAvatar: '',
    title: '已删除的信息', description: '', imageUrls: [], city: '', timeInfo: '', budget: '', comments: [], reports: [],
    'contactPreference.methods': [], updatedAt: now,
  } }, { session });
  await models.Post.updateMany({ $or: [{ likes: id }, { 'comments.authorId': id }, { 'reports.reporterId': id }] }, {
    $pull: { likes: id, comments: { authorId: id }, reports: { reporterId: id } },
  }, { session });
  await models.Message.deleteMany({ senderId: id }, { session });
  await models.Message.updateMany({ 'replyTo.senderId': id }, { $unset: { replyTo: 1 } }, { session });
  await models.Message.updateMany({ $or: [{ readBy: id }, { [`reactionVotes.${reactionKey(id)}`]: { $exists: true } }] }, {
    $pull: { readBy: id }, $unset: { [`reactionVotes.${reactionKey(id)}`]: 1 },
  }, { session });
  // MongoDB rejects $pull and $addToSet on the same path in one update (code 40),
  // so swap the member in two steps: add the placeholder while the filter still
  // matches, then remove the account. Both run inside the same transaction.
  await models.Conversation.updateMany({ userIds: id }, { $addToSet: { userIds: deletedId } }, { session });
  await models.Conversation.updateMany({ userIds: id }, { $pull: { userIds: id } }, { session });
  await models.ContactRequest.deleteMany({ $or: [{ requesterId: id }, { postOwnerId: id }] }, { session });
  await models.UserBlock.deleteMany({ $or: [{ blockerId: id }, { blockedUserId: id }] }, { session });
  await models.EventInterest.deleteMany({ userId: id }, { session });
  await models.PlannerAccount.deleteMany({ userId: id }, { session });
  // New entries are traceable to a post. Legacy hash-only entries may contain an
  // older edited source, so its current hash cannot establish safe ownership.
  // Drop that recomputable legacy cache during deletion rather than retain an
  // untraceable copy of contact details; other traceable posts stay cached.
  await models.PostTranslation.deleteMany({ $or: [{ postId: { $in: postIds } },
    { postId: { $exists: false } }, { postId: null }, { postId: '' }] }, { session });
  // Shared containers retain other people's authored data; only this account's entries are removed.
  await models.Outing.updateMany({ hostId: { $ne: id }, $or: [{ 'members.userId': id }, { 'messages.senderId': id }, { 'timePoll.votes.userId': id }, { 'notices.targetId': id }, { 'notices.actorId': id }] }, {
    $pull: { members: { userId: id }, messages: { senderId: id }, 'timePoll.votes': { userId: id }, notices: { $or: [{ actorId: id }, { targetId: id }] } },
    $inc: { revision: 1, notificationRevision: 1 }, $set: { updatedAt: now },
  }, { session });
  await models.Outing.updateMany({ hostId: id }, { $set: { hostId: deletedId, title: '已取消的小队', description: '', venue: '', city: '', costNote: '', status: 'cancelled', receipts: [], updatedAt: now },
    $pull: { members: { userId: id }, messages: { senderId: id }, 'timePoll.votes': { userId: id }, notices: { $or: [{ actorId: id }, { targetId: id }] } },
    $inc: { revision: 1, notificationRevision: 1 } }, { session });
  await models.ServiceBookingAgenda.deleteMany({ providerId: id }, { session });
  await models.ServiceBookingAgenda.updateMany({ 'bookings.customerId': id }, { $pull: { bookings: { customerId: id } }, $inc: { revision: 1 } }, { session });
  // Keep non-secret safety case/action timestamps, but erase personal evidence and copied profile/post values.
  const reportFilter = { $or: [{ reporterId: id }, { targetUserId: id }, { targetPostId: { $in: postIds } }] };
  await models.Report.updateMany(reportFilter, { $unset: { evidence: 1, detail: 1, adminNote: 1, reporterNickname: 1, targetConversationId: 1 } }, { session });
  await models.Report.updateMany({ reporterId: id }, { $set: { reporterId: deletedId } }, { session });
  await models.Report.updateMany({ targetUserId: id }, { $set: { targetUserId: deletedId, targetId: deletedId } }, { session });
  await models.ModerationLog.updateMany({ $or: [{ adminId: id }, { targetUserId: id }, { targetPostId: { $in: postIds } }] }, { $unset: { previousValue: 1, newValue: 1, reason: 1, note: 1, adminNickname: 1 } }, { session });
  await models.ModerationLog.updateMany({ targetUserId: id }, { $set: { targetUserId: deletedId } }, { session });
  await eraseNotifications(id, { session });
  if (models.AccountAuthChallenge) await models.AccountAuthChallenge.deleteMany({ userId: id }, { session });
  await models.User.deleteOne({ id, accountDeletionPending: true }, { session });
  return { success: true, deletedAt: now };
}

// The page shows the phrase in the reader's language; any of them confirms. Variant
// characters (账/帐/賬/帳, 注/註, 销/銷, 号/號), whitespace and letter case are not
// a reason to refuse an explicit, typed confirmation.
const DELETE_CONFIRMATIONS = Object.freeze({ 'zh-Hans': '注销我的账号', 'zh-Hant': '註銷我的帳號', en: 'DELETE MY ACCOUNT' });
const VARIANTS = { 註: '注', 銷: '销', 帳: '账', 賬: '账', 帐: '账', 號: '号' };
const confirmationKey = value => typeof value === 'string'
  ? value.normalize('NFKC').replace(/[註銷帳賬帐號]/g, char => VARIANTS[char]).replace(/\s+/g, '').toUpperCase() : '';
const ACCEPTED_CONFIRMATIONS = new Set(Object.values(DELETE_CONFIRMATIONS).map(confirmationKey));
const confirmsDeletion = value => ACCEPTED_CONFIRMATIONS.has(confirmationKey(value));
const deletionLocale = value => ['en', 'zh-Hant'].includes(value) ? value : 'zh-Hans';
const DELETION_MESSAGES = {
  confirm: {
    'zh-Hans': '请输入“注销我的账号”（或 DELETE MY ACCOUNT）确认永久删除。',
    'zh-Hant': '請輸入「註銷我的帳號」（或 DELETE MY ACCOUNT）確認永久刪除。',
    en: 'Type DELETE MY ACCOUNT to confirm permanent deletion.',
  },
  failed: {
    'zh-Hans': '账号删除没有完成，账号和资料都没有改动，你仍保持登录。请稍后重试。',
    'zh-Hant': '帳號刪除沒有完成，帳號和資料都沒有改動，你仍保持登入。請稍後重試。',
    en: 'Account deletion did not finish. Nothing was changed and you are still signed in. Please try again later.',
  },
  stuck: {
    'zh-Hans': '账号删除没有完成，账号暂时无法使用。请几分钟后重新登录再试；如仍无法登录，请通过隐私支持联系我们。',
    'zh-Hant': '帳號刪除沒有完成，帳號暫時無法使用。請幾分鐘後重新登入再試；如仍無法登入，請透過隱私支援聯絡我們。',
    en: 'Account deletion did not finish and the account is temporarily unavailable. Sign in again in a few minutes; if that fails, contact privacy support.',
  },
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
// Reopen the account after a failed erasure. A lost reopen would leave the account
// pending (every request refused), so retry briefly before giving up.
async function reopenAccount(User, userId, claim, { attempts = 3, delayMs = 250 } = {}) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await User.updateOne({ id: userId, accountDeletionClaim: claim }, { $set: { accountDeletionPending: false }, $unset: { accountDeletionClaim: 1 } });
      return true;
    } catch {
      if (attempt < attempts) await pause(delayMs * attempt);
    }
  }
  return false;
}
const failureCause = failure => ({ name: typeof failure?.name === 'string' ? failure.name.slice(0, 60) : 'Error',
  ...(['string', 'number'].includes(typeof failure?.code) ? { code: failure.code } : {}) });

function registerAccountPrivacy(app, { models, authenticateToken, confirmCredentials, limit, withTransaction, disconnectUser, eraseNotifications, now = Date.now, reopenDelayMs = 250 }) {
  app.post('/api/users/me/privacy/export', authenticateToken, limit, async (req, res) => {
    const user = await confirmCredentials(req);
    const data = await loadAccountExport(models, user, now());
    res.set('Cache-Control', 'no-store');
    res.set('Content-Disposition', 'attachment; filename="baylink-account.json"');
    res.json(data);
  });
  app.delete('/api/users/me/privacy/account', authenticateToken, limit, async (req, res) => {
    const user = await confirmCredentials(req);
    const locale = deletionLocale(req.body?.locale);
    if (!confirmsDeletion(req.body?.confirmation)) throw error(DELETION_MESSAGES.confirm[locale], 400, 'DELETE_CONFIRMATION_REQUIRED');
    // A sole or accidental administrator deletion must never disable the site's recovery path.
    if (user.role === 'admin') throw error('管理员须先安全移交管理权限，再以普通账号执行删除。', 409, 'ADMIN_HANDOVER_REQUIRED');
    const claim = crypto.randomUUID();
    // The pending flag alone refuses every session and new account operation while
    // erasure runs (and a successful erasure removes the user row). Sessions are not
    // revoked here, so a failed attempt does not sign the owner out.
    const claimed = await models.User.findOneAndUpdate({ id: user.id, password: user.password, accountDeletionPending: { $ne: true },
      $or: [{ activeAccountOperations: 0 }, { activeAccountOperations: { $exists: false } }],
    }, { $set: { accountDeletionPending: true, accountDeletionClaim: claim } }, { new: true });
    if (!claimed) throw error('还有账号操作尚未结束，请稍后重新确认删除。', 409, 'ACCOUNT_OPERATIONS_PENDING');
    disconnectUser(user.id);
    let result;
    try { result = await withTransaction(session => eraseAccountData(models, user, { session, now: now(), eraseNotifications })); }
    catch (failure) {
      // A transaction failure leaves no partial erasure: reopen the account with
      // its sessions intact and report a localized, retryable failure.
      const reopened = await reopenAccount(models.User, user.id, claim, { delayMs: reopenDelayMs });
      if (failure?.publicSafe === true && reopened) throw failure;
      throw Object.assign(error(DELETION_MESSAGES[reopened ? 'failed' : 'stuck'][locale], reopened ? 500 : 503, reopened ? 'ACCOUNT_DELETE_FAILED' : 'ACCOUNT_DELETE_INTERRUPTED'),
        { cause: failureCause(failure) });
    }
    res.json(result);
  });
  app.post('/api/users/me/security/revoke-sessions', authenticateToken, limit, async (req, res) => {
    const user = await confirmCredentials(req);
    const changed = await models.User.updateOne({ id: user.id, password: user.password, passwordChangedAt: user.passwordChangedAt || null, accountDeletionPending: { $ne: true } }, { $set: { sessionsRevokedAt: now() }, $inc: { sessionRevision: 1 } });
    if (changed.modifiedCount !== 1) throw error('账号凭证已变化，请重新登录确认。', 409, 'ACCOUNT_CHANGED');
    disconnectUser(user.id);
    res.json({ success: true });
  });
}

module.exports = { buildAccountExport, loadAccountExport, erasePostContacts, eraseAccountData, acquireAccountOperation, holdAccountOperation, holdPostOperation, runAccountHandler, registerAccountPrivacy, privacyError: error, DELETE_CONFIRMATIONS, confirmsDeletion };
