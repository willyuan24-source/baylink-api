require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const http = require('http');
const { Server } = require('socket.io');
const twilio = require('twilio');
const bcrypt = require('bcryptjs'); // ✨ 新增：引入加密庫
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const ALLOWED_ORIGINS = [
  'https://www.baylink.us',
  'https://baylink.us',
  'http://localhost:5173',
];

const corsOriginCheck = (origin, callback) => {
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    callback(null, true);
  } else {
    callback(new Error('Not allowed by CORS'));
  }
};

// --- 生产环境安全检查 ---
const requiredEnvs = ['MONGO_URI', 'JWT_SECRET', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
const missingEnvs = requiredEnvs.filter(key => !process.env[key]);
if (missingEnvs.length > 0) {
    console.error(`❌ 致命错误: 缺少环境变量: ${missingEnvs.join(', ')}`);
    process.exit(1);
}

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// --- 配置区域 ---
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// Twilio 初始化
const TWILIO_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE = process.env.TWILIO_PHONE_NUMBER;
const twilioClient = (TWILIO_SID && TWILIO_TOKEN) ? twilio(TWILIO_SID, TWILIO_TOKEN) : null;

if (!twilioClient) console.warn("⚠️ 警告: 未配置 Twilio，手机验证将使用模拟模式 (查看 Server Log)。");

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '7d';
const MONGO_URI = process.env.MONGO_URI;
const SEARCH_KEYWORD_MAX_LENGTH = 80; 

app.use(cors({ origin: corsOriginCheck, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

mongoose.connect(MONGO_URI).then(() => console.log('✅ MongoDB Connected')).catch(err => console.error(err));

// --- Socket.io ---
io.on('connection', (socket) => {
  socket.on('join_room', (userId) => { if (userId) socket.join(userId); });
});

// --- Schemas ---
const OfficialVerificationSchema = new mongoose.Schema(
  {
    status: {
      type: String,
      enum: ['none', 'pending', 'approved', 'rejected'],
      default: 'none',
    },
    type: {
      type: String,
      enum: [
        'realtor',
        'service_provider',
        'business',
        'official_account',
        'community_org',
        'other',
        '',
      ],
      default: '',
    },
    description: { type: String, default: '' },
    website: { type: String, default: '' },
    license: { type: String, default: '' },
    socialLink: { type: String, default: '' },
    submittedAt: { type: Number, default: null },
    reviewedAt: { type: Number, default: null },
    reviewedBy: { type: String, default: '' },
    rejectionReason: { type: String, default: '' },
  },
  { _id: false }
);

const defaultOfficialVerification = () => ({
  status: 'none',
  type: '',
  description: '',
  website: '',
  license: '',
  socialLink: '',
  submittedAt: null,
  reviewedAt: null,
  reviewedBy: '',
  rejectionReason: '',
});

const normalizeOfficialVerificationData = (ov) => {
  if (ov == null) return defaultOfficialVerification();
  if (typeof ov === 'string') {
    const s = ov.trim();
    const legacyStatuses = new Set(['none', 'pending', 'approved', 'rejected']);
    return {
      ...defaultOfficialVerification(),
      status: legacyStatuses.has(s) ? s : 'none',
    };
  }
  if (typeof ov !== 'object' || Array.isArray(ov)) return defaultOfficialVerification();
  return {
    status: ov.status || 'none',
    type: ov.type || '',
    description: ov.description || '',
    website: ov.website || '',
    license: ov.license || '',
    socialLink: ov.socialLink || '',
    submittedAt: ov.submittedAt ?? null,
    reviewedAt: ov.reviewedAt ?? null,
    reviewedBy: ov.reviewedBy || '',
    rejectionReason: ov.rejectionReason || '',
  };
};

const UserSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nickname: String,
  role: { type: String, default: 'user' },
  contactType: String,
  contactValue: String,
  isBanned: { type: Boolean, default: false },
  
  // ✨ 信任体系字段
  isPhoneVerified: { type: Boolean, default: false },
  isOfficialVerified: { type: Boolean, default: false },
  phone: String,
  phoneNormalized: String,
  phoneVerifiedAt: Number,
  phoneVerificationCodeHash: String,
  phoneVerificationExpiresAt: Number,
  phoneVerificationAttempts: { type: Number, default: 0 },
  phoneVerificationLastSentAt: Number,
  verifyCode: String, 
  verifyCodeExpires: Number, 
  lastSmsSentAt: Number, 
  verifyAttempts: { type: Number, default: 0 }, // 防暴力破解（旧字段，保留兼容）
  passwordResetTokenHash: String,
  passwordResetExpires: Number,
  passwordResetRequestedAt: Number,
  passwordResetUsedAt: Number,
  passwordChangedAt: Number,

  bio: String,
  avatar: String,
  area: String,
  city: String,
  profileTags: [String],
  interests: [String],
  website: String,
  xiaohongshu: String,
  socialLinks: { linkedin: String, instagram: String },
  officialVerification: {
    type: OfficialVerificationSchema,
    default: () => ({
      status: 'none',
      type: '',
      description: '',
      website: '',
      license: '',
      socialLink: '',
      submittedAt: null,
      reviewedAt: null,
      reviewedBy: '',
      rejectionReason: '',
    }),
  },
  accountStatus: {
    type: String,
    enum: ['active', 'limited', 'suspended'],
    default: 'active',
  },
  accountStatusReason: { type: String, default: '' },
  accountStatusUpdatedAt: { type: Number, default: null },
  accountStatusUpdatedBy: { type: String, default: '' },
  createdAt: { type: Number, default: Date.now }
});

// ✨ 新增：在儲存用戶資料前，自動攔截密碼並進行 Bcrypt Hash 加密
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (e) {
    next(e);
  }
});

UserSchema.post('init', function coerceLegacyOfficialVerification() {
  if (typeof this.officialVerification === 'string') {
    this.set('officialVerification', normalizeOfficialVerificationData(this.officialVerification));
    this.markModified('officialVerification');
  }
});

const PostSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  authorId: String,
  authorNickname: String,
  authorAvatar: String,
  type: String,
  title: String,
  city: String,
  category: String,
  timeInfo: String,
  budget: String,
  description: String,
  imageUrls: [String],
  likes: [String],
  comments: [{ id: String, authorId: String, authorName: String, content: String, createdAt: Number }],
  reports: [{ reporterId: String, reason: String, createdAt: Number }],
  isDeleted: { type: Boolean, default: false },
  createdAt: { type: Number, default: Date.now },
  updatedAt: { type: Number },
  isFeatured: { type: Boolean, default: false },
  featuredAt: { type: Date },
  featuredBy: { type: String },
  adminHidden: { type: Boolean, default: false },
  adminHiddenAt: { type: Number, default: null },
  adminHiddenBy: { type: String, default: '' },
  adminHiddenReason: { type: String, default: '' },
  contactPreference: {
    mode: { type: String, enum: ['dm_first', 'auto_send', 'manual_approve'], default: 'dm_first' },
    methods: [{
      type: { type: String, enum: ['wechat', 'phone', 'email', 'other'], default: 'other' },
      label: { type: String, default: '' },
      value: { type: String, default: '' },
      note: { type: String, default: '' },
      enabled: { type: Boolean, default: true },
    }],
    updatedAt: { type: Number, default: null },
  },
});

const AdSchema = new mongoose.Schema({ id: String, title: String, content: String, imageUrl: String, isVerified: { type: Boolean, default: true } });
const ConversationSchema = new mongoose.Schema({ id: { type: String, unique: true }, userIds: [String], updatedAt: { type: Number, default: Date.now } });
const MessageSchema = new mongoose.Schema({
  id: String,
  conversationId: String,
  senderId: String,
  type: String,
  messageType: { type: String, enum: ['text', 'system', 'contact_card'], default: 'text' },
  content: String,
  contactCard: {
    postId: { type: String, default: '' },
    contactRequestId: { type: String, default: '' },
    methods: [{
      type: { type: String, enum: ['wechat', 'phone', 'email', 'other'], default: 'other' },
      label: { type: String, default: '' },
      value: { type: String, default: '' },
      note: { type: String, default: '' },
    }],
  },
  createdAt: { type: Number, default: Date.now },
});
const ContentSchema = new mongoose.Schema({ key: { type: String, unique: true }, value: String });

const ReportSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  reporterId: String,
  reporterNickname: String,
  targetType: { type: String, enum: ['post', 'user'], required: true },
  targetId: { type: String, required: true },
  targetPostId: { type: String, default: '' },
  targetUserId: { type: String, default: '' },
  reason: {
    type: String,
    enum: ['spam', 'scam', 'harassment', 'illegal', 'misleading', 'duplicate', 'other'],
    required: true,
  },
  detail: { type: String, default: '' },
  status: { type: String, enum: ['open', 'reviewed', 'dismissed'], default: 'open' },
  adminNote: { type: String, default: '' },
  createdAt: { type: Number, default: Date.now },
  updatedAt: { type: Number, default: Date.now },
  reviewedAt: { type: Number, default: null },
  reviewedBy: { type: String, default: '' },
});
ReportSchema.index({ reporterId: 1, targetType: 1, targetId: 1, createdAt: -1 });
ReportSchema.index({ status: 1, createdAt: -1 });
ReportSchema.index({ targetType: 1, status: 1, createdAt: -1 });

const UserBlockSchema = new mongoose.Schema({
  blockerId: { type: String, required: true },
  blockedUserId: { type: String, required: true },
  reason: { type: String, default: '' },
  createdAt: { type: Number, default: Date.now },
  updatedAt: { type: Number, default: Date.now },
});
UserBlockSchema.index({ blockerId: 1, blockedUserId: 1 }, { unique: true });

const ContactRequestSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  postId: { type: String, required: true },
  postOwnerId: { type: String, required: true },
  requesterId: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'declined', 'auto_sent', 'cancelled'], default: 'pending' },
  requestMessage: { type: String, default: '' },
  contactSnapshot: [{
    type: { type: String, enum: ['wechat', 'phone', 'email', 'other'], default: 'other' },
    label: { type: String, default: '' },
    value: { type: String, default: '' },
    note: { type: String, default: '' },
  }],
  messageId: { type: String, default: '' },
  threadId: { type: String, default: '' },
  createdAt: { type: Number, default: Date.now },
  respondedAt: { type: Number, default: null },
  sentAt: { type: Number, default: null },
});
ContactRequestSchema.index({ postId: 1, requesterId: 1, status: 1 });
ContactRequestSchema.index({ postOwnerId: 1, status: 1, createdAt: -1 });
ContactRequestSchema.index({ requesterId: 1, createdAt: -1 });

const ModerationLogSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  adminId: String,
  adminNickname: String,
  action: String,
  targetType: String,
  targetId: String,
  targetUserId: { type: String, default: '' },
  targetPostId: { type: String, default: '' },
  targetReportId: { type: String, default: '' },
  previousValue: mongoose.Schema.Types.Mixed,
  newValue: mongoose.Schema.Types.Mixed,
  reason: { type: String, default: '' },
  note: { type: String, default: '' },
  createdAt: { type: Number, default: Date.now },
});
ModerationLogSchema.index({ createdAt: -1 });
ModerationLogSchema.index({ action: 1, createdAt: -1 });
ModerationLogSchema.index({ targetType: 1, createdAt: -1 });
ModerationLogSchema.index({ targetUserId: 1, createdAt: -1 });
ModerationLogSchema.index({ targetPostId: 1, createdAt: -1 });

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Ad = mongoose.model('Ad', AdSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Message = mongoose.model('Message', MessageSchema);
const Content = mongoose.model('Content', ContentSchema);
const Report = mongoose.model('Report', ReportSchema);
const UserBlock = mongoose.model('UserBlock', UserBlockSchema);
const ContactRequest = mongoose.model('ContactRequest', ContactRequestSchema);
const ModerationLog = mongoose.model('ModerationLog', ModerationLogSchema);

const CONTACT_PREFERENCE_MODES = new Set(['dm_first', 'auto_send', 'manual_approve']);
const CONTACT_METHOD_TYPES = new Set(['wechat', 'phone', 'email', 'other']);
const ACTIVE_CONTACT_REQUEST_STATUSES = ['pending', 'approved', 'auto_sent'];

const defaultContactPreference = () => ({
  mode: 'dm_first',
  methods: [],
  updatedAt: null,
});

const normalizeContactMethod = (raw) => {
  const type = CONTACT_METHOD_TYPES.has(raw?.type) ? raw.type : 'other';
  return {
    type,
    label: trimProfileString(raw?.label || formatContactTypeLabel(type), 40),
    value: trimProfileString(raw?.value || '', 120),
    note: trimProfileString(raw?.note || '', 120),
    enabled: raw?.enabled !== false,
  };
};

const normalizeContactPreference = (raw) => {
  if (!raw || typeof raw !== 'object') return defaultContactPreference();
  const mode = CONTACT_PREFERENCE_MODES.has(raw.mode) ? raw.mode : 'dm_first';
  const methods = Array.isArray(raw.methods)
    ? raw.methods.map(normalizeContactMethod).filter((m) => m.value || m.label)
    : [];
  return { mode, methods, updatedAt: Date.now() };
};

const validateContactPreference = (pref) => {
  if (!pref || !CONTACT_PREFERENCE_MODES.has(pref.mode)) {
    return '联系方式设置无效';
  }
  if (pref.mode === 'auto_send' || pref.mode === 'manual_approve') {
    const enabled = (pref.methods || []).filter((m) => m.enabled !== false && String(m.value || '').trim());
    if (!enabled.length) return '请至少填写一种可用的联系方式';
  }
  return null;
};

const sanitizeContactPreferenceForViewer = (contactPreference, postAuthorId, currentUserId, isAdmin) => {
  const pref = contactPreference || defaultContactPreference();
  const mode = CONTACT_PREFERENCE_MODES.has(pref.mode) ? pref.mode : 'dm_first';
  const canSeeValues = !!isAdmin || (!!currentUserId && currentUserId === postAuthorId);
  const methods = (pref.methods || [])
    .filter((m) => m.enabled !== false)
    .map((m) => {
      const item = {
        type: m.type || 'other',
        label: m.label || '',
        note: m.note || '',
        enabled: m.enabled !== false,
      };
      if (canSeeValues) item.value = m.value || '';
      return item;
    });
  return { mode, methods, updatedAt: pref.updatedAt || null };
};

const buildContactCardMethods = (contactPreference) => (contactPreference?.methods || [])
  .filter((m) => m.enabled !== false && String(m.value || '').trim())
  .map((m) => ({
    type: m.type || 'other',
    label: m.label || formatContactTypeLabel(m.type),
    value: String(m.value).trim(),
    note: m.note || '',
  }));

const formatContactRequestForClient = (doc) => ({
  id: doc.id,
  postId: doc.postId,
  postOwnerId: doc.postOwnerId,
  requesterId: doc.requesterId,
  status: doc.status,
  requestMessage: doc.requestMessage || '',
  threadId: doc.threadId || '',
  messageId: doc.messageId || '',
  createdAt: doc.createdAt,
  respondedAt: doc.respondedAt || null,
  sentAt: doc.sentAt || null,
});

const openOrCreateConversationBetween = async (userIdA, userIdB) => {
  let conv = await Conversation.findOne({ userIds: { $all: [userIdA, userIdB] } });
  if (!conv) {
    await assertCanMessage(userIdA, userIdB);
    conv = await Conversation.create({ id: Date.now().toString(), userIds: [userIdA, userIdB] });
  }
  return conv;
};

const sendContactCardMessage = async ({ conversationId, senderId, recipientId, postId, contactRequestId, methods }) => {
  const msg = await Message.create({
    id: Date.now().toString(),
    conversationId,
    senderId,
    type: 'contact_card',
    messageType: 'contact_card',
    content: 'BAYLINK 联系方式卡片',
    contactCard: { postId, contactRequestId, methods },
    createdAt: Date.now(),
  });
  await Conversation.findOneAndUpdate({ id: conversationId }, { updatedAt: Date.now() });
  if (recipientId) io.to(recipientId).emit('new_message', msg);
  return msg;
};

const formatMessagePreview = (msg) => {
  if (!msg) return '';
  if (msg.messageType === 'contact_card' || msg.type === 'contact_card') return '[联系方式卡片]';
  if (msg.type === 'contact-share') return '[联系方式]';
  return msg.type === 'text' ? (msg.content || '') : `[${msg.type}]`;
};

const MODERATION_LOG_ACTIONS = new Set([
  'official_verification_approved',
  'official_verification_rejected',
  'report_reviewed',
  'report_dismissed',
  'report_reopened',
  'post_hidden',
  'post_unhidden',
  'account_limited',
  'account_suspended',
  'account_restored',
]);
const MODERATION_LOG_TARGET_TYPES = new Set(['user', 'post', 'report', 'official_verification']);

const REPORT_TARGET_TYPES = new Set(['post', 'user']);
const REPORT_REASONS = new Set(['spam', 'scam', 'harassment', 'illegal', 'misleading', 'duplicate', 'other']);
const REPORT_STATUSES = new Set(['open', 'reviewed', 'dismissed', 'all']);
const REPORT_ADMIN_STATUSES = new Set(['open', 'reviewed', 'dismissed']);
const REPORT_DUPLICATE_WINDOW_MS = 24 * 60 * 60 * 1000;

const reportRateByUser = new Map();

const checkReportRateLimit = (userId) => {
  const key = String(userId);
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 5;
  let entry = reportRateByUser.get(key);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 0, windowStart: now };
  }
  entry.count += 1;
  reportRateByUser.set(key, entry);
  if (reportRateByUser.size > 5000) {
    for (const [k, val] of reportRateByUser) {
      if (now - val.windowStart >= windowMs) reportRateByUser.delete(k);
    }
  }
  return entry.count <= maxRequests;
};

const authRateByKey = new Map();

const getClientIp = (req) => {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.trim()) return xf.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
};

const AUTH_RATE_LIMIT_MSG = '操作太频繁，请稍后再试。';

const checkAuthRateLimit = (key, { windowMs = 15 * 60 * 1000, maxRequests = 5 } = {}) => {
  const rateKey = String(key);
  const now = Date.now();
  let entry = authRateByKey.get(rateKey);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 0, windowStart: now };
  }
  entry.count += 1;
  authRateByKey.set(rateKey, entry);
  if (authRateByKey.size > 5000) {
    for (const [k, val] of authRateByKey) {
      if (now - val.windowStart >= windowMs) authRateByKey.delete(k);
    }
  }
  return entry.count <= maxRequests;
};

const requireAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ ok: false, error: '需要管理员权限' });
  }
  next();
};

const clampReportDetail = (value) => {
  const detail = String(value ?? '').trim();
  return detail.length > 500 ? detail.slice(0, 500) : detail;
};

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const normalizeSearchKeyword = (keyword) => {
  const trimmed = String(keyword || '').trim();
  if (trimmed.length > SEARCH_KEYWORD_MAX_LENGTH) {
    return { ok: false, error: '搜索关键词过长' };
  }
  return { ok: true, keyword: trimmed };
};

const parsePublicFeedPagination = (query, defaultLimit = 10) => {
  const pageRaw = parseInt(query.page, 10);
  const limitRaw = parseInt(query.limit, 10);
  const page = Number.isFinite(pageRaw) && pageRaw >= 1 ? pageRaw : 1;
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : defaultLimit;
  return { page, limit, skip: (page - 1) * limit };
};

const formatContactTypeLabel = (contactType) => {
  const t = String(contactType || '').trim().toLowerCase();
  if (t === 'wechat') return '微信';
  if (t === 'phone') return '电话';
  if (t === 'email') return '邮箱';
  return '联系方式';
};

const isAdminUserId = async (userId) => {
  if (!userId) return false;
  const user = await User.findOne({ id: userId }).select('role').lean();
  return user?.role === 'admin';
};

const applyPublicPostVisibility = async (query, viewerUserId) => {
  if (!(await isAdminUserId(viewerUserId))) {
    query.adminHidden = { $ne: true };
  }
};

const getBlockedAuthorIdsForUser = async (userId) => {
  const id = typeof userId === 'object' ? userId?.id : userId;
  if (!id) return [];
  const blocks = await UserBlock.find({ blockerId: id }).select('blockedUserId').lean();
  return blocks.map((b) => b.blockedUserId).filter(Boolean);
};

const getBlockRelation = async (viewerId, targetUserId) => {
  if (!viewerId || !targetUserId || viewerId === targetUserId) {
    return { viewerHasBlockedUser: false, viewerIsBlockedByUser: false };
  }
  const [blockedByViewer, blockedByTarget] = await Promise.all([
    UserBlock.findOne({ blockerId: viewerId, blockedUserId: targetUserId }).select('_id').lean(),
    UserBlock.findOne({ blockerId: targetUserId, blockedUserId: viewerId }).select('_id').lean(),
  ]);
  return {
    viewerHasBlockedUser: !!blockedByViewer,
    viewerIsBlockedByUser: !!blockedByTarget,
  };
};

const ACCOUNT_STATUSES = new Set(['active', 'limited', 'suspended']);

const getAccountStatus = (user) => {
  const status = user?.accountStatus;
  if (ACCOUNT_STATUSES.has(status)) return status;
  return 'active';
};

const assertAccountCanPost = (user) => {
  if (user?.role === 'admin') return null;
  const status = getAccountStatus(user);
  if (status === 'limited' || status === 'suspended') {
    return '你的账号当前受到限制，暂时无法发布内容。';
  }
  return null;
};

const assertAccountCanMessage = (user) => {
  if (user?.role === 'admin') return null;
  const status = getAccountStatus(user);
  if (status === 'limited' || status === 'suspended') {
    return '你的账号当前受到限制，暂时无法发送私信。';
  }
  return null;
};

const MODERATION_LOG_SENSITIVE_KEYS = new Set([
  'email', 'phone', 'password', 'token', 'verifyCode', 'passwordResetTokenHash',
  'phoneVerificationCodeHash', 'phoneNormalized', 'passwordResetToken',
]);

const sanitizeModerationLogValue = (value) => {
  if (value == null) return value;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(sanitizeModerationLogValue);
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (MODERATION_LOG_SENSITIVE_KEYS.has(k)) continue;
      out[k] = sanitizeModerationLogValue(v);
    }
    return out;
  }
  return value;
};

async function createModerationLog({
  admin,
  action,
  targetType,
  targetId,
  targetUserId = '',
  targetPostId = '',
  targetReportId = '',
  previousValue = null,
  newValue = null,
  reason = '',
  note = '',
}) {
  try {
    const now = Date.now();
    await ModerationLog.create({
      id: `${now}_${crypto.randomBytes(4).toString('hex')}`,
      adminId: admin?.id || '',
      adminNickname: admin?.nickname || admin?.name || 'Admin',
      action: String(action || '').trim(),
      targetType: String(targetType || '').trim(),
      targetId: String(targetId || '').trim(),
      targetUserId: String(targetUserId || '').trim(),
      targetPostId: String(targetPostId || '').trim(),
      targetReportId: String(targetReportId || '').trim(),
      previousValue: sanitizeModerationLogValue(previousValue),
      newValue: sanitizeModerationLogValue(newValue),
      reason: trimProfileString(reason, 500),
      note: trimProfileString(note, 500),
      createdAt: now,
    });
  } catch (err) {
    console.error('[moderation log error]', err);
  }
}

const formatModerationLogForAdmin = (doc) => ({
  id: doc.id || String(doc._id),
  admin: {
    id: doc.adminId || '',
    nickname: doc.adminNickname || 'Admin',
  },
  action: doc.action || '',
  targetType: doc.targetType || '',
  targetId: doc.targetId || '',
  targetUserId: doc.targetUserId || '',
  targetPostId: doc.targetPostId || '',
  targetReportId: doc.targetReportId || '',
  previousValue: doc.previousValue ?? {},
  newValue: doc.newValue ?? {},
  reason: doc.reason || '',
  note: doc.note || '',
  createdAt: doc.createdAt,
});

const assertCanMessage = async (senderId, recipientId) => {
  const rel = await getBlockRelation(senderId, recipientId);
  if (rel.viewerHasBlockedUser) {
    const err = new Error('你已屏蔽该用户，取消屏蔽后才能发送消息。');
    err.statusCode = 400;
    throw err;
  }
  if (rel.viewerIsBlockedByUser) {
    const err = new Error('暂时无法向该用户发送消息。');
    err.statusCode = 403;
    throw err;
  }
};

const getCurrentUserIdFromRequest = (req) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return null;
  try { return jwt.verify(authHeader.split(' ')[1], JWT_SECRET).id; } catch (e) { return null; }
};

const resolveReportTarget = async (targetType, targetId) => {
  const id = String(targetId ?? '').trim();
  if (!id) return { ok: false, error: '举报目标无效' };
  try {
    if (targetType === 'post') {
      const post = await Post.findOne({ id, isDeleted: false }).select('id authorId').lean();
      if (!post) return { ok: false, error: '帖子不存在或已删除' };
      return { ok: true, targetId: id, targetPostId: id, targetUserId: post.authorId || '' };
    }
    if (targetType === 'user') {
      const user = await User.findOne({ id }).select('id').lean();
      if (!user) return { ok: false, error: '用户不存在' };
      return { ok: true, targetId: id, targetPostId: '', targetUserId: id };
    }
  } catch (_) {
    return { ok: false, error: '举报目标无效' };
  }
  return { ok: false, error: '举报目标无效' };
};

const formatTrustUserSummary = (user) => {
  if (!user) return null;
  return {
    id: user.id,
    nickname: user.nickname,
    avatar: user.avatar,
    isPhoneVerified: !!user.isPhoneVerified,
    isOfficialVerified: !!user.isOfficialVerified,
    accountStatus: getAccountStatus(user),
  };
};

const formatAdminUserSummary = (user) => {
  if (!user) return null;
  return {
    id: user.id,
    nickname: user.nickname,
    avatar: user.avatar,
    isPhoneVerified: !!user.isPhoneVerified,
    isOfficialVerified: !!user.isOfficialVerified,
    accountStatus: getAccountStatus(user),
    accountStatusReason: user.accountStatusReason || '',
    accountStatusUpdatedAt: user.accountStatusUpdatedAt ?? null,
    accountStatusUpdatedBy: user.accountStatusUpdatedBy || '',
  };
};

const formatAdminPostSummary = (post) => {
  if (!post) return null;
  return {
    id: post.id,
    title: post.title,
    category: post.category,
    area: post.city || '',
    createdAt: post.createdAt,
    adminHidden: !!post.adminHidden,
  };
};

const formatAdminReportsList = async (docs) => {
  const userIds = [...new Set(docs.flatMap((d) => [d.targetUserId, d.reporterId]).filter(Boolean))];
  const postIds = [...new Set(docs.map((d) => d.targetPostId).filter(Boolean))];

  const [users, posts] = await Promise.all([
    userIds.length
      ? User.find({ id: { $in: userIds } }).select('id nickname avatar isPhoneVerified isOfficialVerified accountStatus accountStatusReason accountStatusUpdatedAt accountStatusUpdatedBy').lean()
      : [],
    postIds.length
      ? Post.find({ id: { $in: postIds } }).select('id title category city createdAt adminHidden').lean()
      : [],
  ]);

  const userById = new Map(users.map((u) => [u.id, u]));
  const postById = new Map(posts.map((p) => [p.id, p]));

  return docs.map((doc) => ({
    id: doc.id || String(doc._id),
    targetType: doc.targetType,
    targetId: doc.targetId,
    reason: doc.reason,
    detail: doc.detail || '',
    status: doc.status,
    adminNote: doc.adminNote || '',
    createdAt: doc.createdAt,
    reviewedAt: doc.reviewedAt ?? null,
    reporter: formatTrustUserSummary(userById.get(doc.reporterId)),
    targetUser: formatAdminUserSummary(userById.get(doc.targetUserId)),
    targetPost: formatAdminPostSummary(postById.get(doc.targetPostId)),
  }));
};

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const validatePasswordStrength = (password) =>
  typeof password === 'string' &&
  password.length >= 8 &&
  /[A-Z]/.test(password) &&
  /[a-z]/.test(password) &&
  /[0-9]/.test(password);

const trimProfileString = (value, maxLen) => {
  const s = String(value ?? '').trim();
  if (!s) return '';
  return s.length > maxLen ? s.slice(0, maxLen) : s;
};

const sanitizeProfileStringArray = (value, { maxItems = 12, maxLen = 20 } = {}) => {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const item of value) {
    const s = String(item ?? '').trim();
    if (!s) continue;
    const clipped = s.length > maxLen ? s.slice(0, maxLen) : s;
    if (seen.has(clipped)) continue;
    seen.add(clipped);
    out.push(clipped);
    if (out.length >= maxItems) break;
  }
  return out;
};

const formatPublicProfileFields = (user) => ({
  area: user.area || '',
  city: user.city || '',
  profileTags: user.profileTags || [],
  interests: user.interests || [],
  website: user.website || '',
  xiaohongshu: user.xiaohongshu || '',
  socialLinks: user.socialLinks || { linkedin: '', instagram: '' },
});

const OFFICIAL_VERIFICATION_TYPES = new Set([
  'realtor', 'service_provider', 'business', 'official_account', 'community_org', 'other',
]);
const OFFICIAL_VERIFICATION_TYPE_ALIASES = {
  '房地产经纪': 'realtor',
  '房产经纪': 'realtor',
  '经纪人': 'realtor',
  '本地服务商': 'service_provider',
  '服务商': 'service_provider',
  '商家': 'business',
  '官方账号': 'official_account',
  '社区组织': 'community_org',
  '其他': 'other',
};
const OPTIONAL_OFFICIAL_FIELD_EMPTY = new Set([
  '没有', '无', 'none', 'n/a', 'na', 'null', 'undefined',
]);
const OFFICIAL_VERIFICATION_LIST_STATUSES = new Set(['pending', 'approved', 'rejected', 'all']);

const normalizeOptionalOfficialField = (value) => {
  const s = String(value ?? '').trim();
  if (!s) return '';
  const lower = s.toLowerCase();
  if (OPTIONAL_OFFICIAL_FIELD_EMPTY.has(lower) || OPTIONAL_OFFICIAL_FIELD_EMPTY.has(s)) return '';
  return s;
};

const normalizeOfficialVerificationType = (raw) => {
  const s = String(raw ?? '').trim();
  if (!s) return '';
  if (OFFICIAL_VERIFICATION_TYPES.has(s)) return s;
  return OFFICIAL_VERIFICATION_TYPE_ALIASES[s] || '';
};

const normalizeOptionalOfficialUrl = (value, maxLen) => {
  const normalized = normalizeOptionalOfficialField(value);
  if (!normalized) return { value: '' };
  const clipped = normalized.length > maxLen ? normalized.slice(0, maxLen) : normalized;
  if (!/^https?:\/\//i.test(clipped) || !isValidHttpUrl(clipped)) {
    return { error: '请填写有效链接，或留空。' };
  }
  return { value: clipped };
};

const getOfficialVerificationStatus = (user) => {
  const ov = user?.officialVerification;
  if (typeof ov === 'string') {
    const s = ov.trim();
    if (['none', 'pending', 'approved', 'rejected'].includes(s)) return s;
    return 'none';
  }
  return ov?.status || 'none';
};

const formatPublicOfficialVerification = (user) => {
  const raw = user?.officialVerification;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const ov = normalizeOfficialVerificationData(raw);
  if (ov.status !== 'approved' || !user.isOfficialVerified) return undefined;
  return { status: 'approved', type: ov.type || '' };
};

const formatAdminOfficialVerificationRequest = (user) => {
  const ov = normalizeOfficialVerificationData(user?.officialVerification);
  return {
    id: user.id,
    nickname: user.nickname,
    avatar: user.avatar,
    isPhoneVerified: !!user.isPhoneVerified,
    phoneVerifiedAt: user.phoneVerifiedAt ?? null,
    isOfficialVerified: !!user.isOfficialVerified,
    officialVerification: {
      status: ov.status,
      type: ov.type,
      description: ov.description,
      website: ov.website,
      license: ov.license,
      socialLink: ov.socialLink,
      submittedAt: ov.submittedAt,
      reviewedAt: ov.reviewedAt,
      rejectionReason: ov.rejectionReason,
    },
  };
};

const isValidHttpUrl = (value) => {
  try {
    const url = new URL(String(value).trim());
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

const sanitizeOptionalImageUrl = (value) => {
  const imageUrl = String(value || '').trim();
  if (!imageUrl) return '';
  if (!isValidHttpUrl(imageUrl)) {
    const err = new Error('Invalid image URL');
    err.statusCode = 400;
    throw err;
  }
  return imageUrl;
};

const buildAdPayload = (body) => {
  const { title, content, description, imageUrl } = body || {};
  const finalTitle = String(title || '').trim();
  const finalContent = String(content || description || '').trim();
  if (!finalTitle) {
    const err = new Error('Title is required');
    err.statusCode = 400;
    throw err;
  }
  return {
    title: finalTitle,
    content: finalContent,
    imageUrl: sanitizeOptionalImageUrl(imageUrl),
    isVerified: true,
  };
};

const uploadToCloudinary = async (base64Image) => {
    if (!base64Image || !base64Image.startsWith('data:image')) return null;
    try {
        const result = await cloudinary.uploader.upload(base64Image, { folder: "baylink_posts" });
        return result.secure_url;
    } catch (error) { return null; }
};

const SENSITIVE_USER_FIELDS = [
  'password',
  'verifyCode',
  'verifyCodeExpires',
  'lastSmsSentAt',
  'verifyAttempts',
  'passwordResetTokenHash',
  'passwordResetExpires',
  'passwordResetExpiresAt',
  'passwordResetRequestedAt',
  'passwordResetUsedAt',
  'passwordChangedAt',
  'phoneVerificationCodeHash',
  'phoneVerificationExpiresAt',
  'phoneVerificationAttempts',
  'phoneVerificationLastSentAt',
  'phoneNormalized',
  'phoneVerifiedAt',
  'accountStatusReason',
  'accountStatusUpdatedBy',
  'accountStatusUpdatedAt',
];

const sanitizeUserForClient = (user) => {
  const obj = user && typeof user.toObject === 'function' ? user.toObject() : { ...user };
  for (const field of SENSITIVE_USER_FIELDS) {
    delete obj[field];
  }
  obj.officialVerification = normalizeOfficialVerificationData(obj.officialVerification);
  obj.accountStatus = getAccountStatus(obj);
  return obj;
};

const generateResetToken = () => crypto.randomBytes(32).toString('hex');
const hashResetToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const getFrontendBaseUrl = () => {
  if (process.env.FRONTEND_URL) return String(process.env.FRONTEND_URL).replace(/\/$/, '');
  if (process.env.NODE_ENV === 'production') return 'https://www.baylink.us';
  return 'http://localhost:5173';
};

const canReturnDevResetLink = () =>
  process.env.AUTH_DEV_RETURN_TOKENS === 'true' && process.env.NODE_ENV !== 'production';

const canReturnDevPhoneCode = () =>
  process.env.AUTH_DEV_RETURN_TOKENS === 'true' && process.env.NODE_ENV !== 'production';

const PHONE_VERIFY_COOLDOWN_MS = 60000;
const PHONE_VERIFY_EXPIRES_MS = 10 * 60 * 1000;
const PHONE_VERIFY_MAX_ATTEMPTS = 5;

const normalizePhone = (phone) => {
  const raw = String(phone ?? '').trim();
  if (!raw) return null;
  const cleaned = raw.replace(/[\s().-]/g, '');
  let digits = cleaned.startsWith('+') ? cleaned.slice(1) : cleaned;
  if (/^1\d{10}$/.test(digits)) {
    return { phone: `+${digits}`, phoneNormalized: `+${digits}` };
  }
  if (/^\d{10}$/.test(digits)) {
    return { phone: cleaned.startsWith('+') ? cleaned : digits, phoneNormalized: `+1${digits}` };
  }
  return null;
};

const generatePhoneCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const hashPhoneCode = (code) => crypto.createHash('sha256').update(String(code)).digest('hex');

const mapTwilioSendError = (error) => {
  const code = error?.code;
  if (code === 30034) {
    return { ok: false, status: 503, error: '短信服务正在完成注册，请稍后再试。' };
  }
  if (code === 21266 || code === 21659 || code === 21606) {
    return { ok: false, status: 503, error: '短信服务配置错误，请稍后再试。' };
  }
  return { ok: false, status: 502, error: '短信发送失败，请稍后再试。' };
};

const sendPhoneVerificationViaTwilio = async (phoneNormalized, plainCode) => {
  if (!twilioClient || !TWILIO_PHONE) {
    const err = new Error('Twilio not configured');
    err.code = 'TWILIO_NOT_CONFIGURED';
    throw err;
  }
  await twilioClient.messages.create({
    body: `Your BAYLINK verification code is ${plainCode}. This code expires in 10 minutes. Do not share this code. Reply STOP to opt out or HELP for help. Msg&data rates may apply.`,
    from: TWILIO_PHONE,
    to: phoneNormalized,
  });
};

const persistPhoneVerificationState = async (user, normalized, plainCode) => {
  user.phone = normalized.phone;
  user.phoneNormalized = normalized.phoneNormalized;
  user.phoneVerificationCodeHash = hashPhoneCode(plainCode);
  user.phoneVerificationExpiresAt = Date.now() + PHONE_VERIFY_EXPIRES_MS;
  user.phoneVerificationAttempts = 0;
  user.phoneVerificationLastSentAt = Date.now();
  await user.save();
};

const startPhoneVerificationForUser = async (user, phoneInput) => {
  const normalized = normalizePhone(phoneInput);
  if (!normalized) return { ok: false, status: 400, error: '请输入有效的美国手机号。' };

  if (user.phoneVerificationLastSentAt && Date.now() - user.phoneVerificationLastSentAt < PHONE_VERIFY_COOLDOWN_MS) {
    return { ok: false, status: 429, error: '验证码发送太频繁，请稍后再试。' };
  }

  const plainCode = generatePhoneCode();
  const hasTwilio = !!(twilioClient && TWILIO_PHONE);

  if (hasTwilio) {
    try {
      await sendPhoneVerificationViaTwilio(normalized.phoneNormalized, plainCode);
      await persistPhoneVerificationState(user, normalized, plainCode);
      const payload = { message: '验证码已发送。' };
      if (canReturnDevPhoneCode()) payload.devCode = plainCode;
      return { ok: true, payload };
    } catch (error) {
      console.error('Twilio Error:', error.code, error.message);
      return mapTwilioSendError(error);
    }
  }

  if (canReturnDevPhoneCode()) {
    await persistPhoneVerificationState(user, normalized, plainCode);
    console.log(`[DEV MODE] SMS to ${normalized.phoneNormalized}: ${plainCode}`);
    return { ok: true, payload: { message: '验证码已发送。', devCode: plainCode } };
  }

  if (process.env.NODE_ENV !== 'production') {
    await persistPhoneVerificationState(user, normalized, plainCode);
    console.log(`[DEV MODE] SMS to ${normalized.phoneNormalized}: ${plainCode}`);
    return { ok: true, payload: { message: '验证码已发送。' } };
  }

  console.error('⚠️ Twilio 未配置，生产环境无法发送短信验证码');
  return { ok: false, status: 503, error: '短信服务暂时不可用，请稍后再试。' };
};

const verifyPhoneCodeForUser = async (user, codeInput) => {
  const code = String(codeInput ?? '').trim();
  if (!code) return { ok: false, status: 400, error: '验证码不正确或已过期' };

  if (!user.phoneVerificationCodeHash || !user.phoneVerificationExpiresAt || user.phoneVerificationExpiresAt <= Date.now()) {
    return { ok: false, status: 400, error: '验证码不正确或已过期' };
  }

  if ((user.phoneVerificationAttempts || 0) >= PHONE_VERIFY_MAX_ATTEMPTS) {
    user.phoneVerificationCodeHash = undefined;
    user.phoneVerificationExpiresAt = undefined;
    await user.save();
    return { ok: false, status: 400, error: '验证码不正确或已过期' };
  }

  if (user.phoneVerificationCodeHash !== hashPhoneCode(code)) {
    user.phoneVerificationAttempts = (user.phoneVerificationAttempts || 0) + 1;
    await user.save();
    return { ok: false, status: 400, error: '验证码不正确或已过期' };
  }

  user.isPhoneVerified = true;
  user.phoneVerifiedAt = Date.now();
  user.phoneVerificationCodeHash = undefined;
  user.phoneVerificationExpiresAt = undefined;
  user.phoneVerificationAttempts = 0;
  await user.save();

  return { ok: true, payload: { message: '手机号已验证。', user: sanitizeUserForClient(user) } };
};

const FORGOT_PASSWORD_MESSAGE = '如果这个邮箱已注册，我们会发送重设密码链接。';

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const escapeHtml = (value) => String(value ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const buildPasswordResetEmailHtml = ({ resetLink, user }) => {
  const safeLink = escapeHtml(resetLink);
  const greeting = user?.nickname ? escapeHtml(user.nickname) : '邻居';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#F7F4EC;font-family:'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#F7F4EC;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 2px 16px rgba(23,32,42,0.06);">
        <tr><td style="height:4px;background:linear-gradient(90deg,#16A66A,#128256);"></td></tr>
        <tr><td style="padding:32px 28px 8px;">
          <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:0.12em;color:#16A66A;text-transform:uppercase;">BAYLINK</p>
          <h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#17202A;line-height:1.3;">重设你的 BAYLINK 密码</h1>
          <p style="margin:0 0 8px;font-size:15px;color:#17202A;line-height:1.6;">你好，${greeting}：</p>
          <p style="margin:0 0 24px;font-size:15px;color:#6B7280;line-height:1.6;">我们收到了重设 BAYLINK 密码的请求。请在 30 分钟内点击下面按钮完成重设。</p>
          <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 24px;">
            <tr><td style="border-radius:12px;background-color:#16A66A;">
              <a href="${safeLink}" target="_blank" style="display:inline-block;padding:14px 28px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;">重设密码</a>
            </td></tr>
          </table>
          <p style="margin:0 0 8px;font-size:13px;color:#9A978F;line-height:1.5;">如果按钮无法打开，请复制以下链接到浏览器：</p>
          <p style="margin:0 0 24px;font-size:12px;color:#16A66A;word-break:break-all;line-height:1.5;"><a href="${safeLink}" style="color:#16A66A;">${safeLink}</a></p>
          <p style="margin:0;padding:16px;background:#F3F8F5;border-radius:10px;font-size:13px;color:#6B7280;line-height:1.6;">如果这不是你本人操作，可以忽略这封邮件，你的密码不会改变。</p>
        </td></tr>
        <tr><td style="padding:20px 28px 28px;border-top:1px solid #E3DFD6;">
          <p style="margin:0;font-size:12px;color:#9A978F;text-align:center;">BAYLINK｜湾区生活信息站</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
};

const buildPasswordResetEmailText = ({ resetLink }) => `重设你的 BAYLINK 密码

我们收到了重设 BAYLINK 密码的请求。请在 30 分钟内打开下面链接完成重设：

${resetLink}

如果这不是你本人操作，可以忽略这封邮件，你的密码不会改变。

BAYLINK｜湾区生活信息站`;

const sendPasswordResetEmail = async ({ to, resetLink, user }) => {
  if (!process.env.RESEND_API_KEY) {
    throw new Error('RESEND_API_KEY is not configured');
  }
  if (!process.env.RESEND_FROM_EMAIL) {
    throw new Error('RESEND_FROM_EMAIL is not configured');
  }
  if (!resend) {
    throw new Error('Resend client is not initialized');
  }

  const { data, error } = await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL,
    to,
    subject: '重设你的 BAYLINK 密码',
    html: buildPasswordResetEmailHtml({ resetLink, user }),
    text: buildPasswordResetEmailText({ resetLink }),
  });

  if (error) {
    throw new Error(error.message || 'Resend send failed');
  }

  if (process.env.NODE_ENV !== 'production' && data?.id) {
    console.log(`[Resend] Password reset email sent, id=${data.id}`);
  }

  return data;
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '请先登录' });
  jwt.verify(token, JWT_SECRET, async (err, userPayload) => {
    if (err) return res.status(401).json({ error: '登录已过期，请重新登录。' });
    const dbUser = await User.findOne({ id: userPayload.id });
    if (!dbUser || dbUser.isBanned) return res.status(403).json({ error: '账号不可用或已被限制' });
    if (dbUser.passwordChangedAt && userPayload.iat && userPayload.iat * 1000 < dbUser.passwordChangedAt) {
      return res.status(401).json({ error: '登录已过期，请重新登录。' });
    }
    req.user = dbUser;
    next();
  });
};

// --- Routes ---

// ✨ 手机验证接口（兼容旧前端，内部走新逻辑）
app.post('/api/auth/verify-phone', authenticateToken, async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (phone && !code) {
      const result = await startPhoneVerificationForUser(req.user, phone);
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json({ success: true, ...result.payload });
    }
    if (code) {
      const result = await verifyPhoneCodeForUser(req.user, code);
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json({ success: true, ...result.payload });
    }
    return res.status(400).json({ error: '无效请求' });
  } catch (e) {
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!checkAuthRateLimit(`register:${ip}`, { windowMs: 15 * 60 * 1000, maxRequests: 5 })) {
      return res.status(429).json({ error: AUTH_RATE_LIMIT_MSG });
    }
    const { email, password, nickname, contactType, contactValue } = req.body;
    if (!email || !EMAIL_REGEX.test(String(email).trim())) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (!validatePasswordStrength(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters and include uppercase, lowercase, and a number' });
    }
    if (!nickname || !contactValue) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (await User.findOne({ email: String(email).trim().toLowerCase() })) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const newUser = await User.create({
      id: Date.now().toString(), email: String(email).trim().toLowerCase(), password, nickname,
      role: email === 'admin' ? 'admin' : 'user',
      contactType, contactValue, bio: '这个邻居很懒，什么也没写~',
      socialLinks: { linkedin: '', instagram: '' }
    });
    const token = jwt.sign({ id: newUser.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ ...sanitizeUserForClient(newUser), token });
  } catch (e) { res.status(500).json({ error: '操作失败，请稍后再试' }); }
  });

app.post('/api/auth/login', async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!checkAuthRateLimit(`login:${ip}`, { windowMs: 15 * 60 * 1000, maxRequests: 10 })) {
      return res.status(429).json({ error: AUTH_RATE_LIMIT_MSG });
    }
    const { email, password } = req.body;
    const trimmedEmail = String(email || '').trim();
    let user = null;
    if (trimmedEmail === 'admin') {
      user = await User.findOne({ email: 'admin' });
    } else {
      const lowerEmail = trimmedEmail.toLowerCase();
      user = await User.findOne({ email: lowerEmail });
      if (!user && lowerEmail !== trimmedEmail) {
        user = await User.findOne({ email: trimmedEmail });
      }
    }
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    // ✨ 修改：利用 bcrypt.compare 來安全验证加密後的密碼
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ ...sanitizeUserForClient(user), token });
  } catch (e) { res.status(500).json({ error: '操作失败，请稍后再试' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!checkAuthRateLimit(`forgot:${ip}`, { windowMs: 15 * 60 * 1000, maxRequests: 5 })) {
      return res.status(429).json({ error: AUTH_RATE_LIMIT_MSG });
    }
    const { email } = req.body || {};
    const trimmedEmail = String(email || '').trim();
    if (!trimmedEmail || !EMAIL_REGEX.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    const lowerEmail = trimmedEmail.toLowerCase();
    let user = await User.findOne({ email: lowerEmail });
    if (!user && trimmedEmail === 'admin') {
      user = await User.findOne({ email: 'admin' });
    }
    let devResetLink;
    let devEmailError;
    if (user) {
      const plainToken = generateResetToken();
      user.passwordResetTokenHash = hashResetToken(plainToken);
      user.passwordResetExpires = Date.now() + 30 * 60 * 1000;
      user.passwordResetRequestedAt = Date.now();
      user.passwordResetUsedAt = undefined;
      await user.save();

      const resetLink = `${getFrontendBaseUrl()}/reset-password?token=${plainToken}`;
      const hasResendConfig = Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL);

      if (hasResendConfig) {
        try {
          await sendPasswordResetEmail({ to: user.email, resetLink, user });
        } catch (emailErr) {
          console.error('POST /api/auth/forgot-password email error:', emailErr.message);
          if (canReturnDevResetLink()) {
            devEmailError = emailErr.message;
            devResetLink = resetLink;
          }
        }
      } else if (canReturnDevResetLink()) {
        devResetLink = resetLink;
        console.log(`[DEV] Password reset link for ${user.email}: ${devResetLink}`);
      } else if (process.env.NODE_ENV === 'production') {
        console.error('POST /api/auth/forgot-password: Resend is not configured in production');
      }
    }
    const payload = { message: FORGOT_PASSWORD_MESSAGE };
    if (devResetLink) payload.devResetLink = devResetLink;
    if (devEmailError) payload.devEmailError = devEmailError;
    res.json(payload);
  } catch (e) {
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!checkAuthRateLimit(`reset:${ip}`, { windowMs: 15 * 60 * 1000, maxRequests: 10 })) {
      return res.status(429).json({ error: AUTH_RATE_LIMIT_MSG });
    }
    const { token, newPassword } = req.body || {};
    const plainToken = String(token || '').trim();
    if (!plainToken) {
      return res.status(400).json({ error: '重设链接无效或已过期。' });
    }
    if (!validatePasswordStrength(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters and include uppercase, lowercase, and a number' });
    }
    const tokenHash = hashResetToken(plainToken);
    const user = await User.findOne({ passwordResetTokenHash: tokenHash });
    if (!user || !user.passwordResetExpires || user.passwordResetExpires <= Date.now()) {
      return res.status(400).json({ error: '重设链接无效或已过期。' });
    }
    user.password = newPassword;
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetUsedAt = Date.now();
    user.passwordChangedAt = Date.now();
    await user.save();
    res.json({ message: '密码已更新，请重新登录。' });
  } catch (e) {
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findOne({ id: req.params.id }).select('-password -verifyCode'); // ✨ 安全：排除敏感字段
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({
    id: user.id,
    nickname: user.nickname,
    role: user.role,
    avatar: user.avatar,
    bio: user.bio,
    isPhoneVerified: user.isPhoneVerified,
    isOfficialVerified: user.isOfficialVerified,
    ...formatPublicProfileFields(user),
  });
});

app.get('/api/users/me/blocks', authenticateToken, async (req, res) => {
  try {
    const blocks = await UserBlock.find({ blockerId: req.user.id }).sort({ createdAt: -1 }).lean();
    const userIds = [...new Set(blocks.map((b) => b.blockedUserId).filter(Boolean))];
    const users = userIds.length
      ? await User.find({ id: { $in: userIds } }).select('id nickname avatar isPhoneVerified isOfficialVerified').lean()
      : [];
    const userById = new Map(users.map((u) => [u.id, u]));
    return res.json({
      blocks: blocks.map((b) => {
        const u = userById.get(b.blockedUserId);
        if (!u) return null;
        return {
          id: u.id,
          nickname: u.nickname,
          avatar: u.avatar,
          isPhoneVerified: !!u.isPhoneVerified,
          isOfficialVerified: !!u.isOfficialVerified,
          blockedAt: b.createdAt,
        };
      }).filter(Boolean),
    });
  } catch (e) {
    console.error('GET /api/users/me/blocks error:', e.message);
    return res.status(500).json({ error: '获取屏蔽列表失败' });
  }
});

app.post('/api/users/:userId/block', authenticateToken, async (req, res) => {
  try {
    const blockedUserId = String(req.params.userId ?? '').trim();
    if (!blockedUserId) {
      return res.status(400).json({ error: '请提供要屏蔽的用户' });
    }
    if (blockedUserId === req.user.id) {
      return res.status(400).json({ error: '不能屏蔽自己' });
    }
    const blockedUser = await User.findOne({ id: blockedUserId }).select('id').lean();
    if (!blockedUser) {
      return res.status(404).json({ error: '用户不存在' });
    }
    const now = Date.now();
    await UserBlock.findOneAndUpdate(
      { blockerId: req.user.id, blockedUserId },
      {
        $set: { updatedAt: now, reason: trimProfileString(req.body?.reason, 200) },
        $setOnInsert: { blockerId: req.user.id, blockedUserId, createdAt: now },
      },
      { upsert: true, new: true },
    );
    return res.json({ success: true, message: '已屏蔽该用户。' });
  } catch (e) {
    if (e?.code === 11000) return res.json({ success: true, message: '已屏蔽该用户。' });
    console.error('POST /api/users/:userId/block error:', e.message);
    return res.status(500).json({ error: '屏蔽失败，请稍后再试' });
  }
});

app.delete('/api/users/:userId/block', authenticateToken, async (req, res) => {
  try {
    const blockedUserId = String(req.params.userId ?? '').trim();
    if (!blockedUserId) {
      return res.status(400).json({ error: '请提供要取消屏蔽的用户' });
    }
    await UserBlock.deleteOne({ blockerId: req.user.id, blockedUserId });
    return res.json({ success: true, message: '已取消屏蔽。' });
  } catch (e) {
    console.error('DELETE /api/users/:userId/block error:', e.message);
    return res.status(500).json({ error: '取消屏蔽失败，请稍后再试' });
  }
});

app.get('/api/users/:id/public', async (req, res) => {
  try {
    const user = await User.findOne({ id: req.params.id }).select('-password -verifyCode -email -contactValue -contactType -phone -phoneNormalized');
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const viewerId = getCurrentUserIdFromRequest(req);
    const blockRelation = viewerId ? await getBlockRelation(viewerId, user.id) : {};
    const publicPostQuery = { authorId: user.id, isDeleted: false, adminHidden: { $ne: true } };
    const postCount = await Post.countDocuments(publicPostQuery);
    const recent = await Post.find(publicPostQuery).sort({ createdAt: -1 }).limit(3).lean();
    res.json({
      id: user.id,
      nickname: user.nickname,
      avatar: user.avatar,
      bio: user.bio,
      role: user.role,
      createdAt: user.createdAt,
      isPhoneVerified: user.isPhoneVerified,
      isOfficialVerified: user.isOfficialVerified,
      ...formatPublicProfileFields(user),
      ...(formatPublicOfficialVerification(user)
        ? { officialVerification: formatPublicOfficialVerification(user) }
        : {}),
      ...(viewerId ? blockRelation : {}),
      postCount,
      recentPosts: recent.map((p) => ({
        id: p.id || String(p._id),
        _id: p._id,
        title: p.title,
        description: p.description,
        category: p.category,
        city: p.city,
        type: p.type,
        budget: p.budget,
        imageUrls: p.imageUrls || [],
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
      })),
    });
  } catch (e) { res.status(500).json({ error: '加载失败，请稍后再试' }); }
});

app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const {
      nickname, bio, avatar, socialLinks, isOfficialVerified,
      area, city, profileTags, interests, website, xiaohongshu,
    } = req.body;
    const user = req.user;
    if (nickname !== undefined) {
      const nextNickname = trimProfileString(nickname, 30);
      if (!nextNickname) return res.status(400).json({ error: 'Nickname is required' });
      user.nickname = nextNickname;
    }
    if (bio !== undefined) user.bio = trimProfileString(bio, 240);
    if (area !== undefined) user.area = trimProfileString(area, 40);
    if (city !== undefined) user.city = trimProfileString(city, 40);
    if (website !== undefined) user.website = trimProfileString(website, 120);
    if (xiaohongshu !== undefined) user.xiaohongshu = trimProfileString(xiaohongshu, 120);
    if (profileTags !== undefined) user.profileTags = sanitizeProfileStringArray(profileTags);
    if (interests !== undefined) user.interests = sanitizeProfileStringArray(interests);
    if (socialLinks) {
      const merged = { ...(user.socialLinks || {}) };
      if (socialLinks.linkedin !== undefined) merged.linkedin = trimProfileString(socialLinks.linkedin, 120);
      if (socialLinks.instagram !== undefined) merged.instagram = trimProfileString(socialLinks.instagram, 120);
      user.socialLinks = merged;
    }
    if (user.role === 'admin' && isOfficialVerified !== undefined) user.isOfficialVerified = isOfficialVerified;
    if (avatar && avatar.startsWith('data:image')) {
        const url = await uploadToCloudinary(avatar);
        if (url) user.avatar = url;
    }
    await user.save();
    if (avatar || nickname !== undefined) {
      await Post.updateMany({ authorId: user.id }, { authorNickname: user.nickname, authorAvatar: user.avatar });
    }
    res.json(sanitizeUserForClient(user));
  } catch (e) { res.status(500).json({ error: '更新失败，请稍后再试' }); }
});

app.post('/api/users/me/phone/start', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.body || {};
    const result = await startPhoneVerificationForUser(req.user, phone);
    if (!result.ok) return res.status(result.status).json({ error: result.error });
    res.json(result.payload);
  } catch (e) {
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.post('/api/users/me/phone/verify', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body || {};
    const result = await verifyPhoneCodeForUser(req.user, code);
    if (!result.ok) return res.status(result.status).json({ error: result.error });
    res.json(result.payload);
  } catch (e) {
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.post('/api/users/me/official-verification', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: '请先登录。' });
    }

    const user = await User.findOne({ id: userId });
    if (!user) {
      return res.status(404).json({ error: '用户不存在。' });
    }

    const { type, description, website, license, socialLink } = req.body || {};
    const normalizedType = normalizeOfficialVerificationType(type);
    if (!normalizedType) {
      return res.status(400).json({ error: '请选择有效的认证类型。' });
    }

    const desc = trimProfileString(description, 500);
    if (!desc || desc.length < 10) {
      return res.status(400).json({ error: '请填写更完整的认证说明。' });
    }

    const currentStatus = getOfficialVerificationStatus(user);
    if (currentStatus === 'approved' || user.isOfficialVerified) {
      return res.status(400).json({ error: '已通过认证，无需重复申请' });
    }

    const websiteResult = normalizeOptionalOfficialUrl(website, 160);
    if (websiteResult.error) {
      return res.status(400).json({ error: websiteResult.error });
    }
    const socialResult = normalizeOptionalOfficialUrl(socialLink, 160);
    if (socialResult.error) {
      return res.status(400).json({ error: socialResult.error });
    }

    const normalizedLicense = trimProfileString(normalizeOptionalOfficialField(license), 120);
    const submittedAt = Date.now();

    user.set('officialVerification', {
      status: 'pending',
      type: normalizedType,
      description: desc,
      website: websiteResult.value || '',
      license: normalizedLicense || '',
      socialLink: socialResult.value || '',
      submittedAt,
      reviewedAt: null,
      reviewedBy: '',
      rejectionReason: '',
    });
    user.isOfficialVerified = false;
    await user.save();

    res.json({
      success: true,
      user: sanitizeUserForClient(user),
    });
  } catch (err) {
    console.error('[official-verification submit error]', err);
    res.status(500).json({ error: '提交失败，请稍后再试。' });
  }
});

const buildPostAuthor = (p, authorById) => {
  const authorUser = authorById?.get(p.authorId);
  return {
    id: p.authorId,
    nickname: p.authorNickname || authorUser?.nickname || 'Unknown',
    avatar: p.authorAvatar || authorUser?.avatar,
    isPhoneVerified: !!authorUser?.isPhoneVerified,
    isOfficialVerified: !!authorUser?.isOfficialVerified,
  };
};

const fetchAuthorTrustByIds = async (posts) => {
  const ids = [...new Set(posts.map((p) => p.authorId).filter(Boolean))];
  if (!ids.length) return new Map();
  const users = await User.find({ id: { $in: ids } })
    .select('id nickname avatar isPhoneVerified isOfficialVerified')
    .lean();
  return new Map(users.map((u) => [u.id, u]));
};

const formatPostResponse = (p, currentUserId, authorById, isAdmin = false) => {
  const { contactPreference, ...rest } = p;
  return {
    ...rest,
    contactPreference: sanitizeContactPreferenceForViewer(contactPreference, p.authorId, currentUserId, isAdmin),
    author: buildPostAuthor(p, authorById),
    likesCount: p.likes ? p.likes.length : 0,
    commentsCount: p.comments ? p.comments.length : 0,
    hasLiked: currentUserId ? (p.likes || []).includes(currentUserId) : false,
    isReported: currentUserId ? (p.reports || []).some((r) => r.reporterId === currentUserId) : false,
  };
};

const formatPostsResponseList = async (posts, currentUserId) => {
  const authorById = await fetchAuthorTrustByIds(posts);
  const isAdmin = await isAdminUserId(currentUserId);
  return posts.map((p) => formatPostResponse(p, currentUserId, authorById, isAdmin));
};

app.get('/api/posts/featured', async (req, res) => {
  try {
    const limitRaw = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 0;
    const currentUserId = getCurrentUserIdFromRequest(req);
    let query = { isDeleted: false, isFeatured: true };
    await applyPublicPostVisibility(query, currentUserId);
    if (currentUserId) {
      const blockedIds = await getBlockedAuthorIdsForUser(currentUserId);
      if (blockedIds.length) query.authorId = { $nin: blockedIds };
    }
    let q = Post.find(query).sort({ featuredAt: -1, createdAt: -1 });
    if (limit > 0) q = q.limit(limit);
    const posts = await q.lean();
    res.json({ posts: await formatPostsResponseList(posts, currentUserId) });
  } catch (e) { res.status(500).json({ error: '加载失败，请稍后再试' }); }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    if (req.params.id === 'featured') return res.sendStatus(404);
    const post = await Post.findOne({ id: req.params.id, isDeleted: false }).lean();
    if (!post) return res.status(404).json({ error: '内容不存在或已被移除。' });
    const currentUserId = getCurrentUserIdFromRequest(req);
    if (post.adminHidden && !(await isAdminUserId(currentUserId))) {
      return res.status(404).json({ error: '内容不存在或已被移除。' });
    }
    const authorById = await fetchAuthorTrustByIds([post]);
    const isAdmin = await isAdminUserId(currentUserId);
    res.json(formatPostResponse(post, currentUserId, authorById, isAdmin));
  } catch (e) { res.status(500).json({ error: '加载失败，请稍后再试' }); }
});

app.get('/api/posts', async (req, res) => {
  try {
    const { type, keyword } = req.query;
    const { page, limit, skip } = parsePublicFeedPagination(req.query, 10);
    let query = { isDeleted: false };
    if (type) query.type = type;
    if (keyword) {
      const kwResult = normalizeSearchKeyword(keyword);
      if (!kwResult.ok) return res.status(400).json({ error: kwResult.error });
      if (kwResult.keyword) {
        const regex = new RegExp(escapeRegex(kwResult.keyword), 'i');
        query.$or = [{ title: regex }, { description: regex }, { city: regex }, { category: regex }];
      }
    }
    const currentUserId = getCurrentUserIdFromRequest(req);
    await applyPublicPostVisibility(query, currentUserId);
    if (currentUserId) {
      const blockedIds = await getBlockedAuthorIdsForUser(currentUserId);
      if (blockedIds.length) query.authorId = { $nin: blockedIds };
    }
    const posts = await Post.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
    const totalCount = await Post.countDocuments(query);
    const formatted = await formatPostsResponseList(posts, currentUserId);
    res.json({ posts: formatted, hasMore: totalCount > skip + posts.length });
  } catch (e) { res.status(500).json({ error: '加载失败，请稍后再试' }); }
});

const validatePostBody = (body) => {
  const title = String(body.title || '').trim();
  const description = String(body.description || '').trim();
  const budget = String(body.budget || '').trim();
  if (title.length < 5) return { status: 400, error: 'Title must be at least 5 characters' };
  if (title.length > 80) return { status: 400, error: 'Title must be at most 80 characters' };
  if (description.length < 10) return { status: 400, error: 'Description must be at least 10 characters' };
  if (description.length > 2000) return { status: 400, error: 'Description must be at most 2000 characters' };
  if (budget.length > 30) return { status: 400, error: 'Budget must be at most 30 characters' };
  if (!body.category) return { status: 400, error: 'Category is required' };
  if (!body.city) return { status: 400, error: 'City/area is required' };
  return null;
};

const POST_DAILY_WINDOW_MS = 24 * 60 * 60 * 1000;
const POST_DUPLICATE_WINDOW_MS = 10 * 60 * 1000;

const getDailyPostLimit = (user) => {
  if (user.role === 'admin') return null;
  if (user.isOfficialVerified) return 20;
  if (user.isPhoneVerified) return 10;
  return 3;
};

const HIGH_RISK_CATEGORY_SLUGS = new Set([
  'rent', 'housing', 'roommate', 'service', 'moving', 'cleaning', 'repair', 'ride',
]);
const HIGH_RISK_CATEGORIES_ZH = new Set(['租屋', '搬家', '清洁', '维修', '接送']);

const isHighRiskPostCategory = (body) => {
  const raw = String(body?.category || '').trim();
  if (!raw) return false;
  if (HIGH_RISK_CATEGORIES_ZH.has(raw)) return true;
  return HIGH_RISK_CATEGORY_SLUGS.has(raw.toLowerCase());
};

const checkCreatePostRateLimit = async (user) => {
  const dailyLimit = getDailyPostLimit(user);
  if (dailyLimit == null) return null;
  const windowStart = Date.now() - POST_DAILY_WINDOW_MS;
  const count = await Post.countDocuments({
    authorId: user.id,
    isDeleted: false,
    createdAt: { $gte: windowStart },
  });
  if (count >= dailyLimit) {
    return { status: 429, error: '今天发布次数已达到上限，请明天再试。' };
  }
  return null;
};

const checkDuplicatePost = async (userId, title, description) => {
  const trimmedTitle = String(title || '').trim();
  const trimmedDesc = String(description || '').trim();
  const since = Date.now() - POST_DUPLICATE_WINDOW_MS;
  const dup = await Post.findOne({
    authorId: userId,
    isDeleted: false,
    createdAt: { $gte: since },
    title: trimmedTitle,
    description: trimmedDesc,
  }).lean();
  if (dup) return { status: 429, error: '请不要重复发布相同内容。' };
  return null;
};

const isDefaultCoverUrl = (value) =>
  typeof value === 'string' && value.startsWith('/default-covers/');

const processPostImageUrls = async (imageUrls) => {
  if (!imageUrls || !Array.isArray(imageUrls)) return [];
  const results = await Promise.all(imageUrls.map(async (img) => {
    if (typeof img !== 'string' || !img.trim()) return null;
    const url = img.trim();
    if (isDefaultCoverUrl(url)) return url;
    if (/^https?:\/\//i.test(url)) return url;
    if (url.startsWith('data:image')) return uploadToCloudinary(url);
    return null;
  }));
  return results.filter(Boolean);
};

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const accountPostErr = assertAccountCanPost(req.user);
    if (accountPostErr) return res.status(403).json({ error: accountPostErr });
    const rateErr = await checkCreatePostRateLimit(req.user);
    if (rateErr) return res.status(rateErr.status).json({ error: rateErr.error });
    const validationErr = validatePostBody(req.body);
    if (validationErr) return res.status(validationErr.status).json({ error: validationErr.error });
    const dupErr = await checkDuplicatePost(
      req.user.id,
      req.body?.title,
      req.body?.description,
    );
    if (dupErr) return res.status(dupErr.status).json({ error: dupErr.error });
    const { imageUrls, id: _id, authorId: _authorId, createdAt: _createdAt, updatedAt: _updatedAt, contactPreference: rawContactPreference, ...postData } = req.body;
    const contactPreference = normalizeContactPreference(rawContactPreference);
    const contactPrefErr = validateContactPreference(contactPreference);
    if (contactPrefErr) return res.status(400).json({ error: contactPrefErr });
    const uploadedUrls = await processPostImageUrls(imageUrls);
    const newPost = await Post.create({
      id: Date.now().toString(),
      authorId: req.user.id,
      authorNickname: req.user.nickname,
      authorAvatar: req.user.avatar,
      ...postData,
      contactPreference,
      imageUrls: uploadedUrls,
      isDeleted: false,
      createdAt: Date.now(),
    });
    const p = typeof newPost.toObject === 'function' ? newPost.toObject() : newPost;
    const authorById = await fetchAuthorTrustByIds([p]);
    const payload = formatPostResponse(p, req.user.id, authorById, req.user.role === 'admin');
    if (!req.user.isPhoneVerified && isHighRiskPostCategory(postData)) {
      payload.trustWarning = '为了提升可信度，建议完成手机验证后再发布租房、服务或接送相关信息。';
    }
    res.json(payload);
  } catch (e) { res.status(500).json({ error: '发布失败，请稍后再试' }); }
});

app.patch('/api/posts/:id/feature', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const post = await Post.findOne({ id: req.params.id, isDeleted: false });
    if (!post) return res.sendStatus(404);
    post.isFeatured = true;
    post.featuredAt = new Date();
    post.featuredBy = req.user.id;
    await post.save();
    const authorById = await fetchAuthorTrustByIds([post.toObject()]);
    res.json(formatPostResponse(post.toObject(), req.user.id, authorById));
  } catch (e) { res.status(500).json({ error: '推荐失败，请稍后再试' }); }
});

app.patch('/api/posts/:id/unfeature', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const post = await Post.findOne({ id: req.params.id, isDeleted: false });
    if (!post) return res.sendStatus(404);
    post.isFeatured = false;
    post.featuredAt = null;
    post.featuredBy = null;
    await post.save();
    const authorById = await fetchAuthorTrustByIds([post.toObject()]);
    res.json(formatPostResponse(post.toObject(), req.user.id, authorById));
  } catch (e) { res.status(500).json({ error: '取消推荐失败，请稍后再试' }); }
});

app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id, isDeleted: false });
    if (!post) return res.sendStatus(404);
    if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403);
    const validationErr = validatePostBody(req.body);
    if (validationErr) return res.status(validationErr.status).json({ error: validationErr.error });
    const allowed = ['title', 'description', 'category', 'city', 'budget', 'type', 'timeInfo'];
    for (const key of allowed) {
      if (req.body[key] !== undefined) post[key] = req.body[key];
    }
    if (req.body.imageUrls !== undefined) {
      post.imageUrls = await processPostImageUrls(req.body.imageUrls);
    }
    if (req.body.contactPreference !== undefined) {
      const contactPreference = normalizeContactPreference(req.body.contactPreference);
      const contactPrefErr = validateContactPreference(contactPreference);
      if (contactPrefErr) return res.status(400).json({ error: contactPrefErr });
      post.contactPreference = contactPreference;
    }
    post.updatedAt = Date.now();
    await post.save();
    const p = post.toObject();
    const authorById = await fetchAuthorTrustByIds([p]);
    res.json(formatPostResponse(p, req.user.id, authorById, req.user.role === 'admin'));
  } catch (e) { res.status(500).json({ error: '更新失败，请稍后再试' }); }
});

app.post('/api/posts/:id/report', authenticateToken, (req, res) => {
  res.status(410).json({ error: '请使用新版举报入口。' });
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const idx = post.likes.indexOf(req.user.id); if (idx === -1) post.likes.push(req.user.id); else post.likes.splice(idx, 1); await post.save(); res.json({ success: true }); });
app.delete('/api/posts/:id', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403); post.isDeleted = true; await post.save(); res.json({ success: true }); });
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const comment = { id: Date.now().toString(), authorId: req.user.id, authorName: req.user.nickname, content: req.body.content, createdAt: Date.now() }; post.comments.push(comment); await post.save(); res.json(comment); });

app.post('/api/posts/:postId/contact-requests', authenticateToken, async (req, res) => {
  try {
    const accountMsgErr = assertAccountCanMessage(req.user);
    if (accountMsgErr) return res.status(403).json({ error: accountMsgErr });

    const post = await Post.findOne({ id: req.params.postId, isDeleted: false });
    if (!post) return res.status(404).json({ error: '内容不存在或已被移除。' });
    if (post.adminHidden && req.user.role !== 'admin') return res.status(404).json({ error: '内容不存在或已被移除。' });
    if (post.authorId === req.user.id) return res.status(400).json({ error: '不能请求自己帖子的联系方式。' });

    try {
      await assertCanMessage(req.user.id, post.authorId);
    } catch (blockErr) {
      return res.status(blockErr.statusCode || 403).json({ error: blockErr.message });
    }

    const pref = post.contactPreference || defaultContactPreference();
    const mode = pref.mode || 'dm_first';
    if (mode === 'dm_first') {
      return res.status(400).json({ error: '该帖子仅支持站内私信', status: 'dm_first' });
    }

    const existing = await ContactRequest.findOne({
      postId: post.id,
      requesterId: req.user.id,
      status: { $in: ACTIVE_CONTACT_REQUEST_STATUSES },
    });
    if (existing) {
      return res.json({
        request: formatContactRequestForClient(existing.toObject()),
        status: existing.status,
      });
    }

    const enabledMethods = buildContactCardMethods(pref);
    if (!enabledMethods.length) {
      return res.status(400).json({ error: '帖主尚未设置可分享的联系方式。' });
    }

    const requestMessage = trimProfileString(req.body?.requestMessage || '', 500);

    if (mode === 'manual_approve') {
      const reqDoc = await ContactRequest.create({
        id: `${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        postId: post.id,
        postOwnerId: post.authorId,
        requesterId: req.user.id,
        status: 'pending',
        requestMessage,
        contactSnapshot: [],
        createdAt: Date.now(),
      });
      return res.json({ request: formatContactRequestForClient(reqDoc.toObject()), status: 'pending' });
    }

    const conv = await openOrCreateConversationBetween(req.user.id, post.authorId);
    const reqDoc = await ContactRequest.create({
      id: `${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      postId: post.id,
      postOwnerId: post.authorId,
      requesterId: req.user.id,
      status: 'auto_sent',
      requestMessage,
      contactSnapshot: enabledMethods,
      threadId: conv.id,
      createdAt: Date.now(),
      sentAt: Date.now(),
    });
    const msg = await sendContactCardMessage({
      conversationId: conv.id,
      senderId: post.authorId,
      recipientId: req.user.id,
      postId: post.id,
      contactRequestId: reqDoc.id,
      methods: enabledMethods,
    });
    reqDoc.messageId = msg.id;
    await reqDoc.save();

    return res.json({
      request: formatContactRequestForClient(reqDoc.toObject()),
      status: 'auto_sent',
      threadId: conv.id,
    });
  } catch (e) {
    console.error('POST /api/posts/:postId/contact-requests error:', e);
    res.status(500).json({ error: '请求失败，请稍后再试' });
  }
});

app.get('/api/contact-requests', authenticateToken, async (req, res) => {
  try {
    const role = String(req.query.role || '').trim();
    const status = String(req.query.status || '').trim();
    let query = {};
    if (role === 'owner') {
      query.postOwnerId = req.user.id;
      if (status) query.status = status;
    } else if (role === 'requester') {
      query.requesterId = req.user.id;
    } else {
      return res.status(400).json({ error: 'role 参数无效' });
    }
    const list = await ContactRequest.find(query).sort({ createdAt: -1 }).limit(50).lean();
    const requesterIds = [...new Set(list.map((r) => r.requesterId).filter(Boolean))];
    const requesters = requesterIds.length
      ? await User.find({ id: { $in: requesterIds } }).select('id nickname avatar isPhoneVerified isOfficialVerified').lean()
      : [];
    const requesterById = new Map(requesters.map((u) => [u.id, u]));
    res.json({
      requests: list.map((r) => ({
        ...formatContactRequestForClient(r),
        requester: requesterById.get(r.requesterId) || null,
      })),
    });
  } catch (e) {
    console.error('GET /api/contact-requests error:', e);
    res.status(500).json({ error: '加载失败，请稍后再试' });
  }
});

app.patch('/api/contact-requests/:requestId/approve', authenticateToken, async (req, res) => {
  try {
    const reqDoc = await ContactRequest.findOne({ id: req.params.requestId });
    if (!reqDoc) return res.status(404).json({ error: '请求不存在' });
    if (reqDoc.postOwnerId !== req.user.id && req.user.role !== 'admin') return res.sendStatus(403);
    if (reqDoc.status !== 'pending') return res.status(400).json({ error: '该请求已处理' });

    const post = await Post.findOne({ id: reqDoc.postId, isDeleted: false });
    if (!post) return res.status(404).json({ error: '帖子不存在' });
    const methods = buildContactCardMethods(post.contactPreference);
    if (!methods.length) return res.status(400).json({ error: '暂无可用联系方式' });

    const conv = await openOrCreateConversationBetween(reqDoc.requesterId, req.user.id);
    const msg = await sendContactCardMessage({
      conversationId: conv.id,
      senderId: req.user.id,
      recipientId: reqDoc.requesterId,
      postId: reqDoc.postId,
      contactRequestId: reqDoc.id,
      methods,
    });

    reqDoc.status = 'approved';
    reqDoc.contactSnapshot = methods;
    reqDoc.threadId = conv.id;
    reqDoc.messageId = msg.id;
    reqDoc.respondedAt = Date.now();
    reqDoc.sentAt = Date.now();
    await reqDoc.save();

    res.json({ request: formatContactRequestForClient(reqDoc.toObject()), status: 'approved', threadId: conv.id });
  } catch (e) {
    console.error('PATCH contact-requests approve error:', e);
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.patch('/api/contact-requests/:requestId/decline', authenticateToken, async (req, res) => {
  try {
    const reqDoc = await ContactRequest.findOne({ id: req.params.requestId });
    if (!reqDoc) return res.status(404).json({ error: '请求不存在' });
    if (reqDoc.postOwnerId !== req.user.id && req.user.role !== 'admin') return res.sendStatus(403);
    if (reqDoc.status !== 'pending') return res.status(400).json({ error: '该请求已处理' });

    reqDoc.status = 'declined';
    reqDoc.respondedAt = Date.now();
    await reqDoc.save();

    res.json({ request: formatContactRequestForClient(reqDoc.toObject()), status: 'declined' });
  } catch (e) {
    console.error('PATCH contact-requests decline error:', e);
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});

app.get('/api/ads', async (req, res) => { const ads = await Ad.find({}); res.json(ads); });
app.post('/api/ads', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const payload = buildAdPayload(req.body);
    const ad = await Ad.create({ ...payload, id: Date.now().toString() });
    res.json(ad);
  } catch (e) {
    if (e.statusCode === 400) return res.status(400).json({ error: e.message });
    console.error('POST /api/ads error:', e);
    res.status(500).json({ error: '创建推荐失败，请稍后再试' });
  }
});
app.put('/api/ads/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const payload = buildAdPayload(req.body);
    const ad = await Ad.findOneAndUpdate(
      { id: req.params.id },
      { $set: payload },
      { new: true }
    );
    if (!ad) return res.status(404).json({ error: 'Not found' });
    res.json(ad);
  } catch (e) {
    if (e.statusCode === 400) return res.status(400).json({ error: e.message });
    console.error('PUT /api/ads error:', e);
    res.status(500).json({ error: '更新推荐失败，请稍后再试' });
  }
});
app.delete('/api/ads/:id', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Ad.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.get('/api/content/:key', async (req, res) => { const content = await Content.findOne({ key: req.params.key }); res.json({ value: content ? content.value : '' }); });
app.post('/api/content', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Content.findOneAndUpdate({ key: req.body.key }, { value: req.body.value }, { upsert: true, new: true }); res.json({ success: true }); });

app.get('/api/conversations', authenticateToken, async (req, res) => { const convs = await Conversation.find({ userIds: req.user.id }); const result = await Promise.all(convs.map(async c => { const otherId = c.userIds.find(uid => uid !== req.user.id); const otherUser = await User.findOne({ id: otherId }); const lastMsg = await Message.findOne({ conversationId: c.id }).sort({ createdAt: -1 }); return { id: c.id, updatedAt: c.updatedAt, lastMessage: formatMessagePreview(lastMsg), otherUser: { id: otherUser?.id, nickname: otherUser?.nickname, avatar: otherUser?.avatar, isPhoneVerified: otherUser?.isPhoneVerified, isOfficialVerified: otherUser?.isOfficialVerified } }; })); result.sort((a, b) => b.updatedAt - a.updatedAt); res.json(result); });
app.post('/api/conversations/open-or-create', authenticateToken, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    if (!targetUserId || targetUserId === req.user.id) {
      return res.status(400).json({ error: '无法与自己创建会话。' });
    }
    const targetUser = await User.findOne({ id: targetUserId }).select('id').lean();
    if (!targetUser) {
      return res.status(404).json({ error: '用户不存在' });
    }
    let conv = await Conversation.findOne({ userIds: { $all: [req.user.id, targetUserId] } });
    if (!conv) {
      try {
        await assertCanMessage(req.user.id, targetUserId);
      } catch (blockErr) {
        return res.status(blockErr.statusCode || 403).json({ error: blockErr.message });
      }
      conv = await Conversation.create({ id: Date.now().toString(), userIds: [req.user.id, targetUserId] });
    }
    res.json(conv);
  } catch (e) {
    console.error('POST /api/conversations/open-or-create error:', e.message);
    res.status(500).json({ error: '操作失败，请稍后再试' });
  }
});
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ id: req.params.id });
    if (!conv || !conv.userIds.includes(req.user.id)) {
      return res.status(404).json({ error: '会话不存在。' });
    }
    const msgs = await Message.find({ conversationId: req.params.id }).sort({ createdAt: 1 });
    res.json(msgs);
  } catch (e) {
    console.error('GET /api/conversations/:id/messages error:', e.message);
    res.status(500).json({ error: '加载失败，请稍后再试' });
  }
});
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ id: req.params.id });
    if (!conv || !conv.userIds.includes(req.user.id)) {
      return res.status(404).json({ error: '会话不存在' });
    }
    const accountMsgErr = assertAccountCanMessage(req.user);
    if (accountMsgErr) return res.status(403).json({ error: accountMsgErr });
    const recipientId = conv.userIds.find((uid) => uid !== req.user.id);
    if (recipientId) {
      try {
        await assertCanMessage(req.user.id, recipientId);
      } catch (blockErr) {
        return res.status(blockErr.statusCode || 403).json({ error: blockErr.message });
      }
    }
    const { type, content } = req.body;
    let finalContent = content;
    if (type === 'contact-share') {
      finalContent = `我的联系方式：${formatContactTypeLabel(req.user.contactType)} ${req.user.contactValue || ''}`;
    }
    const msg = await Message.create({
      id: Date.now().toString(),
      conversationId: req.params.id,
      senderId: req.user.id,
      type,
      content: finalContent,
    });
    await Conversation.findOneAndUpdate({ id: req.params.id }, { updatedAt: Date.now() });
    if (recipientId) {
      io.to(recipientId).emit('new_message', msg);
    }
    res.json(msg);
  } catch (e) {
    console.error('POST /api/conversations/:id/messages error:', e.message);
    res.status(500).json({ error: '发送失败' });
  }
});

// --- 举报 / 屏蔽（社区安全轻量版）---
app.post('/api/reports', authenticateToken, async (req, res) => {
  try {
    if (!checkReportRateLimit(req.user.id)) {
      return res.status(429).json({ error: '举报过于频繁，请稍后再试' });
    }

    const targetType = String(req.body?.targetType ?? '').trim();
    const reason = String(req.body?.reason ?? '').trim();
    const detail = clampReportDetail(req.body?.detail ?? req.body?.note);

    if (!REPORT_TARGET_TYPES.has(targetType)) {
      return res.status(400).json({ error: '举报类型无效' });
    }
    if (!REPORT_REASONS.has(reason)) {
      return res.status(400).json({ error: '举报原因无效' });
    }

    const targetCheck = await resolveReportTarget(targetType, req.body?.targetId);
    if (!targetCheck.ok) {
      return res.status(404).json({ error: targetCheck.error });
    }

    if (targetCheck.targetUserId === req.user.id) {
      return res.status(400).json({ error: '不能举报自己的内容' });
    }

    const since = Date.now() - REPORT_DUPLICATE_WINDOW_MS;
    const existingRecent = await Report.findOne({
      reporterId: req.user.id,
      targetType,
      targetId: targetCheck.targetId,
      createdAt: { $gte: since },
    }).select('id').lean();

    if (existingRecent) {
      return res.status(400).json({ error: '你已经举报过该内容，我们会尽快处理。' });
    }

    const now = Date.now();
    const report = await Report.create({
      id: now.toString(),
      reporterId: req.user.id,
      reporterNickname: req.user.nickname,
      targetType,
      targetId: targetCheck.targetId,
      targetPostId: targetCheck.targetPostId || '',
      targetUserId: targetCheck.targetUserId || '',
      reason,
      detail,
      status: 'open',
      adminNote: '',
      createdAt: now,
      updatedAt: now,
      reviewedAt: null,
      reviewedBy: '',
    });

    return res.json({ success: true, message: '举报已提交，感谢你的反馈。', id: report.id });
  } catch (e) {
    console.error('POST /api/reports error:', e.message);
    return res.status(500).json({ error: '举报提交失败，请稍后再试' });
  }
});

app.patch('/api/admin/users/:userId/account-status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = String(req.body?.status ?? '').trim();
    if (!ACCOUNT_STATUSES.has(status)) {
      return res.status(400).json({ error: '账号状态无效' });
    }
    if (req.params.userId === req.user.id) {
      return res.status(400).json({ error: '不能调整自己的账号状态' });
    }

    const user = await User.findOne({ id: req.params.userId });
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const prevAccountStatus = getAccountStatus(user);
    const reason = trimProfileString(req.body?.reason, 300);
    const now = Date.now();
    user.accountStatus = status;
    user.accountStatusReason = status === 'active' ? '' : (reason || '');
    user.accountStatusUpdatedAt = now;
    user.accountStatusUpdatedBy = req.user.id;
    await user.save();

    const accountActionMap = {
      limited: 'account_limited',
      suspended: 'account_suspended',
      active: 'account_restored',
    };
    void createModerationLog({
      admin: req.user,
      action: accountActionMap[status],
      targetType: 'user',
      targetId: user.id,
      targetUserId: user.id,
      previousValue: { accountStatus: prevAccountStatus },
      newValue: { accountStatus: status },
      reason: status === 'active' ? '' : (reason || ''),
    });

    const sanitized = sanitizeUserForClient(user);
    return res.json({
      success: true,
      user: {
        id: sanitized.id,
        nickname: sanitized.nickname,
        avatar: sanitized.avatar,
        accountStatus: sanitized.accountStatus,
        isPhoneVerified: !!sanitized.isPhoneVerified,
        isOfficialVerified: !!sanitized.isOfficialVerified,
      },
    });
  } catch (e) {
    console.error('PATCH /api/admin/users/:userId/account-status error:', e.message);
    return res.status(500).json({ error: '更新账号状态失败' });
  }
});

app.get('/api/admin/official-verifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = String(req.query.status ?? 'pending').trim();
    const filter = {};
    if (status === 'all') {
      filter['officialVerification.status'] = { $in: ['pending', 'approved', 'rejected'] };
    } else if (OFFICIAL_VERIFICATION_LIST_STATUSES.has(status) && status !== 'all') {
      filter['officialVerification.status'] = status;
    } else {
      filter['officialVerification.status'] = 'pending';
    }

    const users = await User.find(filter)
      .select('-password -verifyCode -phoneVerificationCodeHash -passwordResetTokenHash')
      .sort({ 'officialVerification.submittedAt': -1 })
      .limit(100)
      .lean();

    return res.json({ requests: users.map(formatAdminOfficialVerificationRequest) });
  } catch (e) {
    console.error('GET /api/admin/official-verifications error:', e.message);
    return res.status(500).json({ error: '获取认证申请失败' });
  }
});

app.patch('/api/admin/users/:userId/official-verification', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = String(req.body?.status ?? '').trim();
    if (status !== 'approved' && status !== 'rejected') {
      return res.status(400).json({ error: '状态无效' });
    }

    const user = await User.findOne({ id: req.params.userId });
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const currentOv = normalizeOfficialVerificationData(user.officialVerification);
    const prevOv = { status: currentOv.status, type: currentOv.type };

    if (status === 'approved') {
      user.isOfficialVerified = true;
      user.set('officialVerification', {
        ...currentOv,
        status: 'approved',
        reviewedAt: Date.now(),
        reviewedBy: req.user.id,
        rejectionReason: '',
      });
    } else {
      user.isOfficialVerified = false;
      const reason = trimProfileString(req.body?.rejectionReason, 500);
      user.set('officialVerification', {
        ...currentOv,
        status: 'rejected',
        reviewedAt: Date.now(),
        reviewedBy: req.user.id,
        rejectionReason: reason || '资料不足，请补充后重新申请。',
      });
    }

    await user.save();

    const rejectionReason = status === 'rejected'
      ? trimProfileString(req.body?.rejectionReason, 500) || '资料不足，请补充后重新申请。'
      : '';
    void createModerationLog({
      admin: req.user,
      action: status === 'approved' ? 'official_verification_approved' : 'official_verification_rejected',
      targetType: 'official_verification',
      targetId: user.id,
      targetUserId: user.id,
      previousValue: prevOv,
      newValue: { status, type: currentOv.type },
      reason: rejectionReason,
    });

    res.json(sanitizeUserForClient(user));
  } catch (e) {
    res.status(500).json({ error: '审核失败，请稍后再试' });
  }
});

app.get('/api/admin/reports', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = String(req.query.status ?? 'open').trim();
    const type = String(req.query.type ?? 'all').trim();
    const limitRaw = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 50;

    const filter = {};
    if (status && status !== 'all' && REPORT_STATUSES.has(status)) filter.status = status;
    if (type && type !== 'all' && REPORT_TARGET_TYPES.has(type)) filter.targetType = type;

    const reports = await Report.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ reports: await formatAdminReportsList(reports) });
  } catch (e) {
    console.error('GET /api/admin/reports error:', e.message);
    return res.status(500).json({ error: '获取举报列表失败' });
  }
});

app.patch('/api/admin/reports/:reportId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = String(req.body?.status ?? '').trim();
    if (!REPORT_ADMIN_STATUSES.has(status)) {
      return res.status(400).json({ error: '状态无效' });
    }

    const report = await Report.findOne({ id: req.params.reportId });
    if (!report) {
      return res.status(404).json({ error: '举报记录不存在' });
    }

    const prevReportStatus = report.status;
    const adminNote = clampReportDetail(req.body?.adminNote);
    const now = Date.now();
    report.status = status;
    report.adminNote = adminNote || report.adminNote || '';
    report.updatedAt = now;
    if (status === 'reviewed' || status === 'dismissed') {
      report.reviewedAt = now;
      report.reviewedBy = req.user.id;
    } else {
      report.reviewedAt = null;
      report.reviewedBy = '';
    }
    await report.save();

    let reportAction = null;
    if (status === 'reviewed' && prevReportStatus !== 'reviewed') reportAction = 'report_reviewed';
    else if (status === 'dismissed' && prevReportStatus !== 'dismissed') reportAction = 'report_dismissed';
    else if (status === 'open' && prevReportStatus !== 'open') reportAction = 'report_reopened';
    if (reportAction) {
      void createModerationLog({
        admin: req.user,
        action: reportAction,
        targetType: 'report',
        targetId: report.id,
        targetReportId: report.id,
        targetUserId: report.targetUserId || '',
        targetPostId: report.targetPostId || '',
        previousValue: { status: prevReportStatus },
        newValue: { status },
        note: report.adminNote || '',
      });
    }

    const [formatted] = await formatAdminReportsList([report.toObject()]);
    return res.json({ success: true, report: formatted });
  } catch (e) {
    console.error('PATCH /api/admin/reports error:', e.message);
    return res.status(500).json({ error: '更新举报状态失败' });
  }
});

app.patch('/api/admin/posts/:postId/hide', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.postId, isDeleted: false });
    if (!post) return res.status(404).json({ error: '帖子不存在' });
    const reason = trimProfileString(req.body?.reason, 500) || '管理员隐藏';
    post.adminHidden = true;
    post.adminHiddenAt = Date.now();
    post.adminHiddenBy = req.user.id;
    post.adminHiddenReason = reason;
    await post.save();

    void createModerationLog({
      admin: req.user,
      action: 'post_hidden',
      targetType: 'post',
      targetId: post.id,
      targetPostId: post.id,
      targetUserId: post.authorId || '',
      previousValue: { adminHidden: false },
      newValue: { adminHidden: true },
      reason,
    });

    return res.json({ success: true });
  } catch (e) {
    console.error('PATCH /api/admin/posts/:postId/hide error:', e.message);
    return res.status(500).json({ error: '隐藏帖子失败' });
  }
});

app.patch('/api/admin/posts/:postId/unhide', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.postId });
    if (!post) return res.status(404).json({ error: '帖子不存在' });
    post.adminHidden = false;
    post.adminHiddenAt = null;
    post.adminHiddenBy = '';
    post.adminHiddenReason = '';
    await post.save();

    void createModerationLog({
      admin: req.user,
      action: 'post_unhidden',
      targetType: 'post',
      targetId: post.id,
      targetPostId: post.id,
      targetUserId: post.authorId || '',
      previousValue: { adminHidden: true },
      newValue: { adminHidden: false },
    });

    return res.json({ success: true });
  } catch (e) {
    console.error('PATCH /api/admin/posts/:postId/unhide error:', e.message);
    return res.status(500).json({ error: '恢复帖子失败' });
  }
});

app.get('/api/admin/moderation-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const action = String(req.query.action ?? '').trim();
    const targetType = String(req.query.targetType ?? '').trim();
    const targetUserId = String(req.query.targetUserId ?? '').trim();
    const targetPostId = String(req.query.targetPostId ?? '').trim();
    const limitRaw = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 50;

    const filter = {};
    if (action && MODERATION_LOG_ACTIONS.has(action)) filter.action = action;
    if (targetType && MODERATION_LOG_TARGET_TYPES.has(targetType)) filter.targetType = targetType;
    if (targetUserId) filter.targetUserId = targetUserId;
    if (targetPostId) filter.targetPostId = targetPostId;

    const logs = await ModerationLog.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ logs: logs.map(formatModerationLogForAdmin) });
  } catch (e) {
    console.error('GET /api/admin/moderation-logs error:', e.message);
    return res.status(500).json({ error: '获取操作日志失败' });
  }
});

// --- BayBay AI 发帖助手（仅生成草稿，不改发帖逻辑）---
const AI_POST_ASSIST_CATEGORIES = new Set([
  'rent', 'used', 'moving', 'cleaning', 'ride', 'repair', 'translation', 'part-time', 'other',
]);

const AI_DEFAULT_COVERS = [
  '/default-covers/01_求租屋.png',
  '/default-covers/02_找室友.png',
  '/default-covers/03_求帮助.png',
  '/default-covers/04_找搬家.png',
  '/default-covers/05_找清洁.png',
  '/default-covers/06_求接送.png',
  '/default-covers/07_求购二手.png',
  '/default-covers/08_房源出租.png',
  '/default-covers/09_提供服务.png',
  '/default-covers/10_可接单.png',
  '/default-covers/11_搬家服务.png',
  '/default-covers/12_清洁服务.png',
  '/default-covers/13_接送服务.png',
  '/default-covers/14_维修服务.png',
  '/default-covers/15_二手出售.png',
  '/default-covers/16_湾区生活.png',
];

const AI_POST_ASSIST_TONES = new Set(['clear', 'natural', 'concise', 'detailed', 'urgent']);
const AI_POST_ASSIST_REWRITE_MODES = new Set(['shorter', 'moreDetailed', 'moreNatural']);

const normalizeAiTone = (value) => {
  const tone = String(value ?? '').trim();
  return AI_POST_ASSIST_TONES.has(tone) ? tone : 'clear';
};

const normalizeAiRewriteMode = (value) => {
  const mode = String(value ?? '').trim();
  return AI_POST_ASSIST_REWRITE_MODES.has(mode) ? mode : undefined;
};

const getAiDescriptionLengthGuide = (tone, rewriteMode) => {
  if (rewriteMode === 'shorter') return { min: 80, max: 180 };
  if (rewriteMode === 'moreDetailed') return { min: 180, max: 450 };
  switch (tone) {
    case 'concise': return { min: 80, max: 180 };
    case 'natural': return { min: 120, max: 300 };
    case 'detailed': return { min: 180, max: 450 };
    case 'urgent': return { min: 100, max: 260 };
    case 'clear':
    default: return { min: 120, max: 300 };
  }
};

const AI_POST_ASSIST_TONE_GUIDE = {
  clear: '清楚实用、信息完整，适合 BAYLINK 普通帖子；标题和正文都要直接、具体。',
  natural: '更像真实湾区华人用户发帖；不要太像广告或 AI 模板；语气自然、礼貌、有人味。',
  concise: '更简洁；标题短一点；正文重点突出地点、价格、时间、需求。',
  detailed: '更详细；主动补充用户可能需要说明的信息结构；但不要编造不存在的事实。',
  urgent: '可稍作急迫感，表达“希望尽快联系/最近需要”；不要夸张、不要制造恐慌、不要过度营销。',
};

const AI_POST_ASSIST_REWRITE_GUIDE = {
  shorter: '输出更短（覆盖 tone 长度设定）；标题更简短；正文只保留必要信息即可。',
  moreDetailed: '输出更完整（覆盖 tone 长度设定）；帮用户补充结构；不可编造联系方式、具体承诺、房源真实性。',
  moreNatural: '更像真人；减少模板感；避免“本人现需求如下”等生硬表达；更像湾区本地社区发帖语气。',
};

const buildAiPostAssistSystem = () => `你是 BAYLINK 湾区华人本地生活平台的 BayBay 发帖助手。根据用户一句话需求，生成清晰、真实、可发布的帖子草稿。

通用规则：
- 中文优先（除非用户明确要求英文）。
- 标题 5-80 字；正文 80-600 字，不要重复标题，不要把用户原句原样粘贴到正文末尾。
- 必须根据用户提供的 tone 和 rewriteMode（如有）调整标题与正文风格与长度。
- category 只能是：rent, used, moving, cleaning, ride, repair, translation, part-time, other
- type 只能是 client（求帮助/求服务）或 provider（提供服务/出租）
- area 字段请返回中文大区名：旧金山、中半岛、南湾、东湾（不要只写 San Francisco 当 area；Millbrae 等应归中半岛）
- coverSuggestion 必须从以下路径中选一：${AI_DEFAULT_COVERS.join(', ')}
- quickTags 为 2-5 个短标签（字符串数组）
- 只输出一个 JSON 对象，不要 Markdown，不要解释

地区判断（area 字段，非常重要）：
- Millbrae, Burlingame, San Mateo, Foster City, Belmont, San Carlos, Redwood City → 中半岛
- San Francisco, SF, Daly City, South San Francisco → 旧金山
- Palo Alto, Mountain View, Sunnyvale, Santa Clara, Cupertino, San Jose, Milpitas → 南湾
- Oakland, Berkeley, Fremont, Hayward, Union City, Newark, Alameda → 东湾
- Marin, San Rafael, Sausalito → 北湾（若只能选四大区，可写旧金山，但绝不要把 Millbrae 写成旧金山）

求租 vs 出租（type + coverSuggestion，非常重要）：
- 求租/找房/找单间/想租/looking for a room → type=client, category=rent, coverSuggestion=/default-covers/01_求租屋.png
- 出租/有房出租/房源出租/单间出租/room for rent → type=provider, category=rent, coverSuggestion=/default-covers/08_房源出租.png
- 不要把“求租”误判为 provider 或 08_房源出租

文案自然度：
- 像真实湾区华人社区用户发帖，不要太像广告或公文模板。
- 避免“本人现需求如下”“位于某某的单间出租”等生硬表达。
- 求租可用“大家好，我想找…”“如果有合适房源/转租信息，欢迎联系我”等自然语气。
- 不要编造联系方式。

严禁编造（必须遵守）：
- 不要编造任何联系方式（电话、微信、邮箱、Line 等）。
- 不要编造房源真实性、可租状态或具体地址门牌。
- 不要编造服务商资质、执照或“官方认证”。
- 不要承诺价格一定准确；预算/价格只能基于用户原意合理整理，缺信息可留空或写“面议/待沟通”。
- 不要输出法律、财务、移民等专业结论。
- 涉及租房押金、合同、法律政策时，只能提醒用户确认合同、官方信息或咨询专业人士；safetyTip 用提醒语气。

必须严格返回以下 JSON 字段（键名不可改）：
{"title":"","description":"","category":"","type":"","area":"","budget":"","timeInfo":"","quickTags":[],"safetyTip":"","coverSuggestion":""}`;

const buildAiPostAssistUserMessage = ({ intent, type, categoryHint, areaHint, language, tone, rewriteMode, lengthGuide }) => {
  const toneGuide = AI_POST_ASSIST_TONE_GUIDE[tone] || AI_POST_ASSIST_TONE_GUIDE.clear;
  const rewriteGuide = rewriteMode ? AI_POST_ASSIST_REWRITE_GUIDE[rewriteMode] : null;

  const styleLines = [
    `【语气 tone=${tone}】${toneGuide}`,
    rewriteGuide ? `【重写 rewriteMode=${rewriteMode}】${rewriteGuide}` : null,
    `【正文长度】description 控制在 ${lengthGuide.min}-${lengthGuide.max} 字（中文字符计）；rewriteMode 若与 tone 冲突，以 rewriteMode 为准。`,
    '请根据 tone 与 rewriteMode 调整 title 和 description 的写法，其他字段照常填写。',
  ].filter(Boolean);

  return [
    '请根据以下需求生成发帖草稿 JSON。',
    '',
    '用户需求：',
    JSON.stringify({ intent, type, categoryHint: categoryHint || null, areaHint: areaHint || null, language, tone, rewriteMode: rewriteMode || null }),
    '',
    '风格与长度要求：',
    ...styleLines,
  ].join('\n');
};

const aiPostAssistRateByIp = new Map();

const checkAiPostAssistRateLimit = (ip) => {
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 5;
  let entry = aiPostAssistRateByIp.get(ip);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 0, windowStart: now };
  }
  entry.count += 1;
  aiPostAssistRateByIp.set(ip, entry);
  if (aiPostAssistRateByIp.size > 5000) {
    for (const [key, val] of aiPostAssistRateByIp) {
      if (now - val.windowStart >= windowMs) aiPostAssistRateByIp.delete(key);
    }
  }
  return entry.count <= maxRequests;
};

const extractJsonFromAiText = (text) => {
  const trimmed = String(text || '').trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch (_) { /* continue */ }
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) {
    try {
      return JSON.parse(fenced[1].trim());
    } catch (_) { /* continue */ }
  }
  const start = trimmed.indexOf('{');
  const end = trimmed.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try {
      return JSON.parse(trimmed.slice(start, end + 1));
    } catch (_) { /* continue */ }
  }
  return null;
};

const clampStr = (value, maxLen, fallback = '') => {
  const s = String(value ?? '').trim();
  if (!s) return fallback;
  return s.length > maxLen ? s.slice(0, maxLen) : s;
};

const AI_AREA_REGION_RULES = [
  { region: '中半岛', patterns: [/中半岛/i, /\bmillbrae\b/i, /\bburlingame\b/i, /\bsan\s*mateo\b/i, /\bfoster\s*city\b/i, /\bbelmont\b/i, /\bsan\s*carlos\b/i, /\bredwood\s*city\b/i, /半岛/i] },
  { region: '南湾', patterns: [/南湾/i, /\bpalo\s*alto\b/i, /\bmountain\s*view\b/i, /\bsunnyvale\b/i, /\bsanta\s*clara\b/i, /\bcupertino\b/i, /\bsan\s*jose\b/i, /\bmilpitas\b/i, /south\s*bay/i] },
  { region: '东湾', patterns: [/东湾/i, /\boakland\b/i, /\bberkeley\b/i, /\bfremont\b/i, /\bhayward\b/i, /\bunion\s*city\b/i, /\bnewark\b/i, /\balameda\b/i, /east\s*bay/i] },
  { region: '旧金山', patterns: [/旧金山/i, /\bsouth\s*san\s*francisco\b/i, /\bsan\s*francisco\b/i, /\bdaly\s*city\b/i, /\bsf\b/i, /北湾/i, /\bmarin\b/i, /\bsan\s*rafael\b/i, /\bsausalito\b/i] },
];

const AI_REGION_LABELS = new Set(['旧金山', '中半岛', '南湾', '东湾']);

const resolveAreaRegionFromText = (text) => {
  const t = String(text || '').trim();
  if (!t) return '';
  // 先按具体城市匹配，避免 AI 误填「旧金山」盖掉 Millbrae 等关键词
  for (const { region, patterns } of AI_AREA_REGION_RULES) {
    if (patterns.some((p) => p.test(t))) return region;
  }
  for (const label of AI_REGION_LABELS) {
    if (t.includes(label)) return label;
  }
  return '';
};

const inferIntentSignals = (intent) => {
  const t = String(intent || '').trim();
  const rentSeeking = /求租|找房|找单间|想租|租一间|需要租房|looking\s*for\s*(a\s*)?(room|apartment|place)|need\s*(a\s*)?(room|apartment|place)|想找.*(room|studio|单间|(?<!退)房)/i.test(t);
  const rentOffering = /出租|有房出租|房源出租|单间出租|整租出租|合租出租|available\s*(room|apartment)|room\s*for\s*rent|for\s*rent|提供房源/i.test(t);
  const usedSelling = /想卖|出售|转让|卖.*(桌子|沙发|家具|二手)|moving\s*sale|for\s*sale/i.test(t);
  const usedBuying = /求购|想买|收一个|looking\s*for\s*(a\s*)?used/i.test(t);
  const cleaningSeeking = /找清洁|退房清洁|深度清洁|需要清洁|cleaning\s*service/i.test(t);
  return { rentSeeking, rentOffering, usedSelling, usedBuying, cleaningSeeking };
};

const inferCategoryAndType = (intent, fallbackType, fallbackCategory) => {
  const signals = inferIntentSignals(intent);
  let category = fallbackCategory || 'other';
  let type = fallbackType === 'provider' ? 'provider' : 'client';

  if (signals.cleaningSeeking) {
    category = 'cleaning';
    type = 'client';
  } else if (signals.rentOffering && !signals.rentSeeking) {
    category = 'rent';
    type = 'provider';
  } else if (signals.rentSeeking) {
    category = 'rent';
    type = 'client';
  } else if (signals.usedSelling && !signals.usedBuying) {
    category = 'used';
    type = 'provider';
  } else if (signals.usedBuying) {
    category = 'used';
    type = 'client';
  }

  return { category, type };
};

const getDefaultCoverForCategoryType = (category, type) => {
  const client = {
    rent: '/default-covers/01_求租屋.png',
    used: '/default-covers/07_求购二手.png',
    moving: '/default-covers/04_找搬家.png',
    cleaning: '/default-covers/05_找清洁.png',
    ride: '/default-covers/06_求接送.png',
    repair: '/default-covers/14_维修服务.png',
    translation: '/default-covers/16_湾区生活.png',
    'part-time': '/default-covers/10_可接单.png',
    other: '/default-covers/16_湾区生活.png',
  };
  const provider = {
    rent: '/default-covers/08_房源出租.png',
    used: '/default-covers/15_二手出售.png',
    moving: '/default-covers/11_搬家服务.png',
    cleaning: '/default-covers/12_清洁服务.png',
    ride: '/default-covers/13_接送服务.png',
    repair: '/default-covers/14_维修服务.png',
    translation: '/default-covers/09_提供服务.png',
    'part-time': '/default-covers/10_可接单.png',
    other: '/default-covers/16_湾区生活.png',
  };
  const map = type === 'provider' ? provider : client;
  return map[category] || '/default-covers/16_湾区生活.png';
};

const sanitizeAiDescription = (description, title, intent) => {
  let desc = String(description || '').trim();
  const intentTrim = String(intent || '').trim();
  const titleTrim = String(title || '').trim();

  if (intentTrim) {
    if (desc === intentTrim) desc = '';
    if (desc.endsWith(intentTrim)) {
      desc = desc.slice(0, desc.length - intentTrim.length).trim().replace(/[\n，。,.]+$/, '');
    }
    if (desc.includes(intentTrim)) {
      desc = desc.split(intentTrim).join(' ').replace(/\s{2,}/g, ' ').trim();
    }
  }

  if (titleTrim) {
    if (desc === titleTrim) desc = '';
    if (desc.startsWith(titleTrim)) {
      desc = desc.slice(titleTrim.length).trim().replace(/^[\n，。,.]+/, '');
    }
  }

  desc = desc.replace(/\n{3,}/g, '\n\n').trim();
  return desc;
};

const padAiDescription = (description, minLen, maxLen) => {
  let desc = description;
  const fillers = [
    '如果有合适的信息，欢迎私信或留言联系，谢谢。',
    '细节可以再聊，也欢迎邻居推荐或转发。',
    '希望附近有了解的朋友帮忙看看，感谢。',
  ];
  for (const line of fillers) {
    if (desc.length >= minLen) break;
    if (!desc.includes(line)) desc = desc ? `${desc}\n\n${line}` : line;
  }
  return clampStr(desc, maxLen);
};

const normalizeAiPostDraft = (raw, defaults) => {
  const intent = String(defaults.intent || '').trim();

  let category = String(raw?.category || '').trim();
  if (!AI_POST_ASSIST_CATEGORIES.has(category)) category = defaults.categoryHint || defaults.category || 'other';

  let type = String(raw?.type || '').trim();
  if (type !== 'client' && type !== 'provider') type = defaults.type || 'client';

  const inferred = inferCategoryAndType(intent, type, category);
  category = inferred.category;
  type = inferred.type;

  const coverSuggestion = getDefaultCoverForCategoryType(category, type);

  let title = clampStr(raw?.title, 80);
  if (title.length < 5) {
    const signals = inferIntentSignals(intent);
    if (signals.rentSeeking) title = '求租信息';
    else if (signals.rentOffering) title = '房源出租';
    else title = '湾区生活信息';
  }

  const descMin = defaults.descMin ?? 80;
  const descMax = defaults.descMax ?? 600;
  let description = sanitizeAiDescription(clampStr(raw?.description, descMax), title, intent);
  description = padAiDescription(description, descMin, descMax);

  const quickTags = Array.isArray(raw?.quickTags)
    ? raw.quickTags.map((t) => clampStr(t, 20)).filter(Boolean).slice(0, 5)
    : [];

  const locationText = `${intent} ${defaults.areaHint || ''} ${title} ${description}`;
  let area = resolveAreaRegionFromText(locationText);
  if (!area) area = clampStr(raw?.area || defaults.areaHint, 80);

  return {
    title,
    description,
    category,
    type,
    area,
    budget: clampStr(raw?.budget, 30),
    timeInfo: clampStr(raw?.timeInfo, 120),
    quickTags,
    safetyTip: clampStr(raw?.safetyTip, 200, '线下交易与签约请注意核实信息，重要事项以合同与官方信息为准。'),
    coverSuggestion,
  };
};

const callOpenAiPostAssist = async ({ intent, type, categoryHint, areaHint, language, tone, rewriteMode, lengthGuide }) => {
  const model = process.env.OPENAI_MODEL || 'gpt-5.4-mini';
  const maxTokens = lengthGuide.max >= 350 ? 1100 : 900;

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.5,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: buildAiPostAssistSystem() },
        {
          role: 'user',
          content: buildAiPostAssistUserMessage({
            intent,
            type,
            categoryHint,
            areaHint,
            language,
            tone,
            rewriteMode,
            lengthGuide,
          }),
        },
      ],
    }),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    const brief = errText.slice(0, 120);
    throw new Error(`OpenAI HTTP ${res.status}${brief ? `: ${brief}` : ''}`);
  }

  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content;
  const parsed = extractJsonFromAiText(content);
  if (!parsed) throw new Error('Invalid JSON from model');
  return parsed;
};

app.post('/api/ai/post-assist', authenticateToken, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ ok: false, error: 'AI 服务暂未配置，请稍后再试' });
    }

    const intent = String(req.body?.intent ?? '').trim();
    if (intent.length < 5) {
      return res.status(400).json({ ok: false, error: '请至少用 5 个字描述你的需求' });
    }
    if (intent.length > 1000) {
      return res.status(400).json({ ok: false, error: '需求描述不能超过 1000 字' });
    }

    const ip = getClientIp(req);
    if (!checkAiPostAssistRateLimit(ip)) {
      return res.status(429).json({ ok: false, error: '请求过于频繁，请 60 秒后再试' });
    }

    let type = req.body?.type;
    if (type !== 'client' && type !== 'provider') type = 'client';

    let categoryHint;
    const hint = String(req.body?.categoryHint ?? '').trim();
    if (hint && AI_POST_ASSIST_CATEGORIES.has(hint)) categoryHint = hint;

    const areaHint = clampStr(req.body?.areaHint, 80);
    const language = req.body?.language === 'en' ? 'en' : 'zh';
    const tone = normalizeAiTone(req.body?.tone);
    const rewriteMode = normalizeAiRewriteMode(req.body?.rewriteMode);
    const lengthGuide = getAiDescriptionLengthGuide(tone, rewriteMode);

    const rawDraft = await callOpenAiPostAssist({
      intent,
      type,
      categoryHint,
      areaHint,
      language,
      tone,
      rewriteMode,
      lengthGuide,
    });

    const draft = normalizeAiPostDraft(rawDraft, {
      intent,
      type,
      categoryHint: categoryHint || 'other',
      areaHint,
      descMin: lengthGuide.min,
      descMax: lengthGuide.max,
    });

    return res.json({ ok: true, draft });
  } catch (e) {
    console.error('POST /api/ai/post-assist error:', e.message);
    return res.status(502).json({ ok: false, error: 'AI 整理失败，请稍后再试' });
  }
});

// --- BayBay AI Guide 问答（首页助手面板，单轮、不存聊天记录）---
const GUIDE_CHAT_CATEGORIES = new Set(['rent', 'roommate', 'used', 'moving', 'cleaning', 'ride', 'repair', 'other']);

const GUIDE_CATALOG = [
  {
    title: '湾区租房防骗指南',
    slug: 'bay-area-rental-scam-guide',
    url: '/guides/bay-area-rental-scam-guide',
    keywords: ['租房', '求租', '出租', '押金', '房东', '骗局', 'lease', 'room', 'rent'],
    categories: ['rent'],
  },
  {
    title: '新来湾区第一个月 checklist',
    slug: 'bay-area-newcomer-first-month-checklist',
    url: '/guides/bay-area-newcomer-first-month-checklist',
    keywords: ['刚来', '新来', '搬来', '新移民', '留学生', '第一个月', 'checklist'],
    categories: ['other', 'rent'],
  },
  {
    title: '湾区找室友避坑指南',
    slug: 'bay-area-roommate-guide',
    url: '/guides/bay-area-roommate-guide',
    keywords: ['室友', '合租', 'roommate', '找人一起租'],
    categories: ['roommate', 'rent'],
  },
  {
    title: '湾区通勤方式全对比',
    slug: 'bay-area-commute-guide',
    url: '/guides/bay-area-commute-guide',
    keywords: ['通勤', 'Caltrain', 'BART', '开车', '停车', '上班', '交通'],
    categories: ['ride', 'other'],
  },
  {
    title: '湾区二手交易安全指南',
    slug: 'bay-area-used-market-safety-guide',
    url: '/guides/bay-area-used-market-safety-guide',
    keywords: ['二手', '买卖', '出售', '求购', '交易', '取货', 'used'],
    categories: ['used'],
  },
  {
    title: '租房合同签字前 checklist',
    slug: 'rental-lease-signing-checklist',
    url: '/guides/rental-lease-signing-checklist',
    keywords: ['合同', '租约', '签字', 'lease', '押金', '条款'],
    categories: ['rent'],
  },
  {
    title: '租客搬入搬出 checklist',
    slug: 'tenant-move-in-out-checklist',
    url: '/guides/tenant-move-in-out-checklist',
    keywords: ['搬入', '搬出', '退租', '押金', 'move out', 'move in'],
    categories: ['rent', 'moving'],
  },
  {
    title: '本地服务避坑指南',
    slug: 'local-service-safety-guide',
    url: '/guides/local-service-safety-guide',
    keywords: ['清洁', '搬家', '维修', '接送', '服务', '报价', '上门'],
    categories: ['cleaning', 'moving', 'repair', 'ride'],
  },
  {
    title: 'Peninsula 生活指南',
    slug: 'peninsula-living-guide',
    url: '/guides/peninsula-living-guide',
    keywords: ['中半岛', 'Millbrae', 'San Mateo', 'Burlingame', 'Redwood City', 'Peninsula'],
    categories: ['other', 'rent'],
  },
  {
    title: '南湾居住指南',
    slug: 'south-bay-living-guide',
    url: '/guides/south-bay-living-guide',
    keywords: ['南湾', 'San Jose', 'Cupertino', 'Sunnyvale', 'Santa Clara', 'Mountain View'],
    categories: ['other', 'rent'],
  },
];

const GUIDE_CHAT_CATEGORY_KEYWORDS = {
  rent: ['租房', '求租', '出租', '房源', '单间', 'lease', 'rent', '押金', '租约'],
  roommate: ['室友', '合租', 'roommate', '找人一起租'],
  used: ['二手', '出售', '卖', '买', '求购', '家具', '电器', '桌子', '床', 'used'],
  moving: ['搬家', '搬运', 'move', 'truck', 'queen bed'],
  cleaning: ['清洁', '退房清洁', '打扫', 'cleaning'],
  ride: ['接送', '机场', 'SFO', 'ride', 'pickup', 'dropoff'],
  repair: ['维修', '修理', '水管', '电', '门锁', 'repair'],
};

const GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY = {
  rent: 'bay-area-rental-scam-guide',
  roommate: 'bay-area-roommate-guide',
  used: 'bay-area-used-market-safety-guide',
  moving: 'tenant-move-in-out-checklist',
  cleaning: 'local-service-safety-guide',
  ride: 'bay-area-commute-guide',
  repair: 'local-service-safety-guide',
  other: 'bay-area-newcomer-first-month-checklist',
};

const GUIDE_CHAT_SYSTEM = `你是 BAYLINK 湾区华人本地生活平台的 BayBay 问答助手。用户单次提问，请给出简短实用回答。

规则：
- 必须根据用户当前 message 回答，不要把所有问题都当成租房
- 用户问维修就回答维修；问卖东西/二手就回答二手交易；问室友就回答找室友；问搬家/清洁/接送就回答对应主题
- 不确定时先澄清用户想做什么，不要默认当成租房
- 中文优先，answer 控制在 80-180 字
- 适合旧金山湾区华人用户，语气亲切务实
- 不编造房源、服务商、实时政策或价格
- 不给法律、移民、财务、医疗专业结论
- 涉及租房押金、合同、诈骗等高风险话题，只给一般提醒，建议以合同/官方信息/专业人士意见为准
- 回答应自然导向：在 BAYLINK 看指南、浏览分类、发布信息、使用发帖助手
- safetyNote 可选，最多 60 字；无必要则返回空字符串
- 只输出一个 JSON 对象，不要 Markdown，不要解释

必须返回：{"answer":"","safetyNote":""}`;

const normalizeCategoryHint = (categoryHint) => {
  const hint = String(categoryHint ?? '').trim().toLowerCase();
  if (!hint || hint === 'general') return '';
  if (GUIDE_CHAT_CATEGORIES.has(hint)) return hint;
  return '';
};

function inferBayBayIntent(message = '', categoryHint = '') {
  const text = String(message || '').toLowerCase();
  if (/室友|合租|roommate|找人合租|share room/.test(text)) return 'roommate';
  if (/维修|修理|水管|电工|电路|马桶|漏水|家电|handyman|repair|fix/.test(text)) return 'repair';
  if (/卖东西|出东西|二手|转让|家具|家电|出售|used|sell|secondhand/.test(text)) return 'used';
  if (/搬家|搬运|moving|move/.test(text)) return 'moving';
  if (/清洁|打扫|保洁|cleaning|cleaner/.test(text)) return 'cleaning';
  if (/接送|机场|通勤|ride|pickup|dropoff|sfo|sjc/.test(text)) return 'ride';
  if (/租房|房源|找房|求租|押金|看房|租约|rent|housing|apartment/.test(text)) return 'rent';
  if (/\broom\b/.test(text) && !/roommate/.test(text)) return 'rent';
  if (/服务|帮忙|本地服务|service/.test(text)) return 'service';
  const normalizedHint = normalizeCategoryHint(categoryHint);
  return normalizedHint || 'general';
}

const intentToGuideCategory = (intent) => {
  if (intent === 'general' || intent === 'service') return 'other';
  if (intent === 'roommate') return 'roommate';
  return GUIDE_CHAT_CATEGORIES.has(intent) ? intent : 'other';
};

const GUIDE_CHAT_FALLBACK_ANSWERS = {
  repair: '可以先把维修类型、所在区域、希望上门时间、预算和照片说明清楚。建议先确认上门费、材料费和是否有维修后保障。',
  roommate: '找室友时，建议先确认预算、入住时间、区域、通勤、作息、宠物和访客规则。把租约、押金和公共区域使用方式写清楚，会更容易找到合适的人。',
  used: '卖二手时，建议写清物品名称、成色、价格、取货地点和是否可议价。上传真实照片，贵重物品尽量当面交易，不要点陌生付款链接。',
  moving: '找搬家前，建议写清搬出/搬入区域、楼层、电梯、物品数量、是否需要拆装家具和希望时间。',
  cleaning: '找清洁前，建议写清房屋大小、清洁范围、是否需要深度清洁、是否自备工具和希望时间。',
  ride: '找接送前，建议写清出发地、目的地、时间、人数、行李数量和是否需要准时到达。',
  rent: '刚来湾区租房，先别急着交押金。先确认预算、通勤、租约和看房方式，看房或视频看房后再付款更稳妥。',
  service: '联系本地服务前，先把时间、地点、预算和具体需求说清楚，沟通会更顺。',
  general: '可以先告诉我你想找房、找室友、买卖二手、找搬家清洁维修，还是需要本地生活建议。我可以帮你整理成更清楚的方向。',
  other: '可以先告诉我你想找房、找室友、买卖二手、找搬家清洁维修，还是需要本地生活建议。我可以帮你整理成更清楚的方向。',
};

const guideChatRateByIp = new Map();

const checkGuideChatRateLimit = (ip) => {
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 8;
  let entry = guideChatRateByIp.get(ip);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 0, windowStart: now };
  }
  entry.count += 1;
  guideChatRateByIp.set(ip, entry);
  if (guideChatRateByIp.size > 5000) {
    for (const [key, val] of guideChatRateByIp) {
      if (now - val.windowStart >= windowMs) guideChatRateByIp.delete(key);
    }
  }
  return entry.count <= maxRequests;
};

const normalizeGuideChatMessage = (value) => {
  const message = String(value ?? '').trim();
  if (!message) return { ok: false, error: '请输入你的问题' };
  if (message.length < 2) return { ok: false, error: '问题太短，请再补充一点' };
  if (message.length > 500) {
    return { ok: true, message: message.slice(0, 500) };
  }
  return { ok: true, message };
};

const inferGuideChatCategory = (message, categoryHint) =>
  intentToGuideCategory(inferBayBayIntent(message, categoryHint));

const getGuideChatFallbackAnswer = (intent) =>
  GUIDE_CHAT_FALLBACK_ANSWERS[intent] || GUIDE_CHAT_FALLBACK_ANSWERS.general;

const scoreGuideForMessage = (guide, message, category) => {
  const lower = message.toLowerCase();
  let score = 0;
  for (const kw of guide.keywords) {
    if (message.includes(kw) || lower.includes(kw.toLowerCase())) score += 3;
  }
  if (guide.categories.includes(category)) score += 2;
  return score;
};

const pickSuggestedGuides = (message, category) => {
  const ranked = GUIDE_CATALOG
    .map((guide) => ({ guide, score: scoreGuideForMessage(guide, message, category) }))
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const aCat = a.guide.categories.includes(category) ? 1 : 0;
      const bCat = b.guide.categories.includes(category) ? 1 : 0;
      return bCat - aCat;
    });

  const picked = [];
  const seen = new Set();
  for (const { guide, score } of ranked) {
    if (score <= 0 && picked.length >= 1) continue;
    if (seen.has(guide.slug)) continue;
    seen.add(guide.slug);
    picked.push({ title: guide.title, slug: guide.slug, url: guide.url });
    if (picked.length >= 3) break;
  }

  if (picked.length === 0) {
    const fallbackSlug = GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY[category] || GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY.other;
    const fallback = GUIDE_CATALOG.find((g) => g.slug === fallbackSlug) || GUIDE_CATALOG[0];
    picked.push({ title: fallback.title, slug: fallback.slug, url: fallback.url });
  }

  return picked.slice(0, 3);
};

const buildSuggestedActions = (category) => {
  const cat = GUIDE_CHAT_CATEGORIES.has(category) ? category : 'other';
  const actionsByCategory = {
    rent: [
      { label: '看租房分类', type: 'category', url: '/category/rent', category: 'rent' },
      { label: '发布求租', type: 'post', url: '/?type=client&category=rent', postType: 'client', category: 'rent' },
      { label: '让 BayBay 帮我写求租帖', type: 'postAssist', url: '/?postAssist=1&type=client&category=rent', postType: 'client', category: 'rent' },
    ],
    roommate: [
      { label: '发布找室友', type: 'post', url: '/?type=client&category=rent', postType: 'client', category: 'rent' },
      { label: '查看室友相关指南', type: 'guide', url: '/guides/bay-area-roommate-guide' },
      { label: '让 BayBay 帮我写室友帖', type: 'postAssist', url: '/?postAssist=1&type=client&category=rent', postType: 'client', category: 'rent' },
    ],
    used: [
      { label: '看二手分类', type: 'category', url: '/category/used', category: 'used' },
      { label: '发布二手信息', type: 'post', url: '/?type=provider&category=used', postType: 'provider', category: 'used' },
      { label: '让 BayBay 帮我整理二手帖', type: 'postAssist', url: '/?postAssist=1&type=provider&category=used', postType: 'provider', category: 'used' },
    ],
    moving: [
      { label: '看搬家服务', type: 'category', url: '/category/moving', category: 'moving' },
      { label: '发布搬家需求', type: 'post', url: '/?type=client&category=moving', postType: 'client', category: 'moving' },
      { label: '让 BayBay 帮我写搬家需求', type: 'postAssist', url: '/?postAssist=1&type=client&category=moving', postType: 'client', category: 'moving' },
    ],
    cleaning: [
      { label: '看清洁服务', type: 'category', url: '/category/cleaning', category: 'cleaning' },
      { label: '发布清洁需求', type: 'post', url: '/?type=client&category=cleaning', postType: 'client', category: 'cleaning' },
      { label: '让 BayBay 帮我写清洁需求', type: 'postAssist', url: '/?postAssist=1&type=client&category=cleaning', postType: 'client', category: 'cleaning' },
    ],
    ride: [
      { label: '看接送分类', type: 'category', url: '/category/ride', category: 'ride' },
      { label: '发布接送需求', type: 'post', url: '/?type=client&category=ride', postType: 'client', category: 'ride' },
      { label: '让 BayBay 帮我写接送需求', type: 'postAssist', url: '/?postAssist=1&type=client&category=ride', postType: 'client', category: 'ride' },
    ],
    repair: [
      { label: '看维修分类', type: 'category', url: '/category/repair', category: 'repair' },
      { label: '发布维修需求', type: 'post', url: '/?type=client&category=repair', postType: 'client', category: 'repair' },
      { label: '让 BayBay 帮我写维修需求', type: 'postAssist', url: '/?postAssist=1&type=client&category=repair', postType: 'client', category: 'repair' },
    ],
    other: [
      { label: '浏览湾区指南', type: 'guide', url: '/guides', category: 'other' },
      { label: '发布求助', type: 'post', url: '/?type=client&category=other', postType: 'client', category: 'other' },
      { label: '让 BayBay 帮我整理帖子', type: 'postAssist', url: '/?postAssist=1&type=client&category=other', postType: 'client', category: 'other' },
    ],
  };
  return (actionsByCategory[cat] || actionsByCategory.other).slice(0, 3);
};

const INTERACTIVE_CARD_ACTION_TYPES = new Set(['category', 'guide', 'post', 'postAssist']);
const INTERACTIVE_CARD_TYPES = new Set(['checklist', 'safety']);
const INTERACTIVE_CARD_POST_TYPES = new Set(['client', 'provider']);

const validateInteractiveCardAction = (raw) => {
  if (!raw || typeof raw !== 'object') return null;
  const type = String(raw.type ?? '').trim();
  if (!INTERACTIVE_CARD_ACTION_TYPES.has(type)) return null;

  const label = clampStr(raw.label, 40);
  if (!label) return null;

  const action = { label, type };
  const url = String(raw.url ?? '').trim();
  if (url) {
    if (!url.startsWith('/guides') && !url.startsWith('/category')) return null;
    action.url = url;
  }

  const postType = String(raw.postType ?? '').trim();
  if (postType) {
    if (!INTERACTIVE_CARD_POST_TYPES.has(postType)) return null;
    action.postType = postType;
  }

  const category = String(raw.category ?? '').trim();
  if (category) {
    if (!GUIDE_CHAT_CATEGORIES.has(category)) return null;
    action.category = category;
  }

  return action;
};

const validateInteractiveCard = (raw) => {
  if (!raw || typeof raw !== 'object') return null;

  const forbiddenKeys = ['html', 'markdown', 'jsx', 'component'];
  if (forbiddenKeys.some((k) => raw[k] != null && String(raw[k]).trim() !== '')) return null;

  const type = String(raw.type ?? '').trim();
  if (!INTERACTIVE_CARD_TYPES.has(type)) return null;

  const id = clampStr(raw.id, 48);
  const title = clampStr(raw.title, 40);
  if (!id || !title) return null;

  const subtitle = clampStr(raw.subtitle, 80);
  const itemsRaw = Array.isArray(raw.items) ? raw.items.slice(0, 6) : [];
  const items = [];
  for (const item of itemsRaw) {
    if (!item || typeof item !== 'object') continue;
    const itemId = clampStr(item.id, 32);
    const label = clampStr(item.label, 60);
    if (!itemId || !label) continue;
    items.push({ id: itemId, label });
    if (items.length >= 6) break;
  }
  if (items.length === 0) return null;

  const actionsRaw = Array.isArray(raw.actions) ? raw.actions.slice(0, 2) : [];
  const actions = [];
  for (const act of actionsRaw) {
    const validated = validateInteractiveCardAction(act);
    if (validated) actions.push(validated);
    if (actions.length >= 2) break;
  }

  const card = { id, type, title, items };
  if (subtitle) card.subtitle = subtitle;
  if (actions.length > 0) card.actions = actions;
  return card;
};

const GUIDE_CHAT_SHORT_INTRO = {
  rent: '刚来湾区租房，先别急着交押金。先确认预算、通勤、租约和看房方式，下面这些可以逐项核对。',
  roommate: '找室友时，先把预算、入住时间、作息和公共区域规则说清楚，下面这张卡可以帮你快速核对。',
  used: '二手交易最重要的是先确认物品真实性、交易地点和付款方式。下面这张卡可以帮你快速检查。',
  moving: '找搬家前，先把搬出/搬入地点、楼层、物品数量和希望时间说清楚，下面可以逐项核对。',
  cleaning: '找清洁前，先把房屋大小、清洁范围、是否深度清洁和希望时间说清楚，下面可以逐项核对。',
  ride: '找接送前，先把出发地、目的地、时间、人数和行李数量说清楚，下面可以逐项核对。',
  repair: '找维修前，先把故障类型、所在区域、希望上门时间和预算说清楚，下面可以逐项核对。',
};

const getGuideChatShortIntro = (category) => {
  const cat = GUIDE_CHAT_CATEGORIES.has(category) ? category : 'other';
  return GUIDE_CHAT_SHORT_INTRO[cat] || null;
};

const shortenGuideChatAnswer = (answer, maxLen = 120) => {
  const text = String(answer ?? '').trim();
  if (text.length <= maxLen) return text;
  const trimmed = text.slice(0, maxLen - 1).replace(/[，,、；;：:\s]+$/, '');
  return `${trimmed}…`;
};

const buildInteractiveCards = ({ message, category }) => {
  const cat = GUIDE_CHAT_CATEGORIES.has(category) ? category : 'other';
  void message;

  let draft = null;
  if (cat === 'rent') {
    draft = {
      id: 'rent-checklist-v1',
      type: 'checklist',
      title: '租房前先确认这些',
      subtitle: '先把预算、位置和安全细节想清楚，再联系或发帖。',
      items: [
        { id: 'budget', label: '预算范围是否明确' },
        { id: 'commute', label: '通勤区域是否合适' },
        { id: 'move-in', label: '入住时间是否清楚' },
        { id: 'lease', label: '押金和租约条款是否写明' },
        { id: 'viewing', label: '是否能实地或视频看房' },
      ],
      actions: [
        { label: '让 BayBay 帮我写求租帖', type: 'postAssist', postType: 'client', category: 'rent' },
      ],
    };
  } else if (cat === 'roommate') {
    draft = {
      id: 'roommate-checklist-v1',
      type: 'checklist',
      title: '找室友前先确认这些',
      subtitle: '把预算、作息和公共区域规则说清楚，更容易找到合适的人。',
      items: [
        { id: 'budget', label: '预算和入住时间是否明确' },
        { id: 'area', label: '区域和通勤是否合适' },
        { id: 'schedule', label: '作息和访客规则是否说清' },
        { id: 'pets', label: '宠物和公共区域使用是否一致' },
        { id: 'lease', label: '租约、押金和分租关系是否清楚' },
      ],
      actions: [
        { label: '让 BayBay 帮我写室友帖', type: 'postAssist', postType: 'client', category: 'rent' },
      ],
    };
  } else if (cat === 'used') {
    draft = {
      id: 'used-safety-v1',
      type: 'safety',
      title: '二手交易前注意',
      subtitle: '交易前先确认物品、地点和付款方式。',
      items: [
        { id: 'model', label: '确认物品型号和新旧程度' },
        { id: 'media', label: '尽量要求实物照片或视频' },
        { id: 'inspect', label: '当面验货后再付款' },
        { id: 'links', label: '不点击陌生付款链接' },
        { id: 'records', label: '保留聊天记录' },
      ],
      actions: [
        { label: '整理二手帖子', type: 'postAssist', postType: 'provider', category: 'used' },
      ],
    };
  } else if (cat === 'repair') {
    draft = {
      id: 'repair-checklist-v1',
      type: 'checklist',
      title: '找维修前先确认这些',
      subtitle: '把故障、地点和时间说清楚，沟通会更顺。',
      items: [
        { id: 'issue', label: '说明故障现象和位置' },
        { id: 'photos', label: '尽量上传照片或视频' },
        { id: 'time', label: '确认希望上门时间' },
        { id: 'quote', label: '确认上门费和材料费' },
        { id: 'records', label: '保留报价和聊天记录' },
      ],
      actions: [
        { label: '发布维修需求', type: 'postAssist', postType: 'client', category: 'repair' },
      ],
    };
  } else if (cat === 'moving') {
    draft = {
      id: 'moving-checklist-v1',
      type: 'checklist',
      title: '搬家前先确认这些',
      subtitle: '把搬出/搬入地点和物品情况说清楚，报价会更准。',
      items: [
        { id: 'addresses', label: '搬出和搬入地址是否明确' },
        { id: 'access', label: '楼层、电梯和停车是否说明' },
        { id: 'items', label: '大件数量和是否需要拆装' },
        { id: 'time', label: '希望搬家时间是否确定' },
        { id: 'quote', label: '报价是否包含额外费用' },
      ],
      actions: [
        { label: '发布搬家需求', type: 'postAssist', postType: 'client', category: 'moving' },
      ],
    };
  } else if (cat === 'cleaning') {
    draft = {
      id: 'cleaning-checklist-v1',
      type: 'checklist',
      title: '找清洁前先确认这些',
      subtitle: '把房屋大小和清洁范围说清楚，沟通会更顺。',
      items: [
        { id: 'size', label: '房屋大小和房间数量' },
        { id: 'scope', label: '日常清洁还是深度清洁' },
        { id: 'tools', label: '是否需要自备工具或清洁剂' },
        { id: 'time', label: '希望上门时间' },
        { id: 'quote', label: '报价是否包含额外区域' },
      ],
      actions: [
        { label: '发布清洁需求', type: 'postAssist', postType: 'client', category: 'cleaning' },
      ],
    };
  } else if (cat === 'ride') {
    draft = {
      id: 'ride-safety-v1',
      type: 'safety',
      title: '找接送前先确认这些',
      subtitle: '把路线、时间和人数说清楚，安排会更稳。',
      items: [
        { id: 'route', label: '出发地和目的地是否明确' },
        { id: 'time', label: '出发时间和是否需准时到达' },
        { id: 'passengers', label: '人数和行李数量' },
        { id: 'price', label: '报价和付款方式是否说清' },
        { id: 'records', label: '保留聊天记录和确认信息' },
      ],
      actions: [
        { label: '发布接送需求', type: 'postAssist', postType: 'client', category: 'ride' },
      ],
    };
  }

  if (!draft) return [];

  const validated = validateInteractiveCard(draft);
  return validated ? [validated] : [];
};

const buildGuideChatPayload = (message, category, answerOverride) => {
  const intent = inferBayBayIntent(message, '');
  let answer = answerOverride || getGuideChatFallbackAnswer(intent);
  answer = clampStr(answer, 180);
  if (answer.length < 10) {
    answer = getGuideChatFallbackAnswer(intent);
  }

  const safetyNote = '';
  let suggestedGuides = pickSuggestedGuides(message, category);
  if (suggestedGuides.length === 0) {
    const fallbackSlug = GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY[category] || GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY.other;
    const fallback = GUIDE_CATALOG.find((g) => g.slug === fallbackSlug) || GUIDE_CATALOG[0];
    suggestedGuides = [{ title: fallback.title, slug: fallback.slug, url: fallback.url }];
  }

  let suggestedActions = buildSuggestedActions(category);
  if (suggestedActions.length < 2) {
    suggestedActions = buildSuggestedActions('other');
  }

  const interactiveCards = buildInteractiveCards({ message, category });

  if (interactiveCards.length > 0) {
    const shortIntro = getGuideChatShortIntro(category);
    if (shortIntro) {
      answer = shortIntro;
    } else if (answer.length > 120) {
      answer = shortenGuideChatAnswer(answer, 120);
    }
  }

  return {
    ok: true,
    answer,
    suggestedGuides: suggestedGuides.slice(0, 3),
    suggestedActions: suggestedActions.slice(0, 3),
    safetyNote,
    interactiveCards,
  };
};

const normalizeGuideChatResponse = (aiRaw, message, category) => {
  const intent = inferBayBayIntent(message, '');
  let answer = clampStr(aiRaw?.answer, 180);
  if (answer.length < 10) {
    answer = getGuideChatFallbackAnswer(intent);
  }

  const safetyNote = clampStr(aiRaw?.safetyNote, 60);
  let suggestedGuides = pickSuggestedGuides(message, category);
  if (suggestedGuides.length === 0) {
    const fallbackSlug = GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY[category] || GUIDE_CHAT_DEFAULT_SLUG_BY_CATEGORY.other;
    const fallback = GUIDE_CATALOG.find((g) => g.slug === fallbackSlug) || GUIDE_CATALOG[0];
    suggestedGuides = [{ title: fallback.title, slug: fallback.slug, url: fallback.url }];
  }

  let suggestedActions = buildSuggestedActions(category);
  if (suggestedActions.length < 2) {
    suggestedActions = buildSuggestedActions('other');
  }

  const interactiveCards = buildInteractiveCards({ message, category });

  if (interactiveCards.length > 0) {
    const shortIntro = getGuideChatShortIntro(category);
    if (shortIntro) {
      answer = shortIntro;
    } else if (answer.length > 120) {
      answer = shortenGuideChatAnswer(answer, 120);
    }
  }

  return {
    ok: true,
    answer,
    suggestedGuides: suggestedGuides.slice(0, 3),
    suggestedActions: suggestedActions.slice(0, 3),
    safetyNote: safetyNote || '',
    interactiveCards,
  };
};

const callOpenAiGuideChat = async ({ message, category, intent, currentPath }) => {
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  const userPayload = {
    message,
    inferredIntent: intent,
    inferredCategory: category,
    currentPath: currentPath || '/',
  };

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.4,
      max_tokens: 320,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: GUIDE_CHAT_SYSTEM },
        {
          role: 'user',
          content: `用户问题：\n${JSON.stringify(userPayload)}`,
        },
      ],
    }),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    const brief = errText.slice(0, 120);
    throw new Error(`OpenAI HTTP ${res.status}${brief ? `: ${brief}` : ''}`);
  }

  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content;
  const parsed = extractJsonFromAiText(content);
  if (!parsed) throw new Error('Invalid JSON from model');
  return parsed;
};

app.post('/api/ai/guide-chat', async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ ok: false, error: 'AI 问答服务暂未配置，请稍后再试' });
    }

    const normalized = normalizeGuideChatMessage(req.body?.message);
    if (!normalized.ok) {
      return res.status(400).json({ ok: false, error: normalized.error });
    }

    const ip = getClientIp(req);
    if (!checkGuideChatRateLimit(ip)) {
      return res.status(429).json({ ok: false, error: '提问过于频繁，请 60 秒后再试' });
    }

    const message = normalized.message;
    const categoryHint = req.body?.context?.categoryHint;
    const currentPath = String(req.body?.context?.currentPath ?? '/').trim() || '/';
    const intent = inferBayBayIntent(message, categoryHint);
    const category = intentToGuideCategory(intent);

    const aiRaw = await callOpenAiGuideChat({ message, category, intent, currentPath });
    const payload = normalizeGuideChatResponse(aiRaw, message, category);

    return res.json(payload);
  } catch (e) {
    console.error('POST /api/ai/guide-chat error:', e.message);
    const message = String(req.body?.message ?? '').trim();
    const categoryHint = req.body?.context?.categoryHint;
    const category = inferGuideChatCategory(message, categoryHint);
    const payload = buildGuideChatPayload(message, category);
    return res.json(payload);
  }
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
