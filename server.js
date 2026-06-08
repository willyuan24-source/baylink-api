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
const MONGO_URI = process.env.MONGO_URI; 

app.use(cors({ origin: corsOriginCheck, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

mongoose.connect(MONGO_URI).then(() => console.log('✅ MongoDB Connected')).catch(err => console.error(err));

// --- Socket.io ---
io.on('connection', (socket) => {
  socket.on('join_room', (userId) => { if (userId) socket.join(userId); });
});

// --- Schemas ---
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
  verifyCode: String, 
  verifyCodeExpires: Number, 
  lastSmsSentAt: Number, 
  verifyAttempts: { type: Number, default: 0 }, // 防暴力破解

  bio: String,
  avatar: String,
  socialLinks: { linkedin: String, instagram: String },
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
  featuredBy: { type: String }
});

const AdSchema = new mongoose.Schema({ id: String, title: String, content: String, imageUrl: String, isVerified: { type: Boolean, default: true } });
const ConversationSchema = new mongoose.Schema({ id: { type: String, unique: true }, userIds: [String], updatedAt: { type: Number, default: Date.now } });
const MessageSchema = new mongoose.Schema({ id: String, conversationId: String, senderId: String, type: String, content: String, createdAt: { type: Number, default: Date.now } });
const ContentSchema = new mongoose.Schema({ key: { type: String, unique: true }, value: String });

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Ad = mongoose.model('Ad', AdSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Message = mongoose.model('Message', MessageSchema);
const Content = mongoose.model('Content', ContentSchema);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const validatePasswordStrength = (password) =>
  typeof password === 'string' &&
  password.length >= 8 &&
  /[A-Z]/.test(password) &&
  /[a-z]/.test(password) &&
  /[0-9]/.test(password);

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

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, async (err, userPayload) => {
    if (err) return res.sendStatus(403);
    const dbUser = await User.findOne({ id: userPayload.id });
    if (!dbUser || dbUser.isBanned) return res.sendStatus(403);
    req.user = dbUser; 
    next();
  });
};

// --- Routes ---

// ✨ 手机验证接口 (含真实发送 + 安全限流)
app.post('/api/auth/verify-phone', authenticateToken, async (req, res) => {
    const { phone, code } = req.body;
    const user = req.user;

    // 场景 1: 请求发送验证码
    if (phone && !code) {
        // 1. 防刷：60秒限制
        if (user.lastSmsSentAt && Date.now() - user.lastSmsSentAt < 60000) {
            return res.status(429).json({ error: '请求太频繁，请等待60秒' });
        }

        const generatedCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        user.verifyCode = generatedCode;
        user.verifyCodeExpires = Date.now() + 5 * 60 * 1000; // 5分钟有效期
        user.lastSmsSentAt = Date.now();
        user.verifyAttempts = 0; // 重置尝试次数
        await user.save();

        // 2. 发送逻辑
        if (twilioClient && TWILIO_PHONE) {
            try {
                await twilioClient.messages.create({
                    body: `【BAYLINK】您的验证码是 ${generatedCode}，5分钟内有效。工作人员不会向您索要此码。`,
                    from: TWILIO_PHONE,
                    to: phone 
                });
                return res.json({ success: true, message: '验证码已发送至手机' });
            } catch (error) {
                console.error('Twilio Error:', error.message);
                return res.status(500).json({ error: '短信发送失败，请检查手机号格式 (例如 +1...)' });
            }
        } else {
            console.log(`[DEV MODE] SMS to ${phone}: ${generatedCode}`);
            return res.json({ success: true, message: '[开发模式] 验证码已在后台生成' });
        }
    }

    // 场景 2: 验证代码
    if (phone && code) {
        // 3. 安全检查
        if (!user.verifyCode || Date.now() > user.verifyCodeExpires) return res.status(400).json({ error: '验证码已过期，请重新获取' });
        
        if (user.verifyAttempts >= 5) {
            user.verifyCode = undefined; // 错误太多，销毁验证码
            await user.save();
            return res.status(400).json({ error: '尝试次数过多，请重新获取验证码' });
        }

        if (user.verifyCode !== code) {
            user.verifyAttempts = (user.verifyAttempts || 0) + 1;
            await user.save();
            return res.status(400).json({ error: '验证码错误' });
        }

        // 4. 验证成功
        user.contactValue = phone;
        user.isPhoneVerified = true;
        user.verifyCode = undefined;
        user.verifyCodeExpires = undefined;
        user.verifyAttempts = 0;
        await user.save();
        
        return res.json({ success: true, user });
    }
    
    res.status(400).json({ error: '无效请求' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
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
    const token = jwt.sign({ id: newUser.id }, JWT_SECRET);
    
    // ✨ 安全優化：回傳時移除 password 與 verifyCode 等敏感欄位，防 Hash 被窺探
    const userResponse = newUser.toObject();
    delete userResponse.password;
    delete userResponse.verifyCode;
    
    res.json({ ...userResponse, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
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
    
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    
    // ✨ 安全優化：回傳時移除密碼與驗證碼敏感資料
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.verifyCode;
    
    res.json({ ...userResponse, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findOne({ id: req.params.id }).select('-password -verifyCode'); // ✨ 安全：排除敏感字段
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ 
    id: user.id, nickname: user.nickname, role: user.role, avatar: user.avatar, bio: user.bio,
    isPhoneVerified: user.isPhoneVerified, isOfficialVerified: user.isOfficialVerified, 
    socialLinks: user.socialLinks || { linkedin: '', instagram: '' } 
  });
});

app.get('/api/users/:id/public', async (req, res) => {
  try {
    const user = await User.findOne({ id: req.params.id }).select('-password -verifyCode -email -contactValue -contactType');
    if (!user) return res.status(404).json({ error: 'Not found' });
    const postCount = await Post.countDocuments({ authorId: user.id, isDeleted: false });
    const recent = await Post.find({ authorId: user.id, isDeleted: false }).sort({ createdAt: -1 }).limit(3).lean();
    res.json({
      id: user.id,
      nickname: user.nickname,
      avatar: user.avatar,
      bio: user.bio,
      role: user.role,
      createdAt: user.createdAt,
      isPhoneVerified: user.isPhoneVerified,
      isOfficialVerified: user.isOfficialVerified,
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
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { nickname, bio, avatar, socialLinks, isOfficialVerified } = req.body;
    const user = req.user;
    if (nickname) user.nickname = nickname;
    if (bio !== undefined) user.bio = bio;
    if (socialLinks) user.socialLinks = { ...user.socialLinks, ...socialLinks }; 
    if (user.role === 'admin' && isOfficialVerified !== undefined) user.isOfficialVerified = isOfficialVerified;
    if (avatar && avatar.startsWith('data:image')) {
        const url = await uploadToCloudinary(avatar);
        if (url) user.avatar = url;
    }
    await user.save();
    if (avatar || nickname) await Post.updateMany({ authorId: user.id }, { authorNickname: user.nickname, authorAvatar: user.avatar });
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.verifyCode;
    delete userResponse.verifyCodeExpires;
    res.json(userResponse);
  } catch (e) { res.status(500).json({ error: 'Update Failed' }); }
});

const getCurrentUserIdFromRequest = (req) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return null;
  try { return jwt.verify(authHeader.split(' ')[1], JWT_SECRET).id; } catch (e) { return null; }
};

const formatPostResponse = (p, currentUserId) => ({
  ...p,
  author: { nickname: p.authorNickname || 'Unknown', avatar: p.authorAvatar },
  likesCount: p.likes ? p.likes.length : 0,
  commentsCount: p.comments ? p.comments.length : 0,
  hasLiked: currentUserId ? (p.likes || []).includes(currentUserId) : false,
  isReported: currentUserId ? (p.reports || []).some((r) => r.reporterId === currentUserId) : false,
});

app.get('/api/posts/featured', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10);
    const currentUserId = getCurrentUserIdFromRequest(req);
    let q = Post.find({ isDeleted: false, isFeatured: true }).sort({ featuredAt: -1, createdAt: -1 });
    if (limit > 0) q = q.limit(limit);
    const posts = await q.lean();
    res.json({ posts: posts.map((p) => formatPostResponse(p, currentUserId)) });
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    if (req.params.id === 'featured') return res.sendStatus(404);
    const post = await Post.findOne({ id: req.params.id, isDeleted: false }).lean();
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const currentUserId = getCurrentUserIdFromRequest(req);
    res.json(formatPostResponse(post, currentUserId));
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

app.get('/api/posts', async (req, res) => {
  try {
    const { type, keyword, page = 1, limit = 10 } = req.query;
    let query = { isDeleted: false };
    if (type) query.type = type;
    if (keyword) {
        const regex = new RegExp(keyword, 'i');
        query.$or = [{ title: regex }, { description: regex }, { city: regex }, { category: regex }];
    }
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const posts = await Post.find(query).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).lean();
    const totalCount = await Post.countDocuments(query);
    const currentUserId = getCurrentUserIdFromRequest(req);
    const formatted = posts.map((p) => formatPostResponse(p, currentUserId));
    res.json({ posts: formatted, hasMore: totalCount > skip + posts.length });
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
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

const checkCreatePostRateLimit = async (user) => {
  const todayStart = new Date().setHours(0, 0, 0, 0);
  const dailyLimit = user.role === 'admin' ? 100 : 10;
  const count = await Post.countDocuments({ authorId: user.id, isDeleted: false, createdAt: { $gte: todayStart } });
  if (count >= dailyLimit) return { status: 429, error: 'Daily post limit reached.' };
  if (user.role !== 'admin') {
    const latest = await Post.findOne({ authorId: user.id, isDeleted: false }).sort({ createdAt: -1 }).lean();
    if (latest && Date.now() - latest.createdAt < 60000) {
      return { status: 429, error: 'Posting too frequently. Please try again later.' };
    }
  }
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
    const rateErr = await checkCreatePostRateLimit(req.user);
    if (rateErr) return res.status(rateErr.status).json({ error: rateErr.error });
    const validationErr = validatePostBody(req.body);
    if (validationErr) return res.status(validationErr.status).json({ error: validationErr.error });
    const { imageUrls, id: _id, authorId: _authorId, createdAt: _createdAt, updatedAt: _updatedAt, ...postData } = req.body;
    const uploadedUrls = await processPostImageUrls(imageUrls);
    const newPost = await Post.create({
      id: Date.now().toString(),
      authorId: req.user.id,
      authorNickname: req.user.nickname,
      authorAvatar: req.user.avatar,
      ...postData,
      imageUrls: uploadedUrls,
      isDeleted: false,
      createdAt: Date.now(),
    });
    res.json(newPost);
  } catch (e) { res.status(500).json({ error: 'Post Failed' }); }
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
    res.json(formatPostResponse(post.toObject(), req.user.id));
  } catch (e) { res.status(500).json({ error: 'Feature Failed' }); }
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
    res.json(formatPostResponse(post.toObject(), req.user.id));
  } catch (e) { res.status(500).json({ error: 'Unfeature Failed' }); }
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
    post.updatedAt = Date.now();
    await post.save();
    const p = post.toObject();
    res.json(formatPostResponse(p, req.user.id));
  } catch (e) { res.status(500).json({ error: 'Update Failed' }); }
});

app.post('/api/posts/:id/report', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);
    const hasReported = post.reports.some(r => r.reporterId === req.user.id);
    if (!hasReported) { post.reports.push({ reporterId: req.user.id, reason: req.body.reason || 'spam', createdAt: Date.now() }); await post.save(); }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Report Failed' }); }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const idx = post.likes.indexOf(req.user.id); if (idx === -1) post.likes.push(req.user.id); else post.likes.splice(idx, 1); await post.save(); res.json({ success: true }); });
app.delete('/api/posts/:id', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403); post.isDeleted = true; await post.save(); res.json({ success: true }); });
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const comment = { id: Date.now().toString(), authorId: req.user.id, authorName: req.user.nickname, content: req.body.content, createdAt: Date.now() }; post.comments.push(comment); await post.save(); res.json(comment); });
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
    res.status(500).json({ error: e.message || 'Failed to create ad' });
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
    res.status(500).json({ error: e.message || 'Failed to update ad' });
  }
});
app.delete('/api/ads/:id', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Ad.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.get('/api/content/:key', async (req, res) => { const content = await Content.findOne({ key: req.params.key }); res.json({ value: content ? content.value : '' }); });
app.post('/api/content', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Content.findOneAndUpdate({ key: req.body.key }, { value: req.body.value }, { upsert: true, new: true }); res.json({ success: true }); });

app.get('/api/conversations', authenticateToken, async (req, res) => { const convs = await Conversation.find({ userIds: req.user.id }); const result = await Promise.all(convs.map(async c => { const otherId = c.userIds.find(uid => uid !== req.user.id); const otherUser = await User.findOne({ id: otherId }); const lastMsg = await Message.findOne({ conversationId: c.id }).sort({ createdAt: -1 }); return { id: c.id, updatedAt: c.updatedAt, lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.content : `[${lastMsg.type}]`) : '', otherUser: { id: otherUser?.id, nickname: otherUser?.nickname, avatar: otherUser?.avatar, isPhoneVerified: otherUser?.isPhoneVerified, isOfficialVerified: otherUser?.isOfficialVerified } }; })); result.sort((a, b) => b.updatedAt - a.updatedAt); res.json(result); });
app.post('/api/conversations/open-or-create', authenticateToken, async (req, res) => { const { targetUserId } = req.body; let conv = await Conversation.findOne({ userIds: { $all: [req.user.id, targetUserId] } }); if (!conv) { conv = await Conversation.create({ id: Date.now().toString(), userIds: [req.user.id, targetUserId] }); } res.json(conv); });
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => { const msgs = await Message.find({ conversationId: req.params.id }).sort({ createdAt: 1 }); res.json(msgs); });
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => { 
  const { type, content } = req.body; 
  let finalContent = content; 
  if (type === 'contact-share') { finalContent = `我的联系方式：${req.user.contactType.toUpperCase()} ${req.user.contactValue}`; } 
  const msg = await Message.create({ id: Date.now().toString(), conversationId: req.params.id, senderId: req.user.id, type, content: finalContent }); 
  await Conversation.findOneAndUpdate({ id: req.params.id }, { updatedAt: Date.now() }); 
  const conv = await Conversation.findOne({ id: req.params.id });
  if (conv) { const receiverId = conv.userIds.find(uid => uid !== req.user.id); if (receiverId) { io.to(receiverId).emit('new_message', msg); } }
  res.json(msg); 
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

const getClientIp = (req) => {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.trim()) return xf.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
};

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

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
