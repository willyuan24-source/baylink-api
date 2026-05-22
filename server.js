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
        id: p.id,
        title: p.title,
        description: p.description,
        category: p.category,
        city: p.city,
        type: p.type,
        budget: p.budget,
        imageUrls: p.imageUrls || [],
        createdAt: p.createdAt,
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

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
