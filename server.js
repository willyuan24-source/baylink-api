require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2; // 引入 Cloudinary

const app = express();
const PORT = process.env.PORT || 3000;

// --- ⚠️ 配置区域 (请替换为你自己的 Cloudinary 信息) ---
// 为了安全，生产环境建议把这些放入 Render 的环境变量，但在代码里填入也能运行
cloudinary.config({ 
  cloud_name: process.env.dpugh4vfy || '你的CloudName', 
  api_key: process.env.653341452655839 || '你的ApiKey', 
  api_secret: process.env.k3LlWbnU32JnancGX_C_9osYnEk || '你的ApiSecret' 
});

const JWT_SECRET = process.env.JWT_SECRET || 'baylink-secret-key-2025'; 
const MONGO_URI = process.env.MONGO_URI; 

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- MongoDB 连接 ---
if (!MONGO_URI) {
  console.error("❌ 错误: 未设置 MONGO_URI。");
} else {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));
}

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
  bio: String,
  avatar: String, 
  createdAt: { type: Number, default: Date.now }
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
  imageUrls: [String], // 这里现在存的是 http 链接，而不是 base64
  likes: [String],
  contactMarks: [String],
  comments: [{
    id: String,
    authorId: String,
    authorName: String,
    content: String,
    createdAt: Number
  }],
  isDeleted: { type: Boolean, default: false },
  createdAt: { type: Number, default: Date.now }
});

const AdSchema = new mongoose.Schema({
  id: String,
  title: String,
  content: String,
  imageUrl: String,
  isVerified: { type: Boolean, default: true }
});

const ConversationSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  userIds: [String],
  updatedAt: { type: Number, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  id: String,
  conversationId: String,
  senderId: String,
  type: String,
  content: String,
  createdAt: { type: Number, default: Date.now }
});

const ContentSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: String
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Ad = mongoose.model('Ad', AdSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Message = mongoose.model('Message', MessageSchema);
const Content = mongoose.model('Content', ContentSchema);

// --- Helper: 上传图片到 Cloudinary ---
const uploadToCloudinary = async (base64Image) => {
    if (!base64Image || !base64Image.startsWith('data:image')) return null;
    try {
        const result = await cloudinary.uploader.upload(base64Image, {
            folder: "baylink_posts", // 在 Cloudinary 中的文件夹名
        });
        return result.secure_url; // 返回 https 链接
    } catch (error) {
        console.error("Cloudinary upload failed:", error);
        return null;
    }
};

// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, async (err, userPayload) => {
    if (err) return res.sendStatus(403);
    try {
        const dbUser = await User.findOne({ id: userPayload.id });
        if (!dbUser) return res.sendStatus(403);
        if (dbUser.isBanned) return res.status(403).json({ error: 'Account Banned' });
        req.user = dbUser; 
        next();
    } catch (e) {
        return res.sendStatus(500);
    }
  });
};

// --- Routes ---

// Auth
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, nickname, contactType, contactValue } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'User exists' });
    const newUser = await User.create({
      id: Date.now().toString(), email, password, nickname,
      role: email === 'admin' ? 'admin' : 'user',
      contactType, contactValue, bio: '这个邻居很懒，什么也没写~'
    });
    const token = jwt.sign({ id: newUser.id, role: newUser.role }, JWT_SECRET);
    res.json({ ...newUser.toObject(), token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ ...user.toObject(), token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ id: user.id, nickname: user.nickname, role: user.role, avatar: user.avatar, bio: user.bio });
});

app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { nickname, bio, avatar } = req.body; // avatar 此时还是 base64
    const user = req.user;
    if (nickname) user.nickname = nickname;
    if (bio !== undefined) user.bio = bio;
    
    // 处理头像上传
    if (avatar && avatar.startsWith('data:image')) {
        const url = await uploadToCloudinary(avatar);
        if (url) user.avatar = url;
    }

    await user.save();
    // 更新帖子作者信息
    if (avatar || nickname) {
        await Post.updateMany({ authorId: user.id }, { authorNickname: user.nickname, authorAvatar: user.avatar });
    }
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Update Failed' }); }
});

// ✅ 帖子列表 (包含分页)
app.get('/api/posts', async (req, res) => {
  try {
    const { type, keyword, page = 1, limit = 10 } = req.query; // 默认第1页，每页10条
    let query = { isDeleted: false };
    
    if (type) query.type = type;
    if (keyword) {
        const regex = new RegExp(keyword, 'i');
        query.$or = [{ title: regex }, { description: regex }, { city: regex }, { category: regex }];
    }

    // 分页逻辑
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const posts = await Post.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();
    
    // 检查是否还有更多
    const totalCount = await Post.countDocuments(query);
    const hasMore = totalCount > skip + posts.length;

    let currentUserId = null;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        try {
            const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
            currentUserId = decoded.id;
        } catch(e) {}
    }

    const formatted = posts.map(p => ({
        ...p,
        author: { nickname: p.authorNickname || 'Unknown', avatar: p.authorAvatar },
        likesCount: p.likes ? p.likes.length : 0,
        commentsCount: p.comments ? p.comments.length : 0,
        hasLiked: currentUserId ? (p.likes || []).includes(currentUserId) : false,
        isContacted: currentUserId ? (p.contactMarks || []).includes(currentUserId) : false,
        contactInfo: null
    }));
    
    res.json({ posts: formatted, hasMore }); // 返回结构变化：{ posts: [], hasMore: boolean }
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

// ✅ 发布帖子 (上传图片到图床)
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const todayStart = new Date().setHours(0,0,0,0);
    const count = await Post.countDocuments({ authorId: req.user.id, isDeleted: false, createdAt: { $gte: todayStart } });
    if (count >= 5) return res.status(403).json({ error: 'TODAY_LIMIT_REACHED' }); // 放宽到5条

    const { imageUrls, ...postData } = req.body;
    
    // 处理图片上传 (并发上传)
    let uploadedUrls = [];
    if (imageUrls && imageUrls.length > 0) {
        const uploadPromises = imageUrls.map(img => uploadToCloudinary(img));
        const results = await Promise.all(uploadPromises);
        uploadedUrls = results.filter(url => url !== null);
    }

    const newPost = await Post.create({
        id: Date.now().toString(),
        authorId: req.user.id,
        authorNickname: req.user.nickname,
        authorAvatar: req.user.avatar,
        ...postData,
        imageUrls: uploadedUrls, // 存入的是 URL 数组
        isDeleted: false
    });
    res.json(newPost);
  } catch (e) { 
      console.error(e);
      res.status(500).json({ error: 'Post Failed' }); 
  }
});

// 其他操作 (点赞/删除/评论/广告/私信) 保持不变，因为它们不涉及大量数据传输
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => { /* ...同前... */ const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const idx = post.likes.indexOf(req.user.id); if (idx === -1) post.likes.push(req.user.id); else post.likes.splice(idx, 1); await post.save(); res.json({ success: true }); });
app.post('/api/posts/:id/contact-mark', authenticateToken, async (req, res) => { /* ...同前... */ const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); if (!post.contactMarks.includes(req.user.id)) { post.contactMarks.push(req.user.id); await post.save(); } res.json({ success: true }); });
app.delete('/api/posts/:id', authenticateToken, async (req, res) => { /* ...同前... */ const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403); post.isDeleted = true; await post.save(); res.json({ success: true }); });
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => { /* ...同前... */ const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const comment = { id: Date.now().toString(), authorId: req.user.id, authorName: req.user.nickname, content: req.body.content, createdAt: Date.now() }; post.comments.push(comment); await post.save(); res.json(comment); });
app.get('/api/ads', async (req, res) => { const ads = await Ad.find({}); res.json(ads); });
app.post('/api/ads', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const ad = await Ad.create({ ...req.body, id: Date.now().toString(), isVerified: true }); res.json(ad); });
app.delete('/api/ads/:id', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Ad.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.get('/api/content/:key', async (req, res) => { const content = await Content.findOne({ key: req.params.key }); res.json({ value: content ? content.value : '' }); });
app.post('/api/content', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Content.findOneAndUpdate({ key: req.body.key }, { value: req.body.value }, { upsert: true, new: true }); res.json({ success: true }); });
app.get('/api/conversations', authenticateToken, async (req, res) => { const convs = await Conversation.find({ userIds: req.user.id }); const result = await Promise.all(convs.map(async c => { const otherId = c.userIds.find(uid => uid !== req.user.id); const otherUser = await User.findOne({ id: otherId }); const lastMsg = await Message.findOne({ conversationId: c.id }).sort({ createdAt: -1 }); return { id: c.id, updatedAt: c.updatedAt, lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.content : `[${lastMsg.type}]`) : '', otherUser: { id: otherUser?.id, nickname: otherUser?.nickname, avatar: otherUser?.avatar } }; })); result.sort((a, b) => b.updatedAt - a.updatedAt); res.json(result); });
app.post('/api/conversations/open-or-create', authenticateToken, async (req, res) => { const { targetUserId } = req.body; let conv = await Conversation.findOne({ userIds: { $all: [req.user.id, targetUserId] } }); if (!conv) { conv = await Conversation.create({ id: Date.now().toString(), userIds: [req.user.id, targetUserId] }); } res.json(conv); });
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => { const msgs = await Message.find({ conversationId: req.params.id }).sort({ createdAt: 1 }); res.json(msgs); });
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => { const { type, content } = req.body; let finalContent = content; if (type === 'contact-share') { finalContent = `我的联系方式：${req.user.contactType.toUpperCase()} ${req.user.contactValue}`; } const msg = await Message.create({ id: Date.now().toString(), conversationId: req.params.id, senderId: req.user.id, type, content: finalContent }); await Conversation.findOneAndUpdate({ id: req.params.id }, { updatedAt: Date.now() }); res.json(msg); });

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));