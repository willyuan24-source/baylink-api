require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
// ✨ 核心升级：引入 HTTP 和 Socket.io
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const PORT = process.env.PORT || 3000;

// ✨ 核心升级：创建 HTTP 服务器并绑定 Socket.io
// 这一步是为了让服务器既能处理 API 请求，也能维持长连接
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // 允许所有来源连接 (生产环境建议限制为你的前端域名)
    methods: ["GET", "POST"]
  }
});

// --- Cloudinary 配置 ---
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dpugh4vfy', 
  api_key: process.env.CLOUDINARY_API_KEY || '653341452655839', 
  api_secret: process.env.CLOUDINARY_API_SECRET || 'k3LlWbnU32JnancGX_C_9osYnEk' 
});

const JWT_SECRET = process.env.JWT_SECRET || 'baylink-secret-key-2025'; 
const MONGO_URI = process.env.MONGO_URI; 

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

if (!MONGO_URI) { console.error("❌ 错误: 未设置 MONGO_URI。"); } 
else { mongoose.connect(MONGO_URI).then(() => console.log('✅ MongoDB Connected')).catch(err => console.error(err)); }

// --- Socket.io 实时逻辑 ---
io.on('connection', (socket) => {
  console.log(`🔌 新连接: ${socket.id}`);

  // 用户登录后，加入以自己 User ID 命名的房间，方便接收私信
  socket.on('join_room', (userId) => {
    if (userId) {
      socket.join(userId);
      console.log(`👤 用户 ${userId} 已上线`);
    }
  });

  socket.on('disconnect', () => {
    // 这里可以处理用户下线逻辑
  });
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
  bio: String,
  avatar: String,
  socialLinks: { linkedin: String, instagram: String },
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
  imageUrls: [String],
  likes: [String],
  contactMarks: [String],
  comments: [{ id: String, authorId: String, authorName: String, content: String, createdAt: Number }],
  reports: [{ reporterId: String, reason: String, createdAt: Number }],
  isDeleted: { type: Boolean, default: false },
  createdAt: { type: Number, default: Date.now }
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

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, nickname, contactType, contactValue } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ error: 'User exists' });
    const newUser = await User.create({
      id: Date.now().toString(), email, password, nickname,
      role: email === 'admin' ? 'admin' : 'user',
      contactType, contactValue, bio: '这个邻居很懒，什么也没写~',
      socialLinks: { linkedin: '', instagram: '' }
    });
    const token = jwt.sign({ id: newUser.id }, JWT_SECRET);
    res.json({ ...newUser.toObject(), token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.json({ ...user.toObject(), token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ 
    id: user.id, nickname: user.nickname, role: user.role, avatar: user.avatar, bio: user.bio,
    socialLinks: user.socialLinks || { linkedin: '', instagram: '' } 
  });
});

app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { nickname, bio, avatar, socialLinks } = req.body;
    const user = req.user;
    if (nickname) user.nickname = nickname;
    if (bio !== undefined) user.bio = bio;
    if (socialLinks) user.socialLinks = { ...user.socialLinks, ...socialLinks }; 
    if (avatar && avatar.startsWith('data:image')) {
        const url = await uploadToCloudinary(avatar);
        if (url) user.avatar = url;
    }
    await user.save();
    if (avatar || nickname) await Post.updateMany({ authorId: user.id }, { authorNickname: user.nickname, authorAvatar: user.avatar });
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Update Failed' }); }
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
    
    let currentUserId = null;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        try { currentUserId = jwt.verify(authHeader.split(' ')[1], JWT_SECRET).id; } catch(e) {}
    }

    const formatted = posts.map(p => ({
        ...p,
        author: { nickname: p.authorNickname || 'Unknown', avatar: p.authorAvatar },
        likesCount: p.likes ? p.likes.length : 0,
        commentsCount: p.comments ? p.comments.length : 0,
        hasLiked: currentUserId ? (p.likes || []).includes(currentUserId) : false,
        isReported: currentUserId ? (p.reports || []).some(r => r.reporterId === currentUserId) : false 
    }));
    res.json({ posts: formatted, hasMore: totalCount > skip + posts.length });
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const todayStart = new Date().setHours(0,0,0,0);
    const count = await Post.countDocuments({ authorId: req.user.id, isDeleted: false, createdAt: { $gte: todayStart } });
    if (count >= 5) return res.status(403).json({ error: 'TODAY_LIMIT_REACHED' });

    const { imageUrls, ...postData } = req.body;
    let uploadedUrls = [];
    if (imageUrls && imageUrls.length > 0) {
        uploadedUrls = (await Promise.all(imageUrls.map(img => uploadToCloudinary(img)))).filter(u => u !== null);
    }
    const newPost = await Post.create({
        id: Date.now().toString(), authorId: req.user.id, authorNickname: req.user.nickname, authorAvatar: req.user.avatar,
        ...postData, imageUrls: uploadedUrls, isDeleted: false
    });
    res.json(newPost);
  } catch (e) { res.status(500).json({ error: 'Post Failed' }); }
});

app.post('/api/posts/:id/report', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);
    const hasReported = post.reports.some(r => r.reporterId === req.user.id);
    if (!hasReported) {
      post.reports.push({ reporterId: req.user.id, reason: req.body.reason || 'spam', createdAt: Date.now() });
      await post.save();
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Report Failed' }); }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const idx = post.likes.indexOf(req.user.id); if (idx === -1) post.likes.push(req.user.id); else post.likes.splice(idx, 1); await post.save(); res.json({ success: true }); });
app.delete('/api/posts/:id', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403); post.isDeleted = true; await post.save(); res.json({ success: true }); });
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => { const post = await Post.findOne({ id: req.params.id }); if (!post) return res.sendStatus(404); const comment = { id: Date.now().toString(), authorId: req.user.id, authorName: req.user.nickname, content: req.body.content, createdAt: Date.now() }; post.comments.push(comment); await post.save(); res.json(comment); });
app.get('/api/ads', async (req, res) => { const ads = await Ad.find({}); res.json(ads); });
app.post('/api/ads', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const ad = await Ad.create({ ...req.body, id: Date.now().toString(), isVerified: true }); res.json(ad); });
app.delete('/api/ads/:id', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Ad.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.get('/api/content/:key', async (req, res) => { const content = await Content.findOne({ key: req.params.key }); res.json({ value: content ? content.value : '' }); });
app.post('/api/content', authenticateToken, async (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); await Content.findOneAndUpdate({ key: req.body.key }, { value: req.body.value }, { upsert: true, new: true }); res.json({ success: true }); });

// --- 聊天接口 (Socket.io 增强版) ---

app.get('/api/conversations', authenticateToken, async (req, res) => { const convs = await Conversation.find({ userIds: req.user.id }); const result = await Promise.all(convs.map(async c => { const otherId = c.userIds.find(uid => uid !== req.user.id); const otherUser = await User.findOne({ id: otherId }); const lastMsg = await Message.findOne({ conversationId: c.id }).sort({ createdAt: -1 }); return { id: c.id, updatedAt: c.updatedAt, lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.content : `[${lastMsg.type}]`) : '', otherUser: { id: otherUser?.id, nickname: otherUser?.nickname, avatar: otherUser?.avatar } }; })); result.sort((a, b) => b.updatedAt - a.updatedAt); res.json(result); });
app.post('/api/conversations/open-or-create', authenticateToken, async (req, res) => { const { targetUserId } = req.body; let conv = await Conversation.findOne({ userIds: { $all: [req.user.id, targetUserId] } }); if (!conv) { conv = await Conversation.create({ id: Date.now().toString(), userIds: [req.user.id, targetUserId] }); } res.json(conv); });
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => { const msgs = await Message.find({ conversationId: req.params.id }).sort({ createdAt: 1 }); res.json(msgs); });

// ✨ 发送消息接口 - 实时推送
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => { 
  const { type, content } = req.body; 
  let finalContent = content; 
  if (type === 'contact-share') { finalContent = `我的联系方式：${req.user.contactType.toUpperCase()} ${req.user.contactValue}`; } 
  
  // 1. 存入数据库
  const msg = await Message.create({ 
    id: Date.now().toString(), 
    conversationId: req.params.id, 
    senderId: req.user.id, 
    type, 
    content: finalContent 
  }); 
  await Conversation.findOneAndUpdate({ id: req.params.id }, { updatedAt: Date.now() }); 
  
  // 2. ✨ Socket.io 推送逻辑
  const conv = await Conversation.findOne({ id: req.params.id });
  if (conv) {
    const receiverId = conv.userIds.find(uid => uid !== req.user.id);
    if (receiverId) {
        // 直接向对方的“房间”广播消息 -> 对方的前端会立即收到
        io.to(receiverId).emit('new_message', msg);
    }
  }

  res.json(msg); 
});

// ✨ 重要修改：使用 server.listen 启动，而不是 app.listen
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));