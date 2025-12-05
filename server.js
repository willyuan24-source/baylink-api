require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// 从环境变量获取配置，如果没有则使用默认值（仅供测试）
const JWT_SECRET = process.env.JWT_SECRET || 'baylink-secret-key-2025'; 
const MONGO_URI = process.env.MONGO_URI; 

app.use(cors());
// 增加上传限制，防止图片上传失败
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- 连接 MongoDB ---
if (!MONGO_URI) {
  console.error("❌ 错误: 未设置 MONGO_URI 环境变量。请在 Render 后台配置数据库连接字符串。");
} else {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ 成功连接到 MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB 连接失败:', err));
}

// --- 定义数据模型 (Schema) ---

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
  imageUrls: [String],
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

// --- Models ---
const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Ad = mongoose.model('Ad', AdSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Message = mongoose.model('Message', MessageSchema);
const Content = mongoose.model('Content', ContentSchema);

// --- 初始化管理员 ---
const initAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin' });
    if (!adminExists) {
      await User.create({
        id: 'admin', email: 'admin', password: 'Archangel24!', nickname: 'BayLink管理员',
        role: 'admin', contactType: 'email', contactValue: 'admin@baylink.com', bio: '官方管理员'
      });
      console.log('👑 管理员账号已自动创建');
    }
    // 初始化默认文案
    const aboutExists = await Content.findOne({ key: 'baylink_about' });
    if (!aboutExists) {
        await Content.create({ key: 'baylink_about', value: 'BayLink 助手是一个面向旧金山湾区本地居民的信息平台。\n\n我们致力于连接邻里，提供互助便利。' });
        await Content.create({ key: 'baylink_support', value: '如有问题，请联系客服邮箱：\nsupport@baylink.com' });
    }
  } catch (e) {
    console.log('Init check skipped:', e.message);
  }
};
// 连接成功后尝试初始化
mongoose.connection.once('open', initAdmin);


// --- 中间件 ---
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

// --- 接口定义 ---

// 注册
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

// 登录
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ ...user.toObject(), token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 获取用户信息
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findOne({ id: req.params.id });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ id: user.id, nickname: user.nickname, role: user.role, avatar: user.avatar, bio: user.bio, isBanned: user.isBanned });
  } catch (e) { res.status(500).json({ error: 'Server Error' }); }
});

// 更新个人资料
app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { nickname, bio, avatar } = req.body;
    const user = req.user;
    if (nickname) user.nickname = nickname;
    if (bio !== undefined) user.bio = bio;
    if (avatar !== undefined) user.avatar = avatar;
    await user.save();
    
    // 同步更新帖子作者信息
    if (avatar || nickname) {
        await Post.updateMany({ authorId: user.id }, { authorNickname: user.nickname, authorAvatar: user.avatar });
    }
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Update Failed' }); }
});

// 获取帖子列表
app.get('/api/posts', async (req, res) => {
  try {
    const { type, keyword } = req.query;
    let query = { isDeleted: false };
    if (type) query.type = type;
    if (keyword) {
        const regex = new RegExp(keyword, 'i');
        query.$or = [{ title: regex }, { description: regex }, { city: regex }, { category: regex }];
    }

    const posts = await Post.find(query).sort({ createdAt: -1 }).lean();
    
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
    
    res.json(formatted);
  } catch (e) { res.status(500).json({ error: 'Fetch Failed' }); }
});

// 发布帖子
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const todayStart = new Date().setHours(0,0,0,0);
    const count = await Post.countDocuments({ 
        authorId: req.user.id, 
        isDeleted: false, 
        createdAt: { $gte: todayStart } 
    });
    
    if (count >= 3) return res.status(403).json({ error: 'TODAY_LIMIT_REACHED' });

    const newPost = await Post.create({
        id: Date.now().toString(),
        authorId: req.user.id,
        authorNickname: req.user.nickname,
        authorAvatar: req.user.avatar,
        ...req.body,
        isDeleted: false
    });
    res.json(newPost);
  } catch (e) { res.status(500).json({ error: 'Post Failed' }); }
});

// 点赞
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);
    
    const idx = post.likes.indexOf(req.user.id);
    if (idx === -1) post.likes.push(req.user.id);
    else post.likes.splice(idx, 1);
    
    await post.save();
    res.json({ success: true });
  } catch (e) { res.sendStatus(500); }
});

// 标记已联系
app.post('/api/posts/:id/contact-mark', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);
    if (!post.contactMarks.includes(req.user.id)) {
        post.contactMarks.push(req.user.id);
        await post.save();
    }
    res.json({ success: true });
  } catch (e) { res.sendStatus(500); }
});

// 删除帖子
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);
    if (req.user.role !== 'admin' && post.authorId !== req.user.id) return res.sendStatus(403);
    
    post.isDeleted = true;
    await post.save();
    res.json({ success: true });
  } catch (e) { res.sendStatus(500); }
});

// 评论
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ id: req.params.id });
    if (!post) return res.sendStatus(404);

    const comment = {
        id: Date.now().toString(),
        authorId: req.user.id,
        authorName: req.user.nickname,
        content: req.body.content,
        createdAt: Date.now()
    };
    post.comments.push(comment);
    await post.save();
    res.json(comment);
  } catch (e) { res.sendStatus(500); }
});

// 广告
app.get('/api/ads', async (req, res) => {
    const ads = await Ad.find({});
    res.json(ads);
});
app.post('/api/ads', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const ad = await Ad.create({ ...req.body, id: Date.now().toString(), isVerified: true });
    res.json(ad);
});
app.delete('/api/ads/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    await Ad.deleteOne({ id: req.params.id });
    res.json({ success: true });
});

// 公共内容
app.get('/api/content/:key', async (req, res) => {
    const content = await Content.findOne({ key: req.params.key });
    res.json({ value: content ? content.value : '' });
});
app.post('/api/content', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    await Content.findOneAndUpdate(
        { key: req.body.key }, 
        { value: req.body.value }, 
        { upsert: true, new: true }
    );
    res.json({ success: true });
});

// 会话列表
app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const convs = await Conversation.find({ userIds: req.user.id });
        const result = await Promise.all(convs.map(async c => {
            const otherId = c.userIds.find(uid => uid !== req.user.id);
            const otherUser = await User.findOne({ id: otherId });
            const lastMsg = await Message.findOne({ conversationId: c.id }).sort({ createdAt: -1 });
            return {
                id: c.id,
                updatedAt: c.updatedAt,
                lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.content : `[${lastMsg.type}]`) : '',
                otherUser: { id: otherUser?.id, nickname: otherUser?.nickname, avatar: otherUser?.avatar }
            };
        }));
        result.sort((a, b) => b.updatedAt - a.updatedAt);
        res.json(result);
    } catch (e) { res.status(500).json([]); }
});

// 开启会话
app.post('/api/conversations/open-or-create', authenticateToken, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        let conv = await Conversation.findOne({ userIds: { $all: [req.user.id, targetUserId] } });
        if (!conv) {
            conv = await Conversation.create({
                id: Date.now().toString(),
                userIds: [req.user.id, targetUserId]
            });
        }
        res.json(conv);
    } catch (e) { res.status(500).json({error: 'Error'}); }
});

// 获取消息
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
    const msgs = await Message.find({ conversationId: req.params.id }).sort({ createdAt: 1 });
    res.json(msgs);
});

// 发送消息
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
    const { type, content } = req.body;
    let finalContent = content;
    if (type === 'contact-share') {
        finalContent = `我的联系方式：${req.user.contactType.toUpperCase()} ${req.user.contactValue}`;
    }
    const msg = await Message.create({
        id: Date.now().toString(),
        conversationId: req.params.id,
        senderId: req.user.id,
        type,
        content: finalContent
    });
    
    await Conversation.findOneAndUpdate({ id: req.params.id }, { updatedAt: Date.now() });
    res.json(msg);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));