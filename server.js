const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'baylink-secret-key-2025'; 

app.use(cors());

// 允许最大 50MB 的请求体（用于图片上传）
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- 内存数据库 ---
const db = {
  users: [],       
  posts: [],       
  likes: [],       
  comments: [], 
  conversations: [], 
  messages: [],     
  ads: [],
  contactMarks: [],
  // 新增：用于存储公共文案（关于我们、联系客服）
  content: {
    'baylink_about': 'BayLink 助手是一个面向旧金山湾区本地居民的信息平台。\n\n我们致力于连接邻里，提供互助便利。',
    'baylink_support': '如有问题，请联系客服邮箱：\nsupport@baylink.com'
  }
};

// --- 初始化数据：默认管理员 ---
if (db.users.length === 0) {
    db.users.push({
      id: 'admin', 
      email: 'admin', 
      password: 'Archangel24!', // ✅ 密码已更新
      nickname: 'BayLink管理员', 
      role: 'admin',
      contactType: 'email', 
      contactValue: 'admin@baylink.com', 
      isBanned: false
    });
    
    // 默认广告
    db.ads.push({
      id: 'ad1', title: '湾区安心搬家', content: '10年老牌 · 百万保险 · 损坏包赔', isVerified: true,
      imageUrl: 'https://images.unsplash.com/photo-1600585152220-90363fe7e115?auto=format&fit=crop&w=400&q=80'
    });
    console.log('System initialized. Admin Password updated.');
}

// --- 中间件 ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    const dbUser = db.users.find(u => u.id === user.id);
    if (dbUser && dbUser.isBanned) return res.status(403).json({ error: 'Account Banned' });
    next();
  });
};

// --- 基础接口 ---

// Auth
app.post('/api/auth/register', (req, res) => {
  const { email, password, nickname, contactType, contactValue } = req.body;
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'User exists' });
  const newUser = { id: Date.now().toString(), email, password, nickname, role: 'user', contactType, contactValue, isBanned: false };
  if (email === 'admin') newUser.role = 'admin';
  db.users.push(newUser);
  const token = jwt.sign({ id: newUser.id, role: newUser.role }, JWT_SECRET);
  res.json({ ...newUser, token });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  res.json({ ...user, token });
});

// Posts
app.get('/api/posts', (req, res) => {
  const { type, keyword } = req.query;
  let result = db.posts.filter(p => !p.isDeleted);
  if (type) result = result.filter(p => p.type === type);
  if (keyword) {
    const kw = keyword.toLowerCase();
    result = result.filter(p => p.title.toLowerCase().includes(kw) || p.description.toLowerCase().includes(kw) || p.city.toLowerCase().includes(kw) || p.category.toLowerCase().includes(kw));
  }
  const formatted = result.map(p => {
    const author = db.users.find(u => u.id === p.authorId);
    const allComments = db.comments.filter(c => c.postId === p.id);
    let isContacted = false;
    // Check contacted status
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            isContacted = db.contactMarks.some(m => m.userId === decoded.id && m.postId === p.id);
        } catch(e) {}
    }
    return {
      ...p,
      author: { nickname: author?.nickname || 'Unknown', avatarUrl: author?.avatarUrl },
      likesCount: db.likes.filter(l => l.postId === p.id).length,
      commentsCount: allComments.length,
      comments: allComments.map(c => ({ ...c, replies: [] })),
      isContacted,
      contactInfo: null
    };
  });
  formatted.sort((a, b) => b.createdAt - a.createdAt);
  res.json(formatted);
});

app.post('/api/posts', authenticateToken, (req, res) => {
  const todayStart = new Date().setHours(0,0,0,0);
  const todayPosts = db.posts.filter(p => p.authorId === req.user.id && !p.isDeleted && p.createdAt >= todayStart);
  if (todayPosts.length >= 1) return res.status(403).json({ error: 'TODAY_LIMIT_REACHED' });
  const newPost = { id: Date.now().toString(), authorId: req.user.id, ...req.body, createdAt: Date.now(), isDeleted: false };
  db.posts.push(newPost);
  res.json(newPost);
});

app.post('/api/posts/:id/like', authenticateToken, (req, res) => {
  const { id } = req.params;
  const idx = db.likes.findIndex(l => l.userId === req.user.id && l.postId === id);
  if (idx > -1) db.likes.splice(idx, 1); else db.likes.push({ userId: req.user.id, postId: id });
  res.json({ success: true });
});

app.post('/api/posts/:id/contact-mark', authenticateToken, (req, res) => {
  const { id } = req.params;
  if (!db.contactMarks.some(m => m.userId === req.user.id && m.postId === id)) db.contactMarks.push({ userId: req.user.id, postId: id });
  res.json({ success: true });
});

app.delete('/api/posts/:id', authenticateToken, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.sendStatus(404);
  if (user.role !== 'admin' && post.authorId !== user.id) return res.sendStatus(403);
  post.isDeleted = true;
  res.json({ success: true });
});

app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const { content, parentId } = req.body;
  const user = db.users.find(u => u.id === req.user.id);
  const comment = { id: Date.now().toString(), postId: req.params.id, authorId: req.user.id, authorName: user.nickname, content, parentId, createdAt: Date.now() };
  db.comments.push(comment);
  res.json(comment);
});

// Ads
app.get('/api/ads', (req, res) => res.json(db.ads));
app.post('/api/ads', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const ad = { ...req.body, id: Date.now().toString(), isVerified: true };
    db.ads.push(ad);
    res.json(ad);
});
app.delete('/api/ads/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    db.ads = db.ads.filter(a => a.id !== req.params.id);
    res.json({ success: true });
});

// Conversations
app.get('/api/conversations', authenticateToken, (req, res) => {
  const convs = db.conversations.filter(c => c.userIds.includes(req.user.id));
  const result = convs.map(c => {
    const otherId = c.userIds.find(uid => uid !== req.user.id);
    const otherUser = db.users.find(u => u.id === otherId);
    const lastMsg = db.messages.filter(m => m.conversationId === c.id).pop();
    return { id: c.id, updatedAt: c.updatedAt, lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.content : `[${lastMsg.type}]`) : '', otherUser: { id: otherUser?.id, nickname: otherUser?.nickname } };
  }).sort((a, b) => b.updatedAt - a.updatedAt);
  res.json(result);
});
app.post('/api/conversations/open-or-create', authenticateToken, (req, res) => {
  const { targetUserId } = req.body;
  let conv = db.conversations.find(c => c.userIds.includes(req.user.id) && c.userIds.includes(targetUserId));
  if (!conv) {
    conv = { id: Date.now().toString(), userIds: [req.user.id, targetUserId], createdAt: Date.now(), updatedAt: Date.now() };
    db.conversations.push(conv);
  }
  res.json(conv);
});
app.get('/api/conversations/:id/messages', authenticateToken, (req, res) => {
  const msgs = db.messages.filter(m => m.conversationId === req.params.id).sort((a, b) => a.createdAt - b.createdAt);
  res.json(msgs);
});
app.post('/api/conversations/:id/messages', authenticateToken, (req, res) => {
  const { type, content } = req.body;
  let finalContent = content;
  if (type === 'contact-share') {
    const user = db.users.find(u => u.id === req.user.id);
    finalContent = `我的联系方式：${user.contactType.toUpperCase()} ${user.contactValue}`;
  }
  const msg = { id: Date.now().toString(), conversationId: req.params.id, senderId: req.user.id, type, content: finalContent, createdAt: Date.now() };
  db.messages.push(msg);
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (conv) conv.updatedAt = Date.now();
  res.json(msg);
});

// --- ✅ 新增：公共内容管理接口 (About/Support) ---
app.get('/api/content/:key', (req, res) => {
    const key = req.params.key;
    const content = db.content[key] || '';
    res.json({ value: content });
});

app.post('/api/content', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { key, value } = req.body;
    db.content[key] = value;
    res.json({ success: true, value });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));