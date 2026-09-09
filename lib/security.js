const crypto = require('node:crypto');

function normalizeContact(contactType, contactValue) {
  if (!['wechat', 'phone', 'email'].includes(contactType)) return { error: '请选择联系方式类型' };
  if (typeof contactValue !== 'string' || !contactValue.trim()) return { error: '请填写联系方式' };
  const value = contactValue.trim();
  if (value.length > 254 || /[\u0000-\u001f\u007f]/.test(value)) return { error: '联系方式格式无效' };
  if (contactType === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return { error: '请输入有效的联系邮箱' };
  if (contactType === 'wechat' && (/\s/.test(value) || value.length > 64)) return { error: '请填写不含空格的微信号' };
  if (contactType === 'phone') {
    const digits = value.replace(/\D/g, '');
    if (!/^[+\d\s().-]+$/.test(value) || digits.length < 7 || digits.length > 15) return { error: '请输入有效的电话号码，可包含国家代码' };
  }
  return { contactType, contactValue: contactType === 'email' ? value.toLowerCase() : value };
}

function allowedOrigins(config) {
  const origins = ['https://www.baylink.us', 'https://baylink.us'];
  if (config.NODE_ENV !== 'production') {
    origins.push('http://localhost:5173', 'http://localhost:4173', 'http://127.0.0.1:5173', 'http://127.0.0.1:4173');
  }
  for (const raw of [config.FRONTEND_URL, ...(config.CORS_ALLOWED_ORIGINS || '').split(',')]) {
    if (!raw?.trim()) continue;
    const candidate = raw.trim();
    let url;
    try { url = new URL(candidate); } catch { throw new Error('CORS origin configuration is invalid'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
      throw new Error('CORS origins must be exact HTTP(S) origins');
    }
    if (config.NODE_ENV === 'production' && url.protocol !== 'https:') throw new Error('Production CORS origins must use HTTPS');
    origins.push(url.origin);
  }
  return [...new Set(origins)];
}

function apiSecurityHeaders(production) {
  return (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    if (production) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    next();
  };
}

const hashSessionToken = token => crypto.createHash('sha256').update(token).digest('hex');
module.exports = { normalizeContact, allowedOrigins, apiSecurityHeaders, hashSessionToken };
