const SERVICE_CATEGORIES = ['清洁', '搬家', '维修', '翻译', '接送'];
const { categoryAliases } = require('./postSearch');
const SHORT_LIVED_CATEGORIES = ['租屋', '租房', '出租', '闲置', '二手', '兼职'];
const DAY = 86400000;
function publicPostAvailability(post, now = Date.now()) {
  if (post.status === 'closed') return 'closed';
  const expiry = typeof post.expiresAt === 'number' ? post.expiresAt : typeof post.expiresAt === 'string' ? Date.parse(post.expiresAt) : NaN;
  if (Number.isFinite(expiry) && expiry <= now) return 'needs_confirmation';
  const days = SHORT_LIVED_CATEGORIES.includes(post.category) ? 30 : 60;
  return Number.isFinite(post.confirmedAt) && post.confirmedAt > 0 && post.confirmedAt <= now && post.confirmedAt >= now - days * DAY ? 'confirmed' : 'needs_confirmation';
}
const scalar = (value, name) => {
  if (value == null || value === '') return '';
  if (typeof value !== 'string' || value.length > 80) throw new Error(`${name}格式无效`);
  return value.trim();
};

function publicPostFilters(params = {}, now = Date.now()) {
  const category = scalar(params.category, '分类');
  const city = scalar(params.city, '地区');
  const type = scalar(params.type, '信息类型');
  if (type && !['provider', 'client'].includes(type)) throw new Error('信息类型无效');
  const query = { isDeleted: false, status: { $ne: 'closed' } };
  const availability = scalar(params.availability, '有效状态');
  if (availability && !['current', 'all'].includes(availability)) throw new Error('有效状态无效');
  // The website opts into the current inventory. Legacy API callers can still
  // inspect historical records; no old listing is silently deleted or renewed.
  if (availability === 'current') query.$and = [{ $or: [
    { category: { $in: SHORT_LIVED_CATEGORIES }, confirmedAt: { $gte: now - 30 * DAY, $lte: now } },
    { category: { $nin: SHORT_LIVED_CATEGORIES }, confirmedAt: { $gte: now - 60 * DAY, $lte: now } },
  ] }, { $or: [{ expiresAt: { $exists: false } }, { expiresAt: null }, { expiresAt: { $gt: now } }] }];
  if (type) query.type = type;
  if (category && category !== '全部') {
    query.category = { $in: ['service', '本地服务'].includes(category) ? SERVICE_CATEGORIES : categoryAliases(category) };
  }
  if (city && city !== '全部') query.city = city;
  return query;
}

function postLifecycleChanges(body, { creating = false, isOwner = false, previousStatus, now = Date.now() } = {}) {
  if (body.status !== undefined && !['active', 'closed'].includes(body.status)) throw new Error('信息状态无效');
  if (body.confirmAvailability !== undefined && typeof body.confirmAvailability !== 'boolean') throw new Error('有效确认格式无效');
  if (body.confirmAvailability && !isOwner) throw new Error('只有发布者可以确认信息仍然有效');
  if (body.status === 'closed' && body.confirmAvailability) throw new Error('已结束的信息不能同时确认有效');
  const changes = {};
  if (body.status !== undefined) changes.status = body.status;
  if (creating) { changes.status = body.status || 'active'; changes.confirmedAt = changes.status === 'active' ? now : null; }
  else if (body.confirmAvailability === true) { changes.status = 'active'; changes.confirmedAt = now; }
  // Reopening without an explicit confirmation must not preserve an old assurance.
  else if (body.status === 'active' && previousStatus === 'closed') changes.confirmedAt = null;
  return changes;
}

module.exports = { publicPostFilters, publicPostAvailability, postLifecycleChanges, SERVICE_CATEGORIES };
