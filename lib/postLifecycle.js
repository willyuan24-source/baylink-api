const SERVICE_CATEGORIES = ['清洁', '搬家', '维修', '翻译'];
const scalar = (value, name) => {
  if (value == null || value === '') return '';
  if (typeof value !== 'string' || value.length > 80) throw new Error(`${name}格式无效`);
  return value.trim();
};

function publicPostFilters(params = {}) {
  const category = scalar(params.category, '分类');
  const city = scalar(params.city, '地区');
  const type = scalar(params.type, '信息类型');
  if (type && !['provider', 'client'].includes(type)) throw new Error('信息类型无效');
  const query = { isDeleted: false, status: { $ne: 'closed' } };
  if (type) query.type = type;
  if (category && category !== '全部') {
    query.category = ['service', '本地服务'].includes(category) ? { $in: SERVICE_CATEGORIES } : category;
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

module.exports = { publicPostFilters, postLifecycleChanges, SERVICE_CATEGORIES };
