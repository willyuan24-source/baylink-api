const { categoryAliases, detectLocation, literalPattern } = require('./postSearch');
const { isPublicPolicyRequest } = require('./publicResearch');
const MAX_CANDIDATES = 200;
const POST_FIELDS = 'id title city budget confirmedAt createdAt status category description type';
const MONTH = /(?:\/\s*(?:月|mo(?:nth)?\b)|每月|月租|月付|\bper\s+month\b|\bmonthly\b)/i;
const OTHER_PERIOD = /(?:\/\s*(?:天|日|晚|周|小时|day|night|week|hour)|每天|每晚|每周|日租|周租|时薪|per\s+(?:day|night|week|hour))/i;
const NUMBER = '(?:\\d{1,3}(?:,\\d{3})+|\\d+)(?:\\.\\d{1,2})?';
const OTHER_CURRENCY = /人民币|RMB|CNY|¥|欧元|EUR|€|加元|CAD|港币|港元|HKD|AUD|GBP|£|日元/i;

function safeText(value, length) {
  return String(value || '').replace(/[\u0000-\u001f]/g, ' ')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[联系方式已隐藏]')
    .replace(/(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[联系方式已隐藏]')
    .replace(/(?:微信(?:号)?|wechat(?:\s+id)?|weixin(?:\s+id)?|电话|手机|vx|\bwx)\s*[:：=]?\s*[a-z0-9_+().-]{3,}/gi, '[联系方式已隐藏]')
    .slice(0, length).trim();
}

function monthlyRent(post) {
  const budget = String(post.budget || '').trim();
  const context = `${post.title || ''}\n${post.description || ''}`;
  if (!budget || OTHER_PERIOD.test(budget) || /(?:起|起价|以上|以下|以内|约|大概|左右|面议|每人|\/人|per person|from|starting|up to|about|~|～|\d\s*[-–]\s*\$?\d)/i.test(budget)) return null;
  if (OTHER_CURRENCY.test(budget)) return null;
  const numbers = budget.match(new RegExp(NUMBER, 'g')) || [];
  if (numbers.length !== 1) return null;
  const amount = Number(numbers[0].replace(/,/g, ''));
  if (!(amount > 0 && amount < 1000000)) return null;
  const plainBudget = new RegExp(`^(?:(?:USD|US\\$|\\$)\\s*)?${NUMBER}\\s*(?:美元|美金|USD)?$`, 'i').test(budget);
  const explicitBudget = MONTH.test(budget) && !/押金|deposit/i.test(budget);
  // Parse complete monthly amounts rather than searching for the budget as a substring.
  // Deposit clauses cannot establish rent; conflicting rent amounts remain unconfirmed.
  const monthlyAmounts = new Set();
  for (const clause of context.split(/[，。；;\n]|,(?!\d{3}(?:\D|$))/)) {
    if (/押金|deposit|清洁费|每人|\/人|per person|起价|起租价|起\/|\d\s*(?:美元|美金)?\s*起|约|大概|左右|面议|starting|from|about|up to|~|～/i.test(clause) || OTHER_CURRENCY.test(clause)) continue;
    const patterns = [
      new RegExp(`(?:月租|每月|monthly(?:\\s+rent)?)[^\\d\\n]{0,12}(${NUMBER})(?![\\d.])`, 'gi'),
      new RegExp(`(?<![\\d.,])(?:\\$|USD\\s*)?(${NUMBER})(?![\\d.])\\s*(?:美元|美金|USD)?\\s*(?:/\\s*(?:月|mo(?:nth)?\\b)|per\\s+month)`, 'gi'),
    ];
    for (const pattern of patterns) for (const match of clause.matchAll(pattern)) monthlyAmounts.add(Number(match[1].replace(/,/g, '')));
  }
  if (monthlyAmounts.size && (monthlyAmounts.size !== 1 || !monthlyAmounts.has(amount))) return null;
  return explicitBudget || (plainBudget && monthlyAmounts.has(amount)) ? amount : null;
}

function monthlyCeiling(message, category) {
  if (!['rent', 'roommate'].includes(category) || OTHER_PERIOD.test(message) || OTHER_CURRENCY.test(message)) return null;
  const upper = new RegExp(`(?:不超过|最多|上限|低于|少于|under|below|up to)\\s*(?:\\$|USD\\s*)?(${NUMBER})|(?:\\$|USD\\s*)?(${NUMBER})\\s*(?:美元|美金|USD)?\\s*(?:以内|以下|之内|封顶|/月以内|/月以下)`, 'i').exec(message);
  if (!upper) return null;
  const before = message.slice(0, upper.index).split(/[，,。；;\n]/).at(-1);
  const after = message.slice(upper.index + upper[0].length).split(/[，,。；;\n]/)[0];
  const clause = `${before}${upper[0]}${after}`;
  if (!/月租|每月|月预算|monthly|per month|\/月/i.test(clause) || /押金|deposit|每人|\/人|per person/i.test(clause)) return null;
  return Number((upper[1] || upper[2]).replace(/,/g, '')) || null;
}

function isProviderRequest(message) {
  return /我要卖|我想卖|我有.{0,15}(?:出租|出售)|找买家|找租客|找客户|找客源|求职的人|求职者|应聘者|我(?:们)?(?:提供|承接|接单|出租|出售)|(?:find|looking for)\s+(?:clients|customers|candidates)/i.test(message);
}

function planPostSearch(message, category) {
  if (!['rent', 'roommate', 'used', 'moving', 'cleaning', 'ride', 'repair', 'translation', 'part-time'].includes(category)) return null;
  if (isPublicPolicyRequest(message)) return null;
  // An ordinary existence question is a request to check real public listings,
  // just like "find". Keep negated queries and advice/provider requests separate.
  if (/(?:不要|不用|无需|無需|不想|别|別).{0,6}(?:查询|查詢|搜索|搜尋|搜|找|寻找|尋找)|\b(?:do not|don['’]t|not looking to)\s+(?:want to\s+)?(?:find|look|search|browse|show|check|找|搜索|搜尋)(?=\s|$|[，,.。！？!?])/i.test(message)) return null;
  const existenceQuestion = /(?<!没|沒|不|无|無)有[^，,。；;\n！？!?]{1,60}(?:吗|嗎)(?:[？?]|\s*$)|\b(?:are|is)\s+there\b|\bdo\s+you\s+have\b/i.test(message);
  const looking = existenceQuestion || /找|寻找|求租|求购|有哪些|有没有|推荐|想买|购买|站内|平台上|looking|find|available|show me/i.test(message);
  if (!looking || /怎么|如何|注意|避坑|防骗|退款|押金|合同|骗局|攻略|指南|what should|how to/i.test(message)) return null;
  // Selling/publishing requests belong in the composer, not a provider recommendation.
  if (isProviderRequest(message) || /发布|写.{0,5}帖|帮我写/i.test(message)) return null;
  const location = detectLocation(message);
  if (location?.ambiguous) return { needsClarification: true, clarification: `你提到了${location.labels.join('、')}。希望在哪一个地点找信息？确认后我再按目标地区检索。` };
  const roomKind = /\bstudio\b|独立套房|单身公寓/i.test(message) ? 'Studio' : null;
  const maxMonthlyRent = monthlyCeiling(message, category);
  const query = { isDeleted: false, adminHidden: { $ne: true }, status: { $ne: 'closed' }, type: 'provider', category: { $in: categoryAliases(category === 'roommate' ? 'rent' : category) } };
  const conditions = [];
  if (location) {
    const regex = new RegExp(location.aliases.map(literalPattern).join('|'), 'i');
    conditions.push({ $or: [{ city: regex }, { title: regex }] });
  }
  if (roomKind) conditions.push({ $or: [{ title: /\bstudio\b|独立套房|单身公寓/i }, { description: /\bstudio\b|独立套房|单身公寓/i }] });
  if (category === 'roommate') conditions.push({ $or: [{ title: /室友|合租|roommate|shared\s+(?:room|house)/i }, { description: /室友|合租|roommate|shared\s+(?:room|house)/i }] });
  if (conditions.length) query.$and = conditions;
  return { query, category, location: location?.label || '', roomKind, maxMonthlyRent, priceUnclear: maxMonthlyRent == null && /\$|美元|美金|预算|\d.*(?:以内|以下)/i.test(message),
    requestedChinese: /中文|普通话|普通話|国语|國語|\b(?:Chinese|Mandarin|Cantonese)\b/i.test(message),
    requestedToday: /今天|今日|\btoday\b/i.test(message) };
}

function serviceSearchNextStep(plan, locale = 'zh-Hans') {
  if (!['repair', 'cleaning', 'moving', 'translation'].includes(plan?.category)) return '';
  const english = locale === 'en';
  const unverified = [plan.requestedToday ? english ? 'availability today' : '今天能否服务' : '', plan.requestedChinese ? english ? 'Chinese-language service' : '是否可用中文沟通' : ''].filter(Boolean);
  const status = unverified.length ? english ? `Still unverified: ${unverified.join(' and ')}. ` : `尚未确认：${unverified.join('、')}。` : '';
  const next = plan.category === 'repair' ? english
    ? 'Before arranging a visit, ask about the earliest arrival time, service-call or diagnostic fee, and a written estimate for labor and parts.'
    : '联系前先问最早可上门时间、上门或诊断费，以及人工和零件的书面报价。'
    : english ? 'Before booking, ask about availability, language, scope of work and the full written quote.' : '预约前先问可服务时间、沟通语言、服务范围和完整书面报价。';
  return status + next;
}

function publicMatchingPost(post) {
  return {
    id: String(post.id), title: safeText(post.title, 80), city: safeText(post.city, 80), budget: safeText(post.budget, 30),
    ...(Number.isFinite(post.confirmedAt) && post.confirmedAt > 0 ? { confirmedAt: post.confirmedAt } : {}),
    createdAt: Number.isFinite(post.createdAt) ? post.createdAt : 0,
    status: post.status === 'active' ? 'active' : undefined, category: safeText(post.category, 30),
  };
}

function summarizeMatches(posts, plan) {
  const scanned = posts.slice(0, MAX_CANDIDATES);
  let unknownPrices = 0;
  const matching = scanned.filter(post => {
    if (plan.maxMonthlyRent == null) return true;
    const price = monthlyRent(post);
    if (price == null) { unknownPrices += 1; return false; }
    return price <= plan.maxMonthlyRent;
  }).slice(0, 3).map(publicMatchingPost);
  const constraints = [plan.location, plan.roomKind, plan.maxMonthlyRent != null ? `明确月租不超过 $${plan.maxMonthlyRent}` : ''].filter(Boolean);
  const notes = ['仅依据帖子已填写信息匹配；是否仍可用、完整费用和具体需求请与发布者确认。'];
  if (plan.priceUnclear) notes.push('预算单位或上限尚未明确，本次没有按价格筛选。');
  if (unknownPrices) notes.push('月租金额或单位不明确的帖子未计入价格匹配。');
  if (posts.length > MAX_CANDIDATES) notes.push(`本次只检索该类别和区域下最新 ${MAX_CANDIDATES} 条信息。`);
  const next = serviceSearchNextStep(plan);
  return {
    matchingPosts: matching,
    matchNote: notes.join(''),
    answer: (matching.length
      ? `找到 ${matching.length} 条${constraints.length ? `符合已识别条件（${constraints.join('、')}）的` : '该类别的'}公开信息。点开下方帖子查看详情；其他条件尚未核实。`
      : `本次检索没有找到${constraints.length ? `同时符合已识别条件（${constraints.join('、')}）的` : '该类别的'}公开信息。可以调整地区或补充需求，也可以发布求助帖。`)
      + (next ? `\n\n${!matching.length ? '本次只查了站内公开帖子，未找到不代表当地没有服务。' : ''}${next}` : ''),
  };
}

module.exports = { MAX_CANDIDATES, POST_FIELDS, monthlyRent, monthlyCeiling, isProviderRequest, planPostSearch, publicMatchingPost, summarizeMatches, serviceSearchNextStep };
