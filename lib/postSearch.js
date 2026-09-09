// Bounded, literal search: AND between terms, OR only within explicit synonym groups.
const CATEGORY_ALIASES = {
  rent: ['租屋', '租房', '出租'], used: ['闲置', '二手'], moving: ['搬家'], cleaning: ['清洁'],
  ride: ['接送'], repair: ['维修'], translation: ['翻译'], 'part-time': ['兼职'], other: ['其他'],
};
const REGIONS = [
  { name: '中半岛', aliases: ['中半岛', '半岛', 'Peninsula', 'Millbrae', 'Burlingame', 'San Mateo', 'Foster City', 'Belmont', 'San Carlos', 'Redwood City'] },
  { name: '南湾', aliases: ['南湾', 'South Bay', 'San Jose', 'Palo Alto', 'Mountain View', 'Sunnyvale', 'Santa Clara', 'Cupertino', 'Milpitas', 'Los Altos', 'Campbell', 'Saratoga'] },
  { name: '东湾', aliases: ['东湾', 'East Bay', 'Oakland', 'Berkeley', 'Fremont', 'Hayward', 'Union City', 'Newark', 'Alameda', 'San Leandro', 'Dublin', 'Pleasanton', 'Walnut Creek', 'Concord'] },
  { name: '北湾', aliases: ['北湾', 'North Bay', 'Marin', 'San Rafael', 'Sausalito', 'Novato', 'Santa Rosa', 'Napa', 'Sonoma'] },
  { name: '旧金山', aliases: ['旧金山', 'San Francisco', 'SF', 'Daly City', 'South San Francisco'] },
];
const escapeRegex = value => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const literalPattern = value => /[a-z]/i.test(value)
  ? `${/^(?:San Francisco|SF)$/i.test(value) ? '(?<!South\\s{1,3})' : ''}\\b${escapeRegex(value).replace(/\s+/g, '\\s+')}\\b` : escapeRegex(value);
const synonymGroups = [CATEGORY_ALIASES.rent, CATEGORY_ALIASES.used];

function categoryAliases(value) {
  const group = CATEGORY_ALIASES[value] || Object.values(CATEGORY_ALIASES).find(items => items.includes(value));
  return group || [value];
}

function searchTerms(keyword) {
  if (typeof keyword !== 'string' || keyword.length > 80) throw new Error('搜索关键词格式无效或过长');
  let remaining = keyword.trim();
  const terms = [];
  // Chinese compounds such as 南湾租房 are split only at these known concepts.
  for (const group of synonymGroups) {
    const regex = new RegExp(group.map(literalPattern).join('|'), 'gi');
    if (regex.test(remaining)) {
      terms.push(group);
      remaining = remaining.replace(regex, ' ');
    }
  }
  for (const region of REGIONS) {
    const labels = region.aliases.filter(alias => alias === region.name || alias === '半岛' || /^(?:Peninsula|South Bay|East Bay|North Bay)$/i.test(alias));
    const regex = new RegExp(labels.map(literalPattern).join('|'), 'gi');
    if (regex.test(remaining)) {
      terms.push(region.aliases);
      remaining = remaining.replace(regex, ' ');
    }
  }
  for (const token of remaining.split(/[\s，,、；;]+/).filter(Boolean)) terms.push([token]);
  if (terms.length > 8) throw new Error('请精简到 8 个以内的搜索关键词');
  return terms;
}

function keywordFilter(keyword) {
  const terms = searchTerms(keyword);
  return terms.length ? { $and: terms.map(aliases => {
    const regex = new RegExp(aliases.map(literalPattern).join('|'), 'i');
    return { $or: ['title', 'description', 'city', 'category'].map(field => ({ [field]: regex })) };
  }) } : {};
}

function detectLocation(message) {
  // Multiple locations may describe a commute, not the search destination; ask instead of guessing.
  const matches = [];
  const cityAliases = REGIONS.flatMap(region => region.aliases.filter(alias => /[a-z]/i.test(alias)).map(alias => ({ alias, region })))
    .sort((a, b) => b.alias.length - a.alias.length);
  for (const { alias, region } of cityAliases) {
    if (new RegExp(literalPattern(alias), 'i').test(message)) {
      const broad = /^(?:Peninsula|South Bay|East Bay|North Bay)$/i.test(alias);
      const isSf = /^(?:SF|San Francisco)$/i.test(alias);
      matches.push({ label: broad ? region.name : isSf ? 'San Francisco' : alias, aliases: broad ? region.aliases : isSf ? ['SF', 'San Francisco'] : [alias], region: region.name, broad });
    }
  }
  for (const region of REGIONS) {
    if (message.includes(region.name) || (region.name === '中半岛' && message.includes('半岛'))) matches.push({ label: region.name, aliases: region.aliases, region: region.name, broad: true });
  }
  const unique = [...new Map(matches.filter(item => !item.broad || !matches.some(other => !other.broad && other.region === item.region)).map(item => [item.label, item])).values()];
  if (unique.length > 1) return { ambiguous: true, labels: unique.map(item => item.label) };
  return unique.length ? { label: unique[0].label, aliases: unique[0].aliases } : null;
}

module.exports = { CATEGORY_ALIASES, REGIONS, categoryAliases, keywordFilter, literalPattern, detectLocation };
