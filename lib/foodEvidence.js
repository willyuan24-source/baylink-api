// Retrieval constraints, never a claim about a restaurant's current menu,
// availability, or the completeness of the site's/local area's supply.
const DIM_SUM = /饮茶|飲茶|(?:广式|廣式|港式)点心|(?:广式|廣式|港式)點心|(?<![一给給])(?:点心|點心)(?!意|债券|債券|证券|證券|机|機|设备|設備)|\bdim[\s-]+sum\b(?![\s-]*(?:bonds?|securities|machines?|equipment)\b)/iu;
const DIM_SUM_FACT = /饮茶|飲茶|茶楼|茶樓|(?:广式|廣式|港式)(?:点心|點心)|\bdim[\s-]+sum\b/iu;
const DINING_QUERY = /餐[厅廳]|饭[馆館]|美食|好吃|吃[饭飯]|吃得|用餐|(?:吃|找).{0,6}(?:午餐|晚餐|早餐)|\b(?:restaurants?|dining|eat(?:ing)? out|good food|places? to eat|where.{0,18}eat)\b/iu;
const SERVICE = /餐[厅廳]|饭[馆館]|咖啡[馆館店]|茶[楼樓]|烘焙店|餐[车車]|海[鲜鮮]|简餐|簡餐|汉堡|漢堡|\b(?:restaurants?|caf[eé]s?|bakery|bakeries|bistro|eatery|burger|seafood|food trucks?|dining|menus?)\b/iu;
const FOOD_HEADING = /吃[饭飯得]|用餐|美食|餐[厅廳馆館车車]|咖啡|烘焙|饮茶|飲茶|点心|點心|\b(?:food|dining|restaurants?|caf[eé]s?|bakery|bakeries|cuisine|cooking|tasting)\b/iu;
const OTHER_REQUEST = /租[房屋赁賃]|房源|报税|報稅|牙[医醫科]|医保|醫保|保险|保險|入籍|驾照|駕照|证券|證券|债券|債券|\b(?:housing|rentals?|tax|medicare|medical|dental|insurance|citizenship|securities|bonds?)\b/iu;
const OTHER_ACTIVITY = /博物[馆館]|[图圖][书書][馆館]|看展|展[览覽]|[动動]物[园園]|公[园園]|徒步|爬山|散步|[购購]物|[买買]菜|回收|通勤|交通|地[铁鐵]|找人|[结結]伴|\b(?:museums?|libraries|library|exhibitions?|zoos?|parks?|hiking|walking|shopping|recycling|commut\w*|transit|subway|companions?|buddies|buddy)\b/iu;
const NON_FOOD_DIM_SUM = /(?:点心|點心)(?:意|债券|債券|证券|證券|机|機|设备|設備)|\bdim[\s-]+sum[\s-]+(?:bonds?|securities|machines?|equipment)\b/iu;
const clauses = value => String(value || '').normalize('NFKC').split(/[。！？!?；;，,\n]+/u).filter(Boolean);

function foodRequest(value) {
  const input = String(value || '').slice(0, 4000).normalize('NFKC');
  // A quoted term, financial metaphor, historical aside, or mixed unrelated
  // service question must not turn the whole request into restaurant discovery.
  if (NON_FOOD_DIM_SUM.test(input) || OTHER_REQUEST.test(input) || OTHER_ACTIVITY.test(input)
    || /(?:词语|詞語|单词|單詞|意思|翻译|翻譯|\b(?:word|phrase|term|quote|translate)\b)/iu.test(input)) return null;
  const requested = clauses(input).filter(clause => !/(?:之前|以前|上次|曾经|曾經|\b(?:previously|earlier|used to)\b)|(?:不想|不要|不吃|不喝|不找|不是|不用|不需要).{0,20}(?:饮茶|飲茶|点心|點心|吃饭|吃飯|餐厅|餐廳)|\b(?:not (?:looking for|interested in)|do not want|don't want|without|no need for)\b.{0,25}(?:dim[\s-]+sum|restaurants?|dining|food)/iu.test(clause));
  if (requested.some(clause => DIM_SUM.test(clause))) return { kind: 'dim-sum' };
  if (requested.some(clause => DINING_QUERY.test(clause))) return { kind: 'dining' };
  return null;
}

function positiveFoodFact(value, pattern) {
  return clauses(value).some(clause => pattern.test(clause)
    && !/(?:没有|沒有|不提供|不卖|不賣|未确认|未確認|待确认|待確認|询问是否|詢問是否).{0,20}(?:饮茶|飲茶|点心|點心|餐|菜单|菜單)|(?:饮茶|飲茶|点心|點心).{0,16}(?:未确认|未確認|待确认|待確認|不提供)|\b(?:no|not|without|unconfirmed|does not|doesn't|do not|don't)\b.{0,20}(?:dim[\s-]+sum|dining|restaurant|menu)|\bdim[\s-]+sum\b.{0,16}\b(?:unconfirmed|not offered|unavailable)\b/iu.test(clause));
}

function hasPublicSource(row) {
  const references = Array.isArray(row.sourceUrls) ? row.sourceUrls : [];
  const guideSources = Array.isArray(row._guideSources) ? row._guideSources : Array.isArray(row.sources) ? row.sources : [];
  const values = [row.officialUrl, ...references.map(source => typeof source === 'string' ? source : source?.url),
    ...guideSources.map(source => typeof source === 'string' ? source : source?.url)];
  return values.some(value => {
    try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; } catch { return false; }
  });
}

function matchesFoodEvidence(row, request, kind = 'guide') {
  if (!request) return true;
  if (!row || !hasPublicSource(row)) return false;
  const heading = [row.title, row._contentHeading, row.sectionHeading].filter(value => typeof value === 'string').join(' ');
  // Paragraphs are evaluated on their actual excerpt, not on a distant menu
  // mention in another section or the whole guide's broad source metadata.
  const facts = typeof row.text === 'string' ? row.text : typeof row.content === 'string' ? row.content
    : [row.summary, ...(Array.isArray(row.plan) ? row.plan : [])].filter(value => typeof value === 'string').join('\n');
  const ownFoodVenue = kind === 'place' && (row.category === 'food' || /^(?:restaurant|cafe)-/.test(row.id || '') || SERVICE.test(heading));
  const foodFocus = FOOD_HEADING.test(heading) || ownFoodVenue;
  if (kind === 'event' && !foodFocus) return false;
  const serviceFact = positiveFoodFact(facts, SERVICE);
  if (request.kind === 'dim-sum') {
    const exactFact = positiveFoodFact(facts, DIM_SUM_FACT)
      || (ownFoodVenue || serviceFact) && positiveFoodFact(facts, DIM_SUM);
    return exactFact && (foodFocus || kind === 'guide' && serviceFact);
  }
  // A library event's refreshments, nearby cafe, a shop's market location, or
  // an event's "food costs extra" are not evidence of a dining destination.
  return (foodFocus || kind === 'guide' && serviceFact) && (serviceFact || positiveFoodFact(facts, DIM_SUM_FACT));
}

function foodEvidenceGap(request, locale = 'zh-Hans') {
  const specific = request?.kind === 'dim-sum';
  if (locale === 'en') return specific
    ? 'The site records retrieved in this turn do not establish a tea/dim-sum option matching your request. Generic restaurant records do not confirm dim-sum service. Which city or named restaurant should we check? Confirm the current menu and opening arrangements with the official venue; this is not a claim that no options exist on the site or locally.'
    : 'The records retrieved in this turn do not establish a dining option matching your request. Which city or type of food should we check? Confirm current menus and opening arrangements with the official venue; this is not a claim that no options exist on the site or locally.';
  if (locale === 'zh-Hant') return specific
    ? '本輪取得的站內記錄尚未確證符合要求的飲茶／點心選項。一般餐廳資料不能證明提供點心。你想核對哪個城市或哪家店？菜單與營業安排請向店家官方確認；這不表示全站或當地沒有選項。'
    : '本輪取得的記錄尚未確證符合要求的用餐選項。你想核對哪個城市或哪種食物？菜單與營業安排請向店家官方確認；這不表示全站或當地沒有選項。';
  return specific
    ? '本轮取得的站内记录尚未确证符合要求的饮茶／点心选项。一般餐厅资料不能证明提供点心。你想核对哪个城市或哪家店？菜单与营业安排请向店家官方确认；这不表示全站或当地没有选项。'
    : '本轮取得的记录尚未确证符合要求的用餐选项。你想核对哪个城市或哪种食物？菜单与营业安排请向店家官方确认；这不表示全站或当地没有选项。';
}

module.exports = { foodRequest, matchesFoodEvidence, foodEvidenceGap };
