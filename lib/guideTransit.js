const TRANSIT = /公共交通|公交|公車|公车|巴士|地铁|地鐵|轻轨|輕軌|火车|火車|搭车|搭車|轉乘|转乘|\b(?:public transport(?:ation)?|transit|bart|caltrain|muni|samtrans|vta|buses?|trains?|light rail)\b/i;
function isPublicTransitRequest(message) {
  const text = String(message || '');
  if (/租房|租屋|房源|租约|租約|招聘|兼职|兼職|\b(?:rent(?:ing)?|apartments?|jobs?|hiring)\b/i.test(text)) return false;
  // Fare/eligibility questions need benefit guides; an operator name alone
  // must not constrain retrieval to route and commute articles.
  if (/青少年|学生票|學生票|票价|票價|优惠|優惠|折扣|月票|年票|免费|免費|福利|长者|長者|\b(?:free|benefits?|senior|eligibility|youth|student|fares?|discounts?|passes|prices?|tickets?)\b/i.test(text)
    && !/怎么走|怎麼走|轉乘|转乘|从.+到|從.+到|\b(?:route|transfer|from\b.+\bto|how\b.+\b(?:get|go))\b/i.test(text)) return false;
  if (/(?:找|雇|预约|預約|提供|发布|發佈).{0,12}(?:司机|司機|接送|接机|接機)|\b(?:hire|book|offer|advertise)\b.{0,30}\b(?:driver|pickup|private ride|airport transfer)\b/i.test(text)) return false;
  return TRANSIT.test(text) && /公共交通|公交|公車|公车|转乘|轉乘|换乘|換乘|通勤|怎么|怎麼|如何|到|前往|\b(?:public transport(?:ation)?|public transit|route|transfer|commut\w*|from|how|where)\b/i.test(text);
}
const isTransitGuide = guide => /公共交通|通勤|没有车|沒有車|机场|機場|\b(?:commut\w*|transit|without (?:a )?car|airport|bart|caltrain|muni)\b/i.test(`${guide.title || ''} ${(guide.keywords || []).join(' ')}`);

// A guide lookup is not a trip planner. Even a number copied from an example
// in a guide must not become this passenger's current journey time or last train.
const unverifiedTransitTiming = answer => /\b\d+(?:\.\d+)?\s*(?:[-–—至到]\s*\d+(?:\.\d+)?)?\s*(?:minutes?|mins?|hours?|hrs?)\b|\d+\s*(?:[-–—至到]\s*\d+)?\s*(?:分钟|分鐘|小时|小時)|\b\d{1,2}:\d{2}\s*(?:[ap]\.?m\.?)?|\b\d{1,2}\s*[ap]\.?m\.?\b|(?:末班|最後一班|最后一班|首班).{0,15}\d|\b(?:last|first)\s+(?:train|bus|departure).{0,25}(?:midnight|noon)|(?:末班|最后一班|最後一班).{0,15}(?:午夜|凌晨)/i.test(answer || '');
const transitInstruction = 'This is a public-transit journey question, not a request to hire or advertise a driver. Use the provided transport guides for supported route structure and transfer points; do not recommend unrelated sightseeing guides. No live itinerary or timetable was queried. Do not state numerical journey times, walking durations, fares, departure/arrival times or first/last-train cutoffs from memory, examples, or the prior assistant answer. Ask for the local travel date when a timetable matters and link the official trip planners; retain the origin, destination and luggage constraints. Never promise a late-night connection.';
function transitTimingFallback(locale) {
  if (locale === 'en') return 'I have not checked a date-specific timetable, so I cannot confirm the journey time or last connection. Use the transport guides below to identify the route, then check each leg for your local travel date in the BART trip planner, Caltrain timetable and the destination operator’s route planner. Include baggage collection, transfers and the final walk or bus. For a late arrival, confirm the final connecting service before relying on rail.';
  if (locale === 'zh-Hant') return '本次沒有查到指定日期的時刻表，不能確認車程或末班轉乘。先按下方交通指南核對路線，再按灣區當地出行日期分別查 BART 行程查詢、Caltrain 時刻表及目的地公交；把取行李、換乘和最後一段步行／公交一併計入。深夜抵達須確認每一段末班車能銜接，再決定是否搭軌道交通。';
  return '本次没有查到指定日期的时刻表，不能确认车程或末班转乘。先按下方交通指南核对路线，再按湾区当地出行日期分别查 BART 行程查询、Caltrain 时刻表及目的地公交；把取行李、换乘和最后一段步行／公交一并计入。深夜抵达须确认每一段末班车能衔接，再决定是否搭轨道交通。';
}
module.exports = { isPublicTransitRequest, isTransitGuide, unverifiedTransitTiming, transitInstruction, transitTimingFallback };
