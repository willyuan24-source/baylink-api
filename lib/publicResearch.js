const { isSchoolRequest } = require('./guideConversation');

const isLibraryServiceQuestion = value => /图书馆|圖書館|图书证|圖書證|借书证|借書證|\b(?:libraries|library|kanopy|hoopla|SFPL|SMCL)\b/i.test(String(value || ''));
const isPublicInformationRequest = value => /[?？]|怎么|怎麼|如何|哪[里裡些个個]|能否|能不能|是否|行不行|可不可以|是不是|需要|查询|查詢|核实|核實|请查|請查|帮我|幫我|比较|比較|区别|區別|条件|條件|规则|規則|政策|期限|材料|收费|收費|费用|費用|价格|價格|电价|電價|月租|\b(?:how|what|where|when|which|can|could|should|need|help|check|verify|find|compare|explain|rules?|polic(?:y|ies)|requirements?|eligibility|deadlines?|documents?|fees?|prices?|pricing|rates?|hours)\b/i.test(String(value || ''));

// Public rules are information requests, even when phrased as "find" or
// "有哪些". Do not confuse them with looking for an actual provider/listing.
function isPublicPolicyRequest(value) {
  const text = String(value || '');
  return /租客权益|租客權益|租户权利|租戶權利|租金管制|租金上限|租房政策|租屋政策|租赁法规|租賃法規|维修许可|維修許可|消费者权益|消費者權益|\b(?:rent control|tenant(?:s['’]?)? rights|renter(?:s['’]?)? rights|housing laws?)\b/i.test(text)
    || (/租房|租屋|租约|租約|房东|房東|租客|租户|租戶|维修|維修|清洁|清潔|搬家|\b(?:rental|rent|housing|lease|landlord|tenant|repair|cleaning|moving)\b/i.test(text)
      && /政策|法规|法規|法律|权益|權益|规定|規定|许可要求|許可要求|\b(?:rights|laws?|regulations?|rules|permit requirements|legal requirements)\b/i.test(text));
}

// These subjects need program/service facts, not a venue's admission/hour
// schema. Mixed questions also retain a general cited answer, so one museum
// clause cannot erase the requested utility, printing or enrollment rules.
function isNonVisitorResearch(value) {
  const text = String(value || '');
  return isSchoolRequest(text) || isPublicPolicyRequest(text)
    || /租房|租金|月租|租约|租約|保洁|保潔|家政|水管维修|水管維修|搬家服务|搬家服務|\b(?:rentals?|rent|apartments?|housing|plumbers?|plumbing|electricians?|handyman|cleaning|movers?|moving (?:services?|companies)|translation|childcare|daycare)\b/i.test(text)
    || /打印|列印|图书证|圖書證|办卡|辦卡|水电|水電|电价|電價|供水|供电|供電|电力|電力|驾照|駕照|车辆登记|車輛登記|地址更新|更新地址|\b(?:printing|print prices?|library cards?|utilities|electricity|water (?:service|rates?|bills?)|PG\s*&\s*E|EBMUD|ACWD|DMV|driver['’]?s? licen[cs]e|vehicle registration|address change|change of address)\b/i.test(text);
}

module.exports = { isPublicPolicyRequest, isNonVisitorResearch, isLibraryServiceQuestion, isPublicInformationRequest };
