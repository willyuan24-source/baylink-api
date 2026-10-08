// Pre-dispatch for the local eval, in the order POST /api/ai/guide-chat uses:
// safety middleware -> deterministic outing search -> legacy post/provider/
// private-school path -> v2 BayBay assistant. Everything except the intent
// classifier is imported from lib/. inferBayBayIntent lives inside
// createApplication() in server.js, so it is mirrored below and fingerprinted:
// the harness warns when the server copy changes.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const { safetyResponse } = require(path.join(ROOT, 'lib/safetyRouting'));
const { outingChatIntent } = require(path.join(ROOT, 'lib/outingChatIntent'));
const { isProviderRequest, planPostSearch } = require(path.join(ROOT, 'lib/baybaySearch'));
const { resolveConversationRequest, isSchoolRequest } = require(path.join(ROOT, 'lib/guideConversation'));
const { isPublicTransitRequest } = require(path.join(ROOT, 'lib/guideTransit'));
const { normalizeGuideQuery } = require(path.join(ROOT, 'lib/guideLocale'));
const { hasPrivateSearchData } = require(path.join(ROOT, 'lib/guideWebSearch'));

// Mirror of server.js normalizeCategoryHint + inferBayBayIntent + intentToGuideCategory
// (origin/main 963c947). Fingerprint below covers those exact source lines.
export const INTENT_MIRROR_FINGERPRINT = 'f485bcca6321b529';
const GUIDE_CHAT_CATEGORIES = new Set(['rent', 'roommate', 'used', 'moving', 'cleaning', 'ride', 'repair', 'translation', 'part-time', 'other']);
const normalizeCategoryHint = categoryHint => {
  const hint = String(categoryHint ?? '').trim().toLowerCase();
  if (!hint || hint === 'general') return '';
  return GUIDE_CHAT_CATEGORIES.has(hint) ? hint : '';
};
function inferBayBayIntent(message = '', categoryHint = '') {
  const text = String(message || '').toLowerCase();
  if (isSchoolRequest(text)) return 'school';
  if (isPublicTransitRequest(text)) return 'transit';
  if (/翻译|口译|笔译|\b(?:translation|translator|interpretation)\b/.test(text)) return 'translation';
  if (/兼职|招聘|找工作|\b(?:part.time|hiring|jobs?)\b/.test(text)) return 'part-time';
  if (/室友|合租|找人合租|\b(?:roommates?|share room)\b/.test(text)) return 'roommate';
  if (/维修|修理|水管|电工|电路|马桶|漏水|\b(?:handyman|repair|fix)\b/.test(text)) return 'repair';
  if (/搬家|搬运|\b(?:moving|move)\b/.test(text)) return 'moving';
  if (/清洁|打扫|保洁|\b(?:cleaning|cleaner)\b/.test(text)) return 'cleaning';
  if (/接送|接机|送机|机场|通勤|\b(?:ride|pickup|dropoff|airport|sfo|sjc|oak)\b/.test(text)) return 'ride';
  if (/卖东西|出东西|二手|闲置|转让|家具|家电|出售|我想卖|\b(?:used|sell|secondhand)\b/.test(text)) return 'used';
  if (/租房|租屋|出租|月租|房源|找房|求租|押金|看房|租约|单间|\b(?:studio|rent|housing|apartment)\b/.test(text)) return 'rent';
  if (/\broom\b/.test(text) && !/roommate/.test(text)) return 'rent';
  if (/服务|帮忙|本地服务|\bservice\b/.test(text)) return 'service';
  return normalizeCategoryHint(categoryHint) || 'general';
}
const intentToGuideCategory = intent => {
  if (intent === 'general' || intent === 'service') return 'other';
  if (intent === 'roommate') return 'roommate';
  return GUIDE_CHAT_CATEGORIES.has(intent) ? intent : 'other';
};

/** Hash of the server's current copy; differs from the mirror's when server.js changed. */
export function serverIntentFingerprint(serverSource = readFileSync(path.join(ROOT, 'server.js'), 'utf8')) {
  const source = serverSource.replace(/\r\n/g, '\n');
  const hintStart = source.indexOf('const normalizeCategoryHint =');
  const hintEnd = source.indexOf('};', hintStart) + 2;
  const intentStart = source.indexOf('function inferBayBayIntent(');
  const intentEnd = source.indexOf('const GUIDE_CHAT_FALLBACK_ANSWERS');
  if ([hintStart, intentStart, intentEnd].some(index => index < 0)) return 'missing';
  return createHash('sha256').update(`${source.slice(hintStart, hintEnd)}\n${source.slice(intentStart, intentEnd)}`).digest('hex').slice(0, 16);
}

/**
 * Returns a deterministic payload when the request never reaches the v2
 * assistant, otherwise null. `legacy` payloads carry no answer: the legacy
 * guide-chat model path is a different pipeline and is not run by this eval.
 */
export function preDispatch({ message, history, locale, nowMs, secret, guideCatalog, englishGuideCatalog }) {
  const safety = safetyResponse(message, locale, { guideCatalog, englishGuideCatalog });
  if (safety) return safety;
  const outing = outingChatIntent({ message, history, locale, now: nowMs, secret });
  if (outing) return { ...outing, harnessRoute: 'outing' };
  const analysisMessage = normalizeGuideQuery(message);
  const analysisHistory = history.map(item => item.role === 'user' ? { ...item, content: normalizeGuideQuery(item.content) } : item);
  const resolvedRequest = resolveConversationRequest(analysisMessage, analysisHistory);
  const intent = inferBayBayIntent(resolvedRequest, '');
  const category = intentToGuideCategory(intent);
  const searchPlan = intent === 'school' ? null : planPostSearch(resolvedRequest, category);
  const providerRequest = intent !== 'school' && isProviderRequest(resolvedRequest);
  const privateSchoolRequest = intent === 'school' && hasPrivateSearchData(message);
  if (searchPlan || providerRequest || privateSchoolRequest) {
    return { ok: true, harnessRoute: 'legacy', answer: '', legacyReason: searchPlan ? 'post_search' : providerRequest ? 'provider_request' : 'private_school' };
  }
  return null;
}
