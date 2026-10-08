const KINDS = ['guide', 'event', 'place', 'offer', 'opening'];
const REGIONS = ['sf', 'east-bay', 'south-bay', 'peninsula', 'north-bay'];
const TRAVEL = ['any', 'drive', 'transit', 'walk', 'no-car'];
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$/;
const CONTENT_CONTEXT_INSTRUCTION = 'currentPage (and any further contextReferences) are the public items the user is viewing or selected; localMatches are separate site search candidates, not user selections. Both come from the canonical published catalog. Preserve their eligibility, fees, dates and temporalStatus: past/inactive items are reference only, upcoming openings are not yet open, and an offer is not automatically unconditional free admission. A validated event date is a selected published occurrence, never proof of capacity or booking. contextUsed.preferences were explicitly shared for this request; latest user constraints take precedence. Do not infer or claim to read private favorites, saved plans or account preferences. Never claim to have saved, booked or contacted anyone. Catalog sourceUrl and verifiedAt are provenance of published content, not evidence of this reply performing a live check.';
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(`${value}T12:00:00Z`)) && new Date(`${value}T12:00:00Z`).toISOString().startsWith(value);
const invalid = () => Object.assign(new Error('选中内容或偏好格式无效，请重新选择。'), { status: 400 });
function normalizeContentContext(value = {}, locale = 'zh-Hans') {
  if (!plain(value)) throw invalid();
  const notices = []; const references = [];
  if (value.references !== undefined) {
    if (!Array.isArray(value.references) || value.references.length > 3) throw invalid();
    for (const item of value.references) {
      if (!plain(item) || !KINDS.includes(item.kind) || typeof item.id !== 'string' || !ID.test(item.id)) throw invalid();
      const ref = { kind: item.kind, id: item.id };
      if (item.date !== undefined) {
        if (item.kind === 'event' && validDate(item.date)) ref.date = item.date;
        else notices.push(locale === 'en' ? 'An invalid occurrence date was removed; no date was assumed.' : '已移除无效场次日期，没有据此假定可参加日期。');
      }
      if (!references.some(previous => previous.kind === ref.kind && previous.id === ref.id)) references.push(ref);
    }
  }
  let preferences;
  if (value.preferences !== undefined) {
    const p = value.preferences;
    if (!plain(p) || Object.keys(p).some(key => !['regions', 'interests', 'travelMode'].includes(key))
      || (p.regions !== undefined && (!Array.isArray(p.regions) || p.regions.length > 5 || p.regions.some(region => !REGIONS.includes(region))))
      || (p.interests !== undefined && (!Array.isArray(p.interests) || p.interests.length > 12 || p.interests.some(interest => typeof interest !== 'string' || !interest.trim() || interest.length > 40 || /[\u0000-\u001f\u007f]/.test(interest))))
      || (p.travelMode !== undefined && !TRAVEL.includes(p.travelMode))) throw invalid();
    preferences = { regions: [...new Set(p.regions || [])], interests: [...new Set((p.interests || []).map(value => value.trim()))], travelMode: p.travelMode || 'any' };
  }
  return { references, ...(preferences ? { preferences } : {}), notices, explicitReferences: Object.hasOwn(value, 'references') };
}
module.exports = { normalizeContentContext, KINDS, ID, plain, validDate, CONTENT_CONTEXT_INSTRUCTION };
