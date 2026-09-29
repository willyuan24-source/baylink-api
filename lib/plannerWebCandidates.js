const crypto = require('node:crypto');

const FIELD_LIMITS = { name: 160, city: 80, summary: 400, timeSummary: 300, priceSummary: 300 };
const CANDIDATE_PROTOCOL = 'Return only the required JSON object {answer,candidates}, not prose or a fenced block. Both keys are mandatory. Keep answer to at most two short sentences with real inline search citations. Prefer only 2 concise records for real named public places relevant to the query; never exceed 5. Each candidate has exactly name, city, summary, timeSummary, priceSummary. Name is a string; every other field is a string or null. Keep each summary to one short clause. Every non-null string must contain its own real inline search citation inside that JSON string, citing the source supporting that field. Write null for a fact not established by the search; omit a place if its identity has no citation. Do not write invented citation numbers or copy citations from another place. Use no address, coordinates, structured hours, source URL fields, numeric price fields or opening guarantees. timeSummary may describe explicitly qualified regular weekly hours, not assume the requested date is confirmed. priceSummary must distinguish admission from food, shopping or other consumption. These summaries are paraphrases of cited information, not source excerpts. If there are no supported named places, candidates must be an empty array.';
const CANDIDATE_FORMAT = { type: 'json_schema', name: 'baylink_web_candidates', strict: true, schema: {
  type: 'object', additionalProperties: false, required: ['answer', 'candidates'], properties: {
    answer: { type: 'string', description: 'At most two short sentences, with real inline web citations.' },
    candidates: { type: 'array', maxItems: 5, items: { type: 'object', additionalProperties: false,
      required: Object.keys(FIELD_LIMITS), properties: Object.fromEntries(Object.keys(FIELD_LIMITS).map(key => [key, {
        type: key === 'name' ? 'string' : ['string', 'null'], description: `${key}: a short fact with its own real inline web citation${key === 'name' ? '' : ', or null if unconfirmed'}.`,
      }])) } },
  },
} };

// Only this explicit protocol produces cards. Ordinary prose is never scanned for
// venue names, prices or hours. Markers are unpredictable tokens inserted by the
// server at actual validated citation spans, not model-written reference numbers.
function extractCandidateProtocol(text, citationMarkers) {
  if (text.trimStart().startsWith('{')) {
    let structured;
    try { structured = JSON.parse(text); } catch { return { answer: '', candidates: [] }; }
    if (!structured || typeof structured.answer !== 'string' || !Array.isArray(structured.candidates)
      || Object.keys(structured).some(key => !['answer', 'candidates'].includes(key))) return { answer: '', candidates: [] };
    return { answer: structured.answer, candidates: validateCandidates(structured.candidates, citationMarkers) };
  }
  // Retain compatibility with already generated explicit V1 blocks; new requests
  // use the required JSON schema, so cards are no longer an optional prose suffix.
  const start = /^BAYLINK_CANDIDATES_V1[ \t]*\r?$/m.exec(text);
  if (!start) return { answer: text };
  const bodyStart = start.index + start[0].length;
  const remainder = text.slice(bodyStart);
  const end = /^END_BAYLINK_CANDIDATES_V1[ \t]*\r?$/m.exec(remainder);
  const answer = text.slice(0, start.index) + (end ? remainder.slice(end.index + end[0].length) : '');
  if (!end) return { answer, candidates: [] };
  let rows;
  try { rows = JSON.parse(remainder.slice(0, end.index).trim()); } catch { return { answer, candidates: [] }; }
  if (!Array.isArray(rows)) return { answer, candidates: [] };
  return { answer, candidates: validateCandidates(rows, citationMarkers) };
}

function validateCandidates(rows, citationMarkers) {
  const candidates = []; const seen = new Set();
  for (const row of rows.slice(0, 20)) {
    if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).some(key => !Object.hasOwn(FIELD_LIMITS, key))) continue;
    const fields = {}; const urls = new Set(); let identityUrls = [];
    for (const [key, limit] of Object.entries(FIELD_LIMITS)) {
      const value = row[key]; let clean = typeof value === 'string' ? value : '';
      const fieldUrls = [];
      for (const [marker, source] of citationMarkers) {
        if (!clean.includes(marker)) continue;
        fieldUrls.push(source.url); clean = clean.split(marker).join('');
      }
      clean = clean.replace(/[^]*/g, '').replace(/\[\d+\]/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
        .replace(/https?:\/\/[^\s<>]+/g, '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
      fields[key] = fieldUrls.length && clean && clean.length <= limit ? clean : null;
      if (fields[key] !== null) {
        fieldUrls.forEach(url => urls.add(url));
        if (key === 'name') identityUrls = [...new Set(fieldUrls)].sort();
      }
    }
    if (!fields.name) continue;
    const identity = JSON.stringify([fields.name.normalize('NFKC').toLowerCase(), fields.city?.normalize('NFKC').toLowerCase() || null, identityUrls]);
    const id = `web-${crypto.createHash('sha256').update(identity).digest('hex').slice(0, 24)}`;
    if (seen.has(id)) continue;
    seen.add(id); candidates.push({ id, ...fields, sourceUrls: [...urls] });
    if (candidates.length === 5) break;
  }
  return candidates;
}

module.exports = { CANDIDATE_PROTOCOL, CANDIDATE_FORMAT, extractCandidateProtocol };
