// G76 / ENGSEC-10 (API-SEC): phone verification sends SMS to United States numbers only.
//
// +1 is the North American Numbering Plan, which also covers Canada, 16 Caribbean countries
// and Bermuda; SMS to some of them costs many times a US message and is a known "SMS
// pumping" target. BAYLINK serves Bay Area families, its copy already asks for a 美国手机号,
// and nothing in the product serves Canadian or Caribbean members, so those area codes are
// refused, together with codes that are not a place (toll-free, premium, personal-service).
// US territories (Puerto Rico 787/939, US Virgin Islands 340, Guam 671, Northern Mariana
// Islands 670, American Samoa 684) are the United States and stay accepted.
//
// A refusal list, not an allow list: a new US overlay code (they appear every year) keeps
// working without a code change. A new Canadian or Caribbean code would pass until it is
// added here, so the Twilio geo permissions (United States only) stay the provider-side
// backstop (owner checklist). Source: NANPA area-code assignments (nationalnanpa.com),
// as known in 2026-10; Canadian codes from the CNA list (cnac.ca).
const CANADA = Object.freeze([
  204, 226, 236, 249, 250, 257, 263, 289, 306, 343, 354, 365, 367, 368, 382, 403, 416, 418, 428, 431,
  437, 438, 450, 468, 474, 506, 514, 519, 548, 579, 581, 584, 587, 604, 613, 639, 647, 672, 683, 705,
  709, 742, 753, 778, 780, 782, 807, 819, 825, 867, 873, 879, 902, 905, 942,
]);
// Non-US Caribbean and Atlantic NANP members.
const CARIBBEAN = Object.freeze([
  242, // Bahamas
  246, // Barbados
  264, // Anguilla
  268, // Antigua and Barbuda
  284, // British Virgin Islands
  345, // Cayman Islands
  441, // Bermuda
  473, // Grenada
  649, // Turks and Caicos
  658, 876, // Jamaica
  664, // Montserrat
  721, // Sint Maarten
  758, // Saint Lucia
  767, // Dominica
  784, // Saint Vincent and the Grenadines
  809, 829, 849, // Dominican Republic
  868, // Trinidad and Tobago
  869, // Saint Kitts and Nevis
]);
// Non-geographic codes that are not an "easily recognizable code" (those are caught by rule):
// personal communications services (5XX), inbound international (456), US government (710).
const NON_GEOGRAPHIC = Object.freeze([
  456, 521, 523, 524, 525, 526, 527, 528, 529, 532, 535, 538, 542, 543, 545, 546, 547, 549, 550, 552,
  553, 554, 556, 569, 578, 589, 710,
]);
const REFUSED = new Map([...CANADA.map(code => [code, 'non-us']), ...CARIBBEAN.map(code => [code, 'non-us']), ...NON_GEOGRAPHIC.map(code => [code, 'non-geographic'])]);

/**
 * Why an E.164 number (+1NXXNXXXXXX) is not a US mobile/landline we text, or null when it is.
 * 'format': not a valid NANP number; 'non-us': Canada / non-US Caribbean / Bermuda;
 * 'non-geographic': toll-free, premium, personal-service and other non-place codes.
 */
function usPhoneProblem(e164) {
  const match = /^\+1([2-9])(\d)(\d)([2-9]\d{2})\d{4}$/.exec(String(e164 ?? ''));
  if (!match) return 'format';
  const [, first, second, third, exchange] = match;
  const area = Number(`${first}${second}${third}`);
  // N11 exchanges (211, 911, ...) are service codes, never a subscriber line.
  if (/^[2-9]11$/.test(exchange)) return 'format';
  // N11 area codes are service codes; X9X and 37X/96X are reserved for expansion.
  if (second === '1' && third === '1') return 'format';
  if (second === '9' || /^(?:37|96)$/.test(`${first}${second}`)) return 'format';
  // "Easily recognizable codes" (N00, N22 ... N99): toll-free 8XX, premium 900, 500/533/544 ...
  if (second === third) return 'non-geographic';
  return REFUSED.get(area) || null;
}

module.exports = { usPhoneProblem, CANADA, CARIBBEAN, NON_GEOGRAPHIC };
