/** Curated event names, not fuzzy title matching. Mirror changes in frontend named-event-search.ts. */
const waterLanternName = /(?<![a-z0-9])(?:(?:(?:san\s+francisco|sf)\s+)?water\s+lantern\s+festival|(?:san\s+francisco|sf)\s*(?:的\s*)?水[灯燈][节節])(?![a-z0-9])|(?:(?:旧金山|舊金山)\s*(?:的\s*)?)?水[灯燈][节節]/giu;
const excludedVenue = /(?:排除|不要(?:去)?|不去|避开|避開|避免)\s*(?:半岛|半島|foster\s+city)|\b(?:exclude|avoid|not|no|outside)\s+(?:the\s+)?(?:peninsula|foster\s+city)\b/iu;
const negatedName = /(?:不要|不想(?:去|要)?|不去|排除|避开|避開|避免)\s*$|\b(?:no|not|without|avoid|exclude|don['’]t want|do not want)\s*$/iu;

function recognizeNamedEvent(query) {
  let matched = false;
  let blocked = false;
  const constraintText = query.replace(waterLanternName, (name, offset) => {
    matched = true;
    const prefix = query.slice(Math.max(0, offset - 40), offset);
    if (negatedName.test(prefix)) blocked = true;
    // "SF 的水灯节" names the event; "仅限 SF 水灯节" explicitly restricts its location.
    const constrainedCity = /(?:仅限|僅限|只限|仅在|僅在|只在|限于|限於|only in)\s*$/iu.test(prefix)
      ? name.match(/^(?:san\s+francisco|sf|旧金山|舊金山)/iu)?.[0] : undefined;
    if (constrainedCity) return constrainedCity + ' '.repeat(name.length - constrainedCity.length);
    // Only the recognized name is removed. Outside cities, dates, budgets and ages remain.
    return ' '.repeat(name.length);
  });
  return {
    eventIds: matched ? ['foster-city-water-lantern-festival-2026'] : [],
    constraintText,
    blocked: matched && (blocked || excludedVenue.test(constraintText)),
  };
}

module.exports = { recognizeNamedEvent };
