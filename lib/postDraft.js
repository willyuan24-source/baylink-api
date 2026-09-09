function sanitizeAiDescription(description, title) {
  let desc = String(description || '').trim();
  const titleText = String(title || '').trim();
  // A sentence copied from the user's request can contain the only price/date/location.
  // Remove a repeated heading only when a separate body remains; never delete the user's facts.
  if (titleText && desc.startsWith(`${titleText}\n`)) desc = desc.slice(titleText.length).trim();
  return desc.replace(/\n{3,}/g, '\n\n');
}
module.exports = { sanitizeAiDescription };
