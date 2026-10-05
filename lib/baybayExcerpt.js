// Fallback references must stay visibly partial without breaking a condition
// halfway through a word or presenting a dangling source-URL label as advice.
function fallbackExcerpt(value, limit = 450) {
  const text = String(value || '').replace(/https?:\/\/[^\s<>]+/g, '').replace(/[^\n]*[：:]\s*(?=\n|$)/g, '').trim();
  if (text.length <= limit) return text;
  const head = text.slice(0, limit);
  const boundaries = [...head.matchAll(/[。！？](?:\s*)|[.!?](?=\s|$)|\n(?=\n)/g)];
  const end = boundaries.length ? boundaries.at(-1).index + boundaries.at(-1)[0].length : head.lastIndexOf('\n');
  // If there is no complete sentence/paragraph, show a neutral pointer rather
  // than a fragment whose omitted ending could reverse its meaning.
  return end > 0 ? `${head.slice(0, end).trim()} …` : '';
}
module.exports = { fallbackExcerpt };
