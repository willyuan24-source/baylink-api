// Locale-free route templates the web reports with product events, feedback and
// error beacons. Only these strings are ever stored. Anything else, including a
// full URL, a query string or an unknown path, is stored as 'other', so a raw
// path, content id or query can never reach a metrics or feedback row.
//
// Keep in step with the web route table (src/app/route-table.ts). Adding a
// template is additive; old rows keep their values.
const ROUTE_TEMPLATES = Object.freeze([
  '/', '/events', '/events/:id', '/calendar', '/this-week', '/this-month',
  '/offers/:id', '/openings/:id', '/guides', '/guides/:slug', '/category/:slug',
  '/plan', '/my-week', '/me', '/me/bookings', '/messages', '/messages/:id',
  '/together', '/posts/:id', '/users/:id', '/explore', '/tools', '/about', '/archive',
  '/opus-bay', '/ai-in-the-bay', '/privacy', '/terms', '/sms-consent',
  // Account e-mail links. Their tokens travel in the query string, which is always dropped.
  '/reset-password', '/verify-email', '/notifications/unsubscribe',
  // Old entry points that only redirect (/play to /opus-bay, /recommend to /events), so old links stay visible.
  '/play', '/recommend',
  '/not-found', 'other',
]);
const MAX_ROUTE_INPUT = 300;
// /en/... and /zh-Hant/... carry the locale in the path; the template does not.
const LOCALE_PREFIX = /^\/(?:en|zh-Hant|zh-Hans)(?=\/|$)/;
// A concrete id or slug, or a template parameter such as ":categorySlug".
const PARAM_SEGMENT = /^(?::[A-Za-z][A-Za-z0-9]{0,40}|[A-Za-z0-9._~%-]{1,160})$/;
const PATTERNS = ROUTE_TEMPLATES.filter(template => template !== 'other')
  .map(template => ({ template, segments: template === '/' ? [] : template.slice(1).split('/') }));

/**
 * The allowlisted template for a route string, or 'other'. Accepts a template
 * ("/guides/:slug", any parameter name) or a concrete path ("/en/guides/dmv?x=1").
 * Returns null only when the value is not a string, which callers reject.
 */
function routeTemplate(value) {
  if (typeof value !== 'string') return null;
  if (value === 'other') return 'other';
  if (!value || value.length > MAX_ROUTE_INPUT || value[0] !== '/' || value.startsWith('//') || value.includes('\\')) return 'other';
  let path = value.split(/[?#]/, 1)[0].replace(LOCALE_PREFIX, '') || '/';
  if (path.length > 1) path = path.replace(/\/+$/, '') || '/';
  const segments = path === '/' ? [] : path.slice(1).split('/');
  const found = PATTERNS.find(pattern => pattern.segments.length === segments.length
    && pattern.segments.every((segment, index) => segment.startsWith(':') ? PARAM_SEGMENT.test(segments[index]) : segment === segments[index]));
  return found ? found.template : 'other';
}

module.exports = { ROUTE_TEMPLATES, routeTemplate };
