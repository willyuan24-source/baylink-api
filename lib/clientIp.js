const crypto = require('node:crypto');
const net = require('node:net');
const { createRateLimiter, clientIp } = require('./rateLimit');

// Rate-limit and quota key for the visitor. The default (CLIENT_IP_SOURCE unset,
// empty or "cloudflare") shadows req.ip with a KEY, not a raw address: IPv4
// as-is, IPv6 collapsed to its /64. Code that needs a real address must not
// read req.ip. Client-supplied headers are honoured only when the edge is a
// published Cloudflare address: the trusted hop Express resolved or, when that
// hop is a hosting-internal address (Render's own proxies), the first
// non-internal X-Forwarded-For entry left of it. Any other path keys on the
// Express hop itself, so a stale range list fails closed. CLIENT_IP_SOURCE=off
// (or "express") is the rollback: Express req.ip exactly as computed from the
// trust-proxy contract, with the middleware a strict pass-through.

// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6,
// fetched 2026-10-08 UTC. CLOUDFLARE_IP_CIDRS replaces this list when set.
const CLOUDFLARE_IP_RANGES_FETCHED = '2026-10-08';
const CLOUDFLARE_IP_CIDRS = Object.freeze([
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32',
]);
const DIAGNOSTIC_MAX_WINDOW_MS = 2 * 60 * 60 * 1000;
const DIAGNOSTIC_LINES_PER_HOUR = 600;
// Unprobed requests (e.g. platform health checks) are sampled into a small
// share of the hourly budget so they cannot crowd out an engineer's probes.
const DIAGNOSTIC_SAMPLE_EVERY = 20;
const DIAGNOSTIC_SAMPLED_LINES_PER_HOUR = 60;
const DIAGNOSTIC_LOGGED_PATHS = new Set(['/api/health', '/api/ai/usage']);
const DIAGNOSTIC_XFF_ENTRIES = 8;
const PROBE = /^[a-z0-9]{8,24}$/;

/** One textual IP address (no list, zone or whitespace), IPv4-mapped IPv6 unwrapped. */
function parseIp(value) {
  if (typeof value !== 'string' || value.length > 45 || value.includes('%')) return null;
  const family = net.isIP(value);
  if (family === 4) return { family, address: value };
  if (family !== 6) return null;
  let text = value.toLowerCase();
  const dotted = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(2).map(Number);
    text = `${dotted[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const words = [...left, ...Array(tail === undefined ? 0 : 8 - left.length - right.length).fill('0'), ...right].map(word => parseInt(word, 16));
  if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
    return { family: 4, address: [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.') };
  }
  return { family, address: words.map(word => word.toString(16)).join(':'), words };
}

/** IPv4 as-is; IPv6 as its /64. Null for anything that is not one IP. */
function clientKey(value) {
  const ip = parseIp(value);
  if (!ip) return null;
  return ip.family === 4 ? ip.address : `${ip.words.slice(0, 4).map(word => word.toString(16)).join(':')}::/64`;
}

/** IPv4 /24 or IPv6 /48: the most a diagnostic may reveal about an address. */
function addressPrefix(value) {
  const ip = parseIp(value);
  if (!ip) return null;
  return ip.family === 4 ? `${ip.address.split('.').slice(0, 3).join('.')}.0/24` : `${ip.words.slice(0, 3).map(word => word.toString(16)).join(':')}::/48`;
}

function blockList(cidrs, label) {
  const list = new net.BlockList();
  for (const cidr of cidrs) {
    const [address, bits, extra] = cidr.split('/');
    const family = net.isIP(address);
    const prefix = Number(bits);
    if (!family || extra !== undefined || !/^\d{1,3}$/.test(bits || '') || prefix > (family === 4 ? 32 : 128)) throw new Error(`${label} contains an invalid CIDR`);
    list.addSubnet(address, prefix, `ipv${family}`);
  }
  return list;
}

function cloudflareRanges(value) {
  const override = String(value ?? '').split(/[\s,]+/).filter(Boolean);
  return blockList(override.length ? override : CLOUDFLARE_IP_CIDRS, 'CLOUDFLARE_IP_CIDRS');
}

const contains = (list, value) => {
  const ip = parseIp(value);
  return !!ip && list.check(ip.address, `ipv${ip.family}`);
};

const CLIENT_IP_SOURCES = Object.freeze({ '': 'cloudflare', cloudflare: 'cloudflare', off: null, express: null });

/** 'cloudflare' (the default) or null (off: Express req.ip untouched). Anything else stops startup. */
function clientIpSource(config = {}) {
  const value = String(config.CLIENT_IP_SOURCE ?? '').trim().toLowerCase();
  if (!Object.hasOwn(CLIENT_IP_SOURCES, value)) throw new Error('CLIENT_IP_SOURCE must be empty, "cloudflare", "off" or "express"');
  return CLIENT_IP_SOURCES[value];
}

/** X-Forwarded-For entries, left to right, split exactly like Express (spaces trimmed, empty entries skipped). */
function forwardedFor(req) {
  const header = req.headers?.['x-forwarded-for'];
  return typeof header === 'string' ? header.split(',').map(entry => entry.replace(/^ +| +$/g, '')).filter(Boolean) : [];
}

const RESERVED_CLASSES = [
  ['loopback', blockList(['127.0.0.0/8', '::1/128'], 'reserved')],
  ['private', blockList(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'], 'reserved')],
  ['cgnat', blockList(['100.64.0.0/10'], 'reserved')],
  ['link-local', blockList(['169.254.0.0/16', 'fe80::/10'], 'reserved')],
  ['pseudo-ipv4', blockList(['240.0.0.0/4'], 'reserved')],
];
// Addresses no connection arriving over the Internet can come from. Cloudflare
// pseudo-IPv4 (240.0.0.0/4) is deliberately not one: it stands in for an IPv6
// visitor, so it is a client key, never a proxy hop.
const INTERNAL_CLASSES = new Set(['loopback', 'private', 'cgnat', 'link-local']);

const reservedClass = ip => RESERVED_CLASSES.find(([, list]) => list.check(ip.address, `ipv${ip.family}`))?.[0] ?? null;

/** Loopback, private (incl. fc00::/7), CGNAT or link-local; IPv4-mapped forms count as IPv4. */
function internalHop(value) {
  const ip = parseIp(value);
  return !!ip && INTERNAL_CLASSES.has(reservedClass(ip));
}

/** Where Express took req.ip from: "xff[-n]" for the nth trusted entry from the right, else "socket". */
function expressHopFrom(req) {
  const trusted = Array.isArray(req.ips) ? req.ips.length : 0;
  return trusted ? `xff[-${trusted}]` : 'socket';
}

/**
 * The X-Forwarded-For entries and the index of the hop Express resolved as
 * req.ip (entries.length when it is the socket), or null when the chain does
 * not line up with Express's own computation.
 */
function expressHop(req, base) {
  const entries = forwardedFor(req);
  const trusted = Array.isArray(req.ips) ? req.ips.length : 0;
  const index = entries.length - trusted;
  return (trusted ? entries[index] : req.socket?.remoteAddress) === base ? { entries, index } : null;
}

/*
 * The edge behind Render's internal hops. Production (2026-10-08 diagnostics):
 * X-Forwarded-For = [visitor, Cloudflare edge, Render-internal 10.x hop] over a
 * loopback socket, so with TRUST_PROXY_HOPS=1 req.ip is the rotating 10.x hop.
 *
 * Why this walk is safe: each proxy appends the address that connected to it.
 * Cloudflare appends the visitor, Render's load balancer appends the Cloudflare
 * edge, and Render's internal proxies append their internal peers. So every
 * entry right of the Cloudflare-appended visitor was written by Cloudflare or
 * Render infrastructure, and anything a client sends in X-Forwarded-For only
 * ever appears further left. No connection arriving over the Internet can come
 * from an internal address, so a run of internal entries next to the Express
 * hop was appended inside Render's network, and the first non-internal entry is
 * whoever connected to Render from outside. The walk stops there and never
 * steps past a non-internal entry. That edge must then pass the same published
 * Cloudflare gate as an edge Express resolved directly. A request that reaches
 * Render without Cloudflare puts the caller's own public address in that slot,
 * which is not a Cloudflare address, so it fails closed to the Express hop key
 * and forged entries further left (Cloudflare addresses included) are never
 * read. The walk only starts from an X-Forwarded-For entry Express trusted:
 * with trust disabled the socket peer is not known to be a proxy, so its
 * header proves nothing.
 */
function edgeBehindInternalHops(chain) {
  if (!chain || chain.index >= chain.entries.length) return null;
  let index = chain.index - 1;
  while (index >= 0 && internalHop(chain.entries[index])) index--;
  return index < 0 ? null : { address: chain.entries[index], index, from: `xff[-${chain.entries.length - index}]` };
}

const singleHeaderIp = value => parseIp(value) ? value : null;

/**
 * Resolve the counting key. base is Express req.ip under the configured trust
 * setting. Returns { key, from, address } (off), plus edgeFrom in cloudflare
 * mode: from names the source used, address is the value the key was derived
 * from, and edgeFrom is where the hop checked against the Cloudflare ranges
 * came from ("xff[-n]" or "socket"; null when no edge could be identified).
 */
function resolveClientIp(req, { source = null, cloudflare = cloudflareRanges() } = {}, base = clientIp(req)) {
  if (source !== 'cloudflare') return { key: base, from: 'express', address: base };
  const chain = expressHop(req, base);
  // The Express hop is gated first, exactly as before; only an internal hop that fails the gate is walked past.
  const edge = contains(cloudflare, base) || !internalHop(base) ? { address: base, index: chain ? chain.index : null, from: expressHopFrom(req) } : edgeBehindInternalHops(chain);
  if (!edge || !contains(cloudflare, edge.address)) return { key: clientKey(base) ?? base, from: 'edge-not-cloudflare', address: base, edgeFrom: edge ? edge.from : null };
  const header = singleHeaderIp(req.headers?.['cf-connecting-ip']);
  if (header) return { key: clientKey(header), from: 'cf-connecting-ip', address: header, edgeFrom: edge.from };
  // The entry Cloudflare appended immediately left of the edge, never further left.
  const left = edge.index === null ? null : singleHeaderIp(chain.entries[edge.index - 1]);
  if (left) return { key: clientKey(left), from: 'xff-left-of-edge', address: left, edgeFrom: edge.from };
  return { key: clientKey(edge.address) ?? edge.address, from: 'edge-without-client', address: edge.address, edgeFrom: edge.from };
}

function describeAddress(value, cloudflare) {
  const ip = parseIp(value);
  if (!ip) return { class: value === undefined || value === null ? 'absent' : 'invalid' };
  const kind = reservedClass(ip) ?? (cloudflare.check(ip.address, `ipv${ip.family}`) ? 'cloudflare' : 'public');
  return { class: kind, family: ip.family, prefix: addressPrefix(value) };
}

const sameIp = (left, right) => !!left && !!right && parseIp(left)?.address === parseIp(right)?.address;

/** Classified proxy chain for one request. Never contains a full address. */
function describeRequest(req, base, settings) {
  const entries = forwardedFor(req);
  const rightToLeft = entries.slice().reverse();
  const cfHeader = req.headers?.['cf-connecting-ip'];
  const cfIp = singleHeaderIp(cfHeader);
  const cfIndex = cfIp ? rightToLeft.findIndex(entry => sameIp(entry, cfIp)) : -1;
  const cloudflareKey = resolveClientIp(req, { source: 'cloudflare', cloudflare: settings.cloudflare }, base);
  const present = name => req.headers?.[name] !== undefined;
  return {
    mode: settings.source || 'express',
    socket: describeAddress(req.socket?.remoteAddress, settings.cloudflare),
    xffLength: entries.length,
    // Index 0 is the rightmost entry (XFF[-1], appended by the nearest proxy).
    xffRightToLeft: rightToLeft.slice(0, DIAGNOSTIC_XFF_ENTRIES).map(entry => describeAddress(entry, settings.cloudflare)),
    reqIpFrom: expressHopFrom(req),
    reqIp: describeAddress(base, settings.cloudflare),
    headers: Object.fromEntries(['cf-connecting-ip', 'true-client-ip', 'x-real-ip', 'cf-connecting-ipv6', 'cf-pseudo-ipv4', 'forwarded'].map(name => [name, present(name)])),
    cfConnectingIp: cfHeader === undefined ? null : { ...describeAddress(cfHeader, settings.cloudflare), xffMatch: cfIndex >= 0 ? `xff[-${cfIndex + 1}]` : null },
    cfConnectingIpEqualsXffMinus2: sameIp(cfIp, rightToLeft[1]),
    cfColo: /-([A-Z]{3})$/.exec(String(req.headers?.['cf-ray'] || ''))?.[1] || null,
    // edgeFrom: the hop the Cloudflare gate was applied to ("xff[-2]" behind one Render-internal hop).
    cloudflareMode: { keyFrom: cloudflareKey.from, edgeFrom: cloudflareKey.edgeFrom, keyPrefix: addressPrefix(cloudflareKey.address) },
  };
}

function diagnosticWindow(value, startedAt) {
  if (value === undefined || value === null || value === '') return { end: null, reason: null };
  const day = typeof value === 'string' && /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?Z$/.exec(value)?.[1];
  const end = day ? Date.parse(value) : NaN;
  if (!Number.isFinite(end) || new Date(end).toISOString().slice(0, 10) !== day) return { end: null, reason: 'malformed' };
  if (end <= startedAt) return { end: null, reason: 'past' };
  if (end > startedAt + DIAGNOSTIC_MAX_WINDOW_MS) return { end: null, reason: 'more-than-2h-after-start' };
  return { end, reason: null };
}

// Owner-approved (10-08): the owner cannot edit Render env vars this week, so a
// Render boot before this date opens a 90-minute window by itself. After the
// date this default is inert and only CLIENT_IP_DIAGNOSTIC_UNTIL opens one.
const RENDER_DEFAULT_DIAGNOSTIC_BEFORE = Date.parse('2026-10-09T23:00:00Z');
const RENDER_DEFAULT_DIAGNOSTIC_MS = 90 * 60 * 1000;

function renderDefaultDiagnosticUntil(config, startedAt) {
  if (String(config.RENDER ?? '').toLowerCase() !== 'true' || startedAt >= RENDER_DEFAULT_DIAGNOSTIC_BEFORE) return undefined;
  return new Date(Math.min(startedAt + RENDER_DEFAULT_DIAGNOSTIC_MS, RENDER_DEFAULT_DIAGNOSTIC_BEFORE)).toISOString();
}

/**
 * Express wiring. middleware is a strict pass-through while CLIENT_IP_SOURCE
 * is off and no diagnostic window is active. diagnosticRoute answers only
 * inside CLIENT_IP_DIAGNOSTIC_UNTIL (or the Render boot default above) and
 * otherwise falls through to a 404.
 */
function createClientIp(config = {}, { now = Date.now, log = console.log } = {}) {
  const settings = { source: clientIpSource(config), cloudflare: cloudflareRanges(config.CLOUDFLARE_IP_CIDRS) };
  const startedAt = now();
  const diagnostic = diagnosticWindow(config.CLIENT_IP_DIAGNOSTIC_UNTIL || renderDefaultDiagnosticUntil(config, startedAt), startedAt);
  if (diagnostic.end) log(`[client-ip-diag] window open until ${new Date(diagnostic.end).toISOString()}; mode ${settings.source || 'express'}`);
  else if (diagnostic.reason) log(`[client-ip-diag] CLIENT_IP_DIAGNOSTIC_UNTIL ignored: ${diagnostic.reason}`);
  const diagnosing = () => diagnostic.end !== null && now() < diagnostic.end;
  const expressIps = new WeakMap();
  const budget = { hour: null, lines: 0, sampled: 0, unprobed: 0 };
  const diagnosticLimiter = createRateLimiter({ now, capacity: 1000 });
  const secret = String(config.JWT_SECRET || '');
  const fingerprint = key => crypto.createHmac('sha256', secret).update(`client-ip-diag:${key}`).digest('hex').slice(0, 12);

  function observe(req, base) {
    if (req.method !== 'GET' || !DIAGNOSTIC_LOGGED_PATHS.has(req.path)) return;
    const probe = typeof req.query?.probe === 'string' && PROBE.test(req.query.probe) ? req.query.probe : null;
    const hour = Math.floor(now() / 3600000);
    if (budget.hour !== hour) Object.assign(budget, { hour, lines: 0, sampled: 0 });
    if (budget.lines >= DIAGNOSTIC_LINES_PER_HOUR) return;
    if (!probe) {
      if (budget.unprobed++ % DIAGNOSTIC_SAMPLE_EVERY !== 0 || budget.sampled >= DIAGNOSTIC_SAMPLED_LINES_PER_HOUR) return;
      budget.sampled++;
    }
    budget.lines++;
    log(`[client-ip-diag] ${JSON.stringify({ path: req.path, probe, ...describeRequest(req, base, settings) })}`);
  }

  function middleware(req, _res, next) {
    if (!settings.source && !diagnosing()) return next();
    const base = clientIp(req);
    if (diagnosing()) observe(req, base);
    if (settings.source) {
      expressIps.set(req, base);
      Object.defineProperty(req, 'ip', { value: resolveClientIp(req, settings, base).key, configurable: true, enumerable: true, writable: true });
    }
    return next();
  }

  function diagnosticRoute(req, res, next) {
    if (!diagnosing()) return next();
    res.set('Cache-Control', 'no-store');
    const current = clientIp(req);
    if (!diagnosticLimiter.check(`key:${current}`, { windowMs: 60000, maxRequests: 30 }) || !diagnosticLimiter.check('all', { windowMs: 60000, maxRequests: 300 })) {
      res.set('Retry-After', '60');
      return res.status(429).json({ code: 'CLIENT_IP_DIAG_RATE_LIMIT', error: 'Too many diagnostic reads. Wait a minute.' });
    }
    const base = expressIps.get(req) ?? current;
    const cloudflareKey = resolveClientIp(req, { source: 'cloudflare', cloudflare: settings.cloudflare }, base).key;
    return res.json({ ...describeRequest(req, base, settings), fingerprints: { current: fingerprint(current), cloudflare: fingerprint(cloudflareKey) },
      cloudflareRanges: String(config.CLOUDFLARE_IP_CIDRS ?? '').trim() ? 'override' : CLOUDFLARE_IP_RANGES_FETCHED, until: new Date(diagnostic.end).toISOString() });
  }

  return { middleware, diagnosticRoute };
}

module.exports = { CLOUDFLARE_IP_CIDRS, CLOUDFLARE_IP_RANGES_FETCHED, parseIp, clientKey, addressPrefix, cloudflareRanges, clientIpSource, forwardedFor, resolveClientIp, describeRequest, diagnosticWindow, createClientIp };
