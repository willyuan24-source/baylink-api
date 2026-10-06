/** Bounded fixed windows. Active counters are never evicted to make room. */
function createRateLimiter({ now = Date.now, capacity = 20000 } = {}) {
  const entries = new Map();
  let nextSweep = 0;
  function check(key, { windowMs = 900000, maxRequests = 5 } = {}) {
    const time = now();
    if (time >= nextSweep || entries.size >= capacity) {
      for (const [id, row] of entries) if (row.expiresAt <= time) entries.delete(id);
      nextSweep = time + 60000;
    }
    const id = `${windowMs}:${String(key).slice(0, 512)}`;
    let row = entries.get(id);
    if (!row || row.expiresAt <= time) {
      if (!row && entries.size >= capacity) return false;
      row = { count: 0, expiresAt: time + windowMs };
      entries.set(id, row);
    }
    row.count = Math.min(row.count + 1, maxRequests + 1);
    return row.count <= maxRequests;
  }
  return { check, size: () => entries.size };
}

function proxyTrust(config = {}, isTest = false) {
  // Render's edge appends the connecting peer. Trust one hop by default;
  // additional proxies must be configured explicitly as CIDRs, never trust all.
  const value = config.TRUSTED_PROXY_CIDRS;
  if (value) return String(value).split(',').map(value => value.trim()).filter(Boolean);
  if (config.TRUST_PROXY_HOPS !== undefined) {
    const hops = Number(config.TRUST_PROXY_HOPS);
    if (!Number.isInteger(hops) || hops < 0 || hops > 5) throw new Error('TRUST_PROXY_HOPS must be an integer from 0 to 5');
    return hops || false;
  }
  return isTest ? false : 1;
}

const clientIp = req => req.ip || req.socket?.remoteAddress || 'unknown';
module.exports = { createRateLimiter, proxyTrust, clientIp };
