/** Bounded fixed windows. Active counters are never evicted to make room. */
function createRateLimiter({ now = Date.now, capacity = 20000 } = {}) {
  const entries = new Map();
  // One heap entry per admitted fixed window. Rejected requests never add to it.
  // Only the earliest expiry is inspected while all counters are still active.
  const expirations = [];
  const stats = { expiryChecks: 0, heapComparisons: 0, expiredEntries: 0 };
  function earlier(left, right) {
    stats.heapComparisons++;
    return left.expiresAt < right.expiresAt;
  }
  function schedule(row) {
    let index = expirations.length;
    expirations.push(row);
    while (index > 0) {
      const parent = (index - 1) >> 1;
      if (!earlier(row, expirations[parent])) break;
      expirations[index] = expirations[parent];
      index = parent;
    }
    expirations[index] = row;
  }
  function removeEarliest() {
    const first = expirations[0];
    const last = expirations.pop();
    if (expirations.length) {
      let index = 0;
      while (index * 2 + 1 < expirations.length) {
        let child = index * 2 + 1;
        if (child + 1 < expirations.length && earlier(expirations[child + 1], expirations[child])) child++;
        if (!earlier(expirations[child], last)) break;
        expirations[index] = expirations[child];
        index = child;
      }
      expirations[index] = last;
    }
    return first;
  }
  function expire(time) {
    while (expirations.length) {
      stats.expiryChecks++;
      if (expirations[0].expiresAt > time) break;
      const row = removeEarliest();
      if (entries.get(row.id) === row) {
        entries.delete(row.id);
        stats.expiredEntries++;
      }
    }
  }
  function check(key, { windowMs = 900000, maxRequests = 5 } = {}) {
    const time = now();
    expire(time);
    const id = `${windowMs}:${String(key).slice(0, 512)}`;
    let row = entries.get(id);
    if (!row) {
      if (entries.size >= capacity) return false;
      row = { id, count: 0, expiresAt: time + windowMs };
      entries.set(id, row);
      schedule(row);
    }
    row.count = Math.min(row.count + 1, maxRequests + 1);
    return row.count <= maxRequests;
  }
  return {
    check,
    size: () => entries.size,
    // Aggregate snapshots for deterministic complexity checks; never return keys.
    diagnostics: () => Object.freeze({ ...stats, expiryQueueSize: expirations.length }),
  };
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
