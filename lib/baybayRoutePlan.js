const { validDate } = require('./planner');

const MAX_ROUTE_CALLS = 3;
const clock = value => typeof value === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value) ? value : null;
const ref = value => typeof value === 'string' ? value : value?.id;
const rawId = stop => {
  const value = stop?.entityId || stop?.id;
  if (typeof value !== 'string') return null;
  const id = value.replace(/^(?:event|place):/, '');
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,159}$/.test(id) && id !== 'origin' ? id : null;
};
const precise = stop => stop?.location?.precision === 'venue'
  && Number.isFinite(stop.location.lat) && stop.location.lat >= 36 && stop.location.lat <= 40
  && Number.isFinite(stop.location.lng) && stop.location.lng >= -124 && stop.location.lng <= -120;
const duration = value => Number.isInteger(value) && value >= 0 && value <= 720;
// The plan engine has already checked these legs against date, departure time,
// mode and freshness. A model's claims or an unaccepted tool result are not legs.
const hasLeg = (plan, from, to) => Array.isArray(plan?.travelLegs) && plan.travelLegs.some(leg =>
  ref(leg?.from) === from && ref(leg?.to) === to && leg.status === 'estimate' && duration(leg.durationMinutes));

/** Complete missing legs without choosing stops or inventing a departure time.
 * The caller guards site-only mode and owns tool quota, cancellation and route
 * evidence accumulation. makePlan must rebuild from that accumulated evidence.
 * deadline is an absolute wall-clock cutoff, including any caller's reserve.
 */
async function enrichPlanRoutes({ plan, makePlan, route, state = {}, deadline } = {}) {
  if (!Array.isArray(plan?.stops) || !plan.stops.length || plan.stops.length > 12
    || typeof makePlan !== 'function' || typeof route !== 'function'
    || !Number.isFinite(deadline) || Date.now() >= deadline
    || !validDate(state.date) || !['drive', 'transit', 'walk'].includes(state.travelMode)) return plan;
  const selectedIds = plan.stops.map(rawId);
  if (selectedIds.some(id => !id) || new Set(selectedIds).size !== selectedIds.length) return plan;
  let current = plan, calls = 0;
  const stopped = Symbol('deadline-or-tool-failure');
  const withinDeadline = async work => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return stopped;
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(work).catch(() => stopped),
        new Promise(resolve => { timer = setTimeout(() => resolve(stopped), Math.min(remaining, 2 ** 31 - 1)); }),
      ]);
    } finally { clearTimeout(timer); }
  };
  const sameSelection = next => Array.isArray(next?.stops) && next.stops.length === selectedIds.length
    && next.stops.every((stop, index) => rawId(stop) === selectedIds[index]);
  const fill = async (fromId, toId, time) => {
    if (hasLeg(current, fromId, toId)) return true;
    if (!time || calls >= MAX_ROUTE_CALLS || Date.now() >= deadline) return false;
    calls += 1;
    const result = await withinDeadline(() => route({ fromId, toId, time }));
    if (result === stopped || !result?.ok || result.error || ref(result.from) !== fromId || ref(result.to) !== toId || !duration(result.durationMinutes)) return false;
    const rebuilt = await withinDeadline(() => makePlan([...selectedIds]));
    if (rebuilt === stopped || !sameSelection(rebuilt)) return false;
    current = rebuilt;
    // A successful Maps call may still be rejected by the plan's time/mode
    // checks. Do not advance on an estimate the rebuilt plan did not accept.
    return hasLeg(current, fromId, toId);
  };
  const preciseOrigin = typeof state.originCandidateId === 'string' && !!state.originCandidateId.trim();
  for (let index = 0; index < selectedIds.length; index += 1) {
    const stop = current.stops[index];
    if (index === 0 && !preciseOrigin) continue;
    const previous = index ? current.stops[index - 1] : null;
    if (!precise(stop) || previous && !precise(previous)) return current;
    const departure = clock(index ? previous.endTime : state.startTime);
    if (!departure || !await fill(index ? selectedIds[index - 1] : 'origin', selectedIds[index], departure)) return current;
  }
  const last = current.stops[selectedIds.length - 1];
  if (preciseOrigin && precise(last) && clock(last.endTime)) await fill(selectedIds[selectedIds.length - 1], 'origin', clock(last.endTime));
  return current;
}

module.exports = { enrichPlanRoutes };
