// API-BB-5 (API-SYNC-3c follow-up 3, H38 part): which cities a rail system the asker names actually serves.
// A BART day plan with no city ranked Healdsburg and the Livermore outlets, neither of which has a BART
// station. This is a city-level table, not a nearest-station table: it never states a station, a walk or a
// travel time, it only keeps places the named system cannot reach behind the ones it can.
//
// Sources, read 2026-10-15 (an agent read of the operators' own station lists):
// - BART: https://www.bart.gov/stations lists 50 stations. Each is placed in its city by its own name
//   (Daly City, Colma, South San Francisco, San Bruno, Millbrae, Downtown/North Berkeley and Ashby, El
//   Cerrito del Norte and Plaza, Richmond, Orinda, Lafayette, Walnut Creek, Pleasant Hill/Contra Costa
//   Centre, Concord and North Concord/Martinez, Pittsburg Center and Pittsburg/Bay Point, Antioch, San
//   Leandro and Bay Fair, Castro Valley, Hayward and South Hayward, Union City, Fremont and Warm Springs/
//   South Fremont, Dublin/Pleasanton and West Dublin/Pleasanton, Milpitas, Berryessa/North San Jose), and
//   the San Francisco and Oakland stations by their streets and districts (Embarcadero … Balboa Park; 12th
//   St./Oakland City Center … Coliseum, Oakland International Airport). Livermore has no station.
// - Caltrain: https://www.caltrain.com/stations lists 31 stations (San Francisco, 22nd Street, Bayshore,
//   South San Francisco, San Bruno, Millbrae, Broadway (weekends only), Burlingame, San Mateo, Hayward Park,
//   Hillsdale, Belmont, San Carlos, Redwood City, Menlo Park, Palo Alto, Stanford (football only), California
//   Avenue, San Antonio, Mountain View, Sunnyvale, Lawrence, Santa Clara, College Park, San Jose Diridon,
//   Tamien, Capitol, Blossom Hill, Morgan Hill, San Martin, Gilroy). Tamien and south are marked weekday
//   commute hours only, so Morgan Hill, San Martin and Gilroy count only on a weekday.
const { canonicalCity } = require('./bayAreaSearchScope');

const RAIL_CITIES = Object.freeze({
  bart: ['San Francisco', 'Daly City', 'Colma', 'South San Francisco', 'San Bruno', 'Millbrae', 'Oakland', 'Berkeley', 'El Cerrito', 'Richmond', 'Orinda', 'Lafayette',
    'Walnut Creek', 'Pleasant Hill', 'Concord', 'Pittsburg', 'Antioch', 'San Leandro', 'Castro Valley', 'Hayward', 'Union City', 'Fremont', 'Dublin', 'Pleasanton', 'Milpitas', 'San Jose'],
  caltrain: ['San Francisco', 'Brisbane', 'South San Francisco', 'San Bruno', 'Millbrae', 'Burlingame', 'San Mateo', 'Belmont', 'San Carlos', 'Redwood City', 'Menlo Park',
    'Palo Alto', 'Mountain View', 'Sunnyvale', 'Santa Clara', 'San Jose'],
});
const WEEKDAY_ONLY = Object.freeze({ caltrain: ['Morgan Hill', 'San Martin', 'Gilroy'] });
const SERVED = Object.fromEntries(Object.entries(RAIL_CITIES).map(([system, cities]) => [system, new Set(cities.map(city => canonicalCity(city) || city))]));
const WEEKDAY = Object.fromEntries(Object.entries(WEEKDAY_ONLY).map(([system, cities]) => [system, new Set(cities.map(city => canonicalCity(city) || city))]));

// Riding a named rail system ("坐 BART 去", "take Caltrain"); not "不坐 BART" or "BART or driving?".
const RIDE = {
  bart: /(?<!不|别|別|不要|不想|不能|不用|没法|沒法)(?:坐|搭|乘|改坐|改搭|换坐|換坐)\s*(?:捷运\s*)?BART|\b(?<!not |n't |never )(?:take|taking|ride|riding|by|via|using|on)\s+(?:the\s+)?BART\b/i,
  caltrain: /(?<!不|别|別|不要|不想|不能|不用|没法|沒法)(?:坐|搭|乘|改坐|改搭|换坐|換坐)\s*(?:加州火车|加州火車)?\s*Caltrain|\b(?<!not |n't |never )(?:take|taking|ride|riding|by|via|using|on)\s+(?:the\s+)?Caltrain\b/i,
};
/** The rail systems this message says the party rides (bart, caltrain). */
function railSystemsIn(text) {
  const value = String(text || '').slice(0, 4000);
  return Object.keys(RIDE).filter(system => RIDE[system].test(value));
}
/** The rail systems a task state carries (preferences "rail:bart" / "rail:caltrain"). */
function railOf(state) {
  return (state?.preferences || []).filter(value => /^rail:(?:bart|caltrain)$/.test(value)).map(value => value.slice(5));
}
const weekday = date => typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date) && ![0, 6].includes(new Date(`${date}T12:00:00Z`).getUTCDay());
/** Whether one of `systems` has a station in `city` (on `date`, for weekday-only stations). */
function railServes(city, systems, date) {
  const name = canonicalCity(city) || city;
  return !!name && systems.some(system => SERVED[system]?.has(name) || (weekday(date) && WEEKDAY[system]?.has(name)));
}
/** A sort key for the records of a rail ask with no destination city: 0 = a named system reaches the
 * record's city, 1 = it does not (or the record has no city). null when the ask names no rail system. */
function railFit(state) {
  const systems = railOf(state);
  if (!systems.length || state.city || state.travelMode !== 'transit') return null;
  return row => railServes(row?.city, systems, state.date) ? 0 : 1;
}

module.exports = { RAIL_CITIES, WEEKDAY_ONLY, railSystemsIn, railOf, railServes, railFit };
