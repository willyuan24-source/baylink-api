const { assertNoUpdateConflict } = require('./update-conflicts');
const copy = value => value === undefined ? undefined : structuredClone(value);
const get = (row, path) => path.split('.').reduce((value, key) => value?.[key], row);
const set = (row, path, value, remove = false) => {
  const parts = path.split('.'), key = parts.pop(), target = parts.reduce((value, next) => value[next] ||= {}, row);
  if (remove) delete target[key]; else target[key] = copy(value);
};
const matches = (row, query) => Object.entries(query).every(([key, value]) => {
  if (key === '$or') return value.some(item => matches(row, item));
  const actual = get(row, key);
  if (value && typeof value === 'object' && !(value instanceof Date)) return Object.entries(value).every(([operator, expected]) => {
    if (operator === '$exists') return (actual !== undefined) === expected;
    if (operator === '$ne') return actual !== expected;
    if (operator === '$gt') return actual > expected;
    if (operator === '$gte') return actual >= expected;
    if (operator === '$lt') return actual < expected;
    if (operator === '$lte') return actual <= expected;
    if (operator === '$in') return expected.includes(actual);
    throw new Error(`Unsupported notification query: ${operator}`);
  });
  return actual === value;
});
const update = (row, value) => {
  for (const [key, next] of Object.entries(value.$set || {})) set(row, key, next);
  for (const key of Object.keys(value.$unset || {})) set(row, key, undefined, true);
  for (const [key, increment] of Object.entries(value.$inc || {})) set(row, key, (get(row, key) || 0) + increment);
};
function memory(seed = []) {
  const rows = new Map(seed.map((row, index) => [row._id || row.id || String(index), copy(row)]));
  const query = filter => {
    let maximum = Infinity, ordering;
    const result = () => {
      const output = [...rows.values()].filter(row => matches(row, filter)).map(copy);
      if (ordering) output.sort((a, b) => { for (const [key, direction] of Object.entries(ordering)) if (get(a, key) !== get(b, key)) return (get(a, key) < get(b, key) ? -1 : 1) * direction; return 0; });
      return output.slice(0, maximum);
    };
    const object = { sort: order => { ordering = order; return object; }, select: () => object, limit: count => { maximum = count; return object; }, lean: () => object, then: (yes, no) => Promise.resolve(result()).then(yes, no) };
    return object;
  };
  return {
    rows,
    find: (filter = {}) => query(filter),
    findOne: (filter = {}) => {
      const result = query(filter), object = { sort: order => { result.sort(order); return object; }, select: () => object, lean: () => object, then: (yes, no) => result.then(items => items[0] || null).then(yes, no) }; return object;
    },
    exists: async filter => [...rows.values()].some(row => matches(row, filter)),
    create: async row => { const key = row._id || row.id; if (rows.has(key)) throw Object.assign(new Error('Duplicate'), { code: 11000 }); rows.set(key, copy(row)); return copy(row); },
    findOneAndUpdate: async (filter, changes, options = {}) => {
      assertNoUpdateConflict(changes);
      let found = [...rows.entries()].find(([, row]) => matches(row, filter));
      if (!found && options.upsert) {
        const row = { ...copy(filter), ...copy(changes.$setOnInsert || {}) }, key = row._id || row.id;
        if (rows.has(key)) throw Object.assign(new Error('Duplicate'), { code: 11000 });
        rows.set(key, row); found = [key, row];
      }
      if (!found) return null;
      update(found[1], changes); return copy(found[1]);
    },
    updateOne: async function(filter, changes, options = {}) { const row = await this.findOneAndUpdate(filter, changes, options); return { matchedCount: row ? 1 : 0 }; },
    updateMany: async (filter, changes) => { assertNoUpdateConflict(changes); for (const row of rows.values()) if (matches(row, filter)) update(row, changes); },
    deleteMany: async filter => { for (const [key, row] of rows) if (matches(row, filter)) rows.delete(key); },
  };
}
module.exports = { memory };
