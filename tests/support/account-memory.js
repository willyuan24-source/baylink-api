// Mock Mongo subset used only by account security/privacy tests; no database or provider calls.
const clone = value => value === undefined ? undefined : structuredClone(value);
const get = (row, path) => path.split('.').reduce((value, key) => Array.isArray(value) ? value.flatMap(item => item?.[key] ?? []) : value?.[key], row);
const same = (a, b) => a === b || (b === null && a === undefined);
const matches = (row, filter = {}) => Object.entries(filter).every(([key, expected]) => {
  if (key === '$or') return expected.some(item => matches(row, item));
  if (key === '$and') return expected.every(item => matches(row, item));
  const actual = get(row, key);
  if (expected && typeof expected === 'object' && !(expected instanceof Date) && !Array.isArray(expected)) return Object.entries(expected).every(([op, operand]) => {
    if (op === '$exists') return (actual !== undefined) === operand;
    if (op === '$ne') return Array.isArray(actual) ? !actual.some(item => same(item, operand)) : !same(actual, operand);
    if (op === '$in') return (Array.isArray(actual) ? actual : [actual]).some(item => operand.some(value => same(item, value)));
    if (op === '$nin') return !(Array.isArray(actual) ? actual : [actual]).some(item => operand.includes(item));
    if (op === '$gt') return actual > operand;
    if (op === '$gte') return actual >= operand;
    if (op === '$lt') return actual < operand;
    if (op === '$lte') return actual <= operand;
    if (op === '$all') return operand.every(item => actual?.includes(item));
    if (op === '$size') return actual?.length === operand;
    throw new Error(`Unsupported account test query ${op}`);
  });
  return Array.isArray(actual) ? actual.some(item => same(item, expected)) : same(actual, expected);
});
const set = (row, path, value, remove = false) => {
  const keys = path.split('.'), last = keys.pop(), target = keys.reduce((value, key) => value[key] ||= {}, row);
  if (remove) delete target[last]; else target[last] = clone(value);
};
const update = (row, changes) => {
  if (!Object.keys(changes).some(key => key.startsWith('$'))) return Object.assign(row, clone(changes));
  for (const [key, value] of Object.entries(changes.$set || {})) set(row, key, value);
  for (const key of Object.keys(changes.$unset || {})) set(row, key, undefined, true);
  for (const [key, value] of Object.entries(changes.$inc || {})) set(row, key, (get(row, key) || 0) + value);
  for (const [key, value] of Object.entries(changes.$pull || {})) set(row, key, (get(row, key) || []).filter(item => value && typeof value === 'object' ? !matches(item, value) : item !== value));
  for (const [key, value] of Object.entries(changes.$addToSet || {})) set(row, key, [...new Set([...(get(row, key) || []), value])]);
};
function accountMemory(seed = []) {
  const rows = clone(seed);
  const doc = row => row ? { ...clone(row), toObject: () => clone(row), save: async function() { const index = rows.findIndex(value => value.id === this.id); rows[index] = Object.fromEntries(Object.entries(this).filter(([, value]) => typeof value !== 'function')); return this; } } : null;
  const query = (filter, one) => {
    let maximum = Infinity, selection;
    const result = () => {
      let found = rows.filter(row => matches(row, filter)).slice(0, maximum).map(clone);
      if (selection) found = found.map(row => Object.fromEntries(selection.split(/\s+/).filter(key => key in row).map(key => [key, row[key]])));
      return one ? doc(found[0]) : found;
    };
    const q = { limit: value => { maximum = value; return q; }, lean: () => q, select: value => { selection = value; return q; }, sort: () => q, session: () => q, then: (yes, no) => Promise.resolve(result()).then(yes, no) };
    return q;
  };
  return { rows, collection: { findOne: async filter => clone(rows.find(row => matches(row, filter))) },
    find: (filter = {}) => query(filter, false), findOne: (filter = {}) => query(filter, true),
    exists: async filter => rows.some(row => matches(row, filter)), countDocuments: async filter => rows.filter(row => matches(row, filter)).length,
    create: async value => { if (rows.some(row => row.id && row.id === value.id)) throw Object.assign(new Error('Duplicate'), { code: 11000 }); rows.push(clone(value)); return doc(value); },
    findOneAndUpdate: async (filter, changes) => { const row = rows.find(row => matches(row, filter)); if (!row) return null; update(row, changes); return doc(row); },
    updateOne: async (filter, changes) => { const row = rows.find(row => matches(row, filter)); if (!row) return { matchedCount: 0, modifiedCount: 0 }; const before = JSON.stringify(row); update(row, changes); return { matchedCount: 1, modifiedCount: before !== JSON.stringify(row) ? 1 : 0 }; },
    updateMany: async (filter, changes) => { const selected = rows.filter(row => matches(row, filter)); selected.forEach(row => update(row, changes)); return { matchedCount: selected.length, modifiedCount: selected.length }; },
    deleteMany: async filter => { for (let index = rows.length - 1; index >= 0; index--) if (matches(rows[index], filter)) rows.splice(index, 1); },
    deleteOne: async filter => { const index = rows.findIndex(row => matches(row, filter)); if (index >= 0) rows.splice(index, 1); },
    init: async () => {},
  };
}
module.exports = { accountMemory };
