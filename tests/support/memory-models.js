// Deliberately small storage adapter for route tests. No database, credentials or provider SDK calls.
const bcrypt = require('bcryptjs');
const copy = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
let nextObjectId = 0;
const objectId = () => (++nextObjectId).toString(16).padStart(24, '0');
const getPath = (value, path) => path.split('.').reduce((current, key) => current?.[key], value);
function setPath(value, path, next, remove = false) {
  const parts = path.split('.');
  const last = parts.pop();
  const target = parts.reduce((current, key) => current[key] ||= {}, value);
  if (remove) delete target[last]; else target[last] = copy(next);
}
function applyUpdate(row, update) {
  if (!Object.keys(update).some(key => key.startsWith('$'))) return Object.assign(row, copy(update));
  for (const [path, value] of Object.entries(update.$set || {})) setPath(row, path, value);
  for (const path of Object.keys(update.$unset || {})) setPath(row, path, undefined, true);
  for (const [path, value] of Object.entries(update.$inc || {})) setPath(row, path, (getPath(row, path) || 0) + value);
  for (const [path, value] of Object.entries(update.$addToSet || {})) {
    const previous = getPath(row, path) || [];
    if (!previous.includes(value)) setPath(row, path, [...previous, value]);
  }
}

function matches(document, query) {
  return Object.entries(query).every(([key, expected]) => {
    if (key === '$or') return expected.some(item => matches(document, item));
    if (key === '$and') return expected.every(item => matches(document, item));
    const value = getPath(document, key);
    if (expected instanceof RegExp) return expected.test(value || '');
    if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
      return Object.entries(expected).every(([operator, operand]) => {
        if (operator === '$in') return Array.isArray(value) ? value.some(item => operand.includes(item)) : operand.includes(value);
        if (operator === '$nin') return Array.isArray(value) ? value.every(item => !operand.includes(item)) : !operand.includes(value);
        if (operator === '$ne') return Array.isArray(value) ? !value.includes(operand) : value !== operand;
        if (operator === '$all') return Array.isArray(value) && operand.every(item => value.includes(item));
        if (operator === '$gte') return value >= operand;
        if (operator === '$gt') return value > operand;
        if (operator === '$lte') return value <= operand;
        if (operator === '$lt') return value < operand;
        if (operator === '$exists') return (value !== undefined) === operand;
        throw new Error(`Unsupported test query operator: ${operator}`);
      });
    }
    return Array.isArray(value) ? value.includes(expected) : value === expected;
  });
}

function memoryModel(name, seed = []) {
  const rows = seed.map(value => ({ _id: objectId(), ...copy(value) }));
  class Document {
    constructor(value) { Object.assign(this, copy(value)); }
    toObject() { return copy(this); }
    markModified() {}
    async save() {
      if (name === 'User' && this.password && !this.password.startsWith('$2')) this.password = await bcrypt.hash(this.password, 4);
      const index = rows.findIndex(row => name === 'RevokedSession' ? row.tokenHash === this.tokenHash : row.id === this.id);
      if (index < 0) rows.push(this.toObject()); else rows[index] = this.toObject();
      return this;
    }
  }
  class Query {
    constructor(query, one) { this.query = query; this.one = one; this.offset = 0; this.maximum = Infinity; }
    select(fields) { this.fields = fields; return this; }
    lean() { this.plain = true; return this; }
    sort(order) { this.order = order; return this; }
    skip(value) { this.offset = value; return this; }
    limit(value) { this.maximum = value; return this; }
    async exec() {
      let found = rows.filter(row => matches(row, this.query)).map(copy);
      if (this.order) found.sort((a, b) => {
        for (const [key, direction] of Object.entries(this.order)) {
          if (a[key] !== b[key]) return (a[key] < b[key] ? -1 : 1) * direction;
        }
        return 0;
      });
      found = found.slice(this.offset, this.offset + this.maximum);
      if (this.fields) {
        const fields = this.fields.split(/\s+/).filter(Boolean);
        found = found.map(row => fields.some(field => field.startsWith('-'))
          ? Object.fromEntries(Object.entries(row).filter(([key]) => !fields.includes(`-${key}`)))
          : Object.fromEntries(fields.filter(key => key in row).map(key => [key, row[key]])));
      }
      if (!this.plain) found = found.map(row => new Document(row));
      return this.one ? found[0] || null : found;
    }
    then(resolve, reject) { return this.exec().then(resolve, reject); }
  }
  return {
    rows,
    find: query => new Query(query || {}, false),
    findOne: query => new Query(query || {}, true),
    exists: async query => rows.some(row => matches(row, query)),
    countDocuments: async query => rows.filter(row => matches(row, query)).length,
    create: async value => new Document({ _id: objectId(), createdAt: Date.now(), isDeleted: false, likes: [], comments: [], reports: [], ...value }).save(),
    updateOne: async (query, update, options = {}) => {
      const index = rows.findIndex(row => matches(row, query));
      if (index >= 0) applyUpdate(rows[index], update);
      else if (options.upsert) { const row = { _id: objectId(), ...copy(query), ...copy(update.$setOnInsert || {}) }; applyUpdate(row, update); rows.push(row); }
      return { acknowledged: true };
    },
    updateMany: async (query, update) => { rows.filter(row => matches(row, query)).forEach(row => applyUpdate(row, update)); return { acknowledged: true }; },
    findOneAndUpdate: async (query, update, options = {}) => {
      let row = rows.find(row => matches(row, query));
      if (!row && options.upsert) { row = { _id: objectId(), ...copy(query), ...copy(update.$setOnInsert || {}) }; rows.push(row); }
      if (!row) return null;
      applyUpdate(row, update);
      return new Document(row);
    },
    init: async () => {},
  };
}

function createMemoryModels(seed = {}) {
  return Object.fromEntries(['User', 'Post', 'Ad', 'Conversation', 'Message', 'Content', 'Report', 'UserBlock', 'ContactRequest', 'ModerationLog', 'RevokedSession'].map(name => [name, memoryModel(name, seed[name])]));
}

module.exports = { createMemoryModels };
