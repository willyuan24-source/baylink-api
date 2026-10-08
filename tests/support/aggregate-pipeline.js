// A small in-memory runner for the aggregation stages the metric reports use:
// $match (equality, $gte, $lte, $in), $group (field-path keys; $sum, $min, $max),
// $sort (dotted paths) and $limit. It follows Mongo's semantics for those stages
// closely enough for route tests; the real-Mongo smoke run checks the rest.
const getPath = (value, path) => path.split('.').reduce((current, key) => current?.[key], value);
const compare = (a, b) => (a === b ? 0 : a < b ? -1 : 1);

function matches(row, query) {
  return Object.entries(query).every(([field, expected]) => {
    const value = getPath(row, field);
    if (!expected || typeof expected !== 'object' || Array.isArray(expected)) return value === expected;
    return Object.entries(expected).every(([operator, operand]) => {
      // Like Mongo, a range only compares values of the operand's type.
      if (operator === '$gte') return typeof value === typeof operand && value >= operand;
      if (operator === '$lte') return typeof value === typeof operand && value <= operand;
      if (operator === '$in') return operand.includes(value);
      throw new Error(`Unsupported test query operator: ${operator}`);
    });
  });
}

const evaluate = (row, expression) => {
  if (typeof expression === 'string' && expression.startsWith('$')) return getPath(row, expression.slice(1));
  if (expression && typeof expression === 'object') return Object.fromEntries(Object.entries(expression).map(([key, value]) => [key, evaluate(row, value)]));
  return expression;
};

function runPipeline(rows, pipeline) {
  let result = rows.map(row => structuredClone(row));
  for (const stage of pipeline) {
    const [name, spec] = Object.entries(stage)[0];
    if (name === '$match') result = result.filter(row => matches(row, spec));
    else if (name === '$group') {
      const groups = new Map();
      for (const row of result) {
        const _id = evaluate(row, spec._id);
        const key = JSON.stringify(_id);
        const group = groups.get(key) || { _id };
        for (const [field, accumulator] of Object.entries(spec)) {
          if (field === '_id') continue;
          const [operator, expression] = Object.entries(accumulator)[0];
          const value = evaluate(row, expression);
          if (operator === '$sum') group[field] = (group[field] || 0) + (typeof value === 'number' ? value : 0);
          else if (operator === '$min') group[field] = field in group && compare(group[field], value) <= 0 ? group[field] : value;
          else if (operator === '$max') group[field] = field in group && compare(group[field], value) >= 0 ? group[field] : value;
          else throw new Error(`Unsupported test accumulator: ${operator}`);
        }
        groups.set(key, group);
      }
      result = [...groups.values()];
    } else if (name === '$sort') {
      result.sort((left, right) => {
        for (const [field, direction] of Object.entries(spec)) {
          const order = compare(getPath(left, field), getPath(right, field));
          if (order) return order * direction;
        }
        return 0;
      });
    } else if (name === '$limit') result = result.slice(0, spec);
    else throw new Error(`Unsupported test aggregation stage: ${name}`);
  }
  return result;
}

module.exports = { runPipeline };
