const aliases = require('../data/event-id-aliases.json');
const canonicalEventId = id => Object.hasOwn(aliases, id) ? aliases[id] : id;
module.exports = { canonicalEventId };
