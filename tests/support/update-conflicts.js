// MongoDB rejects the whole update at parse time (code 40, whether or not any
// document matches) when two operator paths are equal or one is a dotted prefix of
// the other, e.g. $pull and $addToSet on `userIds`. The test mocks apply operators
// one after another, which would otherwise hide that class of bug (it shipped once:
// account deletion failed for everyone while every test stayed green).
const conflictingUpdatePath = changes => {
  const paths = Object.entries(changes || {}).filter(([operator]) => operator.startsWith('$')).flatMap(([, fields]) => Object.keys(fields || {}));
  for (let i = 0; i < paths.length; i++) for (let j = i + 1; j < paths.length; j++) {
    const [a, b] = [paths[i], paths[j]];
    if (a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`)) return a.length <= b.length ? a : b;
  }
  return null;
};
const assertNoUpdateConflict = changes => {
  const path = conflictingUpdatePath(changes);
  if (path) throw Object.assign(new Error(`Updating the path '${path}' would create a conflict at '${path}'`), { name: 'MongoServerError', code: 40, codeName: 'ConflictingUpdateOperators' });
};
module.exports = { conflictingUpdatePath, assertNoUpdateConflict };
