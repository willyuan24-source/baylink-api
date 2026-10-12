#!/usr/bin/env node
// G44: sign every administrator account out everywhere, without signing in.
//
// For the owner, from the Render shell (MONGO_URI is already in the environment) or a
// local terminal with an env file:
//   node scripts/revoke-admin-sessions.js                 # dry run: counts admin accounts only
//   node scripts/revoke-admin-sessions.js --apply         # revoke
//   node scripts/revoke-admin-sessions.js --env=<file> --apply
// The online equivalent is POST /api/admin/sessions/revoke (docs/account-privacy-and-mfa.md).
// Only sessionRevision / sessionsRevokedAt change; passwords and authenticators do not.
// Nothing secret is printed.
const { readFileSync } = require('node:fs');
const { revokeAdminSessions } = require('../lib/adminSessions');

function parseArgs(argv) {
  const apply = argv.includes('--apply');
  const envPath = argv.find(value => value.startsWith('--env='))?.slice(6);
  const unknown = argv.filter(value => value !== '--apply' && !value.startsWith('--env='));
  return { apply, envPath, unknown };
}

// A minimal model over the `users` collection: only the fields this script reads or writes.
function userModel(mongoose) {
  if (mongoose.models.AdminSessionUser) return mongoose.models.AdminSessionUser;
  const schema = new mongoose.Schema({ id: String, role: String, sessionsRevokedAt: Number, sessionRevision: Number }, { strict: false, collection: 'users' });
  return mongoose.model('AdminSessionUser', schema);
}

async function run({ argv = process.argv.slice(2), env = process.env, mongoose = require('mongoose'), log = console.log } = {}) {
  const { apply, envPath, unknown } = parseArgs(argv);
  if (unknown.length) throw new Error(`Unknown argument: ${unknown[0]} (use --apply and/or --env=<file>)`);
  const source = envPath ? require('dotenv').parse(readFileSync(envPath)) : env;
  const uri = source.MONGO_URI;
  if (!uri) throw new Error('MONGO_URI is not set (Render shell, or pass --env=<file>).');
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
  try {
    const User = userModel(mongoose);
    if (!apply) {
      const count = await User.countDocuments({ role: 'admin' });
      log(`Dry run: ${count} administrator account(s) would be signed out everywhere. Re-run with --apply.`);
      return { applied: false, accounts: count };
    }
    const result = await revokeAdminSessions({ User });
    log(`Signed out ${result.accounts} administrator account(s) everywhere at ${new Date(result.at).toISOString()}. Sign in again (with the authenticator if enabled).`);
    return { applied: true, accounts: result.accounts, at: result.at };
  } finally { await mongoose.disconnect(); }
}

if (require.main === module) run().catch(error => { console.error(`revoke-admin-sessions: ${error.message}`); process.exit(1); });

module.exports = { run, parseArgs };
