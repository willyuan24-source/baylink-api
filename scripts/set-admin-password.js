#!/usr/bin/env node
// G44: give the administrator account a new password without signing in.
//
// The administrator's login name is "admin", which has no mailbox, so the e-mail reset cannot
// reach it. Signed in, the owner can use POST /api/users/me/password; this script is for when
// signing in is not possible (forgotten password) or no web form exists yet.
//   node scripts/set-admin-password.js --env=<file with MONGO_URI>           # dry run: which account
//   node scripts/set-admin-password.js --env=<file with MONGO_URI> --apply   # asks twice, hidden
//   (Render shell: MONGO_URI is already set, so --env can be left out.)
//   --id=<account id> picks one account when there is more than one administrator.
// The new password is typed at a hidden prompt (never an argument, so it stays out of shell
// history) and is never printed. It needs 12+ characters with upper- and lower-case letters
// and a digit. Every session of the account is signed out; the authenticator is unchanged.
const { readFileSync } = require('node:fs');
const bcrypt = require('bcryptjs');

const strongAdminPassword = value => typeof value === 'string' && value.length >= 12 && value.length <= 128
  && /[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value);

function parseArgs(argv) {
  const apply = argv.includes('--apply');
  const envPath = argv.find(value => value.startsWith('--env='))?.slice(6);
  const id = argv.find(value => value.startsWith('--id='))?.slice(5);
  const unknown = argv.filter(value => value !== '--apply' && !value.startsWith('--env=') && !value.startsWith('--id='));
  return { apply, envPath, id, unknown };
}

function userModel(mongoose) {
  if (mongoose.models.AdminPasswordUser) return mongoose.models.AdminPasswordUser;
  const schema = new mongoose.Schema({ id: String, role: String, nickname: String, password: String, passwordChangedAt: Number,
    sessionsRevokedAt: Number, sessionRevision: Number }, { strict: false, collection: 'users' });
  return mongoose.model('AdminPasswordUser', schema);
}

const LINE_BREAK = /\r?\n/;
const NEWLINE = String.fromCharCode(10);

// A prompt that does not echo what is typed (TTY); from a pipe, one line per question.
let pipedLines = null;
async function hiddenPrompt(question) {
  if (!process.stdin.isTTY) {
    if (!pipedLines) { let text = ''; for await (const chunk of process.stdin) text += chunk; pipedLines = text.split(LINE_BREAK); }
    return pipedLines.shift() ?? '';
  }
  const readline = require('node:readline');
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = text => { if (text.includes(question)) process.stdout.write(text); };
    rl.question(question, answer => { rl.close(); process.stdout.write(NEWLINE); resolve(answer); });
  });
}

async function run({ argv = process.argv.slice(2), env = process.env, mongoose = require('mongoose'), log = console.log, readPassword = hiddenPrompt, now = Date.now } = {}) {
  const { apply, envPath, id, unknown } = parseArgs(argv);
  if (unknown.length) throw new Error(`Unknown argument: ${unknown[0]} (use --apply, --env=<file>, --id=<account id>)`);
  const source = envPath ? require('dotenv').parse(readFileSync(envPath)) : env;
  if (!source.MONGO_URI) throw new Error('MONGO_URI is not set (Render shell, or pass --env=<file>).');
  await mongoose.connect(source.MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  try {
    const User = userModel(mongoose);
    const admins = await User.find({ role: 'admin', ...(id ? { id } : {}) }).select('id nickname').lean();
    if (!admins.length) throw new Error(id ? `No administrator account with id ${id}.` : 'No administrator account found.');
    if (admins.length > 1) throw new Error(`${admins.length} administrator accounts: pick one with --id=<${admins.map(row => row.id).join(' | ')}>.`);
    const [admin] = admins;
    if (!apply) {
      log(`Dry run: would set a new password for administrator account ${admin.id} (${admin.nickname || 'no nickname'}). Re-run with --apply.`);
      return { applied: false, id: admin.id };
    }
    const first = await readPassword('New administrator password: ');
    if (!strongAdminPassword(first)) throw new Error('Not changed: use 12-128 characters with upper- and lower-case letters and a digit.');
    const second = await readPassword('Type it again: ');
    if (first !== second) throw new Error('Not changed: the two entries differ.');
    const at = now();
    const hash = await bcrypt.hash(first, 10);
    const result = await User.updateOne({ id: admin.id, role: 'admin' }, {
      $set: { password: hash, passwordChangedAt: at, sessionsRevokedAt: at }, $inc: { sessionRevision: 1 },
      $unset: { passwordResetTokenHash: '', passwordResetExpires: '' },
    });
    if (result && result.matchedCount === 0) throw new Error('Not changed: the account changed while the script ran. Run it again.');
    log(`Password changed for administrator account ${admin.id}; every session of this account is signed out. Sign in again with the new password.`);
    return { applied: true, id: admin.id, at };
  } finally { await mongoose.disconnect(); }
}

if (require.main === module) run().catch(error => { console.error(`set-admin-password: ${error.message}`); process.exit(1); });

module.exports = { run, parseArgs, strongAdminPassword, hiddenPrompt };
