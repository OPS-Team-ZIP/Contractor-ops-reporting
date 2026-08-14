#!/usr/bin/env node
/**
 * encrypt.js — wrap a self-contained HTML file in a password gate.
 *
 * Produces a single index.html that contains ONLY ciphertext. The readable
 * report never exists in the repo, so making the repo public does not expose it.
 *
 * Crypto: PBKDF2-SHA256 (600k iterations) -> AES-256-GCM.
 * GCM is authenticated, so a wrong password fails to decrypt rather than
 * producing garbage.
 *
 * Usage:
 *   GATE_PASSWORD='...' node tools/encrypt.js \
 *     --in source/dashboard.html \
 *     --out dist/index.html \
 *     [--title "Protected report"] \
 *     [--iterations 600000]
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  template: path.join(__dirname, 'gate-template.html'),
  title: 'Protected report',
  iterations: 600000,
};

function parseArgs(argv) {
  const out = { ...DEFAULTS };
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '');
    const val = argv[i + 1];
    if (val === undefined) fail(`Missing value for --${key}`);
    out[key] = key === 'iterations' ? Number(val) : val;
  }
  return out;
}

function fail(msg) {
  console.error(`\n  Error: ${msg}\n`);
  process.exit(1);
}

function judgePassword(pw) {
  const notes = [];
  if (pw.length < 12) {
    notes.push(
      `Password is ${pw.length} characters. Short passwords are the weak link here: ` +
      `anyone who can read the ciphertext can guess offline, as fast as their hardware allows. ` +
      `A 4-5 word passphrase is far stronger and no harder to share.`
    );
  }
  if (!/[^a-zA-Z0-9]/.test(pw) && pw.length < 16) {
    notes.push('No symbols or spaces. Consider a passphrase like "kettle-mango-drift-92".');
  }
  return notes;
}

function main() {
  const args = parseArgs(process.argv);
  const password = process.env.GATE_PASSWORD;

  if (!password) {
    fail(
      'Set the password in the environment, not on the command line:\n' +
      "         GATE_PASSWORD='your-password' node tools/encrypt.js --in ... --out ...\n" +
      '         (Command-line arguments get saved to your shell history.)'
    );
  }
  if (!args.in) fail('--in is required (the readable HTML file to protect)');
  if (!args.out) fail('--out is required (where to write the gated index.html)');
  if (!fs.existsSync(args.in)) fail(`Input file not found: ${args.in}`);
  if (!fs.existsSync(args.template)) fail(`Template not found: ${args.template}`);
  if (!Number.isInteger(args.iterations) || args.iterations < 100000) {
    fail('--iterations must be an integer >= 100000');
  }

  const plaintext = fs.readFileSync(args.in);
  const template = fs.readFileSync(args.template, 'utf8');

  // Derive and encrypt.
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, args.iterations, 32, 'sha256');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // WebCrypto expects the GCM tag appended to the ciphertext.
  const ciphertext = Buffer.concat([body, cipher.getAuthTag()]);

  // Verify the round trip before writing anything, so a bad build never ships.
  const check = crypto.createDecipheriv('aes-256-gcm', key, iv);
  check.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const roundTrip = Buffer.concat([
    check.update(ciphertext.subarray(0, ciphertext.length - 16)),
    check.final(),
  ]);
  if (!roundTrip.equals(plaintext)) fail('Round-trip check failed. Nothing was written.');

  const payload = JSON.stringify({
    v: 1,
    kdf: 'PBKDF2-SHA256',
    cipher: 'AES-256-GCM',
    iter: args.iterations,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ct: ciphertext.toString('base64'),
  });

  const html = template
    .replace(/__TITLE__/g, escapeHtml(args.title))
    .replace('__PAYLOAD__', payload);

  if (html.includes('__PAYLOAD__') || html.includes('__TITLE__')) {
    fail('Template placeholders were not all replaced. Check gate-template.html.');
  }

  fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  fs.writeFileSync(args.out, html);

  const kb = (n) => `${(n / 1024).toFixed(0)} KB`;
  console.log('');
  console.log(`  Encrypted  ${args.in} (${kb(plaintext.length)})`);
  console.log(`  Wrote      ${args.out} (${kb(Buffer.byteLength(html))})`);
  console.log(`  Settings   PBKDF2-SHA256 x ${args.iterations.toLocaleString()}, AES-256-GCM`);
  console.log(`  Page title "${args.title}"`);
  console.log('  Round-trip check passed.');

  const notes = judgePassword(password);
  if (notes.length) {
    console.log('');
    notes.forEach((n) => console.log(`  Note: ${n}`));
  }
  console.log('');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
  ));
}

main();
