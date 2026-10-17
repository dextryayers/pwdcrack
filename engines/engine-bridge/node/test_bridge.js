// Node.js test suite for the pwdcrack addon.
//
// P11.1.02 asks for "a promise based asynchronous API". The previous
// implementation had no async surface at all, and its only function returned the
// literal string "ok" without verifying anything.
//
// These tests run in a real Node process against the built addon, because the
// promise machinery and the N-API string handling only exist once Node is
// present. A Rust unit test cannot see either.
//
// Run by scripts/test-node-bridge.sh.

'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

// MD5 computed here rather than copied, so a change to the hash implementation
// cannot quietly make the expectation wrong.
const md5 = (text) => crypto.createHash('md5').update(text).digest('hex');

const PLAINTEXT = 'pwdcrack-reference-candidate';
const TARGET = md5(PLAINTEXT);
const OTHER = 'abcdefghijklmnopqrstuvwxyz0123456789';

let pwdcrack;
let wordlist;

test.before(() => {
  pwdcrack = require('./pwdcrack.node');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pwdcrack-node-'));
  wordlist = path.join(dir, 'words.txt');
  fs.writeFileSync(wordlist, `${OTHER}\n${PLAINTEXT}\n`);
});

test('the module exports the documented surface', () => {
  const expected = [
    'version',
    'detect',
    'verify',
    'loadFile',
    'loadString',
    'targetCount',
    'targets',
    'reset',
    'results',
    'hashesPerSecond',
    'attackDictionary',
    'attackDictionarySync',
    'attackBruteforce',
    'attackBruteforceSync',
  ];
  for (const name of expected) {
    assert.strictEqual(
      typeof pwdcrack[name],
      'function',
      `${name} is missing or is not a function`,
    );
  }
});

test('version reports the wrapped library', () => {
  assert.match(pwdcrack.version(), /^\d+\.\d+\.\d+$/);
  // The old constant said 1.1.0 while the library was 1.2.0.
  assert.strictEqual(pwdcrack.version(), '1.2.0');
});

// ---------------------------------------------------------------------------
// Detection and verification
// ---------------------------------------------------------------------------

test('detect performs a real detection rather than returning a constant', () => {
  const found = pwdcrack.detect(TARGET);
  assert.strictEqual(found.recognised, true);
  // napi-rs exposes Rust's snake_case as JavaScript's camelCase, so the field
  // is hashType here and hash_type on the Rust and Python surfaces. The binding
  // follows the JavaScript convention rather than making JS callers learn a Rust
  // spelling.
  assert.match(found.hashType, /md5/i);

  const missing = pwdcrack.detect('not a hash at all');
  assert.strictEqual(missing.recognised, false);
  assert.strictEqual(missing.hashType, 'Unknown');
});

test('verify keeps three answers apart', () => {
  // 1, 0, and a thrown error. The previous implementation returned "ok" for
  // everything, so a caller could not tell a recovery from a guess.
  assert.strictEqual(pwdcrack.verify(TARGET, PLAINTEXT), true);
  assert.strictEqual(pwdcrack.verify(TARGET, OTHER), false);
  assert.throws(() => pwdcrack.verify('not a hash at all', PLAINTEXT));
});

test('verify does not truncate a long password', () => {
  // The previous implementation read into a 256 byte buffer and discarded the
  // result, so this could not have been checked at all.
  const long = 'a'.repeat(1000);
  const target = md5(long);
  assert.strictEqual(pwdcrack.verify(target, long), true);
  assert.strictEqual(pwdcrack.verify(target, `${long}b`), false);
});

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

test('loadString and targetCount track the loaded hashes', () => {
  pwdcrack.reset();
  assert.strictEqual(pwdcrack.targetCount(), 0);
  assert.strictEqual(pwdcrack.loadString(`${TARGET}\n`), 1);
  assert.strictEqual(pwdcrack.targetCount(), 1);
  assert.strictEqual(pwdcrack.targets()[0].raw, TARGET);
  pwdcrack.reset();
});

test('loadString reads a user:hash line', () => {
  const alice = md5('alice-password');
  pwdcrack.reset();
  assert.strictEqual(pwdcrack.loadString(`alice:${alice}\n`), 1);
  assert.strictEqual(pwdcrack.targets()[0].username, 'alice');
  pwdcrack.reset();
});

test('an unreadable file throws rather than loading nothing', () => {
  assert.throws(() => pwdcrack.loadFile('/nonexistent/pwdcrack/hashes.txt'));
});

// ---------------------------------------------------------------------------
// The promise based API
// ---------------------------------------------------------------------------

test('attackDictionary returns a promise that resolves to a real outcome', async () => {
  pwdcrack.reset();
  assert.strictEqual(pwdcrack.loadString(`${TARGET}\n`), 1);

  const promise = pwdcrack.attackDictionary(wordlist);
  assert.ok(
    promise instanceof Promise,
    'attackDictionary must return a Promise, so the event loop keeps running',
  );

  const outcome = await promise;
  assert.strictEqual(outcome.cracked, 1);
  assert.strictEqual(outcome.tested, 2, 'two candidates were in the wordlist');
  assert.strictEqual(outcome.results[0].password, PLAINTEXT);
  assert.strictEqual(outcome.results[0].hash, TARGET);
  // The pair must actually be a match.
  assert.strictEqual(md5(outcome.results[0].password), outcome.results[0].hash);
  assert.ok(outcome.hashesPerSecond > 0, 'a finished attack has a measurable rate');
  assert.ok(outcome.seconds > 0);
  pwdcrack.reset();
});

test('attackBruteforce resolves over a literal mask', async () => {
  pwdcrack.reset();
  pwdcrack.loadString(`${TARGET}\n`);
  const outcome = await pwdcrack.attackBruteforce(PLAINTEXT);
  assert.strictEqual(outcome.cracked, 1);
  assert.strictEqual(outcome.results[0].password, PLAINTEXT);
  pwdcrack.reset();
});

test('a rejected attack rejects rather than resolving with zero', async () => {
  pwdcrack.reset();
  // Nothing loaded, so the attack cannot run. A promise that resolved with
  // `cracked: 0` would read as "searched and found nothing".
  await assert.rejects(() => pwdcrack.attackDictionary(wordlist));
  await assert.rejects(() => pwdcrack.attackDictionary('/nonexistent/words.txt'));
});

test('the event loop keeps running during an attack', async () => {
  // The point of the promise API. If the work ran on the main thread, this
  // counter would not advance until the attack finished.
  pwdcrack.reset();
  pwdcrack.loadString(`${TARGET}\n`);

  let ticks = 0;
  const timer = setInterval(() => {
    ticks += 1;
  }, 1);
  const attack = pwdcrack.attackDictionary(wordlist);
  // Let the timer run while the attack is in flight.
  await new Promise((resolve) => setTimeout(resolve, 25));
  clearInterval(timer);

  const outcome = await attack;
  assert.strictEqual(outcome.cracked, 1);
  assert.ok(
    ticks > 0,
    'the timer never fired, so the attack blocked the event loop',
  );
  pwdcrack.reset();
});

test('several attacks can be awaited concurrently', async () => {
  pwdcrack.reset();
  pwdcrack.loadString(`${TARGET}\n`);
  const [a, b] = await Promise.all([
    pwdcrack.attackDictionary(wordlist),
    pwdcrack.attackDictionary(wordlist),
  ]);
  assert.strictEqual(a.cracked, 1);
  assert.strictEqual(b.cracked, 1);
  pwdcrack.reset();
});

test('the synchronous form produces the same answer', () => {
  pwdcrack.reset();
  pwdcrack.loadString(`${TARGET}\n`);
  const outcome = pwdcrack.attackDictionarySync(wordlist, 1);
  assert.strictEqual(outcome.cracked, 1);
  assert.strictEqual(outcome.results[0].password, PLAINTEXT);
  pwdcrack.reset();
});

test('results are readable after an attack', () => {
  pwdcrack.reset();
  pwdcrack.loadString(`${TARGET}\n`);
  pwdcrack.attackDictionarySync(wordlist, 1);
  assert.strictEqual(pwdcrack.results().length, 1);
  assert.strictEqual(pwdcrack.results()[0].password, PLAINTEXT);
  pwdcrack.reset();
});

// ---------------------------------------------------------------------------
// Engine reporting
// ---------------------------------------------------------------------------

test('hashesPerSecond is a measured number', () => {
  const rate = pwdcrack.hashesPerSecond();
  // null rather than 0 before anything is measured: zero reads as "measured, and
  // it was very slow".
  assert.ok(rate === null || rate > 0, `got ${rate}`);
  assert.ok(rate > 0, 'CpuEngine benchmarks itself on construction');
});