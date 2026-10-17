/**
 * pwdcrack: password hash cracking from Node.
 *
 * The declarations here are hand written rather than generated, because napi-rs
 * can emit them and that output is checked in separately when the tool is run.
 * What matters is that they match what the addon actually exports, which
 * `test_bridge.js` asserts by requiring every name listed below.
 *
 * Naming: napi-rs exposes Rust's snake_case as JavaScript's camelCase, so the
 * object fields here are camelCase while the Rust source spells them snake_case.
 */

/** One cracked hash. */
export interface CrackedHash {
  /** The hash string as it was loaded, including any prefix or salt. */
  hash: string;
  /** The cracker's name for it. */
  hashType: string;
  /**
   * The recovered password, or `null` when it was never found.
   *
   * `null` and `""` are different: an empty password is a real recovery.
   */
  password: string | null;
}

/** One loaded hash. */
export interface Target {
  /** The hash string as loaded. */
  raw: string;
  /** The cracker's name for it. */
  hashType: string;
  /** The account name, when the line was `user:hash`. */
  username: string | null;
  /** The salt the parser extracted, when the format has one. */
  salt: string | null;
}

/** What a hash string was recognised as. */
export interface Detection {
  /** The cracker's name, or `"Unknown"`. */
  hashType: string;
  /**
   * False when no parser claimed it, so a caller can branch without comparing
   * against the string `"Unknown"`.
   */
  recognised: boolean;
}

/** The outcome of one attack. */
export interface AttackOutcome {
  /** Hashes recovered. */
  cracked: number;
  /**
   * Candidates tested, counted rather than estimated.
   *
   * Exact to 2^53, because it is a JavaScript number.
   */
  tested: number;
  /** Seconds the attack took. */
  seconds: number;
  /**
   * Candidates per second, or `null` when the run was too short to time.
   *
   * `null` rather than `0`: zero reads as "measured, and it was very slow".
   */
  hashesPerSecond: number | null;
  /** Every recovered hash. */
  results: CrackedHash[];
}

/** The version of the library this addon wraps. */
export function version(): string;

/**
 * The type of a hash string.
 *
 * This performs a real detection. The previous implementation of this binding
 * read its argument, discarded it, and returned the literal string `"ok"`.
 */
export function detect(hash: string): Detection;

/**
 * Whether `password` recovers `hash`.
 *
 * Three answers stay three: `true`, `false`, and a thrown error for a hash that
 * could not be checked. Returning `false` for "not checked" is how a cracker
 * reports a recovery that did not happen.
 *
 * @throws when no parser recognises `hash`.
 */
export function verify(hash: string, password: string): boolean;

/** Loads hashes from a file, replacing anything already loaded. */
export function loadFile(path: string): number;

/** Loads hashes from a string, replacing anything already loaded. */
export function loadString(text: string): number;

/** How many hashes are loaded. */
export function targetCount(): number;

/** Every loaded target. */
export function targets(): Target[];

/** Forgets every loaded hash and result. */
export function reset(): void;

/** Results from the last attack. */
export function results(): CrackedHash[];

/**
 * The engine's measured rate for the reference workload.
 *
 * `null` until something has been measured. Built on each call rather than
 * cached, so the number describes this moment.
 */
export function hashesPerSecond(): number | null;

/**
 * Runs a dictionary attack off the event loop.
 *
 * Use this from a server. Blocking the event loop for the length of an attack
 * turns a Node server into a server that answers nothing.
 */
export function attackDictionary(wordlist: string, threads?: number): Promise<AttackOutcome>;

/**
 * Runs a dictionary attack and returns when it is finished.
 *
 * Blocks the calling thread. `attackDictionary` is the one to use unless the
 * script wants to block.
 */
export function attackDictionarySync(wordlist: string, threads?: number): AttackOutcome;

/** Runs a brute force attack off the event loop. */
export function attackBruteforce(mask: string, threads?: number): Promise<AttackOutcome>;

/** Runs a brute force attack and returns when it is finished. Blocks. */
export function attackBruteforceSync(mask: string, threads?: number): AttackOutcome;