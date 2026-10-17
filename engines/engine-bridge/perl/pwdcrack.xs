/*
 * Perl XS bindings for pwdcrack.
 *
 * These bind to the ABI that engines/engine-bridge/src/c_api.rs actually
 * exports. The previous version of this file declared a different ABI and could
 * not have linked:
 *
 *   declared                         actual
 *   crack_load_hashes(u8*, int)      hash_load_file(const char *)
 *   crack_hash_count()               crack_total_hashes()
 *   crack_verify(u8*,int,u8*,int)    did not exist at all
 *   crack_dictionary_attack(...)     attack_dictionary(const char*, const char*, int)
 *   crack_bruteforce_attack(...)     attack_bruteforce(const char*, u64, u64, int)
 *   crack_get_result(7 arguments)    crack_get_result(3 arguments)
 *   crack_hashes_per_second() -> int crack_hashes_per_second() -> double
 *
 * Six wrong names, a wrong arity, a wrong return type, and one function that was
 * invented. Nothing here was ever compiled, which is the only reason it stayed
 * wrong for that long. `crack_verify` has been added to the C API so this
 * surface can offer it; it is the same code path the CLI's `verify` subcommand
 * uses.
 *
 * Ownership:
 *   - Strings returned as Perl scalars are copies. The caller owns them and must
 *     not free anything.
 *   - Every C string this module receives is copied into a Perl SV first, so the
 *     caller's buffer only has to live for the duration of the call.
 *
 * Build and test:
 *   scripts/test-perl-bridge.sh
 *
 * Error codes: every function that can fail returns either a Perl exception or
 * an explicit code. Nothing signals failure by returning NULL where a value was
 * expected, except where a Perl undef is the natural answer.
 */

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

/* The C ABI, declared inline so this file builds without a generated header
 * being installed first. Kept in step with c_api.rs by hand; the C test suite at
 * engines/engine-bridge/tests/c/test_bridge.c declares the same symbols, so a
 * mismatch shows up when either is compiled. */
extern int crack_init(void);
extern void crack_shutdown(void);
extern int hash_load_file(const char *path);
extern int hash_load_buffer(const unsigned char *data, int len);
extern int attack_dictionary(const char *wordlist, const char *rules, int threads);
extern int attack_bruteforce(const char *mask, unsigned long long start,
                             unsigned long long end, int threads);
extern int crack_verify(const unsigned char *hash, int hash_len,
                        const unsigned char *password, int pass_len);
extern int crack_found_count(void);
extern int crack_total_hashes(void);
extern int crack_get_result(int idx, char **out_hash, char **out_password);
extern void crack_free_string(char *s);
extern double crack_hashes_per_second(void);
extern unsigned long long crack_last_tested(void);
extern double crack_last_duration_secs(void);
extern char *crack_version(void);
extern char *crack_version_owned(void);
extern char *crack_detect_tier(void);
extern char *crack_identify_hash(const unsigned char *hash, int len);
extern int crack_panics_abort(void);
extern unsigned int crack_abi_version(void);

/* Copies a Rust owned C string into a Perl scalar and releases it.
 * Returns &PL_sv_undef for NULL, so "the library had nothing to say" is
 * distinguishable from "the library said nothing useful". */
static SV *own_to_sv(char *owned)
{
    SV *out;
    if (owned == NULL) {
        return &PL_sv_undef;
    }
    out = newSVpv(owned, 0);
    crack_free_string(owned);
    return out;
}

/* Copies a borrowed C string into a Perl scalar. The caller must NOT free it. */
static SV *borrow_to_sv(const char *borrowed)
{
    if (borrowed == NULL) {
        return &PL_sv_undef;
    }
    return newSVpv(borrowed, 0);
}

MODULE = pwdcrack    PACKAGE = pwdcrack

PROTOTYPES: DISABLE

# ── Lifecycle ─────────────────────────────────────────────────────────────

int
init()
    CODE:
        RETVAL = crack_init();
    OUTPUT:
        RETVAL

void
shutdown()
    CODE:
        crack_shutdown();

# ── Hash loading ──────────────────────────────────────────────────────────

int
load_file(path)
        SV *path
    CODE:
    {
        STRLEN len;
        const char *p;
        if (!SvOK(path)) {
            croak("load_file: path is required");
        }
        p = SvPV(path, len);
        RETVAL = hash_load_file(p);
        if (RETVAL < 0) {
            croak("load_file: the library refused with code %d", RETVAL);
        }
    }
    OUTPUT:
        RETVAL

int
load_string(text)
        SV *text
    CODE:
    {
        STRLEN len;
        const char *p;
        if (!SvOK(text)) {
            croak("load_string: text is required");
        }
        p = SvPV(text, len);
        RETVAL = hash_load_buffer((const unsigned char *)p, (int)len);
        if (RETVAL < 0) {
            croak("load_string: the library refused with code %d", RETVAL);
        }
    }
    OUTPUT:
        RETVAL

int
total_hashes()
    CODE:
        RETVAL = crack_total_hashes();
        if (RETVAL < 0) {
            croak("total_hashes: the engine lock is unusable");
        }
    OUTPUT:
        RETVAL

# ── Verification ──────────────────────────────────────────────────────────

# Returns 1 for a match, 0 for a mismatch, and croaks when the question could
# not be answered. A caller must never see a mismatch reported for a hash that
# was not understood.
int
verify(hash, password)
        SV *hash
        SV *password
    CODE:
    {
        STRLEN hlen, plen;
        const char *h, *p;
        if (!SvOK(hash) || !SvOK(password)) {
            croak("verify: both a hash and a password are required");
        }
        h = SvPV(hash, hlen);
        p = SvPV(password, plen);
        RETVAL = crack_verify((const unsigned char *)h, (int)hlen,
                              (const unsigned char *)p, (int)plen);
        if (RETVAL < 0) {
            croak("verify: the hash was not recognised (code %d)", RETVAL);
        }
    }
    OUTPUT:
        RETVAL

# ── Attacks ───────────────────────────────────────────────────────────────

int
dictionary_attack(wordlist, rules = &PL_sv_undef, threads = 0)
        SV *wordlist
        SV *rules
        int threads
    CODE:
    {
        STRLEN wlen, rlen;
        const char *w, *r = NULL;
        if (!SvOK(wordlist)) {
            croak("dictionary_attack: a wordlist path is required");
        }
        w = SvPV(wordlist, wlen);
        if (SvOK(rules)) {
            r = SvPV(rules, rlen);
        }
        RETVAL = attack_dictionary(w, r, threads);
        if (RETVAL < 0) {
            croak("dictionary_attack: the library refused with code %d", RETVAL);
        }
    }
    OUTPUT:
        RETVAL

# The keyspace bounds are `unsigned long long` in C, which the standard Perl
# typemap has no entry for: xsubpp refuses to compile rather than guess, which
# is the right behaviour and also why this file was never built. `UV` is Perl's
# own unsigned integer and is 64 bit on every platform this crate targets, so it
# is used here with an explicit cast rather than a custom typemap that would hide
# the width.
int
bruteforce_attack(mask, start = 0, end = 0, threads = 0)
        SV *mask
        UV start
        UV end
        int threads
    CODE:
    {
        STRLEN mlen;
        const char *m;
        if (!SvOK(mask)) {
            croak("bruteforce_attack: a mask is required");
        }
        m = SvPV(mask, mlen);
        /* end == 0 means the whole keyspace, which is what the C API documents. */
        RETVAL = attack_bruteforce(m, (unsigned long long)start,
                                 (unsigned long long)end, threads);
        if (RETVAL < 0) {
            croak("bruteforce_attack: the library refused with code %d", RETVAL);
        }
    }
    OUTPUT:
        RETVAL

# ── Results ───────────────────────────────────────────────────────────────

int
found_count()
    CODE:
        RETVAL = crack_found_count();
        if (RETVAL < 0) {
            croak("found_count: the engine lock is unusable");
        }
    OUTPUT:
        RETVAL

# Returns a hash reference with keys hash, password and hash_type, or undef
# when there is no such result. Every string is a copy, so nothing here needs
# freeing.
SV *
get_result(index)
        int index
    CODE:
    {
        char *hash = NULL;
        char *password = NULL;
        HV *hv;

        if (crack_get_result(index, &hash, &password) != 0) {
            RETVAL = &PL_sv_undef;
        } else {
            hv = newHV();
            (void)hv_stores(hv, "hash", own_to_sv(hash));
            (void)hv_stores(hv, "password", own_to_sv(password));
            /* The C API's crack_get_result does not return the type, so it is
             * asked for separately rather than invented here. */
            if (hash != NULL) {
                STRLEN hlen = strlen(hash);
                char *type = crack_identify_hash((const unsigned char *)hash,
                                                 (int)hlen);
                (void)hv_stores(hv, "hash_type", own_to_sv(type));
            } else {
                (void)hv_stores(hv, "hash_type", newSV(0));
            }
            RETVAL = newRV_noinc((SV *)hv);
        }
    }
    OUTPUT:
        RETVAL

# ── Statistics ────────────────────────────────────────────────────────────

double
hashes_per_second()
    CODE:
        RETVAL = crack_hashes_per_second();
    OUTPUT:
        RETVAL

UV
last_tested()
    CODE:
        RETVAL = crack_last_tested();
    OUTPUT:
        RETVAL

double
last_duration_secs()
    CODE:
        RETVAL = crack_last_duration_secs();
    OUTPUT:
        RETVAL

# ── Introspection ─────────────────────────────────────────────────────────

SV *
version()
    CODE:
        /* Borrowed, never freed: the string lives for the life of the process. */
        RETVAL = borrow_to_sv(crack_version());
    OUTPUT:
        RETVAL

SV *
detect_tier()
    CODE:
        RETVAL = borrow_to_sv(crack_detect_tier());
    OUTPUT:
        RETVAL

SV *
identify_hash(hash)
        SV *hash
    CODE:
    {
        STRLEN len;
        const char *h;
        if (!SvOK(hash)) {
            croak("identify_hash: a hash is required");
        }
        h = SvPV(hash, len);
        /* Owned by the caller, so copied and released inside own_to_sv. */
        RETVAL = own_to_sv(crack_identify_hash((const unsigned char *)h, (int)len));
    }
    OUTPUT:
        RETVAL

int
panics_abort()
    CODE:
        RETVAL = crack_panics_abort();
    OUTPUT:
        RETVAL

unsigned int
abi_version()
    CODE:
        RETVAL = crack_abi_version();
    OUTPUT:
        RETVAL