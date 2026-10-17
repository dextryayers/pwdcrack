/*
 * Perl XS bindings for pwdcrack.
 *
 * Exposes the same C ABI that engines/engine-bridge/src/c_api.rs exports, so
 * the Perl surface has identical semantics to the C and Python bridges:
 * every function returns a defined value on failure and never throws across
 * the FFI boundary.
 *
 * Ownership rules:
 *   - Strings returned by this module are copied into Perl scalars, so the
 *     caller owns them and must not free them.
 *   - The caller owns any buffer it passes in, and it must stay alive for the
 *     duration of the call only.
 *
 * Build:
 *   cd engines/engine-bridge/perl
 *   perl Makefile.PL
 *   make
 *
 * The Makefile.PL links against libpwdcrack, which is the library target name
 * produced by the pwdcrack cdylib, not libcrack_core.
 */

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

/* The C ABI header contract is declared inline here so this XS file builds
 * without requiring a generated header to be installed first. Only the types
 * the Perl surface actually uses are declared. */
typedef struct {
    const unsigned char *ptr;
    int len;
} pwdcrack_buf;

int  crack_init(void);
void crack_shutdown(void);
int  crack_load_hashes(const unsigned char *path, int len);
int  crack_hash_count(void);
int  crack_verify(const unsigned char *hash, int hash_len,
                  const unsigned char *password, int pass_len);
int  crack_dictionary_attack(const unsigned char *wordlist, int wl_len,
                            const unsigned char *rules, int rules_len,
                            int threads);
int  crack_bruteforce_attack(const unsigned char *mask, int mask_len, int threads);
int  crack_found_count(void);
int  crack_get_result(int index,
                      const unsigned char **out_hash, int *out_hash_len,
                      const unsigned char **out_password, int *out_pass_len,
                      const unsigned char **out_type, int *out_type_len);
char *crack_version(void);
int  crack_hashes_per_second(void);
char *crack_detect_tier(void);

MODULE = pwdcrack    PACKAGE = pwdcrack

PROTOTYPES: DISABLE

# ── Lifecycle ─────────────────────────────────────────────────────────────

int
_init()
    CODE:
        RETVAL = crack_init();
    OUTPUT:
        RETVAL

void
_shutdown()
    CODE:
        crack_shutdown();

# ── Hash loading ──────────────────────────────────────────────────────────

int
load_hashes(path)
        SV *path
    CODE:
    {
        STRLEN len;
        const char *p = SvPV(path, len);
        RETVAL = crack_load_hashes((const unsigned char *)p, (int)len);
    }
    OUTPUT:
        RETVAL

int
hash_count()
    CODE:
        RETVAL = crack_hash_count();
    OUTPUT:
        RETVAL

# ── Verification ──────────────────────────────────────────────────────────

int
verify(hash, password)
        SV *hash
        SV *password
    CODE:
    {
        STRLEN hlen, plen;
        const char *h = SvPV(hash, hlen);
        const char *p = SvPV(password, plen);
        RETVAL = crack_verify((const unsigned char *)h, (int)hlen,
                              (const unsigned char *)p, (int)plen);
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
        const char *w = SvPV(wordlist, wlen);
        const unsigned char *r = NULL;

        if (SvOK(rules)) {
            r = (const unsigned char *)SvPV(rules, rlen);
        }
        RETVAL = crack_dictionary_attack((const unsigned char *)w, (int)wlen,
                                         r, SvOK(rules) ? (int)rlen : 0,
                                         threads);
    }
    OUTPUT:
        RETVAL

int
bruteforce_attack(mask, threads = 0)
        SV *mask
        int threads
    CODE:
    {
        STRLEN mlen;
        const char *m = SvPV(mask, mlen);
        RETVAL = crack_bruteforce_attack((const unsigned char *)m, (int)mlen, threads);
    }
    OUTPUT:
        RETVAL

# ── Results ───────────────────────────────────────────────────────────────

int
found_count()
    CODE:
        RETVAL = crack_found_count();
    OUTPUT:
        RETVAL

SV *
get_result(index)
        int index
    CODE:
    {
        const unsigned char *hash = NULL, *pass = NULL, *type = NULL;
        int hash_len = 0, pass_len = 0, type_len = 0;

        if (crack_get_result(index, &hash, &hash_len, &pass, &pass_len,
                             &type, &type_len) != 0) {
            RETVAL = &PL_sv_undef;
        } else {
            HV *hv = newHV();
            (void)hv_store(hv, "hash", 4, newSVpvn((const char *)hash, hash_len), 0);
            (void)hv_store(hv, "password", 8, newSVpvn((const char *)pass, pass_len), 0);
            (void)hv_store(hv, "hash_type", 9, newSVpvn((const char *)type, type_len), 0);
            RETVAL = newRV_noinc((SV *)hv);
        }
    }
    OUTPUT:
        RETVAL

# ── Introspection ─────────────────────────────────────────────────────────

SV *
version()
    CODE:
    {
        char *v = crack_version();
        RETVAL = v ? newSVpv(v, 0) : &PL_sv_undef;
    }
    OUTPUT:
        RETVAL

SV *
detect_tier()
    CODE:
    {
        char *t = crack_detect_tier();
        RETVAL = t ? newSVpv(t, 0) : &PL_sv_undef;
    }
    OUTPUT:
        RETVAL

double
hashes_per_second()
    CODE:
        RETVAL = (double)crack_hashes_per_second();
    OUTPUT:
        RETVAL
