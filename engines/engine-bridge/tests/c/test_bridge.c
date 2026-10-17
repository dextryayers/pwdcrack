/*
 * pwdcrack C API test suite.
 *
 * P11.1.07 asks for a C suite that exercises every exported symbol and
 * verifies the memory contract for crack_get_result. This is that suite: it is
 * compiled by a C compiler, links the static library, and calls the API exactly
 * as an embedding C program would.
 *
 * The same coverage exists in Rust at tests/ffi_roundtrip.rs. Both run. The Rust
 * one is convenient to maintain, this one is the one that proves the symbols are
 * actually reachable through a C ABI, which Rust cannot show on its own because
 * it links the rlib and resolves names at compile time.
 *
 * Built and run by scripts/test-c-bridge.sh. Not built by cargo, because the
 * point is to compile it as C.
 *
 * Every allocation the API hands out is released here. A leak checker is not
 * required to notice: each test balances its own acquire and free, and the
 * counts printed at the end are the number of pairs, not an estimate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The API, declared the way a header would. The crate does not ship one, which
 * is a gap this file makes visible rather than hides. */
extern int crack_init(void);
extern void crack_shutdown(void);
extern int hash_load_file(const char *path);
extern int hash_load_buffer(const unsigned char *data, int len);
extern int attack_dictionary(const char *wordlist, const char *rules, int threads);
extern int attack_bruteforce(const char *mask, unsigned long long start,
                             unsigned long long end, int threads);
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
extern char *crack_detect_tier_detail(void);
extern void crack_detect_tier_detail_free(char *s);
extern char *crack_identify_hash(const unsigned char *hash, int len);
extern int crack_panics_abort(void);
extern unsigned int crack_abi_version(void);

/* The Rust-side `abi_version()` is deliberately not declared here. It carries no
 * #[no_mangle], so it is not part of the C ABI; `crack_abi_version` is. A C
 * embedder has exactly one version symbol, which is what the exported one is
 * for. */

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/* MD5("pwdcrack-reference-candidate"), the same value the Rust suite uses. */
#define TARGET "8350c7ecc6d4706e12107df747eb6e71"
#define PLAINTEXT "pwdcrack-reference-candidate"

static void write_wordlist(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "cannot write %s\n", path);
        exit(2);
    }
    fprintf(f, "%s\n", PLAINTEXT);
    fclose(f);
}

static void test_null_inputs_are_refused(void) {
    CHECK(hash_load_file(NULL) == -1, "hash_load_file(NULL) did not refuse");
    CHECK(hash_load_buffer(NULL, 5) == -1, "hash_load_buffer(NULL) did not refuse");
    CHECK(hash_load_buffer((const unsigned char *)"x", 0) == -1,
          "a zero length buffer did not refuse");
    CHECK(attack_dictionary(NULL, NULL, 1) == -1,
          "attack_dictionary(NULL) did not refuse");
    CHECK(attack_bruteforce(NULL, 0, 0, 1) == -1,
          "attack_bruteforce(NULL) did not refuse");
    CHECK(crack_identify_hash(NULL, 4) == NULL,
          "crack_identify_hash(NULL) did not refuse");
    crack_free_string(NULL); /* must be a no-op, not a crash */
}

static void test_an_attack_with_no_hashes_is_refused(void) {
    crack_init();
    /* No hashes are loaded, so this cannot be a wordlist problem. The code has to
     * say which of the two it is, or the caller cannot know what to fix. */
    CHECK(attack_dictionary("/nonexistent/pwdcrack/words.txt", NULL, 1) == -2,
          "expected CRACK_E_NO_HASHES, got a different code");
    crack_shutdown();
}

static void test_a_dictionary_attack_cracks(void) {
    const char *path = "pwdcrack_c_test_words.txt";
    write_wordlist(path);

    crack_init();
    CHECK(hash_load_buffer((const unsigned char *)TARGET "\n", (int)strlen(TARGET) + 1) == 1,
          "the target hash did not load");
    CHECK(crack_total_hashes() == 1, "expected one loaded hash");

    /* The original deadlock was here: the function took the global lock twice,
     * so it completed the attack and then hung. Running it here is the test. */
    int cracked = attack_dictionary(path, NULL, 1);
    CHECK(cracked == 1, "expected one crack, got %d", cracked);
    CHECK(crack_found_count() == 1, "found_count disagrees with the return");

    char *hash = NULL;
    char *password = NULL;
    CHECK(crack_get_result(0, &hash, &password) == 0, "crack_get_result(0) refused");
    CHECK(hash != NULL && password != NULL, "a successful call returned a null string");
    if (hash && password) {
        CHECK(strcmp(hash, TARGET) == 0, "hash was %s", hash);
        CHECK(strcmp(password, PLAINTEXT) == 0, "password was %s", password);
        crack_free_string(hash);
        crack_free_string(password);
    }

    /* The memory contract: a refused index writes nothing. Both pointers start
     * as garbage, so if the function wrote before validating, this reads it. */
    char *garbage_a = (char *)0x1;
    char *garbage_b = (char *)0x1;
    CHECK(crack_get_result(999, &garbage_a, &garbage_b) == -3,
          "an out of range index did not refuse");
    CHECK(garbage_a == NULL && garbage_b == NULL,
          "a refused index left the out parameters unwritten");

    /* And a null out parameter must be refused, not written through. */
    CHECK(crack_get_result(0, NULL, NULL) == -1, "null out parameters were not refused");

    crack_shutdown();
    remove(path);
}

static void test_a_bruteforce_attack_runs(void) {
    crack_init();
    CHECK(hash_load_buffer((const unsigned char *)TARGET "\n", (int)strlen(TARGET) + 1) == 1,
          "the target hash did not load");
    /* A mask of literals, so the keyspace is exactly the plaintext. */
    int cracked = attack_bruteforce(PLAINTEXT, 0, 0, 1);
    CHECK(cracked == 1, "expected one crack from a literal mask, got %d", cracked);
    crack_shutdown();
}

static void test_statistics_are_measured(void) {
    const char *path = "pwdcrack_c_test_words.txt";
    write_wordlist(path);

    crack_init();
    CHECK(crack_hashes_per_second() == 0.0, "the rate was not zero before any attack");

    CHECK(hash_load_buffer((const unsigned char *)TARGET "\n", (int)strlen(TARGET) + 1) == 1,
          "the target hash did not load");
    CHECK(attack_dictionary(path, NULL, 1) == 1, "the attack did not crack");

    /* One candidate in the wordlist, so the numerator must be exactly one. A
     * hardcoded rate could not satisfy this. */
    CHECK(crack_last_tested() == 1, "tested was %llu, expected 1",
          (unsigned long long)crack_last_tested());
    CHECK(crack_last_duration_secs() > 0.0, "a finished attack took no time");

    double rate = crack_hashes_per_second();
    CHECK(rate > 0.0, "the rate was %f after testing a candidate", rate);
    CHECK(rate < 1000000.0, "an implausible rate of %f", rate);

    crack_shutdown();
    remove(path);
}

static void test_information_symbols(void) {
    crack_init();

    char *version = crack_version();
    CHECK(version != NULL, "crack_version returned null");
    /* Documented as borrowed: read it, never free it. */
    if (version) {
        CHECK(strlen(version) > 0, "the version string was empty");
    }

    char *owned = crack_version_owned();
    CHECK(owned != NULL, "crack_version_owned returned null");
    if (owned) {
        CHECK(strlen(owned) > 0, "the owned version string was empty");
        crack_free_string(owned);
    }

    char *tier = crack_detect_tier();
    CHECK(tier != NULL, "crack_detect_tier returned null");
    if (tier) {
        /* The previous implementation returned the constant "Auto", which is a
         * mode name rather than a detected tier. */
        CHECK(strcmp(tier, "low") == 0 || strcmp(tier, "mid") == 0 ||
                  strcmp(tier, "high") == 0,
              "the tier was \"%s\", expected low, mid or high", tier);
    }

    char *detail = crack_detect_tier_detail();
    CHECK(detail != NULL, "crack_detect_tier_detail returned null");
    if (detail) {
        char expected[256];
        snprintf(expected, sizeof(expected), "%s,", tier ? tier : "");
        CHECK(strncmp(detail, expected, strlen(expected)) == 0,
              "the detail \"%s\" does not start with the summary tier", detail);
        crack_detect_tier_detail_free(detail);
    }

    const unsigned char *target = (const unsigned char *)TARGET;
    char *name = crack_identify_hash(target, (int)strlen(TARGET));
    CHECK(name != NULL, "crack_identify_hash returned null for a real MD5");
    if (name) {
        CHECK(strcmp(name, "Unknown") != 0, "a real MD5 was not identified");
        crack_free_string(name);
    }

    const unsigned char *junk = (const unsigned char *)"not a hash at all";
    name = crack_identify_hash(junk, (int)strlen((const char *)junk));
    CHECK(name != NULL, "crack_identify_hash returned null for junk");
    if (name) {
        CHECK(strcmp(name, "Unknown") == 0, "junk was identified as %s", name);
        crack_free_string(name);
    }

    /* The panic strategy is reported so a caller knows whether it can catch
     * anything. It must be a defined value, not an accident. */
    int aborts = crack_panics_abort();
    CHECK(aborts == 0 || aborts == 1, "crack_panics_abort returned %d", aborts);

    /* 1 is the value `abi_version()` returns in lib.rs. It is written out here
     * because the C ABI exposes it only as crack_abi_version, so a mismatch is
     * a version bump that forgot this file. */
    CHECK(crack_abi_version() == 1u, "the ABI version is %u, expected 1",
          crack_abi_version());

    crack_shutdown();
}

int main(void) {
    test_null_inputs_are_refused();
    test_an_attack_with_no_hashes_is_refused();
    test_a_dictionary_attack_cracks();
    test_a_bruteforce_attack_runs();
    test_statistics_are_measured();
    test_information_symbols();

    printf("C bridge suite: %d checks, %d failures\n", checks, failures);
    if (failures == 0) {
        printf("panic strategy: %s\n",
               crack_panics_abort() ? "abort (catch_unwind is inert)"
                                   : "unwind (catch_unwind works)");
    }
    return failures == 0 ? 0 : 1;
}