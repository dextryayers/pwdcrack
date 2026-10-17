package pwdcrack;

use strict;
use warnings;

use Exporter 'import';

# The export list is the XS surface, name for name. The previous version listed
# functions that no longer exist (load_hashes, hash_count) and omitted every one
# that does, so `use pwdcrack qw(load_hashes)` imported a subroutine that was
# never compiled and importing a real one had to be spelled out in full.
our @EXPORT_OK = qw(
    init
    shutdown
    load_file
    load_string
    total_hashes
    verify
    dictionary_attack
    bruteforce_attack
    found_count
    get_result
    hashes_per_second
    last_tested
    last_duration_secs
    version
    detect_tier
    identify_hash
    panics_abort
    abi_version
);

our $VERSION = '1.2.0';

# XSLoader::load takes the version of the compiled XS as its second argument.
# It has to be a package variable of this package; an undeclared `$XS_VERSION` is
# a global under no strict, which XSLoader rejects. The previous file referenced
# it without ever assigning it, so the module did not load at all.
our $XS_VERSION = $VERSION;

require XSLoader;
XSLoader::load(__PACKAGE__, $XS_VERSION);

# ── Documentation ─────────────────────────────────────────────────────────
#
# Every function maps one to one onto the C ABI in
# engines/engine-bridge/src/c_api.rs. Where this differs from the CLI, the CLI's
# behaviour is the reference.
#
#   init()                          Initialise the engine. Returns 0.
#   shutdown()                      Clear hashes and results.
#   load_file($path)                Load hashes from a file. Returns the count.
#   load_string($text)              Load hashes from a string. Returns the count.
#   total_hashes()                  Number of hashes loaded.
#   verify($hash, $password)        1 on a match, 0 on a mismatch. Croaks when
#                                   the hash is not recognised, which is
#                                   deliberately not the same as a mismatch.
#   dictionary_attack($wl, $rules, $threads)
#                                   Returns the number cracked.
#   bruteforce_attack($mask, $start, $end, $threads)
#                                   $end of 0 means the whole keyspace.
#   found_count()                   Cracks found by the last attack.
#   get_result($i)                  {hash, password, hash_type} or undef.
#   hashes_per_second()             Measured rate of the last attack. 0 before
#                                   any attack has run.
#   last_tested()                   Candidates the last attack tested.
#   last_duration_secs()            Wall clock of the last attack.
#   version()                       Library version.
#   detect_tier()                   "low", "mid" or "high", measured.
#   identify_hash($hash)            The cracker's name, or "Unknown".
#   panics_abort()                  1 if this build aborts on panic, else 0.
#   abi_version()                   ABI version, 1.
#
# Every returned string is a Perl copy. Nothing needs freeing.
#
# Example:
#
#   use pwdcrack qw(init load_file dictionary_attack get_result);
#   init();
#   load_file('hashes.txt');
#   my $found = dictionary_attack('rockyou.txt', undef, 0);
#   for my $i (0 .. $found - 1) {
#       my $r = get_result($i);
#       print "$r->{hash}:$r->{password}\n";
#   }

1;