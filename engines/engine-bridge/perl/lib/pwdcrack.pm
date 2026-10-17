package pwdcrack;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(
    init
    shutdown
    load_hashes
    hash_count
    verify
    dictionary_attack
    bruteforce_attack
    found_count
    get_result
    version
    detect_tier
    hashes_per_second
);

our $VERSION = '1.2.0';

require XSLoader;
XSLoader::load(__PACKAGE__, $XS_VERSION);

# ── Documentation ─────────────────────────────────────────────────────────
#
# A minimal, honest reference for the XS surface. Every function below maps one
# to one onto the C ABI in engines/engine-bridge/src/c_api.rs.
#
#   init()                      Initialise the engine. Returns 0 on success.
#   shutdown()                  Release engine state.
#   load_hashes($path)          Load a hash file. Returns the number loaded.
#   hash_count()                Number of hashes currently loaded.
#   verify($hash, $password)    1 when the password matches, 0 otherwise.
#   dictionary_attack($wl, $rules, $threads)
#                               Run a dictionary attack. Returns crack count.
#   bruteforce_attack($mask, $threads)
#                               Run a mask attack. Returns crack count.
#   found_count()               Cracks found by the last attack.
#   get_result($i)              Hash ref at index $i, or undef.
#   version()                   Library version string.
#   detect_tier()               Detected hardware tier.
#   hashes_per_second()         Last measured hash rate.
#
# Example:
#
#   use pwdcrack qw(init load_hashes dictionary_attack get_result);
#   init();
#   load_hashes('hashes.txt');
#   my $found = dictionary_attack('rockyou.txt', undef, 0);
#   for my $i (0 .. $found - 1) {
#       my $r = get_result($i);
#       print "$r->{hash}:$r->{password}\n";
#   }

1;
