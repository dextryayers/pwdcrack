use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Spec;

# Every Perl binding is exercised here, including the ones that were declared
# against an ABI that did not exist and could never have been called.
#
# The tests that matter most are the negative ones: a binding that croaks when it
# should return, or returns undef when it should croak, is worse than one that
# fails to build, because it looks like it works.

my $TARGET    = '8350c7ecc6d4706e12107df747eb6e71';
my $PLAINTEXT = 'pwdcrack-reference-candidate';

use_ok('pwdcrack') or BAIL_OUT("pwdcrack.pm did not load, so nothing below can run");

# ── introspection ────────────────────────────────────────────────────────

my $version = pwdcrack::version();
ok(defined $version && length $version, 'version() returned a non-empty string');

my $tier = pwdcrack::detect_tier();
ok(
    defined $tier && ($tier eq 'low' || $tier eq 'mid' || $tier eq 'high'),
    "detect_tier() returned a detected tier, got '" . (defined $tier ? $tier : 'undef') . "'"
);

is(pwdcrack::abi_version(), 1, 'abi_version() agrees with the Rust constant');
like(pwdcrack::panics_abort(), qr/^[01]$/, 'panics_abort() is 0 or 1');

# ── loading ──────────────────────────────────────────────────────────────

pwdcrack::init();

is(pwdcrack::total_hashes(), 0, 'a fresh engine has no hashes');
is(pwdcrack::found_count(), 0, 'a fresh engine has no results');
is(pwdcrack::hashes_per_second(), 0, 'the rate is zero before any attack');
is(pwdcrack::last_tested(), 0, 'nothing has been tested yet');

my $loaded = pwdcrack::load_string("$TARGET\n");
is($loaded, 1, 'load_string() recognised one MD5');
is(pwdcrack::total_hashes(), 1, 'the hash is counted');

my $identified = pwdcrack::identify_hash($TARGET);
isnt($identified, 'Unknown',
    'identify_hash() recognised a real MD5')
    or diag('identify_hash returned: ' . (defined $identified ? $identified : 'undef'));
like($identified, qr/MD5/i,
    'identify_hash() named the type it recognised');

is(pwdcrack::identify_hash('not a hash at all'), 'Unknown',
    'identify_hash() reports Unknown for a string no parser claimed');

# ── verification ─────────────────────────────────────────────────────────

# The three answers must stay three: a match, a mismatch, and a refusal.
is(pwdcrack::verify($TARGET, $PLAINTEXT), 1, 'the correct password verifies');
is(pwdcrack::verify($TARGET, 'not the password'), 0, 'a wrong password does not verify');

my $err = '';
eval { pwdcrack::verify('not a hash at all', $PLAINTEXT); 1 } or $err = $@;
like($err, qr/not recognised/,
    'an unrecognisable hash is a refusal, not a reported mismatch');

$err = '';
eval { pwdcrack::verify(undef, 'x'); 1 } or $err = $@;
like($err, qr/required/, 'a missing argument is refused');

# ── attacks ──────────────────────────────────────────────────────────────

my $dir = tempdir(CLEANUP => 1);
my $wordlist = File::Spec->catfile($dir, 'words.txt');
open my $fh, '>', $wordlist or die "cannot write $wordlist: $!";
print $fh "$PLAINTEXT\n";
close $fh;

my $cracked = pwdcrack::dictionary_attack($wordlist);
is($cracked, 1, 'dictionary_attack() cracked the hash');
is(pwdcrack::found_count(), 1, 'found_count() agrees');

is(pwdcrack::last_tested(), 1, 'one candidate was tested');
cmp_ok(pwdcrack::hashes_per_second(), '>', 0,
    'the rate is a real measurement after an attack, not a constant');

my $result = pwdcrack::get_result(0);
ok(ref $result eq 'HASH', 'get_result() returned a hash reference');
is($result->{hash}, $TARGET, 'the reported hash is the one that was asked about');
is($result->{password}, $PLAINTEXT, 'the reported password is the plaintext');
ok(exists $result->{hash_type}, 'the result carries a hash_type key');

is(pwdcrack::get_result(999), undef, 'an out of range index is undef, not garbage');

# Brute force over a literal mask: the keyspace is the plaintext itself.
pwdcrack::init();
pwdcrack::load_string($TARGET);
is(pwdcrack::bruteforce_attack($PLAINTEXT), 1,
    'bruteforce_attack() with a literal mask cracks the hash');

pwdcrack::init();
$err = '';
eval { pwdcrack::dictionary_attack('/nonexistent/pwdcrack/words.txt'); 1 } or $err = $@;
like($err, qr/refused/,
    'an attack with nothing loaded is refused, not silently run against nothing');

$err = '';
eval { pwdcrack::load_file('/nonexistent/pwdcrack/hashes.txt'); 1 } or $err = $@;
like($err, qr/refused/, 'an unreadable hash file is refused');

pwdcrack::shutdown();
is(pwdcrack::total_hashes(), 0, 'shutdown cleared the loaded hashes');

done_testing();