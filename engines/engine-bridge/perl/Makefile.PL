use ExtUtils::MakeMaker;
use File::Spec;

# Build against the Rust static library.
#
# The archive name comes from the package name in
# engines/engine-bridge/Cargo.toml, which is "engine-bridge", so cargo produces
# libengine_bridge.a. The previous -lpwdcrack referred to a name that does not
# exist, so linking always failed.
#
# Static, not shared, on purpose. A shared link would need LD_LIBRARY_PATH set
# for every run of the suite, and a wrong path there fails at load time with a
# message that does not mention the library at all.
#
# Two MakeMaker fields matter and they are easy to confuse:
#
#   LIB       search path for the compiler, as -L
#   LDDLFLAGS the same, for the linker, which is what links the shared object
#             this module actually loads
#
# Setting only LIB leaves the .so with undefined symbols and a load time error
# that names a symbol rather than the missing library, which is why the first
# build of this reported "undefined symbol: crack_version".
#
# Expected locations, in order:
#   $PWDCRACK_LIB_DIR      explicit override
#   $PROFILE (default debug)
#   ../../../target/<profile>

my $profile = $ENV{PROFILE} || 'debug';

# Absolute, because the build happens in a scratch directory that is not under
# the workspace. A relative -L computed here would resolve against the scratch
# directory and point at nothing.
my @dirs = grep { defined && length } (
    $ENV{PWDCRACK_LIB_DIR},
    File::Spec->rel2abs("../../../target/$profile"),
);

die "no Rust archive directory found; set PWDCRACK_LIB_DIR or run the build\n"
    unless grep { -f File::Spec->catfile($_, 'libengine_bridge.a') } @dirs;

my $archive_dir = (grep { -f File::Spec->catfile($_, 'libengine_bridge.a') } @dirs)[0];

# Everything in LDDLFLAGS rather than LIBS.
#
# MakeMaker filters LIBS before handing them to the linker: -ldl and -lm were
# dropped as "standard", and -lengine_bridge went with them, leaving a shared
# object whose symbols are all undefined. Writing the whole link line by hand is
# the only way to be sure what the linker was told.
# The archive goes in through MYEXTLIB, which is the mechanism Perl extensions
# use to bundle a static library.
#
# Two things LDDLFLAGS cannot do here:
#
#  * MakeMaker expands $(LDDLFLAGS) before $(OBJECT), and a static archive placed
#    before the object that needs it contributes nothing: the linker only pulls
#    archive members that satisfy symbols undefined at that point. MYEXTLIB is
#    expanded after $(OBJECT).
#  * -lengine_bridge would resolve to libengine_bridge.so, the cdylib sitting in
#    the same directory, leaving every crack_* symbol undefined at load time. The
#    error names a symbol, not the library, so it reads like a missing export.
#
# MakeMaker links a MYEXTLIB archive with --whole-archive, which is what a Rust
# staticlib needs: its entry points are not referenced from inside the archive,
# so a normal pull would leave them out.
my $archive = File::Spec->catfile($archive_dir, 'libengine_bridge.a');

WriteMakefile(
    NAME          => 'pwdcrack',
    VERSION_FROM  => 'lib/pwdcrack.pm',
    PREREQ_PM     => {},
    MYEXTLIB      => $archive,
    LIBS          => [ '-lpthread', '-ldl', '-lm' ],
    LDDLFLAGS     => '-shared',
    INC           => '-I.',
    XS            => { 'pwdcrack.xs' => 'pwdcrack.c' },
    CLEAN         => { 'pwdcrack.c' => 1 },
    # Without this, `make test` links a program that calls nothing and reports
    # success, which is how a binding that cannot work passes CI.
    test          => { TESTS => 't/*.t' },
);
