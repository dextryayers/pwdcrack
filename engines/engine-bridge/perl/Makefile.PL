use ExtUtils::MakeMaker;

# Build against the pwdcrack cdylib.
#
# The library target name comes from [lib] name in the root Cargo.toml, which is
# "pwdcrack", so the artefact is libpwdcrack.so on Linux and
# pwdcrack.dll on Windows. The previous -lcrack_core here referred to a name
# that never existed, so linking always failed.
#
# Expected locations, in order of preference:
#   $PWDCRACK_LIB_DIR      explicit override
#   ../../../target/release (cargo build --release at the workspace root)
#   ../../../target/debug   (cargo build at the workspace root)

my @lib_dirs = grep { defined && length } (
    $ENV{PWDCRACK_LIB_DIR},
    '../../../target/release',
    '../../../target/debug',
);

WriteMakefile(
    NAME          => 'pwdcrack',
    VERSION_FROM  => 'lib/pwdcrack.pm',
    PREREQ_PM     => {},
    LIBS          => [ '-lpwdcrack' ],
    LIB           => join(' ', @lib_dirs),
    INC           => '-I.',
    OBJECT        => 'pwdcrack.o',
    XS            => { 'pwdcrack.xs' => 'pwdcrack.c' },
    CLEAN         => { 'pwdcrack.c' => 1 },
);
