use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'pwdcrack',
    VERSION_FROM      => 'lib/pwdcrack.pm',
    PREREQ_PM         => {},
    LIBS              => ['-L../../target/release -lcrack_core'],
    INC               => '-I.',
    OBJECT            => 'pwdcrack.o',
    # XS file
    XS                => {'pwdcrack.xs' => 'pwdcrack.c'},
);
