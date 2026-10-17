# pwdcrack
#
# Thin shortcuts over cargo. The build tool is Cargo, not make: every recipe
# below is one cargo invocation, and the compilation itself is driven by
# Cargo.toml and the workspace members.
#
# Why this file exists at all: to make the common commands short. Anything that
# is not a shortcut belongs in scripts/, not here. Scripts are grouped by theme
# and can be read top to bottom; a Makefile cannot be both.
#
#     make            release build
#     make test       run the test suite
#     make matrix     build every feature combination
#     make help       list targets

CARGO  := cargo
PREFIX ?= /usr/local

# Library artefact name comes from [lib] name in Cargo.toml, which is
# "pwdcrack". An earlier version of this file referenced libcrack-core.so,
# which never existed, so those copies silently did nothing.
LIBNAME := libpwdcrack.so

.PHONY: all build release test bench clean install uninstall package matrix help

all: release

## build: debug build, fast iteration
build:
	$(CARGO) build

## release: optimised build, the one you run
release:
	$(CARGO) build --release

## test: unit and integration tests
test:
	$(CARGO) test

## bench: criterion benchmarks
bench:
	$(CARGO) bench

## matrix: build every feature combination
# Catches feature-gated compile errors that a default build hides. This project
# shipped three of those, which is why it exists.
matrix:
	./scripts/test-matrix.sh

## clean: remove build artefacts
clean:
	$(CARGO) clean

## install: install the binary to $(PREFIX)/bin
install: release
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 target/release/pwdcrack $(DESTDIR)$(PREFIX)/bin/
	@if [ -f target/release/$(LIBNAME) ]; then \
		install -d $(DESTDIR)$(PREFIX)/lib; \
		install -m 0644 target/release/$(LIBNAME) $(DESTDIR)$(PREFIX)/lib/; \
		echo "installed $(LIBNAME)"; \
	fi

## uninstall: remove an installation
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pwdcrack
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LIBNAME)

## package: build a release tarball
package:
	./scripts/package.sh

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
