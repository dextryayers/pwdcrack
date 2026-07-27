SHELL := /bin/bash
CARGO := cargo
TARGET_DIR := target

# ============================================================
# BUILD ALL
# ============================================================

.PHONY: all build build-release test clean

all: build-release

build:
	$(CARGO) build

build-release:
	$(CARGO) build --release

build-low:
	RUSTFLAGS="-C target-cpu=pentium4" $(CARGO) build --release --features tier-low

build-mid:
	RUSTFLAGS="-C target-cpu=haswell" $(CARGO) build --release --features tier-mid

build-high:
	RUSTFLAGS="-C target-cpu=native" $(CARGO) build --release --features tier-high

# Cross-compilation targets
build-arm64:
	rustup target add aarch64-unknown-linux-gnu
	$(CARGO) build --release --target aarch64-unknown-linux-gnu --features tier-mid

build-arm32:
	rustup target add armv7-unknown-linux-gnueabihf
	$(CARGO) build --release --target armv7-unknown-linux-gnueabihf --features tier-low

build-x86-32:
	rustup target add i686-unknown-linux-gnu
	$(CARGO) build --release --target i686-unknown-linux-gnu --features tier-low

build-android-arm64:
	rustup target add aarch64-linux-android
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang \
		$(CARGO) build --release --target aarch64-linux-android --features tier-mid

build-android-arm32:
	rustup target add armv7-linux-androideabi
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi21-clang \
		$(CARGO) build --release --target armv7-linux-androideabi --features tier-low

build-all: build build-release build-low build-mid build-high build-arm64 build-arm32 build-x86-32

# ============================================================
# TESTING
# ============================================================

test:
	$(CARGO) test

test-release:
	$(CARGO) test --release

test-all: test test-release
	$(CARGO) test --features tier-low
	$(CARGO) test --features tier-mid
	$(CARGO) test --features tier-high

# ============================================================
# BENCHMARK
# ============================================================

bench:
	$(CARGO) bench

bench-md5:
	./target/release/pwdcrack benchmark md5

bench-all:
	./target/release/pwdcrack benchmark all

# ============================================================
# CLEAN
# ============================================================

clean:
	$(CARGO) clean
	rm -rf $(TARGET_DIR)

distclean: clean
	rm -rf engines/*/target

# ============================================================
# PACKAGE
# ============================================================

package: build-release
	mkdir -p dist
	cp target/release/pwdcrack dist/
	cp target/release/libcrack-core.so dist/ 2>/dev/null || true
	strip dist/pwdcrack
	tar czf pwdcrack-$(shell git describe --tags 2>/dev/null || echo "dev")-x86_64-linux.tar.gz dist/
	rm -rf dist

# ============================================================
# DOCKER
# ============================================================

docker-low:
	docker build -f docker/Dockerfile.low -t pwdcrack:low .

docker-mid:
	docker build -f docker/Dockerfile.mid -t pwdcrack:mid .

docker-high:
	docker build -f docker/Dockerfile.high -t pwdcrack:high .

docker-android:
	docker build -f docker/Dockerfile.android -t pwdcrack:android .

# ============================================================
# INSTALL
# ============================================================

install: build-release
	cp target/release/pwdcrack /usr/local/bin/
	cp target/release/libcrack-core.so /usr/local/lib/ 2>/dev/null || true

uninstall:
	rm -f /usr/local/bin/pwdcrack
	rm -f /usr/local/lib/libcrack-core.so

# ============================================================
# HELP
# ============================================================

help:
	@echo "pwdcrack build targets:"
	@echo "  make              Build release"
	@echo "  make build        Debug build"
	@echo "  make build-low    Low-end optimized"
	@echo "  make build-mid    Mid-range optimized"
	@echo "  make build-high   High-end optimized (native)"
	@echo "  make build-arm64  Cross-compile for ARM64"
	@echo "  make build-arm32  Cross-compile for ARM32"
	@echo "  make test         Run all tests"
	@echo "  make bench        Run benchmarks"
	@echo "  make package      Create release tarball"
	@echo "  make install      Install to /usr/local"
	@echo "  make docker-mid   Build Docker image"
	@echo "  make clean        Remove build artifacts"
