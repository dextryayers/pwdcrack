#!/usr/bin/env bash
# Runs every RTL testbench and fails on any mismatch.
#
# # What it checks, and what it does not
#
# It checks that the generated vectors are current, that each testbench compiles,
# that it terminates, and that every comparison it makes holds. That is real
# verification of whatever the testbench exercises, which for every core here is
# the full digest against an independent oracle.
#
# It does not check synthesis, timing closure or resource utilisation. Those need
# Vivado or Quartus, neither of which is present on the build machine, and no
# utilisation or timing figure is claimed anywhere in this repository. See
# docs/FPGA_RESULTS.md for how to obtain one and where to record it.
#
# # Where the testbenches live
#
# `rtl/sim/`, named `tb_<core>.sv`. The older copies that sat next to the cores
# in `rtl/cores/` used two naming conventions, none of them compiled, and two of
# them asserted values their cores could not produce. They are gone.
#
# # Why a timeout
#
# A testbench that never finishes is a hang with no output, and it is
# indistinguishable from a core that is waiting for something that never arrives.
# Every run here is bounded. A testbench that hits the bound fails with a report
# of its own name, not as a stalled pipeline.
#
# # Where the vectors come from
#
# `rtl/sim/vectors/*.svh`, all emitted by scripts/gen-rtl-vectors.py from Python
# hashlib, zlib and a pure Python MD4. Nothing is transcribed. The drift check at
# the start regenerates them in memory and fails if the committed files differ,
# so a hand edited expectation is a build failure rather than a silent
# disagreement with the oracle.
#
# # Usage
#
#   scripts/simulate.sh                 every testbench
#   scripts/simulate.sh sha256           testbenches whose path contains "sha256"
#   VERBOSE=1 scripts/simulate.sh        show each testbench's full output
#   scripts/simulate.sh --inventory      list cores and whether each has vectors
#   scripts/simulate.sh --list           list the testbenches that would run

set -uo pipefail
cd "$(dirname "$0")/.."

RTL="engines/engine-fpga/rtl"
SIM="$RTL/sim"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

INVENTORY_ONLY=0
if [ "${1:-}" = "--inventory" ]; then
    INVENTORY_ONLY=1
    shift
fi

# ---- locate a simulator ----
# A system install is always preferred. Otherwise a private one, which
# scripts/setup-iverilog.sh unpacks without root.
if command -v iverilog >/dev/null 2>&1; then
    IVL_BIN="$(command -v iverilog)"
    VVP_BIN="$(command -v vvp)"
elif [ -x /tmp/pwdcrack-iverilog/usr/bin/iverilog ]; then
    IVL_BIN="/tmp/pwdcrack-iverilog/usr/bin/iverilog"
    VVP_BIN="/tmp/pwdcrack-iverilog/usr/bin/vvp"
    export IVL_ROOT="/tmp/pwdcrack-iverilog/usr/lib/x86_64-linux-gnu/ivl"
    export PATH="$IVL_ROOT:$IVL_BIN:$PATH"
elif [ -x /tmp/opencode/iverilog_root/usr/bin/iverilog ]; then
    IVL_BIN="/tmp/opencode/iverilog_root/usr/bin/iverilog"
    VVP_BIN="/tmp/opencode/iverilog_root/usr/bin/vvp"
    export IVL_ROOT="/tmp/opencode/iverilog_root/usr/lib/x86_64-linux-gnu/ivl"
    export PATH="$IVL_ROOT:$IVL_BIN:$PATH"
else
    cat >&2 <<'EOF'
no Verilog simulator found.

Install one, or unpack the Debian package without root:

  scripts/setup-iverilog.sh

which does:

  apt-get download iverilog
  dpkg-deb -x iverilog_*.deb /tmp/pwdcrack-iverilog
  ln -s lib/x86_64-linux-gnu /tmp/pwdcrack-iverilog/usr/x86_64-linux-gnu
EOF
    exit 2
fi

# ---- vectors must be current ----
# Before anything is simulated. A stale vector file means every result below is
# about an expectation nobody can account for.
if ! ./scripts/gen-rtl-vectors.py --check > "$WORK/vectors" 2>&1; then
    echo "VECTOR DRIFT"
    sed 's/^/    /' "$WORK/vectors"
    echo
    echo "  run scripts/gen-rtl-vectors.py --write and commit the result"
    exit 1
fi
VECTOR_COUNT=$(./scripts/gen-rtl-vectors.py --list | awk '{s+=$2} END {print s}')

# ---- collect testbenches ----
mapfile -t BENCHES < <(find "$SIM" -maxdepth 1 -name 'tb_*.sv' | sort)

if [ $# -gt 0 ]; then
    mapfile -t BENCHES < <(printf '%s\n' "${BENCHES[@]}" | grep -- "$1")
fi

if [ ${#BENCHES[@]} -eq 0 ]; then
    echo "no testbench matched"
    exit 2
fi

# ---- the inventory ----
# Every core in rtl/cores, whether or not it has a testbench. This is the answer
# to "what does this design actually contain", and it is printed rather than
# written down by hand for the same reason the testbenches are generated.
inventory() {
    printf '%-22s %-14s %s\n' "CORE" "VECTORS" "TESTBENCH"
    printf '%-22s %-14s %s\n' "----" "-------" "---------"
    local core vecs tb stem
    for core in $(cd "$RTL" && ls cores/*.sv common/*.sv 2>/dev/null | \
                  sed 's|.*/||; s|\.sv$||' | sort); do
        # The vector files are named after the algorithm, not the module:
        # vectors/md5.svh for md5_core. The CRC core is the exception, its file
        # is vectors/crc32.svh, so both spellings are tried.
        stem="${core%_core}"
        if [ -f "$SIM/vectors/$stem.svh" ]; then
            vecs=$(grep -c '^        check' "$SIM/vectors/$stem.svh")
        elif [ -f "$SIM/vectors/$core.svh" ]; then
            vecs=$(grep -c '^        check' "$SIM/vectors/$core.svh")
        elif [ -f "$SIM/vectors/crc32.svh" ] && [ "$core" = "crc_accelerator" ]; then
            vecs=$(grep -c '^        check' "$SIM/vectors/crc32.svh")
        else
            vecs="-"
        fi
        # A testbench is listed when it instantiates the core. Matching on the
        # bare name instead would credit sha512_core to tb_sha384_core, because
        # the wrapper mentions sha512_core in a comment.
        tb="-"
        local candidate
        for candidate in "$SIM"/tb_*.sv; do
            if [ -f "$candidate" ] && grep -qE "^[[:space:]]*$core[[:space:]]+(dut|u_)" "$candidate"; then
                tb="$(basename "$candidate")"
                break
            fi
        done
        printf '%-22s %-14s %s\n' "$core" "$vecs" "$tb"
    done
}

if [ "$INVENTORY_ONLY" = "1" ]; then
    inventory
    exit 0
fi

echo "simulator:  $($IVL_BIN -V 2>&1 | head -1)"
echo "vectors:    $VECTOR_COUNT generated, none drifted"
echo "testbenches: ${#BENCHES[@]}"
echo

# ---- the core under test ----
# `tb_md5_core` -> `cores/md5_core.sv`. An empty result means the testbench
# exercises only the shared helpers, which is a legitimate case: tb_padding has
# no core.
resolve_core() {
    local base="$1" candidate
    base="${base#tb_}"
    for candidate in "$RTL/cores/$base.sv" "$RTL/cores/${base%_core}.sv" \
                     "$RTL/cores/${base%_core}_opt.sv"; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# ---- extra sources a testbench needs ----
# A testbench that instantiates the top level needs every core it contains, and
# two cores are wrappers: `ntlm_core` contains `md4_core` and `sha384_core`
# contains `sha512_core`. Linking a wrapper without its inner core gives an
# elaboration error that names the missing module and nothing else, which is
# accurate and unhelpful at the same time.
extra_sources() {
    local tb_base="$1"
    case "$tb_base" in
        tb_top)            echo "$RTL/top.sv $RTL/cores/md5_core.sv $RTL/cores/md4_core.sv
                                   $RTL/cores/sha1_core.sv $RTL/cores/sha256_core.sv
                                   $RTL/cores/sha512_core.sv $RTL/cores/sha384_core.sv
                                   $RTL/cores/ripemd160_core.sv
                                   $RTL/cores/crc_accelerator.sv" ;;
        tb_ntlm_core)      echo "$RTL/cores/md4_core.sv" ;;
        tb_sha384_core)    echo "$RTL/cores/sha512_core.sv" ;;
        *)                 echo "" ;;
    esac
}

# How long one testbench may run. The slowest core is SHA-512 at 82 cycles per
# block over 22 vectors, plus the top level's 8, which is a few thousand
# simulation steps. The bound is generous; it exists to turn a hang into a
# failure.
RUN_TIMEOUT="${SIM_TIMEOUT:-120}"

PASS=0
FAIL=0
FAILED_LIST=()

for tb in "${BENCHES[@]}"; do
    name="$(basename "$tb" .sv)"
    out="$WORK/$name.vvp"
    log="$WORK/$name.log"

    incs=(-I"$SIM" -I"$SIM/vectors")
    core_src="$(resolve_core "$name" || true)"
    extra="$(extra_sources "$name")"
    # A testbench with no core of its own is compiled alone, which tb_padding is.
    [ -z "$core_src" ] && core_src=""
    # shellcheck disable=SC2086
    if ! timeout "$RUN_TIMEOUT" "$IVL_BIN" -g2012 "${incs[@]}" -o "$out" \
            $core_src $extra "$tb" > "$WORK/$name.compile" 2>&1; then
        if [ $? -eq 124 ]; then
            echo "COMPILE TIMEOUT  $name"
        else
            echo "COMPILE FAIL  $name"
        fi
        grep -v 'sorry: constant selects' "$WORK/$name.compile" | head -8 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
        echo
        continue
    fi

    if timeout "$RUN_TIMEOUT" "$VVP_BIN" "$out" > "$log" 2>&1; then
        # Exit status alone is not trusted. A testbench that ran and compared
        # nothing exits 0, and several of the originals did exactly that, so an
        # explicit pass tally is required.
        if grep -qE '=== .*: [0-9]+ passed, 0 failed' "$log"; then
            tally="$(grep -oE '[0-9]+ passed, 0 failed, [0-9]+ total' "$log" | head -1)"
            echo "PASS            $name  ($tally)"
            PASS=$((PASS + 1))
            [ "${VERBOSE:-0}" = "1" ] && sed 's/^/    /' "$log"
        else
            echo "NO ASSERT       $name  (exited 0 but reported no clean tally)"
            head -10 "$log" | sed 's/^/    /'
            FAIL=$((FAIL + 1))
            FAILED_LIST+=("$name")
        fi
    else
        status=$?
        if [ "$status" -eq 124 ]; then
            echo "RUN TIMEOUT     $name  (${RUN_TIMEOUT}s, the clock never stopped)"
        else
            echo "RUN FAIL        $name"
        fi
        head -14 "$log" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
    fi
    echo
done

echo "================================"
echo "  $PASS passed, $FAIL failed"
echo "================================"
if [ ${#FAILED_LIST[@]} -gt 0 ]; then
    echo "failed:"
    for f in "${FAILED_LIST[@]}"; do echo "  - $f"; done
fi
echo
echo "inventory:"
inventory

exit $(( FAIL > 0 ? 1 : 0 ))