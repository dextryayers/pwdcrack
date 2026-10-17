#!/usr/bin/env bash
# Runs every RTL testbench under Icarus Verilog and fails on any mismatch.
#
# # Why a local extract rather than a system install
#
# This machine has no Verilog simulator and `sudo` needs a password, so
# iverilog cannot be installed. It is distributed as a plain .deb, which can be
# unpacked without root:
#
#   apt-get download iverilog
#   dpkg-deb -x iverilog_*.deb ivroot
#
# The unpacked tree is self contained and needs only IVL_ROOT pointing at it.
# `scripts/setup-iverilog.sh` does this and prints the path to add to PATH.
# If a system iverilog is present, that one is used instead.
#
# # What this does and does not check
#
# It checks that a testbench runs and that its assertions hold. That is real
# verification of whatever the testbench actually exercises.
#
# It does not check synthesis, timing closure, or resource utilisation. Those
# need Vivado or Quartus, neither of which is present here, and no utilisation or
# timing figure is claimed anywhere. See docs/PHASE8_STATUS.md.
#
# # Usage
#
#   scripts/simulate.sh              run every testbench
#   scripts/simulate.sh md5          run testbenches whose name contains "md5"

set -uo pipefail
cd "$(dirname "$0")/.."

RTL="engines/engine-fpga/rtl"
SIM="$RTL/sim"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- locate a simulator ----
if command -v iverilog >/dev/null 2>&1; then
    IVL_BIN="$(command -v iverilog)"
    VVP_BIN="$(command -v vvp)"
elif [ -x /tmp/opencode/iverilog_root/usr/bin/iverilog ]; then
    IVL_BIN="/tmp/opencode/iverilog_root/usr/bin/iverilog"
    VVP_BIN="/tmp/opencode/iverilog_root/usr/bin/vvp"
    export IVL_ROOT="/tmp/opencode/iverilog_root/usr/lib/x86_64-linux-gnu/ivl"
    export PATH="$IVL_ROOT:$PATH"
else
    echo "no Verilog simulator found."
    echo
    echo "Install one, or unpack the Debian package without root:"
    echo "  apt-get download iverilog"
    echo "  dpkg-deb -x iverilog_*.deb /tmp/opencode/iverilog_root"
    echo "then re-run. scripts/setup-iverilog.sh does both."
    exit 2
fi

echo "simulator: $($IVL_BIN -V 2>&1 | head -1)"

# ---- collect testbenches ----
# Both naming conventions are accepted so nothing is silently skipped:
#   tb_<name>_core.sv   the convention the plan asks for
#   <name>_tb.sv        the convention already used by three cores
mapfile -t BENCHES < <(
    find "$RTL" -name 'tb_*.sv' -o -name '*_tb.sv' 2>/dev/null | sort
)

if [ -n "${1:-}" ]; then
    mapfile -t BENCHES < <(printf '%s\n' "${BENCHES[@]}" | grep -- "$1")
fi

if [ ${#BENCHES[@]} -eq 0 ]; then
    echo "no testbench matched"
    exit 2
fi

echo "testbenches: ${#BENCHES[@]}"
echo

PASS=0
FAIL=0
FAILED_LIST=()

for tb in "${BENCHES[@]}"; do
    name="$(basename "$tb" .sv)"
    out="$WORK/$name.vvp"

    # Every core directory is on the include path so a testbench can pull in the
    # shared tb_common.svh.
    incs=(-I"$RTL/common" -I"$SIM" -I"$RTL/cores")
    for d in "$RTL"/*/; do
        [ -d "$d" ] && incs+=("-I${d%/}")
    done

    # Compile the core under test alongside the testbench.
    #
    # A testbench instantiates a module by name, and iverilog needs that module's
    # source in the compile set. Passing only the testbench produced
    # "Unknown module type" for every core, which looks like a broken design and
    # is actually a broken invocation. The core is found by matching the
    # testbench name against the core files, which is why both naming
    # conventions are handled: tb_<name>_core.sv and <name>_tb.sv.
    core_src=""
    for cand in "$RTL/cores/${name#tb_}.sv" "$RTL/cores/${name%.sv}.sv" \
                "$RTL/cores/${name%%_*}.sv" "$RTL/cores/${name%_core}.sv" \
                "$RTL/cores/${name%.sv}.sv"; do
        # Strip a trailing _core from the derived name and try the _opt variant.
        base="$(basename "$cand" .sv)"
        for v in "$RTL/cores/$base.sv" "$RTL/cores/${base%_core}.sv" \
                 "$RTL/cores/${base%_core}_core.sv" "$RTL/cores/${base%.sv}_core.sv"; do
            if [ -f "$v" ] && [ "$v" != "$tb" ]; then
                core_src="$v"
                break 2
            fi
        done
    done

    # top_tb drives the whole design, so it needs every source, not one core.
    if [ "$name" = "top_tb" ]; then
        core_src="$(find "$RTL" -name '*.sv' ! -name 'tb_*' ! -name '*_tb.sv' | sort | tr '\n' ' ')"
    fi

    if [ -z "$core_src" ]; then
        echo "NO CORE       $name  (no core source matched this testbench)"
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
        continue
    fi

    # shellcheck disable=SC2086
    if ! "$IVL_BIN" -g2012 -o "$out" "${incs[@]}" $core_src "$tb" > "$WORK/$name.compile" 2>&1; then
        echo "COMPILE FAIL  $name"
        sed 's/^/    /' "$WORK/$name.compile" | head -8
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
        continue
    fi

    if "$VVP_BIN" "$out" > "$WORK/$name.run" 2>&1; then
        # A testbench that runs but prints no pass marker has not verified
        # anything, so require an explicit success line rather than trusting the
        # exit status alone. Several of the original testbenches exited 0 without
        # ever comparing an output.
        if grep -qiE '\b(all tests? passed|test(s)? passed|PASS)\b' "$WORK/$name.run"; then
            echo "PASS          $name"
            PASS=$((PASS + 1))
        else
            echo "NO ASSERT     $name  (ran but printed no pass marker)"
            sed 's/^/    /' "$WORK/$name.run" | head -6
            FAIL=$((FAIL + 1))
            FAILED_LIST+=("$name")
        fi
    else
        echo "RUN FAIL      $name"
        sed 's/^/    /' "$WORK/$name.run" | head -12
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
    fi
done

echo
echo "================================"
echo "  $PASS passed, $FAIL failed"
echo "================================"
if [ ${#FAILED_LIST[@]} -gt 0 ]; then
    echo "failed:"
    for f in "${FAILED_LIST[@]}"; do echo "  - $f"; done
fi

exit $(( FAIL > 0 ? 1 : 0 ))