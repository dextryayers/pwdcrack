#!/usr/bin/env bash
# Runs every RTL testbench under Icarus Verilog and fails on any mismatch.
#
# # Where the testbenches live
#
# `rtl/sim/`, named `tb_<core>_core.sv`. The older copies that sat next to the
# cores in `rtl/cores/` used two different naming conventions and none of them
# compiled, because each was written in SystemVerilog that Icarus Verilog 12
# cannot parse. See `rtl/sim/tb_common.svh` for the four specific limitations it
# works around and how each was confirmed.
#
# A testbench with no matching core, such as `tb_padding.sv`, is compiled alone.
#
# # Why a local extract rather than a system install
#
# This machine has no Verilog simulator and `sudo` needs a password, so
# iverilog cannot be installed. It ships as a plain .deb that unpacks without
# root:
#
#   apt-get download iverilog
#   dpkg-deb -x iverilog_*.deb ivroot
#
# The unpacked tree is self contained and needs IVL_ROOT pointing at it. A
# symlink from usr/x86_64-linux-gnu to usr/lib/x86_64-linux-gnu is required,
# because the Debian build resolves its own root relative to that path.
# `scripts/setup-iverilog.sh` does this and prints the path to add to PATH. A
# system iverilog is preferred when one exists.
#
# # What this does and does not check
#
# It checks that a testbench compiles, runs, and that every comparison it makes
# holds. That is real verification of whatever the testbench exercises.
#
# It does not check synthesis, timing closure, or resource utilisation. Those
# need Vivado or Quartus, neither of which is present here, and no utilisation or
# timing figure is claimed anywhere. See docs/PHASE8_STATUS.md.
#
# # Usage
#
#   scripts/simulate.sh              run every testbench
#   scripts/simulate.sh md5          run testbenches whose path contains "md5"
#   VERBOSE=1 scripts/simulate.sh    show each testbench's full output

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
    cat >&2 <<'EOF'
no Verilog simulator found.

Install one, or unpack the Debian package without root:

  apt-get download iverilog
  dpkg-deb -x iverilog_*.deb /tmp/opencode/iverilog_root
  ln -s lib/x86_64-linux-gnu /tmp/opencode/iverilog_root/usr/x86_64-linux-gnu

scripts/setup-iverilog.sh does all three.
EOF
    exit 2
fi

echo "simulator: $($IVL_BIN -V 2>&1 | head -1)"

# ---- collect testbenches ----
#
# Only rtl/sim is searched. The testbenches that used to sit in rtl/cores were
# written in SystemVerilog Icarus Verilog 12 cannot parse, none of them ever ran,
# and several stated wrong expected values. They are not part of the report:
# a list that is mostly known dead entries hides the two that matter.
#
# Every testbench in rtl/sim follows the tb_<core>_core.sv convention and includes
# tb_common.svh. A testbench with no matching core, such as tb_padding, is
# compiled alone.
mapfile -t BENCHES < <(find "$SIM" -name 'tb_*.sv' 2>/dev/null | sort)

if [ -n "${1:-}" ]; then
    mapfile -t BENCHES < <(printf '%s\n' "${BENCHES[@]}" | grep -- "$1")
fi

if [ ${#BENCHES[@]} -eq 0 ]; then
    echo "no testbench matched"
    exit 2
fi

echo "testbenches: ${#BENCHES[@]}"
echo

# ---- resolve the core under test ----
#
# `tb_md5_core.sv` -> `md5_core.sv`, then `md5.sv`, then `md5_opt.sv`.
# Empty output means the testbench exercises only the shared helpers, which is a
# legitimate case: tb_padding has no core.
resolve_core() {
    local tb="$1" base
    base="$(basename "$tb" .sv)"
    base="${base#tb_}"            # tb_md5_core -> md5_core
    base="${base%_core}"          # md5_core    -> md5
    local d
    for d in "$RTL/cores" "$RTL"; do
        [ -d "$d" ] || continue
        local c
        for c in "$d/${base}_core.sv" "$d/${base}.sv" "$d/${base}_opt.sv"; do
            if [ -f "$c" ] && [ "$c" != "$tb" ]; then
                echo "$c"
                return 0
            fi
        done
    done
    return 1
}

PASS=0
FAIL=0
FAILED_LIST=()

for tb in "${BENCHES[@]}"; do
    name="$(basename "$tb" .sv)"
    out="$WORK/$name.vvp"

    incs=(-I"$SIM")
    for d in "$RTL"/*/; do
        [ -d "$d" ] && incs+=("-I${d%/}")
    done

    core_src="$(resolve_core "$tb" || true)"

    if [ -z "$core_src" ]; then
        # No core to link. The testbench must then be self contained apart from
        # the shared header, which is what tb_padding is.
        echo "LONE          $name  (no core matched, compiling alone)"
    else
        echo "CORE          $name -> $(basename "$core_src")"
    fi

    # shellcheck disable=SC2086
    if ! "$IVL_BIN" -g2012 -o "$out" "${incs[@]}" $core_src "$tb" \
            > "$WORK/$name.compile" 2>&1; then
        echo "COMPILE FAIL  $name"
        sed 's/^/    /' "$WORK/$name.compile" | head -8
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$name")
        echo
        continue
    fi

    if "$VVP_BIN" "$out" > "$WORK/$name.run" 2>&1; then
        # Exit status alone is not trusted. A testbench that ran but compared
        # nothing exits 0, and several of the originals did exactly that, so an
        # explicit pass tally is required.
        if grep -qE '=== .*: [0-9]+ passed, 0 failed' "$WORK/$name.run"; then
            tally="$(grep -oE '[0-9]+ passed, [0-9]+ failed, [0-9]+ total' \
                    "$WORK/$name.run" | head -1)"
            echo "PASS          $name  ($tally)"
            PASS=$((PASS + 1))
            [ "${VERBOSE:-0}" = "1" ] && sed 's/^/    /' "$WORK/$name.run"
        else
            echo "NO ASSERT     $name  (exited 0 but reported no clean tally)"
            sed 's/^/    /' "$WORK/$name.run" | head -10
            FAIL=$((FAIL + 1))
            FAILED_LIST+=("$name")
        fi
    else
        echo "RUN FAIL      $name"
        sed 's/^/    /' "$WORK/$name.run" | head -14
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

exit $(( FAIL > 0 ? 1 : 0 ))