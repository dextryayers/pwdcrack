# Run every RTL testbench under ModelSim, Questa or Vivado's xsim.
#
#   vsim -c -do scripts/simulate.tcl
#   vivado -mode batch -source scripts/simulate.tcl
#
# # Why this exists next to scripts/simulate.sh
#
# scripts/simulate.sh is the gate: it runs on any machine, needs no licence, and
# is what CI runs. This script is for the case where a vendor simulator is the
# one that will be used to synthesise, because it elaborates the same sources
# with a different front end, and a construct Icarus accepts and a vendor tool
# rejects is exactly the kind of thing that only shows up at bitstream time.
#
# # What it does not do
#
# It has not been run in this repository. No ModelSim, Questa or Vivado
# installation exists on the build machine, and claiming a result nobody
# observed is the thing this whole phase is about avoiding. The results
# recorded in docs/PHASE8_STATUS.md all come from scripts/simulate.sh under
# Icarus Verilog 12.
#
# # Differences from the Icarus path
#
#   * `vlog`/`vlib`/`vmap` instead of `iverilog`, so the sources are compiled
#     into a library first.
#   * `+incdir+` for `rtl/sim` and `rtl/sim/vectors`.
#   * `run -all` and then `quit -code`, so a testbench that calls `$fatal` ends
#     the run with a non zero status.
#   * Wrappers such as `ntlm_core` need the core they contain, exactly as in the
#     Icarus path; the list is kept in step with scripts/simulate.sh.

set src_dir [file normalize [file dirname [info script]]/../rtl]
set sim_dir [file join $src_dir sim]
set out_dir [file normalize [file dirname [info script]]/../build/vsim]

file mkdir $out_dir
cd $out_dir

vlib work
vmap work work

set incs [list "+incdir+$sim_dir" "+incdir+[file join $sim_dir vectors]"]

# Every core, in dependency order. Listing all of them for every testbench is
# wasteful but simple, and elaboration is not the slow part.
set cores [list \
    [file join $src_dir cores md5_core.sv] \
    [file join $src_dir cores md4_core.sv] \
    [file join $src_dir cores sha1_core.sv] \
    [file join $src_dir cores sha256_core.sv] \
    [file join $src_dir cores sha512_core.sv] \
    [file join $src_dir cores sha384_core.sv] \
    [file join $src_dir cores ripemd160_core.sv] \
    [file join $src_dir cores crc_accelerator.sv] \
    [file join $src_dir cores ntlm_core.sv] \
    [file join $src_dir top.sv] \
]

# Testbench module name to the files it needs beyond the shared list above.
set tb_list [list \
    "tb_padding|{}" \
    "tb_md5_core|{}" \
    "tb_md4_core|{}" \
    "tb_sha1_core|{}" \
    "tb_sha256_core|{}" \
    "tb_sha512_core|{}" \
    "tb_sha384_core|{}" \
    "tb_ripemd160_core|{}" \
    "tb_ntlm_core|{}" \
    "tb_crc_accelerator|{}" \
    "tb_top|{}" \
]

vlog -sv {*}$incs {*}$cores

set failures 0
foreach entry $tb_list {
    set name [lindex $entry 0]
    set extra [lindex $entry 1]
    set tb [file join $sim_dir $name.sv]
    if {![file exists $tb]} {
        puts "MISSING       $name  ([file tail $tb] does not exist)"
        incr failures
        continue
    }

    if {[catch {vlog -sv {*}$incs {*}$extra $tb} msg]} {
        puts "COMPILE FAIL  $name"
        puts $msg
        incr failures
        continue
    }

    # `run -all` rather than a fixed duration: the testbenches end with
    # `$finish` or `$fatal`, so the simulation stops when the work is done. The
    # tally is read from the transcript, because a testbench that ran and
    # compared nothing exits cleanly and would otherwise be counted as a pass.
    file delete -force transcript
    set code [catch {vsim -c -onfinish stop $name -do "run -all; quit"} msg]

    set tally "no tally"
    if {[file exists transcript]} {
        set fh [open transcript r]
        set txt [read $fh]
        close $fh
        if {[regexp {=== .*: ([0-9]+) passed, ([0-9]+) failed} $txt -> passed failed]} {
            set tally "$passed passed, $failed failed"
            if {$failed != 0} {
                incr failures
                puts "FAIL          $name  ($tally)"
                continue
            }
        }
    }
    if {$code != 0} {
        incr failures
        puts "RUN FAIL      $name  (vsim exited $code)"
        puts $msg
        continue
    }
    puts "PASS          $name  ($tally)"
}

puts ""
puts "  [expr {[llength $tb_list] - $failures}] passed, $failures failed"
puts ""
puts ""
puts "### Icarus remains the gate: scripts/simulate.sh ###"
puts "### This script exists to catch what a vendor front end rejects. ###"
puts ""