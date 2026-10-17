# pwdcrack FPGA synthesis, implementation and bitstream.
#
#   vivado -mode batch -source scripts/build.tcl
#
# # Status: never run
#
# No Vivado installation exists on the build machine for this repository, so
# nothing below has produced a bitstream, a utilisation number or a timing
# number here. The script is written to be run on a machine that has Vivado, and
# to fail loudly when something is wrong rather than to produce a plausible
# report.
#
# What the previous version of this script claimed is worth recording: it read
# every .sv file in the directory, which meant the unverified cores were included
# in the design, and it printed "Cores: MD5, SHA256, NTLM (fully pipelined)",
# which was true of one core and false of the other two.
#
# This version reads an explicit file list, checks the constraints apply to
# ports that exist, and fails on unconstrained endpoints.
#
# Results go in docs/FPGA_RESULTS.md.

set part "xc7a200t-2fbg484-2"
set top pwdcrack_top
set src_dir [file normalize [file dirname [info script]]/../rtl]
set out_dir [file normalize [file dirname [info script]]/../build/vivado]

# The verified cores, in dependency order. sha384_core contains a sha512_core and
# ntlm_core contains an md4_core, so the order matters.
set sources [list \
    [file join $src_dir cores md5_core.sv] \
    [file join $src_dir cores md4_core.sv] \
    [file join $src_dir cores ntlm_core.sv] \
    [file join $src_dir cores sha1_core.sv] \
    [file join $src_dir cores sha256_core.sv] \
    [file join $src_dir cores sha512_core.sv] \
    [file join $src_dir cores sha384_core.sv] \
    [file join $src_dir cores ripemd160_core.sv] \
    [file join $src_dir cores crc_accelerator.sv] \
    [file join $src_dir top.sv] \
]

file mkdir $out_dir
cd $out_dir

create_project pwdcrack_fpga . -part $part -force
set_property target_language Verilog [current_project]

foreach f $sources {
    if {![file exists $f]} {
        error "source file listed in build.tcl does not exist: $f"
    }
    read_verilog -sv $f
}
set_property top $top [current_fileset]

# Check the constraints before using them. An unmatched get_ports returns an empty
# collection and Vivado warns rather than fails, so a constraint file naming
# ports this design does not have produces a timing report for a design with no
# constrained clock, and that report looks like a result.
read_xdc [file normalize [file join $src_dir .. constraints pwdcrack.xdc]]
if {[llength [get_ports -quiet clk]] != 1} {
    error "the constraint file names a 'clk' port and this design does not have one.
Check scripts/build.tcl's file list against rtl/top.sv."
}

synth_design -top $top -part $part -flatten_hierarchy rebuilt
write_checkpoint -force post_synth.dcp

opt_design
place_design
route_design
write_checkpoint -force post_route.dcp

# Unconstrained endpoints are a failure, not a warning. A report that silently
# omits the register to register paths is worse than no report.
set unconstrained [get_timing_paths -report_unconstrained -max_paths 1 -nworst 1]
if {[llength $unconstrained] > 0} {
    error "there are unconstrained endpoints. Run:
    report_timing -report_unconstrained -file build/vivado/unconstrained.rpt
and fix the constraints before trusting any timing number."
}

write_bitstream -force pwdcrack.bit
report_utilization -file utilization.rpt
report_timing -summary -file timing.rpt
report_timing -report_unconstrained -file unconstrained.rpt
report_power -file power.rpt

puts ""
puts "Build complete."
puts "  part:     $part"
puts "  clock:    see constraints/pwdcrack.xdc"
puts "  reports:  $out_dir"
puts ""
puts "Record these in docs/FPGA_RESULTS.md, with the tool version and the commit."
puts "A number without those three things is not a measurement."