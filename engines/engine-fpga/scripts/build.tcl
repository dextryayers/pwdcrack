# pwdcrack FPGA Bitstream Build Script
# Usage: vivado -mode batch -source scripts/build.tcl

set part xcku060-ffva1156-2-e
set top pwdcrack_top
set src_dir [file normalize [file dirname [info script]]/../rtl]

create_project pwdcrack_fpga ./build/pwdcrack_fpga -part $part -force

# Read RTL sources
read_verilog -sv [glob $src_dir/*.sv]
read_verilog -sv [glob $src_dir/cores/*.sv]
read_verilog -sv [glob $src_dir/common/*.sv]

# Read constraints
read_xdc [file normalize [file dirname [info script]]/../constraints/pwdcrack.xdc]

# Synthesize
synth_design -top $top -part $part -flatten_hierarchy rebuilt
write_checkpoint -force ./build/post_synth.dcp

# Place and route
opt_design
place_design
route_design
write_checkpoint -force ./build/post_route.dcp

# Generate bitstream
write_bitstream -force ./build/pwdcrack.bit
write_bitstream -force -bin_file ./build/pwdcrack.bin

# Report utilization and timing
report_utilization -file ./build/utilization.rpt
report_timing -file ./build/timing.rpt
report_power -file ./build/power.rpt

puts "Build complete: pwdcrack.bit generated"
puts "Target: $part @ 200MHz"
puts "Cores: MD5, SHA256, NTLM (fully pipelined)"