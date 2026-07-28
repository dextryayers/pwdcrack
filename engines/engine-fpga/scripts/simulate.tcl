# pwdcrack FPGA Simulation Script
# Usage: vivado -mode batch -source scripts/simulate.tcl
# Or:     vsim -do scripts/simulate.tcl (for ModelSim)

set src_dir [file normalize [file dirname [info script]]/../rtl]

# Compile all sources
vlog -sv [glob $src_dir/*.sv]
vlog -sv [glob $src_dir/cores/*.sv]
vlog -sv [glob $src_dir/common/*.sv]

# Run individual core testbenches
puts "=== MD5 Core Test ==="
vsim -c md5_tb
run 1000 ns
log -r /*

puts "=== SHA256 Core Test ==="
vsim -c sha256_tb
run 1000 ns

puts "=== Top-Level Test ==="
vsim -c top_tb
run 2000 ns

puts "### All simulations complete ###"