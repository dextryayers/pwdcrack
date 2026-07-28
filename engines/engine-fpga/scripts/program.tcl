# pwdcrack FPGA Programmer Script
# Usage: vivado -mode batch -source scripts/program.tcl

set bit_path [file normalize [file dirname [info script]]/../build/pwdcrack.bit]

# Open hardware manager
open_hw_manager
connect_hw_server -url localhost:3121
current_hw_target [get_hw_targets]
open_hw_target
current_hw_device [lindex [get_hw_devices] 0]
refresh_hw_device -update_hw_probes false

# Program FPGA
set_property PROGRAM.FILE $bit_path [current_hw_device]
program_hw_devices [current_hw_device]

puts "FPGA programmed: $bit_path"

# Verify
refresh_hw_device [lindex [get_hw_devices] 0]
puts "Programming complete. pwdcrack FPGA cores ready."

disconnect_hw_server
close_hw_manager