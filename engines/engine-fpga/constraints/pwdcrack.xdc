# pwdcrack FPGA constraints.
#
# # Status: an example, not a validated constraint set
#
# No FPGA is present in this repository, no vendor tool is installed on the
# build machine, and this file has not been through Vivado's `check_timing` or
# `lint_xdc`. It is written against the ports `rtl/top.sv` actually has, so it is
# at least internally consistent with the design, and the previous version of it
# was not: it constrained `pcie_clk`, `pcie_rx_data*`, `ddr_addr*` and `uart_rx`,
# none of which are ports of anything in this repository. Applied to this design
# it would have produced `[get_ports pcie_clk]` matching nothing, and Vivado warns
# rather than fails, so the run would have continued and produced a timing report
# for a design with no constrained clock.
#
# Before using it: set PART to the device you have, add the pin locations and
# the I/O standards for that board, and run `report_timing -report_unconstrained`
# until it reports nothing.
#
# Usage:
#   vivado -mode batch -source scripts/build.tcl
#
# See docs/FPGA_RESULTS.md for what has and has not been measured.

# The one clock in the design. `create_clock` on a port that exists is the whole
# requirement; everything else is timing budget for the outside world.
#
# 300 MHz is the target from docs/plan.md P8.4.01, expressed as the period the
# tool will try to meet. It has not been met anywhere yet.
create_clock -name core_clk -period 3.333 [get_ports clk]

# The reset is asynchronous and deassertion is not synchronised in this design.
#
# That is stated here rather than fixed, because fixing it is a design change:
# a reset released at an arbitrary point in the clock cycle gives every register
# in the design a different metastability probability, and on an FPGA with
# hundreds of thousands of registers that is a real failure rate. The standard
# fix is a reset synchroniser in the top level. It is not here, so the honest
# constraint is a false path from the reset, which tells the tool not to time the
# recovery and removal arcs. That is the same as saying the reset timing is not
# checked, which is true.
set_false_path -from [get_ports rst_n]

# Input and output delays for a source synchronous interface at 300 MHz.
#
# These are budgets, not measurements: they say how much of the 3.333 ns cycle
# the outside world is allowed to need. For a board with a real interface, read
# them from that interface's specification.
set_input_delay  -clock core_clk -max 1.200 [get_ports {valid hash_sel[*] msg_blk[*] state_in[*]}]
set_input_delay  -clock core_clk -min 0.100 [get_ports {valid hash_sel[*] msg_blk[*] state_in[*]}]
set_input_delay  -clock core_clk -max 1.200 [get_ports {crc_valid crc_init crc_byte_last crc_byte_in[*]}]
set_input_delay  -clock core_clk -min 0.100 [get_ports {crc_valid crc_init crc_byte_last crc_byte_in[*]}]

set_output_delay -clock core_clk -max 1.500 [get_ports {ready done digest_out[*] crc_out[*] crc_done}]
set_output_delay -clock core_clk -min 0.100 [get_ports {ready done digest_out[*] crc_out[*] crc_done}]

# The cores are all driven from the same clock and none of them generates one.
set_clock_groups -group [get_clocks core_clk]

# Process variation. Vivado applies a derate by default; these make it explicit
# so a change here is a deliberate act rather than an inherited default.
set_timing_derate -early 0.95
set_timing_derate -late 1.05