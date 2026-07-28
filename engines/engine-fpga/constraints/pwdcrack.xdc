# pwdcrack FPGA Timing Constraints
# Target: Xilinx Kintex UltraScale XCKU060
# Clock: 200MHz PCIe reference (5ns period)

# Primary clock from PCIe reference
create_clock -period 5.000 -name pcie_clk [get_ports pcie_clk]

# Generated clocks for core logic (synchronous to pcie_clk)
# All cores run at same rate as PCIe clock

# Input delays
set_input_delay -clock pcie_clk -max 2.0 [get_ports pcie_rx_data*]
set_input_delay -clock pcie_clk -min 0.5 [get_ports pcie_rx_data*]

# Output delays
set_output_delay -clock pcie_clk -max 2.5 [get_ports pcie_tx_data*]
set_output_delay -clock pcie_clk -min 0.5 [get_ports pcie_tx_data*]

# DDR4 interface constraints
set_output_delay -clock pcie_clk -max 1.5 [get_ports ddr_addr*]
set_output_delay -clock pcie_clk -min 0.3 [get_ports ddr_addr*]
set_output_delay -clock pcie_clk -max 1.5 [get_ports ddr_cke]

# False paths on UART (debug only)
set_false_path -from [get_ports uart_rx]
set_false_path -to [get_ports uart_tx]

# Clock groups (all synchronous)
set_clock_groups -group [get_clocks pcie_clk]

# Timing exceptions for pipeline stages
# All hash cores have 65/49 stage pipelines — multi-cycle within pipeline
# Pipeline registers are close together, let tool optimize

# Derate for process variation
set_timing_derate -early 0.95
set_timing_derate -late 1.05

# Report
puts "Constraints loaded: 200MHz target for pwdcrack FPGA cores"