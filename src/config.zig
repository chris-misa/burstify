//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Definitions for the json configuration files
//!

pub const Config = struct {
    input_pcap: []u8, // name of base pcap file to read
    targets: []Target, // list of parameter setting to run

    src_out: bool, // write extra output file with list of source addresses
    dst_out: bool, // write extra output file with list of destination addresses
    burst_out: bool, // write extra output file with start, end, and number of packets of each burst
};

pub const Target = struct {
    output_pcap: []u8, // Name of the output generated from this target
    time: TimeParameters,
    addr: AddrParameters,
};

///
/// Parameters controlling the time-domain process
///
pub const TimeParameters = struct {
    a_on: f64, // shape parameter of the on-period Pareto distribution
    m_on: f64, // position parameter of the on-period Pareto distribution
    a_off: f64, // shape parameter of the off-period Pareto distribution
    m_off: f64, // position parameter of the off-period Pareto distribution
    a_pkts: f64, // shape parameter of the packets-per-burst distribution
    m_pkts: f64, // position parameter of the packets-per-burst distribution
    flow_rate: f64, // mean flow-arrival rate
    total_duration: f64, // total duration of the output trace
};

///
/// Parameters controlling the address space-domain process
///
pub const AddrParameters = struct {
    src_sigma: f64, // parameter of the logit-normal generator in the source address cascade
    dst_sigma: f64, // parameter of the logit-normal generator in the destination address cascade
};
