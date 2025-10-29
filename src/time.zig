//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Functions for dealing with trace timeseries
//!

const std = @import("std");

///
/// Struct for keeping track of the non-key information associated with each packet.
///
pub const Packet = struct {
    time: f64,
    sport: u16,
    dport: u16,
    proto: u8,
    len: u16,
    tcpflags: u8,
};

pub const Burst = struct {
    start_time: f64,
    end_time: f64,
    packets: std.ArrayList(Packet),
};

pub const Flow = struct {
    saddr: u32,
    daddr: u32,
    bursts: std.ArrayList(Burst),
};


pub const TimeAnalyzer = struct {
    // TODO
};

pub fn generate(a_on: f64, a_off: f64, num_bursts: u32) std.ArrayList(struct { f64, f64 }) {
    // TODO
}
