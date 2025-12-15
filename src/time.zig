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

    pub fn lessThan(
        context: void,
        l: Packet,
        r: Packet,
    ) bool {
        _ = context;
        return l.time < r.time;
    }
};

pub const Burst = struct {
    start_time: f64,
    end_time: f64,
    packets: std.ArrayList(Packet),

    pub fn init(allocator: std.mem.Allocator, time: f64) Burst {
        const packets = std.ArrayList(Packet).init(allocator);
        return Burst{
            .start_time = time,
            .end_time = time,
            .packets = packets,
        };
    }

    pub fn deinit(self: *Burst) void {
        self.packets.deinit();
    }
};

pub const FlowKey = struct {
    saddr: u32,
    daddr: u32,
};

pub const FlowMap = std.AutoHashMap(FlowKey, std.ArrayList(Burst));

///
/// FlowAnalyzer accumulates packets, sorting them into flows and grouping each flow into bursts of packets
///
pub const TimeAnalyzer = struct {
    flows: FlowMap,
    burst_timeout: f64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, burst_timeout_sec: f64) error{OutOfMemory}!TimeAnalyzer {
        const flows = FlowMap.init(allocator);
        return TimeAnalyzer{
            .flows = flows,
            .burst_timeout = burst_timeout_sec,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TimeAnalyzer) void {
        var it = self.flows.valueIterator();
        while (it.next()) |bursts| {
            for (bursts.items) |*burst| {
                burst.deinit();
            }
            bursts.deinit();
        }
        self.flows.deinit();
    }

    ///
    /// Add a packet with the given key and auxiliary fields.
    ///
    pub fn addPkt(self: *TimeAnalyzer, key: FlowKey, pkt: Packet) error{OutOfMemory}!void {
        const time = pkt.time;
        if (self.flows.getPtr(key)) |*bursts| {
            // Previously-observed key
            var burst: *Burst = &bursts.*.items[bursts.*.items.len - 1];
            if (time - burst.end_time >= self.burst_timeout) {
                // Handle burst timeout
                var new_burst = Burst.init(self.allocator, time);
                try new_burst.packets.append(pkt);
                try bursts.*.append(new_burst);
            } else {
                // Add packet to burst
                try burst.packets.append(pkt);
                burst.end_time = time;
            }
        } else {
            // First-time observing this key
            var new_burst = Burst.init(self.allocator, time);
            try new_burst.packets.append(pkt);
            var bursts = std.ArrayList(Burst).init(self.allocator);
            try bursts.append(new_burst); // LEAK
            try self.flows.put(key, bursts);
        }
    }

    ///
    /// Fits the burst on and off times (separately) over all flows to Pareto distributions using MLE:
    /// alpha = n / (sum_i ln(x_i / x_min)).
    ///
    /// Returns the estimated shape parameter for on and off distributions respectively.
    ///
    pub fn pareto_fit(self: TimeAnalyzer) error{OutOfMemory}!struct { f64, f64 } {
        const a_on = a_on_blk: {
            const on_durs = try self.get_on_durations();
            defer on_durs.deinit();

            var n: f64 = 0;
            var m: f64 = 0;
            for (on_durs.items) |dur| {
                if (dur >= self.burst_timeout) {
                    n += 1.0;
                    const x = @log(dur / self.burst_timeout);
                    m += (x - m) / n;
                }
            }
            break :a_on_blk (1.0 / m);
        };

        const a_off = a_off_blk: {
            const off_durs = try self.get_off_durations();
            defer off_durs.deinit();

            var n: f64 = 0;
            var m: f64 = 0;
            for (off_durs.items) |dur| {
                if (dur >= self.burst_timeout) {
                    n += 1.0;
                    const x = @log(dur / self.burst_timeout);
                    m += (x - m) / n;
                }
            }
            break :a_off_blk (1.0 / m);
        };

        return .{ a_on, a_off };
    }

    ///
    /// Return a ArrayList of on-durations
    /// Caller is responsible for calling ArrayList.deinit()
    ///
    pub fn get_on_durations(self: TimeAnalyzer) error{OutOfMemory}!std.ArrayList(f64) {
        var res = std.ArrayList(f64).init(self.allocator);
        var it = self.flows.valueIterator();
        while (it.next()) |bursts| {
            for (bursts.items) |burst| {
                try res.append(burst.end_time - burst.start_time);
            }
        }
        return res;
    }

    ///
    /// Return a ArrayList of off-durations
    /// Caller is responsible for calling ArrayList.deinit()
    ///
    pub fn get_off_durations(self: TimeAnalyzer) error{OutOfMemory}!std.ArrayList(f64) {
        var res = std.ArrayList(f64).init(self.allocator);
        var it = self.flows.valueIterator();
        while (it.next()) |bursts| {
            for (0..bursts.items.len - 1) |i| {
                const dt = bursts.items[i + 1].start_time - bursts.items[i].end_time;
                try res.append(dt);
            }
        }
        return res;
    }
};

///
/// Generate a sequence of bursts, denoted by {start_time, end_time, num_packets} tuples that
/// have Pareto on and off times with the specified shape parameters and are normalized to
/// fill the given duration (in seconds) and contain the total number of packets.
///
/// Because of rounding errors, the total number of packets in the generated bursts might not
/// exactly equal the requested number of packets. However, it is guaranteed to be less than
/// or equal to the requested number.
///
/// Caller is responsible for freeing the result.
///
pub fn generate(
    a_on: f64,
    m_on: f64,
    a_off: f64,
    m_off: f64,
    num_bursts: u32,
    total_packets: u32,
    total_duration: f64,
    rand: *std.Random,
    allocator: std.mem.Allocator,
) error{OutOfMemory}![]struct { f64, f64, u32 } {
    if (m_on <= 0.0 or m_off <= 0.0) {
        @panic("Can't have minimum value of Pareto distribution <= 0 (m_on or m_off)");
    }
    if (a_on <= 0.0 or a_off <= 0.0) {
        @panic("Can't have shape value of Pareto distribution <= 0 (a_on or a_off)");
    }

    if (num_bursts > total_packets) {
        @panic("Can't generate more bursts than the total number of packets");
    }

    var output = try allocator.alloc(struct { f64, f64, u32 }, num_bursts);

    // Get raw start and end times
    var cur: f64 = pareto(a_off, m_off, rand);
    var total_on: f64 = 0.0;
    for (0..num_bursts) |i| {
        const on_dur = pareto(a_on, m_on, rand);
        const off_dur = pareto(a_off, m_off, rand);
        output[i] = .{ cur, cur + on_dur, 0 };
        cur += on_dur;
        cur += off_dur;
        total_on += on_dur;
    }

    // Normalize to total_duration
    for (output) |*burst| {
        burst.*.@"0" *= (total_duration / cur);
        burst.*.@"1" *= (total_duration / cur);
    }
    total_on *= (total_duration / cur);

    // Distribute packets
    const aux_pkts = total_packets - num_bursts; // Reserve one packet per burst; only distribute remaining packets.
    const pkts_per_sec = @as(f64, @floatFromInt(aux_pkts)) / total_on;
    var on_pos: f64 = 0.000000001;
    var remaining_pkts = aux_pkts;
    for (output) |*burst| {
        const start_time = burst.@"0";
        const end_time = burst.@"1";
        const off_pos = on_pos + (end_time - start_time) * pkts_per_sec;
        var pkts = @as(u32, @intFromFloat(@floor(off_pos))) - @as(u32, @intFromFloat(@floor(on_pos)));

        // Because of rounding errors, the math here is not exact so enforce an exact upper bound.
        if (pkts > remaining_pkts) {
            pkts = remaining_pkts;
        }
        remaining_pkts -= pkts;

        burst.*.@"2" = pkts + 1;
        on_pos = off_pos;
    }
    return output;
}

pub fn pareto(a: f64, m: f64, rand: *std.Random) f64 {
    return m * @exp(rand.*.floatExp(f64) / a);
}
