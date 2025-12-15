//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Combine the addr and time capabilities to generate packet-level traces
//!

const std = @import("std");

const addr = @import("addrs.zig");
const time = @import("time.zig");
const conf = @import("config.zig");
const bp = @import("burst_process.zig");

const Burst = struct {
    key: time.FlowKey,
    start_time: f64,
    end_time: f64,
    packets: std.ArrayList(time.Packet),
    cur_pkt_idx: usize,

    pub fn init(
        key: time.FlowKey,
        start_time: f64,
        end_time: f64,
        packets: std.ArrayList(time.Packet),
    ) Burst {
        return Burst{
            .key = key,
            .start_time = start_time,
            .end_time = end_time,
            .packets = packets,
            .cur_pkt_idx = 0,
        };
    }
    pub fn deinit(self: Burst) void {
        self.packets.deinit();
    }

    pub fn compare(
        context: void,
        l: Burst,
        r: Burst,
    ) std.math.Order {
        _ = context;
        return std.math.order(l.start_time, r.start_time);
    }
};

// Pop returns smallest start_time first.
const BurstQueue = std.PriorityQueue(Burst, void, Burst.compare);

///
/// Generator definition
///
pub const Generator = struct {
    params: struct {
        time: conf.TimeParameters,
        addr: conf.AddrParameters,
    },

    src_map: addr.AddrMap,
    dst_map: addr.AddrMap,

    input_flows: *const time.TimeAnalyzer,
    bursts: BurstQueue,
    active_bursts: BurstQueue,

    allocator: std.mem.Allocator,
    rand: *std.Random,

    ///
    /// Create a new Generator.
    /// Note that the Generator only holds a pointer to the TimeAnalyzer and does not manage it's memory.
    ///
    pub fn init(
        allocator: std.mem.Allocator,
        rand: *std.Random,
        flows: *const time.TimeAnalyzer,
        time_params: conf.TimeParameters,
        addr_params: conf.AddrParameters,
    ) (error{OutOfMemory} || addr.AddrAnalyzerError)!Generator {
        const src_map = try get_addr_map(
            allocator,
            rand,
            &flows.flows,
            struct {
                fn f(k: time.FlowKey) u32 {
                    return k.saddr;
                }
            }.f,
            addr_params.src_sigma,
        );

        const dst_map = try get_addr_map(
            allocator,
            rand,
            &flows.flows,
            struct {
                fn f(k: time.FlowKey) u32 {
                    return k.daddr;
                }
            }.f,
            addr_params.dst_sigma,
        );

        var bursts: BurstQueue = try generate_bursts(allocator, rand, src_map, dst_map, &flows.flows, time_params);
        var active_bursts = BurstQueue.init(allocator, {});
        const first_burst = bursts.remove();
        try active_bursts.add(first_burst);

        return Generator{
            .params = .{ .time = time_params, .addr = addr_params },
            .src_map = src_map,
            .dst_map = dst_map,
            .input_flows = flows,
            .bursts = bursts,
            .active_bursts = active_bursts,
            .allocator = allocator,
            .rand = rand,
        };
    }

    pub fn deinit(self: *Generator) void {
        self.src_map.deinit();
        self.dst_map.deinit();
        {
            var it = self.bursts.iterator();
            while (it.next()) |elem| {
                elem.deinit();
            }
        }
        self.bursts.deinit();
        {
            var it = self.active_bursts.iterator();
            while (it.next()) |elem| {
                elem.deinit();
            }
        }
        self.active_bursts.deinit();
    }

    pub fn nextPacket(self: *Generator) error{OutOfMemory}!?struct { time.FlowKey, time.Packet } {

        // Get active burst from which this packet should come
        var next_active = blk: {
            if (self.active_bursts.peek()) |active| {
                if (self.bursts.peek()) |next| {
                    if (next.start_time < active.start_time) {
                        // Take next from self.bursts, leave active on self.active_bursts
                        break :blk self.bursts.remove();
                    } else {
                        // Take active from self.active_bursts, leave next on self.bursts
                        break :blk self.active_bursts.remove();
                    }
                } else {
                    break :blk self.active_bursts.remove();
                }
            } else if (self.bursts.peek()) |next| {
                _ = next;
                break :blk self.bursts.remove();
            } else {
                return null;
            }
        };

        // Extract the key and packet packet
        const key = next_active.key;
        const pkt = next_active.packets.items[next_active.cur_pkt_idx];

        // Advance the burst's pointer
        next_active.cur_pkt_idx += 1;

        // Push the burst back on active_bursts if it's not done.
        if (next_active.cur_pkt_idx < next_active.packets.items.len) {
            next_active.start_time = next_active.packets.items[next_active.cur_pkt_idx].time;
            try self.active_bursts.add(next_active);
        } else {
            next_active.deinit();
        }
        return .{ key, pkt };
    }
};

///
/// Create AddrMap for field determined by project of all flows in flows
///
fn get_addr_map(
    allocator: std.mem.Allocator,
    rand: *std.Random,
    flows: *const time.FlowMap,
    comptime project: fn (time.FlowKey) u32,
    sigma: f64,
) (error{OutOfMemory} || addr.AddrAnalyzerError)!addr.AddrMap {

    // Collect distinct addresses from flows
    var addrs = try addr.AddrAnalyzer.init(allocator);
    defer addrs.deinit();
    {
        var it = flows.keyIterator();
        while (it.next()) |k| {
            try addrs.addAddr(project(k.*));
        }
    }
    try addrs.prefixify();

    // Get singular scaling exponents
    var from_addrs = try allocator.alloc(struct { u32, f64 }, addrs.n());
    defer allocator.free(from_addrs);
    {
        var it = addrs.data[32].keyIterator();
        var i: u32 = 0;
        while (it.next()) |x| {
            const alpha = try addrs.getSingularity(x.*);
            from_addrs[i] = .{ x.*, alpha };
            i += 1;
        }
    }

    // Generate synthetic addresses at target sigma
    var to_addrs = try addr.generate(sigma, @intCast(addrs.n()), rand, allocator);
    defer to_addrs.deinit();

    // Create map
    return addr.AddrMap.init(allocator, rand, from_addrs, to_addrs.items);
}

pub const BurstTimes = struct {
    start_time: f64,
    end_time: f64,
    pkts: u32,
};

pub fn pareto(a: f64, m: f64, rand: *std.Random) f64 {
    return m * @exp(rand.*.floatExp(f64) / a);
}

///
/// Generate a Pareto renewal process for a single flow
///
fn burst_process(
    allocator: std.mem.Allocator,
    rand: *std.Random,
    config: conf.TimeParameters,
    start: f64,
    pkts: u32,
) error{OutOfMemory}![]BurstTimes {
    const pkts_per_sec: f64 = @as(f64, @floatFromInt(pkts)) / (config.total_duration - start);

    var bursts = std.ArrayList(BurstTimes).init(allocator);

    var cur = start;
    var remaining_pkts = pkts;
    while (cur < config.total_duration and remaining_pkts > 0) {
        const on_dur = pareto(config.a_on, config.m_on, rand);
        const off_dur = pareto(config.a_off, config.m_off, rand);
        const burst_pkts = blk: {
            const p = @as(u32, @intFromFloat(@floor(on_dur * pkts_per_sec))) + 1;
            if (p < remaining_pkts) {
                break :blk p;
            } else {
                break :blk remaining_pkts;
            }
        };
        var burst = BurstTimes{
            .start_time = cur,
            .end_time = cur + on_dur,
            .pkts = burst_pkts,
        };

        cur += on_dur;
        cur += off_dur;
        remaining_pkts -= burst_pkts;

        if (burst.end_time > config.total_duration) {
            burst.end_time = config.total_duration;
            burst.pkts += remaining_pkts;
        }
        try bursts.append(burst);
    }

    return bursts.toOwnedSlice();
}

///
/// Generate synthetic bursts and collect in a BurstQueue
///
fn generate_bursts(
    allocator: std.mem.Allocator,
    rand: *std.Random,
    src_map: addr.AddrMap,
    dst_map: addr.AddrMap,
    flows: *const time.FlowMap,
    time_params: conf.TimeParameters,
) error{OutOfMemory}!BurstQueue {

    // Generate flow arrival process
    const num_flows = flows.count();
    const flow_starts = try allocator.alloc(f64, num_flows);
    defer allocator.free(flow_starts);
    for (flow_starts) |*start| {
        start.* = rand.*.float(f64) * time_params.total_duration;
    }
    std.mem.sort(
        f64,
        flow_starts,
        {},
        struct {
            pub fn lt(context: void, l: f64, r: f64) bool {
                _ = context;
                return l < r;
            }
        }.lt,
    );

    // Sort flow keys based on time of first packet
    const flow_keys = try allocator.alloc(struct { time.FlowKey, f64 }, num_flows);
    defer allocator.free(flow_keys);
    {
        var it = flows.iterator();
        var i: u32 = 0;
        while (it.next()) |elem| {
            flow_keys[i].@"0" = elem.key_ptr.*;
            flow_keys[i].@"1" = elem.value_ptr.*.items[0].packets.items[0].time;
            i += 1;
        }
    }
    std.mem.sort(
        struct { time.FlowKey, f64 },
        flow_keys,
        {},
        struct {
            pub fn lt(context: void, l: struct { time.FlowKey, f64 }, r: struct { time.FlowKey, f64 }) bool {
                _ = context;
                return l.@"1" < r.@"1";
            }
        }.lt,
    );

    // Generate burst processes for each flow
    var bursts = BurstQueue.init(allocator, {});

    for (0..num_flows) |i| {
        const key = flow_keys[i].@"0";
        const in_flow_start = flow_keys[i].@"1";
        const in_bursts = flows.get(key).?.items;
        const out_flow_start = flow_starts[i];

        const flow_start = in_flow_start;
        _ = out_flow_start;

        var pkts: usize = 0;
        for (in_bursts) |burst| {
            pkts += burst.packets.items.len;
        }

        if (pkts == 1) {
            var packets = try std.ArrayList(time.Packet).initCapacity(allocator, 1);
            var pkt = in_bursts[0].packets.items[0];
            pkt.time = flow_start;
            try packets.append(pkt);

            const out_key = time.FlowKey{
                .saddr = src_map.get(key.saddr) orelse @panic("source address not in AddrMap!"),
                .daddr = dst_map.get(key.daddr) orelse @panic("destination address not in AddrMap!"),
            };

            const new_burst = Burst.init(out_key, pkt.time, pkt.time, packets);
            try bursts.add(new_burst);
        } else {
            const synth_bursts: []BurstTimes = try burst_process(
                allocator,
                rand,
                time_params,
                flow_start,
                @intCast(pkts),
            );
            defer allocator.free(synth_bursts);

            var in_burst_idx: u32 = 0;
            var in_pkt_idx: u32 = 0;
            for (synth_bursts) |burst| {
                var packets = try std.ArrayList(time.Packet).initCapacity(allocator, burst.pkts);
                const num_pkts_f = @as(f64, @floatFromInt(burst.pkts));

                for (0..burst.pkts) |j| {
                    if (in_burst_idx >= in_bursts.len) {
                        std.debug.print("pkts = {}, in_bursts.len = {}, num_pkts = {}\n", .{
                            pkts,
                            in_bursts.len,
                            burst.pkts,
                        });
                        @panic("Ran out of input bursts!");
                    }
                    var pkt = in_bursts[in_burst_idx].packets.items[in_pkt_idx];
                    in_pkt_idx += 1;
                    if (in_pkt_idx >= in_bursts[in_burst_idx].packets.items.len) {
                        in_pkt_idx = 0;
                        in_burst_idx += 1;
                    }
                    // pkt.time = burst.start_time + rand.*.float(f64) * (burst.end_time - burst.start_time);
                    const j_f = @as(f64, @floatFromInt(j));
                    pkt.time = burst.start_time + (j_f / num_pkts_f) * (burst.end_time - burst.start_time);
                    try packets.append(pkt);
                }

                // Sort packets in burst
                // std.mem.sort(time.Packet, packets.items, {}, time.Packet.lessThan);

                // Take burst start and end from packet timestamps
                const start_time = packets.items[0].time;
                const end_time = packets.items[packets.items.len - 1].time;

                const out_key = time.FlowKey{
                    .saddr = src_map.get(key.saddr) orelse @panic("source address not in AddrMap!"),
                    .daddr = dst_map.get(key.daddr) orelse @panic("destination address not in AddrMap!"),
                };

                const new_burst = Burst.init(out_key, start_time, end_time, packets);
                try bursts.add(new_burst);
            }
        }
    }

    return bursts;
}
