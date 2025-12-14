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
        const src_map = try get_addr_map(allocator, rand, &flows.flows, struct {
            fn f(k: time.FlowKey) u32 {
                return k.saddr;
            }
        }.f, addr_params.src_sigma);

        const dst_map = try get_addr_map(allocator, rand, &flows.flows, struct {
            fn f(k: time.FlowKey) u32 {
                return k.daddr;
            }
        }.f, addr_params.dst_sigma);

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

        // Extract the packet
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
        return .{ next_active.key, pkt };
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
    var bursts = BurstQueue.init(allocator, {});

    var burst_process = bp.BurstGenerator.init(allocator, rand, time_params);
    // const flow_count = flows.count();
    // var flow_idx: u32 = 0;

    var it = flows.iterator();
    while (it.next()) |elem| {
        const input_key: *time.FlowKey = elem.key_ptr;
        const input_bursts: []time.Burst = elem.value_ptr.items;

        // Count total packets
        var pkts: usize = 0;
        for (input_bursts) |burst| {
            pkts += burst.packets.items.len;
        }

        // flow_idx += 1;
        // if (flow_idx % 10000 == 0) {
        //     std.debug.print("{d}/{d}\n", .{ flow_idx, flow_count });
        // }

        // if (pkts == 1) {
        //     // Avoid overheads of generating bursts for single-packet flows
        //     // Just take packet's arrival time as uniform random in range implied by duration
        //
        //     if (input_bursts.len != 1 or input_bursts[0].packets.items.len != 1) {
        //         @panic("in single-packet flow case, but the flow has more than one burst or packets!");
        //     }
        //
        //     var pkt = input_bursts[0].packets.items[0];
        //     pkt.time = rand.*.float(f64) * time_params.total_duration;
        //
        //     var packets = try std.ArrayList(time.Packet).initCapacity(allocator, 1);
        //     try packets.append(pkt);
        //
        //     const key = time.FlowKey{
        //         .saddr = src_map.get(input_key.saddr) orelse @panic("source address not in AddrMap!"),
        //         .daddr = dst_map.get(input_key.daddr) orelse @panic("destination address not in AddrMap!"),
        //     };
        //
        //     const new_burst = Burst.init(key, pkt.time, pkt.time, packets);
        //     try bursts.add(new_burst);
        // } else
        {

            // Generate synth bursts
            const synth_bursts: []bp.BurstTimes = try burst_process.next(@intCast(pkts));
            // const synth_bursts: []struct { f64, f64, u32 } = try time.generate(
            //     time_params.a_on,
            //     time_params.m_on,
            //     time_params.a_off,
            //     time_params.m_off,
            //     @intCast(input_bursts.len),
            //     @intCast(pkts),
            //     time_params.total_duration,
            //     rand,
            //     allocator,
            // );
            defer allocator.free(synth_bursts);

            // Copy packets from this flow into synth bursts
            var input_burst_idx: u32 = 0;
            var input_pkt_idx: u32 = 0;

            for (synth_bursts) |burst| {
                // const start_time: f64 = burst.@"0";
                // const end_time: f64 = burst.@"1";
                // const num_pkts: u32 = burst.@"2";
                // const num_pkts_f = @as(f64, @floatFromInt(num_pkts));
                const num_pkts_f = @as(f64, @floatFromInt(burst.pkts));

                var packets = try std.ArrayList(time.Packet).initCapacity(allocator, burst.pkts);

                for (0..burst.pkts) |i| {
                    if (input_burst_idx >= input_bursts.len) {
                        std.debug.print("pkts = {}, input_bursts.len = {}, num_pkts = {}\n", .{
                            pkts,
                            input_bursts.len,
                            burst.pkts,
                        });
                        @panic("Ran out of input bursts!");
                    }
                    var pkt = input_bursts[input_burst_idx].packets.items[input_pkt_idx];
                    input_pkt_idx += 1;
                    if (input_pkt_idx >= input_bursts[input_burst_idx].packets.items.len) {
                        input_pkt_idx = 0;
                        input_burst_idx += 1;
                    }
                    const i_f = @as(f64, @floatFromInt(i));
                    pkt.time = burst.start_time + i_f * (burst.end_time - burst.start_time) / num_pkts_f; // Distribute packets uniformly over burst duration
                    try packets.append(pkt);
                }

                if (packets.items.len != burst.pkts) {
                    std.debug.print("packets.items.len = {d}, burst.pkts = {d}\n", .{ packets.items.len, burst.pkts });
                    @panic("This shouldn't happen");
                }

                const key = time.FlowKey{
                    .saddr = src_map.get(input_key.saddr) orelse @panic("source address not in AddrMap!"),
                    .daddr = dst_map.get(input_key.daddr) orelse @panic("destination address not in AddrMap!"),
                };

                const new_burst = Burst.init(key, burst.start_time, burst.end_time, packets);
                try bursts.add(new_burst);
            }
        }
    }

    return bursts;
}
