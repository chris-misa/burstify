//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Executable that generates sonata ground truth for particular synthetic traffics
//!
const std = @import("std");

const addr = @import("addrs.zig");
const time = @import("time.zig");
const gen = @import("generator.zig");
const conf = @import("config.zig");
const util = @import("util.zig");

pub fn main() !void {
    if (std.os.argv.len != 2) {
        std.debug.print("Usage: {s} <config json file>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const config_filepath = std.mem.span(std.os.argv[1]);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    // Read config
    const config_file = try std.fs.cwd().readFileAlloc(allocator, config_filepath, 4096);
    defer allocator.free(config_file);

    const config = try std.json.parseFromSlice(conf.Config, allocator, config_file, .{ .allocate = .alloc_always });
    defer config.deinit();

    // Read the base pcap file and parse into flows
    std.debug.print("Reading from {s}\n", .{config.value.input_pcap});
    var flows: time.TimeAnalyzer = try util.read_pcap(config.value.input_pcap, allocator) orelse return; // should be const?
    defer flows.deinit();

    std.debug.print("Read {d} flows\n", .{flows.flows.count()});

    // Loop over different trace-generation targets
    var threads = try std.ArrayList(std.Thread).initCapacity(allocator, config.value.targets.len);
    defer threads.deinit();

    for (config.value.targets, 0..) |target, i| {
        std.debug.print("Starting target {s}\n", .{target.output_pcap});

        var rand_gen = std.Random.DefaultPrng.init(12345 + i);
        const rand = rand_gen.random();

        const thread = try std.Thread.spawn(.{}, run_target, .{ allocator, rand, &flows, target });
        try threads.append(thread);
    }

    for (threads.items) |thread| {
        thread.join();
    }
}

fn run_target(allocator: std.mem.Allocator, rand: std.Random, flows: *const time.TimeAnalyzer, target: conf.Target) !void {
    var generator = try gen.Generator.init(allocator, rand, flows, target.time, target.addr);
    defer generator.deinit();

    // hacked
    {
        const filename = try util.strcat(allocator, target.output_pcap, ".bursts.csv");
        defer allocator.free(filename);
        const outfile = try std.fs.cwd().createFile(filename, .{});
        defer outfile.close();
        const out = outfile.writer();
        try out.print("start_time,end_time,pkts\n", .{});

        var it = generator.bursts.iterator();
        while (it.next()) |burst| {
            try out.print("{}, {}, {}\n", .{ burst.start_time, burst.end_time, burst.packets.items.len });
        }
    }

    const threshold = 45;
    const epoch_duration: f64 = 1.0;

    var common = try QueryCommon.init(allocator, target.output_pcap, epoch_duration);
    defer common.deinit();
    var query = try DDoS.init(allocator, &common, threshold);
    defer query.deinit();

    while (try generator.nextPacket()) |elem| {
        const key: time.FlowKey = elem.@"0";
        const pkt: time.Packet = elem.@"1";

        try query.process(key, pkt);
    }

    // Dump partial results of last epoch
    try query.output();
}

///
/// Common state and operations required across all queries
///
const QueryCommon = struct {
    epoch_duration: f64,
    next_epoch: ?f64,

    results_outfile: std.fs.File,
    metadata_outfile: std.fs.File,

    results_out: std.fs.File.Writer,
    metadata_out: std.fs.File.Writer,

    pub fn init(allocator: std.mem.Allocator, base_name: []u8, epoch_duration: f64) (std.fs.File.OpenError || error{OutOfMemory})!QueryCommon {
        const results_filename = try util.strcat(allocator, base_name, ".out.csv");
        defer allocator.free(results_filename);
        const results_outfile = try std.fs.cwd().createFile(results_filename, .{});

        const metadata_filename = try util.strcat(allocator, base_name, ".metadata.csv");
        defer allocator.free(metadata_filename);
        const metadata_outfile = try std.fs.cwd().createFile(metadata_filename, .{});

        return QueryCommon{
            .epoch_duration = epoch_duration,
            .next_epoch = null,
            .results_outfile = results_outfile,
            .metadata_outfile = metadata_outfile,
            .results_out = results_outfile.writer(),
            .metadata_out = metadata_outfile.writer(),
        };
    }

    pub fn deinit(self: *QueryCommon) void {
        self.results_outfile.close();
        self.metadata_outfile.close();
    }

    ///
    /// Checks if the epoch should be updated at cur_time.
    ///
    pub fn check_epoch(self: *QueryCommon, cur_time: f64) bool {
        if (self.next_epoch) |nxt| {
            if (cur_time > nxt) {
                return true;
            } else {
                return false;
            }
        } else {
            // Set first epoch
            self.next_epoch = cur_time + self.epoch_duration;
            return false;
        }
    }

    ///
    /// Advances the epoch by self.epoch_duration
    ///
    pub fn advance_epoch(self: *QueryCommon) void {
        self.next_epoch = self.next_epoch.? + self.epoch_duration;
    }
};

///
/// DDoS from Sonata, ground-truth computation
///
const DDoS = struct {
    const Self = @This();

    common: *QueryCommon,
    allocator: std.mem.Allocator,

    distinct: std.AutoHashMap(struct { u32, u32 }, void),
    reduce: std.AutoHashMap(u32, u32),
    threshold: u32,

    pub fn init(allocator: std.mem.Allocator, common: *QueryCommon, threshold: u32) std.io.AnyWriter.Error!Self {
        // Create query-specific state
        const d = std.AutoHashMap(struct { u32, u32 }, void).init(allocator);
        const r = std.AutoHashMap(u32, u32).init(allocator);
        // Write output file headers
        try common.results_out.print("time,dst\n", .{});
        try common.metadata_out.print("time,distinct_card,reduce_card\n", .{});
        return DDoS{ .common = common, .allocator = allocator, .distinct = d, .reduce = r, .threshold = threshold };
    }

    pub fn deinit(self: *Self) void {
        self.distinct.deinit();
        self.reduce.deinit();
    }

    pub fn process(self: *Self, key: time.FlowKey, pkt: time.Packet) (std.io.AnyWriter.Error || error{OutOfMemory})!void {
        if (self.common.check_epoch(pkt.time)) {
            try self.output();
            self.distinct.clearRetainingCapacity();
            self.reduce.clearRetainingCapacity();
            self.common.advance_epoch();
        }

        if (!self.distinct.contains(.{ key.saddr, key.daddr })) {
            try self.distinct.put(.{ key.saddr, key.daddr }, {});
            if (self.reduce.getPtr(key.daddr)) |val| {
                val.* += 1;
            } else {
                try self.reduce.put(key.daddr, 1);
            }
        }
    }

    pub fn output(self: *Self) (std.io.AnyWriter.Error || error{OutOfMemory})!void {
        if (self.common.next_epoch) |nxt| {
            const out_time: f64 = nxt - self.common.epoch_duration;

            // Output query results for ground-truth
            const res = try self.result(self.allocator);
            defer res.deinit();
            for (res.items) |dst| {
                try self.common.results_out.print("{d},{}\n", .{ out_time, addr.Addr{ .base = dst } });
            }

            // Output metadata counts
            try self.common.metadata_out.print("{d},{d},{d}\n", .{ out_time, self.distinct.count(), self.reduce.count() });
        } else {
            @panic("Trying to output query results before next_epoch is set!");
        }
    }

    pub fn result(self: Self, allocator: std.mem.Allocator) error{OutOfMemory}!std.ArrayList(u32) {
        var res = std.ArrayList(u32).init(allocator);
        var it = self.reduce.iterator();
        while (it.next()) |elem| {
            if (elem.value_ptr.* > self.threshold) {
                try res.append(elem.key_ptr.*);
            }
        }
        return res;
    }
};
