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

    var rand_gen = std.Random.DefaultPrng.init(12345);
    const rand = rand_gen.random();

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

    for (config.value.targets) |target| {
        std.debug.print("Executing target {s}\n", .{target.output_pcap});

        var generator = try gen.Generator.init(allocator, rand, &flows, target.time, target.addr);
        defer generator.deinit();

        const query_gen = struct {
            fn f(alloc: std.mem.Allocator) DDoS {
                return DDoS.init(alloc, 45);
            }
        }.f;
        
        var query = query_gen(allocator);
        defer query.deinit();

        var next_epoch: ?f64 = null;
        const epoch_duration: f64 = 1.0; // TODO: need some Sonata- or solution-specific config that holds this info...

        const outfile_name = try util.strcat(allocator, target.output_pcap, ".csv");
        defer allocator.free(outfile_name);
        const outfile = try std.fs.cwd().createFile(outfile_name, .{});
        defer outfile.close();
        const out = outfile.writer();
        try out.print("time,dst\n", .{});

        while (try generator.nextPacket()) |elem| {
            const key: time.FlowKey = elem.@"0";
            const pkt: time.Packet = elem.@"1";

            if (next_epoch) |nxt| {
                if (pkt.time > nxt) {
                    // Epoch expired: dump and reset
                    const res = try query.result(allocator);
                    defer res.deinit();
                    for (res.items) |dst| {
                        try out.print("{d},{}\n", .{ nxt - epoch_duration, addr.Addr{ .base = dst } });
                    }
                    query.deinit();
                    query = query_gen(allocator);
                    next_epoch = nxt + epoch_duration;
                }
            } else {
                // Set first epoch
                next_epoch = pkt.time + epoch_duration;
            }
            try query.process(key, pkt);
        }
        
        // Dump partial results of last epoch
        const res = try query.result(allocator);
        defer res.deinit();
        for (res.items) |dst| {
            try out.print("{d},{}\n", .{ next_epoch.? - epoch_duration, addr.Addr{ .base = dst } });
        }
    }
}

const DDoS = struct {
    const Self = @This();

    distinct: std.AutoHashMap(struct { u32, u32 }, void),
    reduce: std.AutoHashMap(u32, u32),
    threshold: u32,

    pub fn init(allocator: std.mem.Allocator, threshold: u32) Self {
        const d = std.AutoHashMap(struct { u32, u32 }, void).init(allocator);
        const r = std.AutoHashMap(u32, u32).init(allocator);
        return DDoS{ .distinct = d, .reduce = r, .threshold = threshold };
    }

    pub fn deinit(self: *Self) void {
        self.distinct.deinit();
        self.reduce.deinit();
    }

    pub fn process(self: *Self, key: time.FlowKey, pkt: time.Packet) error{OutOfMemory}!void {
        _ = pkt;
        if (!self.distinct.contains(.{ key.saddr, key.daddr })) {
            try self.distinct.put(.{ key.saddr, key.daddr }, {});
            if (self.reduce.getPtr(key.daddr)) |val| {
                val.* += 1;
            } else {
                try self.reduce.put(key.daddr, 1);
            }
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
