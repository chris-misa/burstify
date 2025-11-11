//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Executable that actually generates synthetic traces based on addr.zig and time.zig
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

        const outfile_name = try util.strcat(allocator, target.output_pcap, ".csv");
        defer allocator.free(outfile_name);
        const outfile = try std.fs.cwd().createFile(outfile_name, .{});
        defer outfile.close();
        const out = outfile.writer();

        try out.print("time,saddr,daddr,sport,dport,proto,len,tcpflags\n", .{});
        while (try generator.nextPacket()) |pkt| {
            const key = pkt.@"0";
            const bdy = pkt.@"1";
            try out.print("{d},{s},{s},{d},{d},{d},{d},{d}\n", .{ bdy.time, addr.Addr{ .base = key.saddr }, addr.Addr{ .base = key.daddr }, bdy.sport, bdy.dport, bdy.proto, bdy.len, bdy.tcpflags });
        }

        // // ... just try the time mapping for now...
        // const burst_outfile_name = try std.mem.concat(
        //     allocator,
        //     u8,
        //     &[_][]const u8{target.output_pcap, ".bursts.csv"}
        // );
        // defer allocator.free(burst_outfile_name);
        // const burst_outfile = try std.fs.cwd().createFile(burst_outfile_name, .{});
        // defer burst_outfile.close();
        // const burst_out = burst_outfile.writer();
        // try burst_out.print("label,dur,pkts\n", .{});
        // {
        //     var it = flows.flows.iterator();
        //     while (it.next()) |elem| {
        //         const bursts = elem.value_ptr; // std.ArrayList(Burst)
        //         // Count the number of packets...
        //         var pkts: usize = 0;
        //         for (bursts.items) |burst| {
        //             pkts += burst.packets.items.len;
        //         }
        //         const synth_bursts = try time.generate(
        //             target.time.a_on,
        //             target.time.m_on,
        //             target.time.a_off,
        //             target.time.m_off,
        //             @intCast(pkts),
        //             target.time.total_duration,
        //             rand,
        //             allocator
        //         );
        //         defer allocator.free(synth_bursts);
        //
        //         for (synth_bursts) |burst| {
        //             try burst_out.print("on,{d},{d}\n", .{burst.@"1" - burst.@"0", burst.@"2"});
        //         }
        //         for (0..synth_bursts.len - 1) |i| {
        //             try burst_out.print("off,{d},0\n", .{
        //                 synth_bursts[i + 1].@"0" - synth_bursts[i].@"1"
        //             });
        //         }
        //     }
        // }

    }
}
