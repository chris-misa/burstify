//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read a pcap file and report on/off and address structure fits
//!

const std = @import("std");

const addr = @import("addrs.zig");
const time = @import("time.zig");
const gen = @import("generator.zig");
const conf = @import("config.zig");
const util = @import("util.zig");

pub fn main() !void {
    if (std.os.argv.len != 2 and std.os.argv.len != 3) {
        std.debug.print("Usage: {s} <pcap file> [<on/off times output file>]\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const filepath = std.mem.span(std.os.argv[1]);
    const bursts_outfile = if (std.os.argv.len == 3) std.mem.span(std.os.argv[2]) else null;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    // Read the pcap file and parse into flows
    std.debug.print("Reading from {s}\n", .{filepath});
    var flows: time.TimeAnalyzer = try util.read_pcap(filepath, allocator) orelse @panic("Failed to read file");
    defer flows.deinit();

    std.debug.print("Read {d} flows\n", .{flows.flows.count()});

    if (bursts_outfile) |outfile_name| {
        std.debug.print("Writing on/off times to {s}\n", .{outfile_name});
        const outfile = try std.fs.cwd().createFile(outfile_name, .{});
        defer outfile.close();
        const out = outfile.writer();
        try out.print("type,duration\n", .{});

        const on_durs = try flows.get_on_durations();
        for (on_durs.items) |dur| {
            try out.print("on,{d}\n", .{dur});
        }

        const off_durs = try flows.get_off_durations();
        for (off_durs.items) |dur| {
            try out.print("off,{d}\n", .{dur});
        }
    }

    var srcs: addr.AddrAnalyzer = try addr.AddrAnalyzer.init(allocator);
    defer srcs.deinit();
    var dsts: addr.AddrAnalyzer = try addr.AddrAnalyzer.init(allocator);
    defer dsts.deinit();
    {
        var it = flows.flows.keyIterator();
        while (it.next()) |key| {
            try srcs.addAddr(key.saddr);
            try dsts.addAddr(key.daddr);
        }
    }

    std.debug.print("Read {d} source addresses and {d} destination addresses\n", .{ srcs.n(), dsts.n() });

    std.debug.print("Fitting...\n", .{});

    const on_params, const off_params = try flows.pareto_fit();
    const on_alpha, const on_m = on_params;
    const off_alpha, const off_m = off_params;
    const srcs_sigma = try srcs.logit_normal_fit();
    const dsts_sigma = try dsts.logit_normal_fit();

    std.debug.print("alpha_on = {d}, m_on = {d}; alpha_off = {d}, m_off = {d}\n", .{
        on_alpha,
        on_m,
        off_alpha,
        off_m,
    });
    std.debug.print("sigma_srcs = {d}, sigma_dsts = {d}\n", .{ srcs_sigma, dsts_sigma });
}
