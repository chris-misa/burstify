//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Utility to produce a packet-level csv from a pcap file for visualization
//!

const std = @import("std");
const pcap = @cImport(@cInclude("pcap/pcap.h"));

const hdr = @import("parse_headers.zig");
const addr = @import("addrs.zig");

pub fn main() !void {
    if (std.os.argv.len != 2) {
        std.debug.print("Usage: {s} <pcap file>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const filename = std.mem.span(std.os.argv[1]);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    // Read the pcap file and parse into flows
    std.debug.print("Reading from {s}\n", .{filename});

    try process_file(filename, allocator);
}

fn process_file(filename: []u8, allocator: std.mem.Allocator) !void {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    var filename_c: []u8 = try allocator.alloc(u8, filename.len + 1);
    defer allocator.free(filename_c);
    @memcpy(filename_c[0..filename.len], filename);
    filename_c[filename.len] = 0;

    const hdl = pcap.pcap_open_offline(@ptrCast(filename_c), &errbuf);
    defer pcap.pcap_close(hdl);
    if (hdl == null) {
        std.debug.print("Failed to open file \"{s}\": {s}\n", .{ filename, errbuf });
        return;
    }

    const dlt: i32 = pcap.pcap_datalink(hdl);
    if (dlt != pcap.DLT_EN10MB and dlt != pcap.DLT_RAW) {
        std.debug.print("Unsupported data-link type: {}\n", .{dlt});
        return;
    }

    var pkt: [*c]const u8 = undefined;
    var pcap_hdr: pcap.pcap_pkthdr = undefined;

    const stdout = std.io.getStdOut().writer();
    try stdout.print("time,srcip,dstip\n", .{});

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        var p: hdr.struct_headers = .{};

        _ = hdr.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

        // Only look at ipv4 packets (for now)
        if (p.ipv4) |ipv4| {
            const t: f64 =
                @as(f64, @floatFromInt(pcap_hdr.ts.tv_sec)) +
                @as(f64, @floatFromInt(pcap_hdr.ts.tv_usec)) / 1000000.0;

            const srcip = addr.Addr{ .base = ipv4.saddr };
            const dstip = addr.Addr{ .base = ipv4.daddr };
            try stdout.print("{},{},{}\n", .{ t, srcip, dstip });
        }
    }
}
