//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Utilities for handling pcap files and other real-wold stuff
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));

const hdr = @import("parse_headers.zig");
const time = @import("time.zig");

pub fn strcat(allocator: std.mem.Allocator, s1: []const u8, s2: []const u8) error{OutOfMemory}![]u8 {
    return std.mem.concat(allocator, u8, &[_][]const u8{ s1, s2 });
}

pub fn read_pcap(filename: []u8, allocator: std.mem.Allocator) error{OutOfMemory}!?time.TimeAnalyzer {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    var filename_c: []u8 = try allocator.alloc(u8, filename.len + 1);
    defer allocator.free(filename_c);
    @memcpy(filename_c[0..filename.len], filename);
    filename_c[filename.len] = 0;

    const hdl = pcap.pcap_open_offline(@ptrCast(filename_c), &errbuf);
    defer pcap.pcap_close(hdl);
    if (hdl == null) {
        std.debug.print("Failed to open file \"{s}\": {s}\n", .{ filename, errbuf });
        return null;
    }

    const dlt: i32 = pcap.pcap_datalink(hdl);
    if (dlt != pcap.DLT_EN10MB and dlt != pcap.DLT_RAW) {
        std.debug.print("Unsupported data-link type: {}\n", .{dlt});
        return null;
    }

    var pkt: [*c]const u8 = undefined;
    var pcap_hdr: pcap.pcap_pkthdr = undefined;

    var analyzer = try time.TimeAnalyzer.init(allocator, 0.01);

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        try onePacket(dlt, pcap_hdr, pkt, &analyzer);
    }
    return analyzer;
}

fn onePacket(dlt: i32, pcap_hdr: pcap.pcap_pkthdr, pkt: [*c]const u8, analyzer: *time.TimeAnalyzer) !void {
    var p: hdr.struct_headers = .{};

    _ = hdr.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

    // Only look at ipv4 packets (for now)
    if (p.ipv4) |ipv4| {
        const t: f64 =
            @as(f64, @floatFromInt(pcap_hdr.ts.tv_sec)) +
            @as(f64, @floatFromInt(pcap_hdr.ts.tv_usec)) / 1000000.0;

        const sport = if (p.tcp) |tcp| tcp.source else if (p.udp) |udp| udp.source else 0;
        const dport = if (p.tcp) |tcp| tcp.dest else if (p.udp) |udp| udp.dest else 0;
        const tcpflags = if (p.tcp) |tcp| tcp.flags else 0;

        const key = time.FlowKey{ .saddr = ipv4.saddr, .daddr = ipv4.daddr };
        const packet = time.Packet{ .time = t, .sport = @byteSwap(sport), .dport = @byteSwap(dport), .proto = ipv4.protocol, .len = @byteSwap(ipv4.tot_len), .tcpflags = tcpflags };
        try analyzer.addPkt(key, packet);
    }
}
