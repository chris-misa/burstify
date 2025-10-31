//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read a pcap file and report the on-duration of all bursts.
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));

const h = @import("parse_headers.zig");
const time = @import("time.zig");

pub fn main() !void {
    if (std.os.argv.len != 2) {
        std.debug.print("Usage: {s} <filename>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const filename = std.os.argv[1];

    std.debug.print("Reading from: {s}\n", .{filename});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
    const hdl = pcap.pcap_open_offline(filename, &errbuf);
    defer pcap.pcap_close(hdl);
    if (hdl == null) {
        std.debug.print("Failed to open file \"{s}\": {s}\n", .{ filename, errbuf });
        std.process.exit(1);
    }

    const dlt: i32 = pcap.pcap_datalink(hdl);
    if (dlt != pcap.DLT_EN10MB and dlt != pcap.DLT_RAW) {
        std.debug.print("Unsupported data-link type: {}\n", .{dlt});
    }

    var pkt: [*c]const u8 = undefined;
    var pcap_hdr: pcap.pcap_pkthdr = undefined;

    var analyzer = try time.TimeAnalyzer.init(allocator, 0.01);
    defer analyzer.deinit();

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        try onePacket(dlt, pcap_hdr, pkt, &analyzer);
    }
    try finish(&analyzer);
}

fn onePacket(dlt: i32, pcap_hdr: pcap.pcap_pkthdr, pkt: [*c]const u8, analyzer: *time.TimeAnalyzer) !void {
    var p: h.struct_headers = .{};

    _ = h.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

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

fn finish(analyzer: *time.TimeAnalyzer) !void {
    const a_on, const a_off = try analyzer.pareto_fit();
    std.debug.print("a_on = {d}, a_off = {d}\n", .{ a_on, a_off });
    // const on_durs = try analyzer.get_on_durations();
    // defer on_durs.deinit();
    //
    // const off_durs = try analyzer.get_off_durations();
    // defer off_durs.deinit();
    //
    // const stdout = std.io.getStdOut().writer();
    // try stdout.print("label,dur\n", .{});
    // for (on_durs.items) |dur| {
    //     try stdout.print("on,{d:.6}\n", .{dur});
    // }
    // for (off_durs.items) |dur| {
    //     try stdout.print("off,{d:.6}\n", .{dur});
    // }
}
