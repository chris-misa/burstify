//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read IPv4 packets from a pcap file, organize into source-dest flows, timeseries of each flow
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));

const h = @import("parse_headers.zig");
const addr = @import("addrs.zig");

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
        //fail test; can't try in defer as defer is executed after we return
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

    var pfxs = try addr.PrefixMap.init(allocator);
    defer pfxs.deinit();

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        try onePacket(dlt, pcap_hdr, pkt, &pfxs);
    }
    try finish(&pfxs);
}

fn onePacket(dlt: i32, pcap_hdr: pcap.pcap_pkthdr, pkt: [*c]const u8, pfxs: *addr.PrefixMap) error{OutOfMemory}!void {
    var p: h.struct_headers = .{};

    _ = h.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

    // Only look at ipv4 packets (for now)
    if (p.ipv4) |ipv4| {
        try pfxs.addAddr(ipv4.saddr);
    }
}

fn finish(pfxs: *addr.PrefixMap) error{OutOfMemory}!void {
    const sigma = try pfxs.logit_normal_fit();
    std.debug.print("sigma = {d:.6}\n", .{ sigma });
}
