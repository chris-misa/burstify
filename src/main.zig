//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read IPv4 packets from a pcap file, organize into source-dest flows, timeseries of each flow
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));
const h = @import("parse_headers.zig");

const Key = struct { saddr: u32, daddr: u32 };

const Val = struct { sport: u16, dport: u16, proto: u8, len: u16, tcpflags: u8 };

const Burst = struct { first: f64, last: f64, counts: std.AutoHashMap(Val, u32) };

const State = std.AutoHashMap(Key, std.ArrayList(Burst));

const burst_timeout_sec = 0.01;

fn onePacket(dlt: i32, pcap_hdr: pcap.pcap_pkthdr, pkt: [*c]const u8, state: *State, allocator: std.mem.Allocator) error{OutOfMemory}!void {
    const t: f64 =
        @as(f64, @floatFromInt(pcap_hdr.ts.tv_sec)) +
        @as(f64, @floatFromInt(pcap_hdr.ts.tv_usec)) / 1000000.0;

    var p: h.struct_headers = .{};

    _ = h.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

    // Only look at ipv4 packets (for now)
    if (p.ipv4) |ipv4| {

        // Project the fields we need
        const key: Key = .{ .saddr = ipv4.saddr, .daddr = ipv4.daddr };

        const sport = if (p.tcp) |tcp| tcp.source else if (p.udp) |udp| udp.source else 0;
        const dport = if (p.tcp) |tcp| tcp.dest else if (p.udp) |udp| udp.dest else 0;
        const tcpflags = if (p.tcp) |tcp| tcp.flags else 0;
        const val: Val = .{ .sport = @byteSwap(sport), .dport = @byteSwap(dport), .proto = ipv4.protocol, .len = @byteSwap(ipv4.tot_len), .tcpflags = tcpflags };

        if (state.getPtr(key)) |*bursts| {
            // Previously-observed key
            var burst: *Burst = &bursts.*.items[bursts.*.items.len - 1];
            if (t - burst.last >= burst_timeout_sec) {
                // Handle burst timeout
                var counts = std.AutoHashMap(Val, u32).init(allocator);
                try counts.put(val, 1);
                const new_burst: Burst = .{ .first = t, .last = t, .counts = counts };
                try bursts.*.append(new_burst);
            } else {
                // Add packet to burst
                if (burst.counts.getPtr(val)) |count| {
                    count.* += 1;
                } else {
                    try burst.counts.put(val, 1);
                }
                burst.last = t;
            }
        } else {
            // First-time observing this key
            var counts = std.AutoHashMap(Val, u32).init(allocator);
            try counts.put(val, 1);
            const new_burst: Burst = .{ .first = t, .last = t, .counts = counts };

            var bursts = std.ArrayList(Burst).init(allocator);
            try bursts.append(new_burst);
            try state.put(key, bursts);
        }
    }
}

fn printState(state: *State) void {
    var it = state.iterator();
    while (it.next()) |elem| {
        const key = elem.key_ptr;
        const bursts = elem.value_ptr;

        const src = std.net.Ip4Address.init(@bitCast(key.saddr), 0);
        const dst = std.net.Ip4Address.init(@bitCast(key.daddr), 0);
        std.debug.print("{} -> {}\n", .{ src, dst });
        for (bursts.items) |burst| {
            std.debug.print("  {d:.6} {d:.6}\n", .{ burst.first, burst.last - burst.first });
            var it2 = burst.counts.iterator();
            while (it2.next()) |elem2| {
                std.debug.print("    {}: {}\n", .{ elem2.key_ptr, elem2.value_ptr.* });
            }
        }
    }
}

fn printPktsPerFlow(state: *State) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("src,dst,pkts\n", .{});

    var it = state.iterator();
    while (it.next()) |elem| {
        const key = elem.key_ptr;
        const bursts = elem.value_ptr;

        // const src = std.net.Ip4Address.init(@bitCast(key.saddr), 0);
        // const dst = std.net.Ip4Address.init(@bitCast(key.daddr), 0);

        var pkts: u64 = 0;
        for (bursts.items) |burst| {
            var it2 = burst.counts.iterator();
            while (it2.next()) |elem2| {
                pkts += elem2.value_ptr.*;
            }
        }
        try stdout.print("{d},{d},{d}\n", .{ key.saddr, key.daddr, pkts });
    }
}

fn deinitState(state: *State) void {
    var it = state.valueIterator();
    while (it.next()) |bursts| {
        for (bursts.items) |*burst| {
            burst.*.counts.deinit();
        }
        bursts.deinit();
    }
    state.deinit();
}

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

    var state = State.init(allocator);
    defer deinitState(&state);

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        try onePacket(dlt, pcap_hdr, pkt, &state, allocator);
        // TODO: if we actually run out of memory, we should break the loop and exit...
    }

    // printState(&state);
    try printPktsPerFlow(&state);
}
