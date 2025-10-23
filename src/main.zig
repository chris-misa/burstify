//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read IPv4 packets from a pcap file, organize into source-dest flows, timeseries of each flow
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));
const h = @import("parse_headers.zig");

const Key = struct { saddr: u32, daddr: u32 };

const Val = struct { time: f64, sport: u16, dport: u16, proto: u8 };

const State = std.AutoHashMap(Key, std.ArrayList(Val));

fn onePacket(dlt: i32, pcap_hdr: pcap.pcap_pkthdr, pkt: [*c]const u8, state: *State, allocator: std.mem.Allocator) error{OutOfMemory}!void {
    // because this can error out, we have to specify so in the return type!!!
    const t: f64 =
        @as(f64, @floatFromInt(pcap_hdr.ts.tv_sec)) +
        @as(f64, @floatFromInt(pcap_hdr.ts.tv_usec)) / 1000000.0;

    var p: h.struct_headers = .{};

    _ = h.parse_headers(dlt == pcap.DLT_EN10MB, pkt, pkt + pcap_hdr.caplen, &p);

    // Only look at ipv4 packets (for now)
    if (p.ipv4) |ipv4| {
        const sport = if (p.tcp) |tcp| tcp.source else if (p.udp) |udp| udp.source else 0;
        const dport = if (p.tcp) |tcp| tcp.dest else if (p.udp) |udp| udp.dest else 0;

        const key: Key = .{ .saddr = ipv4.saddr, .daddr = ipv4.daddr };
        const val: Val = .{ .time = t, .sport = sport, .dport = dport, .proto = ipv4.protocol };

        if (state.getPtr(key)) |*vals| {
            try vals.*.append(val);
        } else {
            var vals = std.ArrayList(Val).init(allocator);
            try vals.append(val);
            try state.put(key, vals);
        }
    }
}

fn printState(state: *State) void {
    var it = state.iterator();
    while (it.next()) |elem| {
        const src = std.net.Ip4Address.init(@bitCast(elem.key_ptr.saddr), 0);
        const dst = std.net.Ip4Address.init(@bitCast(elem.key_ptr.daddr), 0);
        std.debug.print("{} -> {}\n", .{ src, dst });
        for (elem.value_ptr.items) |val| {
            std.debug.print("  {d:.6}\n", .{val.time});
        }
    }
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
    defer {
        var it = state.valueIterator();
        while (it.next()) |vals| {
            vals.deinit();
        }
        state.deinit();
    }

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        try onePacket(dlt, pcap_hdr, pkt, &state, allocator);
        // TODO: if we actually run out of memory, we should break the loop and exit...
    }

    printState(&state);

    std.debug.print("Read {} packets\n", .{i});
}
