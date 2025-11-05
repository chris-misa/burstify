//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Executable that actually generates synthetic traces based on addr.zig and time.zig
//!

const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));

const hdr = @import("parse_headers.zig");
const addr = @import("addrs.zig");
const time = @import("time.zig");
const gen = @import("generator.zig");

const Target = struct {
    output_pcap: []u8, // Name of the output generated from this target
    time: gen.TimeParameters,
    addr: gen.AddrParameters,
};
    

const Config = struct {
    input_pcap: []u8, // name of base pcap file to read
    targets: []Target, // list of parameter setting to run

    src_out: bool, // write extra output file with list of source addresses
    dst_out: bool, // write extra output file with list of destination addresses
    burst_out: bool, // write extra output file with start, end, and number of packets of each burst
};

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

    const config = try std.json.parseFromSlice(Config, allocator, config_file, .{ .allocate = .alloc_always });
    defer config.deinit();

    // Read the base pcap file and parse into flows
    std.debug.print("Reading from {s}\n", .{ config.value.input_pcap });
    var flows: time.TimeAnalyzer = try read_pcap(config.value.input_pcap, allocator) orelse return; // should be const?
    defer flows.deinit();

    std.debug.print("Read {d} flows\n", .{ flows.flows.count() });

    for (config.value.targets) |target| {
        std.debug.print("Executing target {s}\n", .{ target.output_pcap });

        var generator = try gen.Generator.init(
            allocator,
            rand,
            &flows,
            target.time,
            target.addr
        );
        defer generator.deinit();

        const outfile_name = try strcat(allocator, target.output_pcap, ".csv");
        defer allocator.free(outfile_name);
        const outfile = try std.fs.cwd().createFile(outfile_name, .{});
        defer outfile.close();
        const out = outfile.writer();

        try out.print("time,saddr,daddr,sport,dport,proto,len,tcpflags\n", .{});
        while (try generator.nextPacket()) |pkt| {
            // pkt: struct { time.FlowKey, time.Packet }
            const key = pkt.@"0";
            const bdy = pkt.@"1";
            try out.print("{d},{s},{s},{d},{d},{d},{d},{d}\n", .{
                bdy.time,
                addr.Addr{.base = key.saddr},
                addr.Addr{.base = key.daddr},
                bdy.sport,
                bdy.dport,
                bdy.proto,
                bdy.len,
                bdy.tcpflags
            });
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


fn read_pcap(filename: []u8, allocator: std.mem.Allocator) error{OutOfMemory}!?time.TimeAnalyzer {
    
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

fn strcat(allocator: std.mem.Allocator, s1: []const u8, s2: []const u8) error{OutOfMemory}![]u8 {
    return std.mem.concat(
        allocator,
        u8,
        &[_][]const u8 { s1, s2 }
    );
}
