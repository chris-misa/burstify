const std = @import("std");

const pcap = @cImport(@cInclude("pcap/pcap.h"));

pub fn main() !void {
    if (std.os.argv.len != 2) {
        std.debug.print("Usage: {s} <filename>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const filename = std.os.argv[1];

    std.debug.print("Reading from: {s}\n", .{filename});

    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
    const hdl = pcap.pcap_open_offline(filename, &errbuf);
    defer pcap.pcap_close(hdl);
    if (hdl == null) {
        std.debug.print("Failed to open file \"{s}\": {s}\n", .{ filename, errbuf });
        std.process.exit(1);
    }

    const dlt = pcap.pcap_datalink(hdl);
    if (dlt != pcap.DLT_EN10MB and dlt != pcap.DLT_RAW) {
        std.debug.print("Unsupported data-link type: {}\n", .{dlt});
    }

    var pkt: [*c]const u8 = undefined;
    var pcap_hdr: pcap.pcap_pkthdr = undefined;

    var i: u32 = 0;

    while (true) {
        pkt = pcap.pcap_next(hdl, &pcap_hdr);
        if (pkt == null) {
            break;
        }
        std.debug.print("pkt time: {}.{}\n", .{ pcap_hdr.ts.tv_sec, pcap_hdr.ts.tv_usec });
        i = i + 1;
        if (i > 5) {
            break;
        }
    }

    std.debug.print("Read {} packets\n", .{i});

    // // stdout is for the actual output of your application, for example if you
    // // are implementing gzip, then only the compressed bytes should be sent to
    // // stdout, not any debugging messages.
    // const stdout_file = std.io.getStdOut().writer();
    // var bw = std.io.bufferedWriter(stdout_file);
    // const stdout = bw.writer();
    //
    // try stdout.print("Run `zig build test` to run the tests.\n", .{});
    //
    // try bw.flush(); // Don't forget to flush!
}
