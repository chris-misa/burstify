const std = @import("std");
const time = @import("time.zig");

pub fn main() !void {
    if (std.os.argv.len != 8) {
        std.debug.print("Usage: {s} <bursts> <pkts> <duration> <a_on> <m_on> <a_off> <m_off>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const num_bursts: u32 = try std.fmt.parseUnsigned(u32, std.mem.span(std.os.argv[1]), 10);
    const total_packets: u32 = try std.fmt.parseUnsigned(u32, std.mem.span(std.os.argv[2]), 10);
    const total_duration: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[3]));
    const a_on: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[4]));
    const m_on: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[5]));
    const a_off: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[6]));
    const m_off: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[7]));

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    var gen = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = gen.random();

    const bursts = try time.generate(
        a_on,
        m_on,
        a_off,
        m_off,
        num_bursts,
        total_packets,
        total_duration,
        rand,
        allocator,
    );
    defer allocator.free(bursts);

    const stdout = std.io.getStdOut().writer();
    var synth_pkts: u32 = 0;

    try stdout.print("start_time,end_time,pkts\n", .{});
    for (bursts) |burst| {
        try stdout.print("{d},{d},{d}\n", .{ burst.@"0", burst.@"1", burst.@"2" });
        synth_pkts += burst.@"2";
    }

    try stdout.print("Total packets: {d}\n", .{synth_pkts});
}
