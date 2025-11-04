const std = @import("std");
const time = @import("time.zig");

pub fn main() !void {

    if (std.os.argv.len != 3) {
        std.debug.print("Usage: {s} <pkts> <duration>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const total_packets: u32 = try std.fmt.parseUnsigned(u32, std.mem.span(std.os.argv[1]), 10);
    const total_duration: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[2]));

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

    const bursts = try time.generate(1.2, 0.01, 0.4, 0.01, total_packets, total_duration, rand, allocator);
    defer allocator.free(bursts);

    const stdout = std.io.getStdOut().writer();

    try stdout.print("start_time,end_time,pkts\n", .{});
    for (bursts) |burst| {
        try stdout.print("{d},{d},{d}\n", .{burst.@"0", burst.@"1", burst.@"2"});
    }
}
