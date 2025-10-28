//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Test the address generator.
//!

const std = @import("std");

const addr = @import("addrs.zig");

pub fn main() !void {
    if (std.os.argv.len != 3) {
        std.debug.print("Usage: {s} <sigma> <number of addresses>\n", .{std.os.argv[0]});
        std.process.exit(0);
    }
    const sigma: f64 = try std.fmt.parseFloat(f64, std.mem.span(std.os.argv[1]));
    const n: u32 = try std.fmt.parseUnsigned(u32, std.mem.span(std.os.argv[2]), 10);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    var gen = std.Random.DefaultPrng.init(12345);
    const rand = gen.random();

    const res = try addr.generate(sigma, n, rand, allocator);
    defer res.deinit();

    const stdout = std.io.getStdOut().writer();
    for (res.items) |a| {
        try stdout.print("{}.{}.{}.{}\n", .{ (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF });
    }
}
