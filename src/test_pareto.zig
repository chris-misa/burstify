//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Double check that the Pareto generator works properly.
//!

const std = @import("std");

const time = @import("time.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var gen = std.Random.DefaultPrng.init(12345);
    const rand = gen.random();

    try stdout.print("a,x\n", .{});
    for ([_]f64{0.2, 0.4, 1.0, 1.2}) |a| {
        for (0..10) |_| {
            try stdout.print("{d},{d}\n", .{a, time.pareto(a, 0.01, rand)});
        }
    }
}
