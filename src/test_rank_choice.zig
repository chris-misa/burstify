//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Simple tests of rank_choice()
//!

const std = @import("std");

const gen = @import("generator.zig");

pub fn print_one(idxs: std.ArrayList(usize), probs: std.ArrayList(f64)) void {
    for (0..idxs.items.len) |i| {
        const idx = idxs.items[i];
        const p = probs.items[i];
        std.debug.print("    idx = {}, p = {}\n", .{ idx, p });
    }
}

pub fn test_one(allocator: std.mem.Allocator, in_count: usize, out_count: usize) error{OutOfMemory}!void {
    std.debug.print("in_count = {d}, out_count = {d}\n", .{ in_count, out_count });
    for (0..in_count) |x| {
        std.debug.print("  x = {d}:\n", .{x});
        const idxs, const probs = try gen.rank_choices(allocator, x, in_count, out_count);
        defer {
            idxs.deinit();
            probs.deinit();
        }
        print_one(idxs, probs);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    try test_one(allocator, 4, 4);
    try test_one(allocator, 3, 4);
    try test_one(allocator, 4, 3);
    try test_one(allocator, 3, 20);
    try test_one(allocator, 20, 3);
}
