//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read a list of IP addresses and estimate structure function
//!

const std = @import("std");

const addr = @import("addrs.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        // fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) @panic("TEST FAIL: leaked memory");
    }

    const stdin = std.io.getStdIn();

    var buffer: [1024]u8 = undefined;
    var count: u32 = 0;

    var pfxs = try addr.AddrAnalyzer.init(allocator);
    defer pfxs.deinit();

    while (true) {
        if (try nextLine(stdin.reader(), &buffer)) |line| {
            count += 1;
            const a = try addr.string_to_ipv4(line);
            try pfxs.addAddr(a);
        } else {
            break;
        }
    }
    std.debug.print("Read {} lines\n", .{count});

    const structure_function = try pfxs.structure_function(allocator);
    defer allocator.free(structure_function);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("q,tau,sd\n", .{});
    for (structure_function) |elem| {
        try stdout.print("{d},{d},{d}\n", .{ elem.@"0", elem.@"1", elem.@"2" });
    }
}

fn nextLine(reader: anytype, buffer: []u8) !?[]const u8 {
    const line = (try reader.readUntilDelimiterOrEof(
        buffer,
        '\n',
    )) orelse return null;
    // trim annoying windows-only carriage return character
    if (@import("builtin").os.tag == .windows) {
        return std.mem.trimRight(u8, line, "\r");
    } else {
        return line;
    }
}
