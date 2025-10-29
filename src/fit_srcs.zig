//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Read a list of IP addresses and do the logit-normal fit
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

    var pfxs = try addr.PrefixMap.init(allocator);
    defer pfxs.deinit();

    while (true) {
        if (try nextLine(stdin.reader(), &buffer)) |line| {
            count += 1;
            const a = try string_to_ipv4(line);
            try pfxs.addAddr(a);
        } else {
            break;
        }
    }
    std.debug.print("Read {} lines\n", .{count});
    const sigma = try pfxs.logit_normal_fit();
    std.debug.print("sigma = {d:.6}\n", .{sigma});

    {
        var it = pfxs.data[32].keyIterator();
        var alphas: []f64 = try allocator.alloc(f64, pfxs.n());
        defer allocator.free(alphas);

        var i: u32 = 0;
        while (it.next()) |x| {
            alphas[i] = try pfxs.getSingularity(x.*);
            i += 1;
        }
        std.mem.sort(f64, alphas, {}, comptime std.sort.asc(f64));

        std.debug.print("min alpha = {d:.6}\n", .{alphas[0]});
        std.debug.print("max alpha = {d:.6}\n", .{alphas[pfxs.n() - 1]});
    }
}

fn string_to_ipv4(str: []const u8) !u32 {
    var i: u32 = 0;
    while (str[i] == ' ') i += 1;
    var s = i;
    while (str[i] != '.') i += 1;
    const b1 = try std.fmt.parseUnsigned(u8, str[s..i], 10);
    i += 1;
    s = i;
    while (str[i] != '.') i += 1;
    const b2 = try std.fmt.parseUnsigned(u8, str[s..i], 10);
    i += 1;
    s = i;
    while (str[i] != '.') i += 1;
    const b3 = try std.fmt.parseUnsigned(u8, str[s..i], 10);
    i += 1;
    const b4 = try std.fmt.parseUnsigned(u8, str[i..str.len], 10);
    return (@as(u32, b1) << 24) + (@as(u32, b2) << 16) + (@as(u32, b3) << 8) + b4;
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
