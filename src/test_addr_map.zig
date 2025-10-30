//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Test the address map
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
    const sigma = try pfxs.logit_normal_fit();
    std.debug.print("sigma = {d:.6}\n", .{sigma});

    {
        var alphas: []struct { u32, f64 } = try allocator.alloc(struct { u32, f64 }, pfxs.n());
        defer allocator.free(alphas);

        var i: u32 = 0;
        var it = pfxs.data[32].keyIterator();
        while (it.next()) |x| {
            const alpha = try pfxs.getSingularity(x.*);
            alphas[i] = .{ x.*, alpha };
            i += 1;
        }

        var gen = std.Random.DefaultPrng.init(12345);
        const rand = gen.random();

        const synth_alphas: std.ArrayList(struct { u32, f64 }) = try addr.generate(sigma, count, rand, allocator);
        defer synth_alphas.deinit();

        var map = try addr.AddrMap.init(allocator, rand, alphas, synth_alphas.items);
        defer map.deinit();

        std.debug.print("--- smallest alpha ---\n", .{});
        for (alphas[0..10]) |a| {
            const image = map.get(a.@"0");
            if (image) |img| {
                std.debug.print("{s} -> {s}\n", .{ addr.Prefix{ .base = a.@"0", .len = 32 }, addr.Prefix{ .base = img, .len = 32 } });
            } else {
                std.debug.print("no mapping for {s}\n", .{addr.Prefix{ .base = a.@"0", .len = 32 }});
            }
        }
        std.debug.print("--- largest alpha ---\n", .{});
        for (alphas[count - 11 ..]) |a| {
            const image = map.get(a.@"0");
            if (image) |img| {
                std.debug.print("{s} -> {s}\n", .{ addr.Prefix{ .base = a.@"0", .len = 32 }, addr.Prefix{ .base = img, .len = 32 } });
            } else {
                std.debug.print("no mapping for {s}\n", .{addr.Prefix{ .base = a.@"0", .len = 32 }});
            }
        }
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
