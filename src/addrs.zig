//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Functions for dealing with IPv4 addresses
//!

const std = @import("std");

pub const Prefix = struct { base: u32, len: u32 };

pub const PrefixMap = struct {
    data: []std.AutoHashMap(u32, f64),
    n: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!PrefixMap {
        const data = try allocator.alloc(std.AutoHashMap(u32, f64), 33);
        for (data) |*elem| {
            elem.* = std.AutoHashMap(u32, f64).init(allocator);
        }
        return PrefixMap{ .data = data, .n = 0, .allocator = allocator };
    }

    pub fn deinit(self: *PrefixMap) void {
        for (self.data) |*elem| {
            elem.deinit();
        }
        self.allocator.free(self.data);
    }

    ///
    /// Adds the given address to the prefix map
    /// (After all addresses are added, prefixify() must be called to actually form the map)
    ///
    pub fn addAddr(self: *PrefixMap, addr: u32) error{OutOfMemory}!void {
        if (!self.data[32].contains(addr)) {
            try self.data[32].put(addr, 1.0);
            self.*.n += 1;
        }
    }

    ///
    /// Form the prefix map for the addresses already added.
    /// Returns the total number of addresses.
    ///
    fn prefixify(self: *PrefixMap) error{OutOfMemory}!void {
        const m = self.*.data;
        // Sum children
        for (0..32) |i| {
            const pl = 32 - i;
            const mask: u32 = @truncate(@as(u64, 0xFFFFFFFF) << @truncate(i + 1));
            var it = m[pl].iterator();
            while (it.next()) |elem| {
                const addr = elem.key_ptr.* & mask;
                if (m[pl - 1].getPtr(addr)) |next_elem| {
                    next_elem.* += elem.value_ptr.*;
                } else {
                    try m[pl - 1].put(addr, elem.value_ptr.*);
                }
            }
        }

        // Normalize
        // const n = @as(f64, @floatFromInt(self.n));
        // for (0..33) |pl| {
        //     var it = m[pl].valueIterator();
        //     while (it.next()) |v| {
        //         v.* /= n;
        //     }
        // }
    }

    ///
    /// Look up the weight (w) of how much mass goes left at the given prefix.
    /// (Note that how much mass goes right is just (1.0 - w).)
    ///
    fn get_w(self: *PrefixMap, pfx: Prefix) f64 {
        const m = self.*.data;
        const pl = pfx.len + 1;
        const l_base: u32 = pfx.base;
        const r_base: u32 = pfx.base | (@as(u32, 1) << @truncate(32 - pl));

        const l: f64 = if (m[pl].get(l_base)) |v| v else 0.0;
        const r: f64 = if (m[pl].get(r_base)) |v| v else 0.0;

        return l / (l + r);
    }

    ///
    /// Performs a symmetric logit-normal fit of the weights of the given prefix map.
    /// Returns the fit value of sigma.
    ///
    pub fn logit_normal_fit(self: *PrefixMap) error{OutOfMemory}!f64 {
        const m = self.*.data;

        try self.prefixify();

        var count: u64 = 0;
        var m1: f64 = 0.0;
        var m2: f64 = 0.0;

        for (8..32) |pl| {
            var it = m[pl].iterator();
            while (it.next()) |elem| {
                // Skip the singletons
                // if (elem.value_ptr.* > 1.0 / n) {
                if (elem.value_ptr.* > 1.0) {
                    var w = self.get_w(.{ .base = elem.key_ptr.*, .len = @intCast(pl) });
                    if (w == 0.0) {
                        w = 1.0 / (2.0 * elem.value_ptr.*);
                    }
                    if (w == 1.0) {
                        w = 1.0 - (1.0 / (2.0 * elem.value_ptr.*));
                    }

                    const x = @log(w / (1.0 - w));

                    // Welford's algorithm...
                    count += 1;
                    const d = x - m1;
                    m1 += d / @as(f64, @floatFromInt(count));
                    const d2 = x - m1;
                    m2 += d * d2;
                }
            }
        }
        return @sqrt(m2 / @as(f64, @floatFromInt(count - 1)));
    }
};
