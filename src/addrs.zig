//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Functions for dealing with IPv4 addresses
//!

const std = @import("std");

pub const Prefix = struct {
    base: u32,
    len: u32,

    pub fn format(
        self: Prefix,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{d}.{d}.{d}.{d},{d}", .{
            (self.base >> 24) & 0xFF,
            (self.base >> 16) & 0xFF,
            (self.base >> 8) & 0xFF,
            self.base & 0xFF,
            self.len
        });
    }
};

const PrefixMapError = error{AddingToAlreadyBuiltMap};

///
/// PrefixMap accumulates addresses (using PrefixMap.addAddr()) then forms the prefix tree of cascade structure.
///
/// Once this structure is formed, several analysis can be performed.
/// * PrefixMap.logit_normal_fit() fits the distribution of the weights to a symmetric logit-normal distribution returning the fit parameter sigma.
/// * PrefixMap.getSingularity(addr) estimates the singular scaling exponent at addr.
///
/// Note that the analysis functions automatically form the prefix tree (by calling PrefixMap.prefixify()) so you can't add more addresses after calling them.
///
pub const PrefixMap = struct {
    data: []std.AutoHashMap(u32, f64),
    allocator: std.mem.Allocator,
    is_prefixified: bool,

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!PrefixMap {
        const data = try allocator.alloc(std.AutoHashMap(u32, f64), 33);
        for (data) |*elem| {
            elem.* = std.AutoHashMap(u32, f64).init(allocator);
        }
        return PrefixMap{ .data = data, .allocator = allocator, .is_prefixified = false };
    }

    pub fn deinit(self: *PrefixMap) void {
        for (self.data) |*elem| {
            elem.deinit();
        }
        self.allocator.free(self.data);
    }

    ///
    /// Returns the number of addresses stored
    ///
    pub fn n(self: *PrefixMap) usize {
        return self.data[32].count();
    }

    ///
    /// Adds the given address to the prefix map with weight 1.
    /// (After all addresses are added, prefixify() must be called to actually form the map)
    ///
    pub fn addAddr(self: *PrefixMap, addr: u32) (error{OutOfMemory} || PrefixMapError)!void {
        try self.addAddrWeight(addr, 1.0);
    }

    ///
    /// Adds the given address to the prefix map with arbitrary weight.
    /// (After all addresses are added, prefixify() must be called to actually form the map)
    ///
    pub fn addAddrWeight(self: *PrefixMap, addr: u32, weight: f64) (error{OutOfMemory} || PrefixMapError)!void {
        if (self.is_prefixified) {
            return error.AddingToAlreadyBuiltMap;
        } else if (!self.data[32].contains(addr)) {
            try self.data[32].put(addr, weight);
        }
    }

    ///
    /// Increments the given address's weight by one.
    /// (After all addresses are added, prefixify() must be called to actually form the map)
    ///
    pub fn incrAddr(self: *PrefixMap, addr: u32) (error{OutOfMemory} || PrefixMapError)!void {
        if (self.is_prefixified) {
            return error.AddingToAlreadyBuiltMap;
        }
        if (self.data[32].getPtr(addr)) |v| {
            v.* += 1.0;
        } else {
            try self.data[32].put(addr, 1.0);
        }
    }

    ///
    /// Performs a symmetric logit-normal fit of the weights of the given prefix map.
    /// Returns the fit value of sigma.
    ///
    pub fn logit_normal_fit(self: *PrefixMap) error{OutOfMemory}!f64 {
        const m = self.*.data;

        if (!self.is_prefixified) {
            try self.prefixify();
        }

        var count: u64 = 0;
        var m1: f64 = 0.0;
        var m2: f64 = 0.0;

        for (8..32) |pl| {
            var it = m[pl].iterator();
            while (it.next()) |elem| {
                // Skip the singletons
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

    ///
    /// Returns the singular scaling estimate (alpha(x)) at the given /32 address w.r.t. this prefix map.
    ///
    pub fn getSingularity(self: *PrefixMap, addr: u32) error{OutOfMemory}!f64 {
        if (!self.is_prefixified) {
            try self.prefixify();
        }

        const nf: f64 = @as(f64, @floatFromInt(self.n()));
        var slope: SlopeFitter = .{};

        // Go down prefix tree towards addr and estimate the slope along the way.
        for (0..33) |pl| {
            const mask: u32 = @truncate(@as(u64, 0xFFFFFFFF) << @truncate(32 - pl));
            if (self.data[pl].get(addr & mask)) |count| {
                if (count > 1.0) {
                    const x = @as(f64, @floatFromInt(pl));
                    const y = -@log2(count / nf);
                    slope.addPoint(x, y);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        return slope.fit();
    }

    ///
    /// Form the prefix map for the addresses already added.
    /// Returns the total number of addresses.
    ///
    fn prefixify(self: *PrefixMap) error{OutOfMemory}!void {
        const m = self.*.data;
        // Sum children, bottom-up
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

        self.*.is_prefixified = true;
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
};


///
/// generate() constructs a conservative cascade with symmetric logit-normal(sigma) generator
/// and samples n addresses.
///
/// The caller is responsible for freeing the returned slice.
///
pub fn generate(
    sigma: f64,
    n: u32,
    rand: std.Random,
    allocator: std.mem.Allocator
) error{OutOfMemory}!std.ArrayList(struct {u32, f64}) {
    const root = Prefix{ .base = 0, .len = 0 };
    var res = try std.ArrayList(struct{u32, f64}).initCapacity(allocator, n);
    const slope: SlopeFitter = .{};
    try gen_rec(sigma, n, root, n, rand, &res, slope);
    return res;
}

fn gen_rec(
    sigma: f64,
    total: u32,
    pfx: Prefix,
    n: u32,
    rand: std.Random,
    res: *std.ArrayList(struct {u32, f64}),
    slope: SlopeFitter
) error{OutOfMemory}!void {
    if (n == 0) {
        return;
    } else if (pfx.len == 32) {
        const alpha = slope.fit();
        try res.append(.{ pfx.base, alpha });
    } else {
        const normal: f64 = rand.floatNorm(f64) * sigma;
        const w: f64 = 1.0 / (1 + @exp(-normal));
        const left_count: u32 = @intFromFloat(@round(@as(f64, @floatFromInt(n)) * w));
        const right_count: u32 = @intFromFloat(@round(@as(f64, @floatFromInt(n)) * (1.0 - w)));
        const left = Prefix{ .base = pfx.base, .len = pfx.len + 1 };
        const right = Prefix{ .base = pfx.base | (@as(u32, 1) << @truncate(32 - (pfx.len + 1))), .len = pfx.len + 1 };
        const left_count2, const right_count2 = balance(left, left_count, right, right_count);

        var slope2 = slope;
        if (n > 1) {
            const x = @as(f64, @floatFromInt(pfx.len));
            const y = -@log2(@as(f64, @floatFromInt(n)) / @as(f64, @floatFromInt(total)));
            slope2.addPoint(x, y);
        }
        
        try gen_rec(sigma, total, left, left_count2, rand, res, slope2);
        try gen_rec(sigma, total, right, right_count2, rand, res, slope2);
    }
}

///
/// Get number of addresses that can fit in this prefix.
///
fn getCapacity(pfx: Prefix) u32 {
    return @truncate(@as(u64, 1) << @truncate(32 - pfx.len));
}

///
/// Balance the given left and right prefix counts.
/// Returns { left_count, right_count} such that both are below their respective capacities.
///
fn balance(left: Prefix, left_count: u32, right: Prefix, right_count: u32) struct { u32, u32 } {
    const left_cap = getCapacity(left);
    const right_cap = getCapacity(right);
    var left_final: u32 = undefined;
    var right_final: u32 = undefined;

    if (@as(u64, left_count) + @as(u64, right_count) > @as(u64, left_cap) + @as(u64, right_cap)) {
        // A balance is not possible...
        std.debug.print("ERROR: trying to balance more addresses than total capacity ({} > {})\n", .{ left_count + right_count, left_cap + right_cap });
        @panic("...this shouldn't happen");
    } else if (left_count > left_cap) {
        // Spill from left to right
        left_final = left_cap;
        right_final = right_count + (left_count - left_cap);
    } else if (right_count > right_cap) {
        // Spill from right to left
        left_final = left_count + (right_count - right_cap);
        right_final = right_cap;
    } else {
        // No spill
        left_final = left_count;
        right_final = right_count;
    }
    return .{ left_final, right_final };
}

///
/// Utility for estimating slopes using ordinary least-squares.
///
pub const SlopeFitter = struct {
    mx: f64 = 0.0,
    my: f64 = 0.0,
    c: f64 = 0.0,
    v: f64 = 0.0,
    count: f64 = 0.0,

    pub fn addPoint(self: *SlopeFitter, x: f64, y: f64) void {
        // Welford-type algorithm for variance and covariance
        self.*.count += 1.0;
        const dx = x - self.*.mx;
        self.*.mx += dx / self.*.count;
        self.*.my += (y - self.*.my) / self.*.count;
        self.*.c += dx * (y - self.*.my);
        self.*.v += dx * (x - self.*.mx);
    }

    pub fn fit(self: SlopeFitter) f64 {
        // covariance is c / (count - 1)
        // variance is v / (count - 1)
        // ... so the (count - 1) terms cancel out.
        return self.c / self.v;
    }
};
