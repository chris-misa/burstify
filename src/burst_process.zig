//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Continuous burst generation process
//!

const std = @import("std");

const conf = @import("config.zig");

pub const BurstTimes = struct {
    start_time: f64,
    end_time: f64,
    pkts: u32,
};

///
/// Object that produces windowed observations of a continuous sequence of burst
///
pub const BurstGenerator = struct {
    rand: *std.Random,
    allocator: std.mem.Allocator,
    conf: conf.TimeParameters, // a_on, m_om, a_off, m_off, total_duration
    first_time: bool,
    start_on: bool,
    start_offset: f64,

    pub fn init(allocator: std.mem.Allocator, rand: *std.Random, config: conf.TimeParameters) BurstGenerator {
        if (config.m_on <= 0.0 or config.m_off <= 0.0) {
            @panic("Can't have minimum value of Pareto distribution <= 0 (m_on or m_off)");
        }
        if (config.a_on <= 0.0 or config.a_off <= 0.0) {
            @panic("Can't have shape value of Pareto distribution <= 0 (a_on or a_off)");
        }
        if (config.m_off >= config.total_duration) {
            @panic("Can't have minimum of off duration (m_off) greater than or equal to total duration...would look forever.");
        }

        return BurstGenerator{
            .rand = rand,
            .allocator = allocator,
            .conf = config,
            .first_time = true,
            .start_on = false,
            .start_offset = 0.0,
        };
    }

    ///
    /// Returns a slice of burst times with the given number of packets.
    ///
    pub fn next(self: *BurstGenerator, num_pkts: u32) error{OutOfMemory}![]BurstTimes {
        if (self.first_time) {
            // Make sure first start_offset < total_duration
            // self.start_offset = while (true) {
            //     const res = pareto(self.conf.a_off, self.conf.m_off, self.rand);
            //     if (res < self.conf.total_duration) break res;
            // } else unreachable;
            self.start_offset = @mod(pareto(self.conf.a_off, self.conf.m_off, self.rand), self.conf.total_duration);
            self.first_time = false;
        }

        var temp_bursts = std.ArrayList(BurstTimes).init(self.allocator);
        defer temp_bursts.deinit();

        // Starting from start_offset, generate on, off bursts until cur goes over total_duration
        var cur: f64 = if (self.start_on) 0.0 else self.start_offset;
        var total_on: f64 = 0.0;

        while (true) {
            const on_dur = if (self.start_on) self.start_offset else pareto(self.conf.a_on, self.conf.m_on, self.rand);
            const off_dur = pareto(self.conf.a_off, self.conf.m_off, self.rand);
            self.start_on = false;
            var burst = BurstTimes{
                .start_time = cur,
                .end_time = cur + on_dur,
                .pkts = 0,
            };

            // If this burst extends over total_duration, chop it and set up to start on next time.
            if (burst.end_time > self.conf.total_duration) {
                self.start_on = true;
                self.start_offset = @mod(burst.end_time, self.conf.total_duration);
                burst.end_time = self.conf.total_duration;
                total_on += burst.end_time - burst.start_time;
                try temp_bursts.append(burst);
                break;
            } else {
                total_on += on_dur;
                try temp_bursts.append(burst);
                cur += (on_dur + off_dur);

                // If the off period after this burst extends over total duration, chop it and set up to start off next time.
                if (cur >= self.conf.total_duration) {

                    // Move cur back by total_duration and update start_offset for next time
                    cur = @mod(cur, self.conf.total_duration);
                    self.start_offset = cur;
                    break;
                }
            }
        }

        // Alternative distribution algorithm:
        // for 0..num_pkts select a burst weighted by burst duration, add one to that burst
        const props = try self.allocator.alloc(f64, temp_bursts.items.len);
        defer self.allocator.free(props);

        for (props, 0..) |*p, i| {
            p.* = temp_bursts.items[i].end_time - temp_bursts.items[i].start_time;
        }

        for (0..num_pkts) |_| {
            const idx = self.rand.*.weightedIndex(f64, props);
            temp_bursts.items[idx].pkts += 1;
        }

        var num_nonzero: u32 = 0;
        for (temp_bursts.items) |burst| {
            if (burst.pkts > 0) {
                num_nonzero += 1;
            }
        }

        // // Distribute packets based on uniform mapping between on time and the total number of packets
        // const pkts_per_sec = @as(f64, @floatFromInt(num_pkts)) / total_on;
        // // var on_pos: f64 = 0.000000001; // to make sure the final floor reaches the last packet
        // // var on_pos: f64 = self.rand.*.float(f64); // initialize between 0 and 1 packets
        //
        // var on_pos: f64 = 0.5;
        // var num_nonzero: u32 = 0;
        //
        // // Construct a random order to go through bursts
        // const burst_idx: []usize = try self.allocator.alloc(usize, temp_bursts.items.len);
        // defer self.allocator.free(burst_idx);
        // for (0..burst_idx.len) |i| {
        //     burst_idx[i] = i;
        // }
        // self.rand.*.shuffle(usize, burst_idx);
        //
        // for (burst_idx) |idx| {
        //     const burst = &temp_bursts.items[idx];
        //     const off_pos = on_pos + (burst.end_time - burst.start_time) * pkts_per_sec;
        //     const pkts = @as(u32, @intFromFloat(@floor(off_pos))) - @as(u32, @intFromFloat(@floor(on_pos)));
        //
        //     burst.*.pkts = pkts;
        //     if (pkts > 0) {
        //         num_nonzero += 1;
        //     }
        //
        //     on_pos = off_pos;
        // }

        // Allocate, populate, and return output
        var output = try self.allocator.alloc(BurstTimes, num_nonzero);
        var idx: u32 = 0;
        for (temp_bursts.items) |burst| {
            if (burst.pkts > 0) {
                output[idx] = burst;
                idx += 1;
            }
        }
        return output;
    }
};

pub fn pareto(a: f64, m: f64, rand: *std.Random) f64 {
    return m * @exp(rand.*.floatExp(f64) / a);
}
