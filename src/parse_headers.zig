//! Copyright: 2025 Chris Misa
//! License: (See ./LICENSE)
//!
//! Utilities for parsing network packet headers
//!
//! Originally this was mostly translated from a c header file, but several manual edits were required.
//!

pub const struct_ethhdr = extern struct {
    h_dest: [6]u8 align(1),
    h_source: [6]u8 align(1),
    h_proto: u16 align(1),
};

pub const struct_iphdr = extern struct {
    version_ihl: u8 align(1),
    dscp_ecn: u8 align(1),
    tot_len: u16 align(1),
    id: u16 align(1),
    frag_off: u16 align(1),
    ttl: u8 align(1),
    protocol: u8 align(1),
    check: u16 align(1),
    saddr: u32 align(1),
    daddr: u32 align(1),
};

pub fn ip_version(h: *const struct_iphdr) u4 {
    return @truncate(h.version_ihl >> 4);
}

pub fn ip_ihl(h: *const struct_iphdr) u4 {
    return @truncate(h.version_ihl & 0xF);
}

pub const struct_tcphdr = extern struct {
    source: u16 align(1),
    dest: u16 align(1),
    seq: u32 align(1),
    ack_seq: u32 align(1),
    res_doff: u8 align(1),
    flags: u8 align(1),
    window: u16 align(1),
    check: u16 align(1),
    urg_ptr: u16 align(1),
};

pub const struct_udphdr = extern struct {
    source: u16 align(1),
    dest: u16 align(1),
    len: u16 align(1),
    check: u16 align(1),
};

pub const TCP_FLAG_CWR: c_int = 32768;
pub const TCP_FLAG_ECE: c_int = 16384;
pub const TCP_FLAG_URG: c_int = 8192;
pub const TCP_FLAG_ACK: c_int = 4096;
pub const TCP_FLAG_PSH: c_int = 2048;
pub const TCP_FLAG_RST: c_int = 1024;
pub const TCP_FLAG_SYN: c_int = 512;
pub const TCP_FLAG_FIN: c_int = 256;
pub const TCP_RESERVED_BITS: c_int = 15;
pub const TCP_DATA_OFFSET: c_int = 240;

pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_IGMP: c_int = 2;
pub const IPPROTO_IPIP: c_int = 4;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_EGP: c_int = 8;
pub const IPPROTO_PUP: c_int = 12;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IDP: c_int = 22;
pub const IPPROTO_TP: c_int = 29;
pub const IPPROTO_DCCP: c_int = 33;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPPROTO_RSVP: c_int = 46;
pub const IPPROTO_GRE: c_int = 47;
pub const IPPROTO_ESP: c_int = 50;
pub const IPPROTO_AH: c_int = 51;
pub const IPPROTO_MTP: c_int = 92;
pub const IPPROTO_BEETPH: c_int = 94;
pub const IPPROTO_ENCAP: c_int = 98;
pub const IPPROTO_PIM: c_int = 103;
pub const IPPROTO_COMP: c_int = 108;
pub const IPPROTO_L2TP: c_int = 115;
pub const IPPROTO_SCTP: c_int = 132;
pub const IPPROTO_UDPLITE: c_int = 136;
pub const IPPROTO_MPLS: c_int = 137;
pub const IPPROTO_ETHERNET: c_int = 143;
pub const IPPROTO_RAW: c_int = 255;
pub const IPPROTO_MPTCP: c_int = 262;
pub const IPPROTO_MAX: c_int = 263;
const enum_unnamed_11 = c_uint;
pub const IPPROTO_HOPOPTS: c_int = 0;
pub const IPPROTO_ROUTING: c_int = 43;
pub const IPPROTO_FRAGMENT: c_int = 44;
pub const IPPROTO_ICMPV6: c_int = 58;
pub const IPPROTO_NONE: c_int = 59;
pub const IPPROTO_DSTOPTS: c_int = 60;
pub const IPPROTO_MH: c_int = 135;

pub const struct_headers = struct {
    eth: ?*const struct_ethhdr = null,
    ipv4: ?*const struct_iphdr = null,
    tcp: ?*const struct_tcphdr = null,
    udp: ?*const struct_udphdr = null,
};

pub inline fn parse_ether(data_start: [*c]const u8, data_end: [*c]const u8, headers: *struct_headers) [*c]const u8 {
    const eth: *const struct_ethhdr =
        @as(*const struct_ethhdr, @ptrCast(data_start));
    const size: usize = @sizeOf(struct_ethhdr);
    if (data_start + size <= data_end) {
        headers.*.eth = eth;
        return data_start + size;
    }
    return null;
}

pub inline fn parse_ipv4(data_start: [*c]const u8, data_end: [*c]const u8, headers: *struct_headers) [*c]const u8 {
    const ip: *const struct_iphdr = @ptrCast(data_start);
    const size: usize = @as(u16, ip_ihl(ip)) * 4;
    if (ip_version(ip) == 4 and data_start + size <= data_end) {
        headers.*.ipv4 = ip;
        return data_start + size;
    }
    return null;
}

pub inline fn parse_tcp(data_start: [*c]const u8, data_end: [*c]const u8, headers: *struct_headers) [*c]const u8 {
    const tcp: *const struct_tcphdr = @ptrCast(data_start);
    const size: usize = @sizeOf(struct_tcphdr);
    if (data_start + size <= data_end) {
        headers.*.tcp = tcp;
        return data_start + size;
    }
    return null;
}
pub inline fn parse_udp(data_start: [*c]const u8, data_end: [*c]const u8, headers: *struct_headers) [*c]const u8 {
    const udp: *const struct_udphdr = @ptrCast(data_start);
    const size: c_int = @sizeOf(struct_udphdr);
    if (data_start + size <= data_end) {
        headers.*.udp = udp;
        return data_start + size;
    }
    return null;
}

pub inline fn parse_headers(hasEther: bool, data_start: [*c]const u8, data_end: [*c]const u8, headers: *struct_headers) [*c]const u8 {
    var cur: [*c]const u8 = data_start;
    if (hasEther) {
        cur = parse_ether(data_start, data_end, headers);
        if (headers.*.eth) |eth| {
            if (@byteSwap(eth.h_proto) != 0x0800) {
                cur = null;
            }
        }
    } else {
        cur = data_start;
    }
    if (cur != null) {
        cur = parse_ipv4(cur, data_end, headers);
        if (cur != null) {
            if (headers.ipv4.?.protocol == IPPROTO_TCP) {
                cur = parse_tcp(cur, data_end, headers);
            } else if (headers.ipv4.?.protocol == IPPROTO_UDP) {
                cur = parse_udp(cur, data_end, headers);
            }
        }
    }
    return cur;
}
