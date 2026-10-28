//! 最小 DER/BER 读取器 —— 只为解析 RSA 私钥（PKCS#1 / PKCS#8）与 SPKI 公钥。
//!
//! macOS 工具的公共 DER 编解码模块。
//! 只实现「够用」的子集：SEQUENCE / INTEGER / OCTET STRING / BIT STRING / OID / NULL，
//! 支持长格式长度（0x81 / 0x82 …），拒绝不定长（BER 的 0x80），因为密钥文件里不该出现。

const std = @import("std");

pub const Error = error{
    Truncated,
    BadTag,
    UnexpectedTag,
    IndefiniteLength,
    LengthOverflow,
    Unsupported,
};

/// 一个 TLV 节点：tag 字节 + 内容切片（内容不含 tag 与长度字段）。
pub const Tlv = struct {
    tag: u8,
    body: []const u8,

    pub fn is(self: Tlv, expected: u8) bool {
        return self.tag == expected;
    }

    /// 断言 tag 并返回自身，便于链式解析。
    pub fn expect(self: Tlv, expected: u8) Error!Tlv {
        if (self.tag != expected) return error.UnexpectedTag;
        return self;
    }
};

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;

/// 读取一个 TLV，返回节点与「下一个字节」的偏移。
pub fn read(data: []const u8, offset: usize) Error!struct { tlv: Tlv, next: usize } {
    if (offset >= data.len) return error.Truncated;
    const tag = data[offset];
    var pos = offset + 1;
    if (pos >= data.len) return error.Truncated;

    const first = data[pos];
    pos += 1;
    var len: usize = 0;
    if (first < 0x80) {
        len = first;
    } else if (first == 0x80) {
        return error.IndefiniteLength;
    } else {
        const count: usize = first & 0x7f;
        if (count > 4) return error.LengthOverflow;
        if (pos + count > data.len) return error.Truncated;
        for (data[pos .. pos + count]) |byte| {
            len = std.math.mul(usize, len, 256) catch return error.LengthOverflow;
            len = std.math.add(usize, len, byte) catch return error.LengthOverflow;
        }
        pos += count;
    }
    const end = std.math.add(usize, pos, len) catch return error.LengthOverflow;
    if (end > data.len) return error.Truncated;
    return .{ .tlv = .{ .tag = tag, .body = data[pos..end] }, .next = end };
}

/// 遍历 SEQUENCE 的子元素。
pub const Iterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn init(tlv: Tlv) Error!Iterator {
        if (tlv.tag != TAG_SEQUENCE) return error.UnexpectedTag;
        return .{ .body = tlv.body };
    }

    pub fn next(self: *Iterator) Error!?Tlv {
        if (self.pos >= self.body.len) return null;
        const result = try read(self.body, self.pos);
        self.pos = result.next;
        return result.tlv;
    }
};

/// 把 INTEGER 的字节内容转成定长大端字节串（去掉 DER 的符号位前导 0）。
/// 结果右对齐写入 `out`；数值超出 `out` 长度时报错。
pub fn integerToFixed(body: []const u8, out: []u8) Error!void {
    const bytes = stripLeadingZeros(body);
    if (bytes.len > out.len) return error.LengthOverflow;
    @memset(out, 0);
    @memcpy(out[out.len - bytes.len ..], bytes);
}

/// 把 INTEGER 内容读成 u32（用于 e = 65537 这种小指数）。
pub fn integerToU32(body: []const u8) Error!u32 {
    const bytes = stripLeadingZeros(body);
    if (bytes.len > 4) return error.LengthOverflow;
    var value: u32 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

// ───────────────────────── DER 编码（只用于生成 SPKI 公钥 PEM） ─────────────────────────

/// 计算「长度字段」需要多少字节。
pub fn lengthSize(len: usize) usize {
    if (len < 0x80) return 1;
    if (len <= 0xff) return 2;
    if (len <= 0xffff) return 3;
    return 4;
}

/// 写入长度字段，返回写入的字节数。
pub fn writeLength(out: []u8, len: usize) usize {
    if (len < 0x80) {
        out[0] = @intCast(len);
        return 1;
    }
    if (len <= 0xff) {
        out[0] = 0x81;
        out[1] = @intCast(len);
        return 2;
    }
    if (len <= 0xffff) {
        out[0] = 0x82;
        out[1] = @intCast(len >> 8);
        out[2] = @intCast(len & 0xff);
        return 3;
    }
    out[0] = 0x83;
    out[1] = @intCast((len >> 16) & 0xff);
    out[2] = @intCast((len >> 8) & 0xff);
    out[3] = @intCast(len & 0xff);
    return 4;
}

/// 去掉大端字节串的前导 0x00（Zig 0.17 没有 `mem.trimLeft`，自己写）。
pub fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var index: usize = 0;
    while (index < bytes.len and bytes[index] == 0) index += 1;
    return bytes[index..];
}

/// DER INTEGER 的编码长度：大端字节，若最高位为 1 需要补一个 0x00。
pub fn integerSize(magnitude: []const u8) usize {
    const trimmed = stripLeadingZeros(magnitude);
    const needs_pad = trimmed.len == 0 or (trimmed[0] & 0x80) != 0;
    const content = trimmed.len + @intFromBool(needs_pad);
    return 1 + lengthSize(content) + content;
}

/// 编码 DER INTEGER 到 `out`，返回写入字节数。
pub fn writeInteger(out: []u8, magnitude: []const u8) usize {
    const trimmed = stripLeadingZeros(magnitude);
    const needs_pad = trimmed.len == 0 or (trimmed[0] & 0x80) != 0;
    const content = trimmed.len + @intFromBool(needs_pad);
    var pos: usize = 0;
    out[pos] = TAG_INTEGER;
    pos += 1;
    pos += writeLength(out[pos..], content);
    if (needs_pad) {
        out[pos] = 0;
        pos += 1;
    }
    @memcpy(out[pos..][0..trimmed.len], trimmed);
    return pos + trimmed.len;
}

/// rsaEncryption OID 的完整 AlgorithmIdentifier 编码（含 SEQUENCE 头与 NULL 参数）。
pub const RSA_ALGORITHM_IDENTIFIER = [_]u8{
    0x30, 0x0d, // SEQUENCE, 13 bytes
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID 1.2.840.113549.1.1.1
    0x05, 0x00, // NULL
};

/// 把 (n, e) 编码成 SubjectPublicKeyInfo DER。`n` 必须是定长大端（RSA-2048 → 256 字节）。
pub fn encodeSpki(allocator: std.mem.Allocator, n: []const u8, e: u32) ![]u8 {
    var e_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_bytes, e, .big);
    var e_trimmed: []const u8 = &e_bytes;
    while (e_trimmed.len > 1 and e_trimmed[0] == 0) e_trimmed = e_trimmed[1..];

    const n_size = integerSize(n);
    const e_size = integerSize(e_trimmed);
    const rsa_pub_content = n_size + e_size;
    const rsa_pub_size = 1 + lengthSize(rsa_pub_content) + rsa_pub_content;

    const bit_string_content = 1 + rsa_pub_size; // 前导 0x00 = unused bits
    const bit_string_size = 1 + lengthSize(bit_string_content) + bit_string_content;

    const spki_content = RSA_ALGORITHM_IDENTIFIER.len + bit_string_size;
    const total = 1 + lengthSize(spki_content) + spki_content;

    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    var pos: usize = 0;
    out[pos] = TAG_SEQUENCE;
    pos += 1;
    pos += writeLength(out[pos..], spki_content);
    @memcpy(out[pos..][0..RSA_ALGORITHM_IDENTIFIER.len], &RSA_ALGORITHM_IDENTIFIER);
    pos += RSA_ALGORITHM_IDENTIFIER.len;

    out[pos] = TAG_BIT_STRING;
    pos += 1;
    pos += writeLength(out[pos..], bit_string_content);
    out[pos] = 0; // unused bits
    pos += 1;

    out[pos] = TAG_SEQUENCE;
    pos += 1;
    pos += writeLength(out[pos..], rsa_pub_content);
    pos += writeInteger(out[pos..], n);
    pos += writeInteger(out[pos..], e_trimmed);

    std.debug.assert(pos == total);
    return out;
}

test "integer size and encode roundtrip" {
    var buf: [300]u8 = undefined;
    var n: [256]u8 = undefined;
    @memset(&n, 0xab);
    n[0] = 0xc1;
    const size = integerSize(&n);
    const written = writeInteger(&buf, &n);
    try std.testing.expectEqual(size, written);
    try std.testing.expectEqual(@as(u8, TAG_INTEGER), buf[0]);
}

test "read rejects indefinite length" {
    const data = [_]u8{ 0x30, 0x80, 0x00 };
    try std.testing.expectError(error.IndefiniteLength, read(&data, 0));
}
