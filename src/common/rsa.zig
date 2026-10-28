//! RSA-2048 签发 / 解密 —— 平台无关。
//!
//! 只做本项目需要的两件事，都用 Zig 标准库的 `std.crypto.ff` 完成（无需 OpenSSL）：
//!
//!   · `sign`    激活码：PKCS#1 v1.5 **type-1** 填充 → sig = EM^d mod n
//!   · `decrypt` 请求码：c^d mod n → 剥 **type-2** 填充 → 内层 JSON
//!
//! 之所以能只用 N/D：这两个运算都只需要 `x^d mod n`，不需要 CRT 参数（p/q/dp/dq/qinv）。
//!
//! 字节序约定（这是本项目最容易踩的坑，务必遵守）：
//!   · DER / 网络 / base64 里的大整数一律 **大端**；
//!   · `std.crypto.ff` 的 `Fe.fromBytes` / `toBytes` 由调用方显式指定端序，这里统一用 `.big`。

const std = @import("std");
const der = @import("der.zig");
const pem = @import("pem.zig");

/// RSA-2048 的模长（字节）
pub const MODULUS_LEN: usize = 256;
/// 指数固定 65537
pub const PUBLIC_EXPONENT: u32 = 65537;
/// PKCS#1 v1.5 要求至少 8 个 0xFF 填充字节
pub const MIN_PADDING: usize = 8;
/// payload 上限：256 - 3（00 01 + 00 分隔）- 8（最少填充）
pub const MAX_PAYLOAD: usize = MODULUS_LEN - 3 - MIN_PADDING;

const Modulus = std.crypto.ff.Modulus(2048);

pub const Error = error{
    InvalidKey,
    NotRsa2048,
    UnsupportedExponent,
    PayloadTooLarge,
    BadPadding,
    NotRequestCode,
    InvalidRequestCode,
    MissingField,
    OutOfMemory,
} || pem.Error || der.Error;

/// 解析后的 RSA 私钥（只保留签发需要的 N / D）。
pub const PrivateKey = struct {
    n: [MODULUS_LEN]u8,
    d: [MODULUS_LEN]u8,
    e: u32,

    /// 从 PEM 文本解析私钥。同时支持 PKCS#1（RSA PRIVATE KEY）与 PKCS#8（PRIVATE KEY）。
    pub fn fromPem(allocator: std.mem.Allocator, text: []const u8) Error!PrivateKey {
        const der_bytes = try pem.firstBase64(allocator, text);
        defer allocator.free(der_bytes);
        return fromDer(der_bytes);
    }

    /// 从 DER 字节解析私钥。
    pub fn fromDer(bytes: []const u8) Error!PrivateKey {
        const outer = try der.read(bytes, 0);
        const outer_seq = try outer.tlv.expect(der.TAG_SEQUENCE);

        // 先按 PKCS#1 试：SEQUENCE { ver, n, e, d, ... }
        if (parsePkcs1(outer_seq)) |key| {
            return key;
        } else |_| {}

        // 再按 PKCS#8 试：SEQUENCE { ver, AlgorithmIdentifier, OCTET STRING(RSAPrivateKey) }
        var it = try der.Iterator.init(outer_seq);
        _ = (try it.next()) orelse return error.InvalidKey; // version
        _ = (try it.next()) orelse return error.InvalidKey; // algorithm
        const octets = (try it.next()) orelse return error.InvalidKey;
        if (octets.tag != der.TAG_OCTET_STRING) return error.InvalidKey;
        const inner = try der.read(octets.body, 0);
        return parsePkcs1(try inner.tlv.expect(der.TAG_SEQUENCE));
    }

    fn parsePkcs1(sequence: der.Tlv) Error!PrivateKey {
        var it = try der.Iterator.init(sequence);
        _ = (try it.next()) orelse return error.InvalidKey; // version
        const n_tlv = (try it.next()) orelse return error.InvalidKey;
        const e_tlv = (try it.next()) orelse return error.InvalidKey;
        const d_tlv = (try it.next()) orelse return error.InvalidKey;
        if (n_tlv.tag != der.TAG_INTEGER or e_tlv.tag != der.TAG_INTEGER or d_tlv.tag != der.TAG_INTEGER)
            return error.InvalidKey;

        var key = PrivateKey{
            .n = undefined,
            .d = undefined,
            .e = try der.integerToU32(e_tlv.body),
        };
        try der.integerToFixed(n_tlv.body, &key.n);
        try der.integerToFixed(d_tlv.body, &key.d);
        if (key.e != PUBLIC_EXPONENT) return error.UnsupportedExponent;
        // 模数最高位必须置位才是标准 RSA-2048（否则说明不是 2048 位）
        if ((key.n[0] & 0x80) == 0) return error.NotRsa2048;
        return key;
    }

    /// 公钥模数（大端，256 字节）。
    pub fn modulus(self: PrivateKey) [MODULUS_LEN]u8 {
        return self.n;
    }

    /// 生成 SPKI 公钥 DER。
    pub fn publicSpkiDer(self: PrivateKey, allocator: std.mem.Allocator) Error![]u8 {
        return der.encodeSpki(allocator, &self.n, self.e) catch return error.OutOfMemory;
    }

    /// 生成 PEM 公钥文本（默认 CRLF，与 Navicat 内嵌格式一致）。
    pub fn publicPem(self: PrivateKey, allocator: std.mem.Allocator, line_ending: []const u8) Error![]u8 {
        const spki = try self.publicSpkiDer(allocator);
        defer allocator.free(spki);
        return pem.encode(allocator, "PUBLIC KEY", spki, line_ending);
    }

    fn modulusField(self: PrivateKey) Error!Modulus {
        return Modulus.fromBytes(&self.n, .big) catch return error.InvalidKey;
    }

    /// sig = EM^d mod n，返回 256 字节大端。
    fn rawPrivate(self: PrivateKey, em: *const [MODULUS_LEN]u8) Error![MODULUS_LEN]u8 {
        const m = try self.modulusField();
        const x = Modulus.Fe.fromBytes(m, em, .big) catch return error.InvalidKey;
        const exp = Modulus.Fe.fromBytes(m, &self.d, .big) catch return error.InvalidKey;
        const y = m.pow(x, exp) catch return error.InvalidKey;
        var out: [MODULUS_LEN]u8 = undefined;
        y.toBytes(&out, .big) catch return error.InvalidKey;
        return out;
    }

    /// PKCS#1 v1.5 type-1 填充：`00 01 FF..FF 00 <payload>`。
    pub fn padType1(payload: []const u8) Error![MODULUS_LEN]u8 {
        if (payload.len > MAX_PAYLOAD) return error.PayloadTooLarge;
        var em: [MODULUS_LEN]u8 = undefined;
        em[0] = 0x00;
        em[1] = 0x01;
        const separator = MODULUS_LEN - payload.len - 1;
        @memset(em[2..separator], 0xff);
        em[separator] = 0x00;
        @memcpy(em[separator + 1 ..], payload);
        return em;
    }

    /// 用私钥签一段 payload，返回 256 字节签名（大端）。
    pub fn sign(self: PrivateKey, payload: []const u8) Error![MODULUS_LEN]u8 {
        const em = try padType1(payload);
        return self.rawPrivate(&em);
    }

    /// 用私钥解一段 256 字节密文（请求码走的是 type-2 填充）。
    /// 返回解出的内层明文切片（指向 `out`，生命周期由调用方保证）。
    pub fn decryptRequest(self: PrivateKey, ciphertext: []const u8, out: *[MODULUS_LEN]u8) Error![]const u8 {
        if (ciphertext.len != MODULUS_LEN) return error.InvalidRequestCode;
        var block: [MODULUS_LEN]u8 = undefined;
        @memcpy(&block, ciphertext);
        out.* = try self.rawPrivate(&block);

        // 必须从调用方的 `out` 取切片：返回局部 `block` 的切片会指向已失效的栈内存
        if (out[0] != 0x00) return error.NotRequestCode;
        if (out[1] == 0x01) return error.NotRequestCode; // 这是激活码（type-1），不是请求码
        if (out[1] != 0x02) return error.BadPadding;

        var index: usize = 2;
        while (index < out.len and out[index] != 0x00) index += 1;
        if (index >= out.len) return error.BadPadding;
        return out[index + 1 ..];
    }
};

/// 用公钥（N, E）验证一段签名是否是 PKCS#1 v1.5 type-1 结构，返回还原出的 EM 块。
/// 主要用于自检：证明「自己签的码能被自己的公钥验过」。
pub fn verifySignature(n: []const u8, signature: []const u8, out: *[MODULUS_LEN]u8) Error![]u8 {
    if (n.len != MODULUS_LEN or signature.len != MODULUS_LEN) return error.NotRsa2048;
    const m = Modulus.fromBytes(n, .big) catch return error.InvalidKey;
    const x = Modulus.Fe.fromBytes(m, signature, .big) catch return error.InvalidKey;
    var e_bytes: [3]u8 = .{ 0x01, 0x00, 0x01 };
    const y = m.powWithEncodedPublicExponent(x, &e_bytes, .big) catch return error.InvalidKey;
    y.toBytes(out, .big) catch return error.InvalidKey;

    if (out[0] != 0x00 or out[1] != 0x01) return error.BadPadding;
    var index: usize = 2;
    while (index < out.len and out[index] == 0xff) index += 1;
    if (index >= out.len or out[index] != 0x00) return error.BadPadding;
    return out[index + 1 ..];
}

// ───────────────────────── 请求码 / 激活码 的文本处理 ─────────────────────────
/// 去掉请求码里的所有空白（Navicat 复制出来的常带折行）。
pub fn stripWhitespace(allocator: std.mem.Allocator, text: []const u8) Error![]u8 {
    const out = try allocator.alloc(u8, text.len);
    var len: usize = 0;
    for (text) |byte| {
        switch (byte) {
            ' ', '\t', '\r', '\n' => {},
            else => {
                out[len] = byte;
                len += 1;
            },
        }
    }
    return allocator.realloc(out, len) catch {
        allocator.free(out);
        return error.OutOfMemory;
    };
}

/// base64 解码请求码，要求恰好 256 字节。
pub fn decodeRequestCode(allocator: std.mem.Allocator, text: []const u8) Error![]u8 {
    const cleaned = try stripWhitespace(allocator, text);
    defer allocator.free(cleaned);
    if (cleaned.len == 0) return error.InvalidRequestCode;

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(cleaned) catch return error.InvalidRequestCode;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    decoder.decode(out, cleaned) catch return error.InvalidRequestCode;
    if (out.len != MODULUS_LEN) return error.InvalidRequestCode;
    return out;
}

/// 大端 256 字节 → base64 激活码。
pub fn encodeActivationCode(allocator: std.mem.Allocator, signature: *const [MODULUS_LEN]u8) Error![]u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(MODULUS_LEN));
    _ = encoder.encode(out, signature);
    return out;
}


test "pad type1 structure" {
    const payload = "{\"K\":\"X\"}";
    const em = try PrivateKey.padType1(payload);
    try std.testing.expectEqual(@as(u8, 0x00), em[0]);
    try std.testing.expectEqual(@as(u8, 0x01), em[1]);
    try std.testing.expectEqual(@as(u8, 0xff), em[2]);
    const separator = MODULUS_LEN - payload.len - 1;
    try std.testing.expectEqual(@as(u8, 0x00), em[separator]);
    try std.testing.expectEqualSlices(u8, payload, em[separator + 1 ..]);
}

test "pad type1 rejects oversized payload" {
    var big: [MAX_PAYLOAD + 1]u8 = undefined;
    @memset(&big, 'a');
    try std.testing.expectError(error.PayloadTooLarge, PrivateKey.padType1(&big));
}

test "stripWhitespace removes CRLF" {
    const allocator = std.testing.allocator;
    const cleaned = try stripWhitespace(allocator, "abc\r\ndef \tghi\n");
    defer allocator.free(cleaned);
    try std.testing.expectEqualStrings("abcdefghi", cleaned);
}

fn hexToFixed(comptime hex: []const u8, out: *[MODULUS_LEN]u8) void {
    for (0..MODULUS_LEN) |i| {
        const hi = std.fmt.charToDigit(hex[i * 2], 16) catch unreachable;
        const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch unreachable;
        out[i] = (hi << 4) | lo;
    }
}

test "decryptRequest returns payload living in caller buffer" {
    // 一次性测试密钥（勿用于真实签发）
    const n_hex =
        "ab4fbf1e7ee1566c6143dfe075f346dab07b0c3106a82782de017b61784d32ea" ++
        "6f930023bc8dc97f3609575024812ec4577f528058bc2d4eb63ad8ec2edefa99" ++
        "8f3c02562c0cfe64e5655438d13a3cde4f984e52a8bf41baa97d1870a643c5d6" ++
        "bd7a4f34f28bfe5f6250c63c319ea7aa5b705acc0b5fc9dc6f76b4ba2f6af694" ++
        "e2cb1f57c452cd662c9b4cd506afff516528404e0e6b0124ae5524772b6a39ab" ++
        "09d339ffc6ed5e48c9461831cb76bbe65bb595ceec5717fa7810d4b3ab46f4f5" ++
        "17567d19c4f7d329eb9f952eb872c57b1630cd438c1b163d28f1dfe7b6565527" ++
        "eee10205b7095344b70cd6affcdea58f59bb42f3a27839f9161616a117127401";
    const d_hex =
        "2eea5c10e1f69c507a22b881244c47af447dae4d0ee1a65074b43b31ea5c5a01" ++
        "522513f8b57eaf1c23945351236e2d7c9fe9c2925bbacd3dad32588df61822d1" ++
        "4324d00f01695d920c30bfebff80cf82a291b78173ad4d36ed8bd0d1a8f70e8b" ++
        "4cc0de4845d489095e4778c2ab6423cec7d3f149c823a788b30df358b9fbb523" ++
        "85b54c84a5c1a62fef98bcbac96009f9e5eab331a940586ecee426210643a9d0" ++
        "658317e390d980c0c173a420e1fc62f403c11ef56e80a4b9d9118f25db8beaed" ++
        "1f3484b338727e3ee2dac8e648693d73b9d725abd651bcbd18656d367aba7be7" ++
        "efff529b9e5cec74329e4065f08752ef4bba04b7ead42851e892bbb63f862f71";

    var n: [MODULUS_LEN]u8 = undefined;
    var d: [MODULUS_LEN]u8 = undefined;
    hexToFixed(n_hex, &n);
    hexToFixed(d_hex, &d);
    const key = PrivateKey{ .n = n, .d = d, .e = PUBLIC_EXPONENT };

    const payload = "{\"K\":\"TESTKEY\",\"DI\":\"00112233445566778899\"}";
    var em: [MODULUS_LEN]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;
    const separator = MODULUS_LEN - payload.len - 1;
    @memset(em[2..separator], 0xff);
    em[separator] = 0x00;
    @memcpy(em[separator + 1 ..], payload);

    const m = try Modulus.fromBytes(&n, .big);
    const x = try Modulus.Fe.fromBytes(m, &em, .big);
    const cipher_fe = try m.powWithEncodedPublicExponent(x, &[_]u8{ 0x01, 0x00, 0x01 }, .big);
    var cipher: [MODULUS_LEN]u8 = undefined;
    try cipher_fe.toBytes(&cipher, .big);

    const recovered = try key.rawPrivate(&cipher);
    try std.testing.expectEqualSlices(u8, &em, &recovered);

    var out: [MODULUS_LEN]u8 = undefined;
    const inner = try key.decryptRequest(&cipher, &out);
    try std.testing.expectEqualStrings(payload, inner);
}
