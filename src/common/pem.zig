//! PEM 编解码 —— 平台无关。
//!
//! 只处理本项目用到的两种块：
//!   · `-----BEGIN PUBLIC KEY-----`      SPKI（navicat.exe 里内嵌的就是这种，460 字节）
//!   · `-----BEGIN RSA PRIVATE KEY-----` PKCS#1
//!   · `-----BEGIN PRIVATE KEY-----`     PKCS#8（本项目的 keygen 产出的就是这种）

const std = @import("std");

pub const Error = error{
    MissingHeader,
    MissingFooter,
    InvalidBase64,
    OutOfMemory,
};

pub const Block = struct {
    /// 头部标签，例如 "PUBLIC KEY"
    label: []const u8,
    /// base64 解码后的 DER 字节（调用方负责释放）
    der: []u8,

    pub fn deinit(self: Block, allocator: std.mem.Allocator) void {
        allocator.free(self.der);
    }
};

const base64_decoder = std.base64.standard.Decoder;
const base64_encoder = std.base64.standard.Encoder;

fn findLabel(data: []const u8, label: []const u8) ?struct { body_start: usize, body_end: usize } {
    var header_buf: [128]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "-----BEGIN {s}-----", .{label}) catch return null;
    const start = std.mem.indexOf(u8, data, header) orelse return null;
    var footer_buf: [128]u8 = undefined;
    const footer = std.fmt.bufPrint(&footer_buf, "-----END {s}-----", .{label}) catch return null;
    const body_start = start + header.len;
    const footer_pos = std.mem.indexOfPos(u8, data, body_start, footer) orelse return null;
    return .{ .body_start = body_start, .body_end = footer_pos };
}

/// 从 PEM 文本里取出指定标签的块；`label` 不含 `-----BEGIN ` 前缀。
pub fn decode(allocator: std.mem.Allocator, data: []const u8, label: []const u8) Error!Block {
    const range = findLabel(data, label) orelse return error.MissingHeader;
    // 统计有效 base64 字符数（忽略空白、CRLF 与行尾）
    var count: usize = 0;
    for (data[range.body_start..range.body_end]) |byte| {
        switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/', '=' => count += 1,
            ' ', '\t', '\r', '\n' => {},
            else => return error.InvalidBase64,
        }
    }
    if (count == 0 or count % 4 != 0) return error.InvalidBase64;

    const compact = try allocator.alloc(u8, count);
    defer allocator.free(compact);
    var index: usize = 0;
    for (data[range.body_start..range.body_end]) |byte| {
        switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/', '=' => {
                compact[index] = byte;
                index += 1;
            },
            else => {},
        }
    }

    const decoded_len = base64_decoder.calcSizeForSlice(compact) catch return error.InvalidBase64;
    const der = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(der);
    base64_decoder.decode(der, compact) catch return error.InvalidBase64;
    return .{ .label = label, .der = der };
}

/// 把 DER 编码成 PEM 文本（64 列 + CRLF + 末尾换行）。
/// `line_ending` 传 "\r\n" 可得到与 Navicat 内嵌 PEM 完全一致的格式。
pub fn encode(
    allocator: std.mem.Allocator,
    label: []const u8,
    der: []const u8,
    line_ending: []const u8,
) Error![]u8 {
    const b64_len = base64_encoder.calcSize(der.len);
    const b64 = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64);
    _ = base64_encoder.encode(b64, der);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    out.appendSlice(allocator, "-----BEGIN ") catch return error.OutOfMemory;
    out.appendSlice(allocator, label) catch return error.OutOfMemory;
    out.appendSlice(allocator, "-----") catch return error.OutOfMemory;
    out.appendSlice(allocator, line_ending) catch return error.OutOfMemory;

    var pos: usize = 0;
    while (pos < b64.len) : (pos += 64) {
        const end = @min(pos + 64, b64.len);
        out.appendSlice(allocator, b64[pos..end]) catch return error.OutOfMemory;
        out.appendSlice(allocator, line_ending) catch return error.OutOfMemory;
    }

    out.appendSlice(allocator, "-----END ") catch return error.OutOfMemory;
    out.appendSlice(allocator, label) catch return error.OutOfMemory;
    out.appendSlice(allocator, "-----") catch return error.OutOfMemory;
    out.appendSlice(allocator, line_ending) catch return error.OutOfMemory;
    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// 从 PEM 文本里取出第一段 base64（不管标签），用于宽松读取。
pub fn firstBase64(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const labels = [_][]const u8{ "PUBLIC KEY", "RSA PRIVATE KEY", "PRIVATE KEY" };
    for (labels) |label| {
        if (decode(allocator, data, label)) |block| {
            defer block.deinit(allocator);
            return allocator.dupe(u8, block.der) catch return error.OutOfMemory;
        } else |_| {}
    }
    return error.MissingHeader;
}

test "encode and decode roundtrip with CRLF" {
    const allocator = std.testing.allocator;
    const der = [_]u8{ 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d };
    const pem = try encode(allocator, "PUBLIC KEY", &der, "\r\n");
    defer allocator.free(pem);
    try std.testing.expect(std.mem.indexOf(u8, pem, "-----BEGIN PUBLIC KEY-----\r\n") != null);

    const block = try decode(allocator, pem, "PUBLIC KEY");
    defer block.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &der, block.der);
}

test "decode ignores whitespace" {
    const allocator = std.testing.allocator;
    const text = "-----BEGIN PUBLIC KEY-----\r\nMIIB\r\nIjAN\r\n-----END PUBLIC KEY-----\r\n";
    const block = try decode(allocator, text, "PUBLIC KEY");
    defer block.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 6), block.der.len);
}
