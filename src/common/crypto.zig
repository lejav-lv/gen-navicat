const std = @import("std");
const openssl = @import("openssl.zig");

pub const Error = error{
    InvalidHex,
    InvalidLength,
    InvalidPadding,
    InvalidBase32,
    OutOfMemory,
};

pub fn hexDecode(allocator: std.mem.Allocator, text: []const u8) Error![]u8 {
    if (text.len % 2 != 0) return error.InvalidHex;
    const out = allocator.alloc(u8, text.len / 2) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    for (out, 0..) |*byte, i| {
        const hi = std.fmt.charToDigit(text[i * 2], 16) catch return error.InvalidHex;
        const lo = std.fmt.charToDigit(text[i * 2 + 1], 16) catch return error.InvalidHex;
        byte.* = (hi << 4) | lo;
    }
    return out;
}

pub fn hexEncodeUpper(allocator: std.mem.Allocator, bytes: []const u8) Error![]u8 {
    const digits = "0123456789ABCDEF";
    const out = allocator.alloc(u8, bytes.len * 2) catch return error.OutOfMemory;
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}

pub fn isHex(text: []const u8) bool {
    if (text.len == 0 or text.len % 2 != 0) return false;
    for (text) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

pub fn md5(data: []const u8) [16]u8 {
    return std.crypto.hash.Md5.hashResult(data);
}

pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const pad_len = 16 - (data.len % 16);
    const out = allocator.alloc(u8, data.len + pad_len) catch return error.OutOfMemory;
    @memcpy(out[0..data.len], data);
    @memset(out[data.len..], @intCast(pad_len));
    return out;
}

pub fn pkcs7Unpad(data: []u8) Error![]u8 {
    if (data.len == 0 or data.len % 16 != 0) return error.InvalidPadding;
    const pad_len = data[data.len - 1];
    if (pad_len < 1 or pad_len > 16 or pad_len > data.len) return error.InvalidPadding;
    for (data[data.len - pad_len ..]) |byte| {
        if (byte != pad_len) return error.InvalidPadding;
    }
    return data[0 .. data.len - pad_len];
}

pub fn aesCbcEncrypt(
    allocator: std.mem.Allocator,
    key: [16]u8,
    iv: [16]u8,
    plaintext: []const u8,
    pad: bool,
) Error![]u8 {
    var input_owned: ?[]u8 = null;
    const input = if (pad) blk: {
        const padded = try pkcs7Pad(allocator, plaintext);
        input_owned = padded;
        break :blk padded;
    } else plaintext;
    defer if (input_owned) |owned| allocator.free(owned);
    if (input.len % 16 != 0) return error.InvalidLength;

    const out = allocator.alloc(u8, input.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    var cipher = std.crypto.core.aes.Aes128.initEnc(key);
    var previous = iv;
    var i: usize = 0;
    while (i < input.len) : (i += 16) {
        var block: [16]u8 = undefined;
        for (0..16) |j| block[j] = input[i + j] ^ previous[j];
        cipher.encrypt(out[i..][0..16], &block);
        previous = out[i..][0..16].*;
    }
    return out;
}

pub fn aesCbcDecrypt(
    allocator: std.mem.Allocator,
    key: [16]u8,
    iv: [16]u8,
    ciphertext: []const u8,
    unpad: bool,
) Error![]u8 {
    if (ciphertext.len % 16 != 0) return error.InvalidLength;
    const out = allocator.alloc(u8, ciphertext.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    var cipher = std.crypto.core.aes.Aes128.initDec(key);
    var previous = iv;
    var i: usize = 0;
    while (i < ciphertext.len) : (i += 16) {
        var block: [16]u8 = undefined;
        cipher.decrypt(&block, ciphertext[i..][0..16]);
        for (0..16) |j| out[i + j] = block[j] ^ previous[j];
        previous = ciphertext[i..][0..16].*;
    }
    if (unpad) {
        const plain = try pkcs7Unpad(out);
        const shortened = allocator.realloc(out, plain.len) catch return plain;
        return shortened;
    }
    return out;
}

pub fn randomBytes(io: std.Io, buffer: []u8) void {
    io.random(buffer);
}

const base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32Encode(data: []const u8) [16]u8 {
    std.debug.assert(data.len == 10);
    var out: [16]u8 = undefined;
    var accumulator: u32 = 0;
    var bits: u5 = 0;
    var out_index: usize = 0;
    for (data) |byte| {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const index: usize = @intCast((accumulator >> bits) & 0x1f);
            out[out_index] = switch (base32_alphabet[index]) {
                'I' => '8',
                'O' => '9',
                else => |ch| ch,
            };
            out_index += 1;
        }
    }
    if (bits > 0) {
        const index: usize = @intCast((accumulator << (5 - bits)) & 0x1f);
        out[out_index] = switch (base32_alphabet[index]) {
            'I' => '8',
            'O' => '9',
            else => |ch| ch,
        };
        out_index += 1;
    }
    std.debug.assert(out_index == 16);
    return out;
}

pub fn base32Decode(text: []const u8) Error![10]u8 {
    if (text.len != 16) return error.InvalidBase32;
    var out: [10]u8 = undefined;
    var out_index: usize = 0;
    var accumulator: u32 = 0;
    var bits: u5 = 0;
    for (text) |raw_ch| {
        const ch = std.ascii.toUpper(raw_ch);
        const normalized = switch (ch) {
            '8' => 'I',
            '9' => 'O',
            else => ch,
        };
        const value: u5 = switch (normalized) {
            'A'...'Z' => @intCast(normalized - 'A'),
            '2'...'7' => @intCast(normalized - '2' + 26),
            else => return error.InvalidBase32,
        };
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (out_index >= out.len) return error.InvalidBase32;
            out[out_index] = @intCast((accumulator >> bits) & 0xff);
            out_index += 1;
        }
    }
    if (out_index != out.len) return error.InvalidBase32;
    return out;
}

pub fn desEncrypt(allocator: std.mem.Allocator, key: [8]u8, data: []const u8) Error![]u8 {
    if (data.len % 8 != 0) return error.InvalidLength;
    const out = allocator.alloc(u8, data.len) catch return error.OutOfMemory;
    var i: usize = 0;
    while (i < data.len) : (i += 8) {
        out[i..][0..8].* = openssl.desEncryptBlock(key, data[i..][0..8].*);
    }
    return out;
}

pub fn desDecrypt(allocator: std.mem.Allocator, key: [8]u8, data: []const u8) Error![]u8 {
    if (data.len % 8 != 0) return error.InvalidLength;
    const out = allocator.alloc(u8, data.len) catch return error.OutOfMemory;
    var i: usize = 0;
    while (i < data.len) : (i += 8) {
        out[i..][0..8].* = openssl.desDecryptBlock(key, data[i..][0..8].*);
    }
    return out;
}
