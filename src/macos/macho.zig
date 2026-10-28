//! macOS ARM64 Mach-O inspection and a deliberately version-pinned patch.
//! Thin and universal containers are parsed separately; all offsets below are
//! relative to the ARM64 slice. Unknown binaries are rejected before any write.
const std = @import("std");

pub const supported_sha256 = "0a51210bb5fc20e0931a6326d7c0d51953e009b3da0d910c4a66003f0a839ff5";
pub const function_offset: usize = 0x2a7fbfc;
pub const storage_function: u64 = 0x23b0;
pub const key_offset: usize = 56;
pub const public_key_len: usize = 392;
pub const patch_len: usize = key_offset + public_key_len;
pub const profile_name = "Navicat Premium 18.0.5 (321), macOS arm64";

fn range(data: []const u8, offset: usize, size: usize) ![]const u8 {
    if (offset > data.len or size > data.len - offset) return error.TruncatedMachO;
    return data[offset..][0..size];
}
fn read32(data: []const u8, offset: usize, endian: std.builtin.Endian) !u32 {
    return std.mem.readInt(u32, (try range(data, offset, 4))[0..4], endian);
}
fn read64(data: []const u8, offset: usize, endian: std.builtin.Endian) !u64 {
    return std.mem.readInt(u64, (try range(data, offset, 8))[0..8], endian);
}

pub const Image = struct {
    data: []const u8,
    slice_offset: usize,
    slice_size: usize,
    command_count: u32,
    command_size: u32,

    pub fn bytes(self: Image) []const u8 {
        return self.data[self.slice_offset..][0..self.slice_size];
    }

    pub fn parse(data: []const u8) !Image {
        const magic = try read32(data, 0, .big);
        var offset: usize = 0;
        var size: usize = data.len;
        if (magic == 0xcafebabe or magic == 0xcafebabf) {
            const count = try read32(data, 4, .big);
            if (count == 0 or count > 64) return error.InvalidMachO;
            const wide = magic == 0xcafebabf;
            const stride: usize = if (wide) 32 else 20;
            const table_end = 8 + @as(usize, count) * stride;
            _ = try range(data, 0, table_end);
            var found = false;
            for (0..count) |i| {
                const entry = 8 + i * stride;
                const arch = try read32(data, entry, .big);
                const off: usize = if (wide) @intCast(try read64(data, entry + 8, .big)) else try read32(data, entry + 8, .big);
                const len: usize = if (wide) @intCast(try read64(data, entry + 16, .big)) else try read32(data, entry + 12, .big);
                if (off < table_end or len == 0) return error.InvalidMachO;
                _ = try range(data, off, len);
                if (arch == 0x0100000c) {
                    if (found) return error.AmbiguousArm64Slice;
                    found = true;
                    offset = off;
                    size = len;
                }
            }
            if (!found) return error.NoArm64Slice;
        } else if (magic != 0xcffaedfe) return error.NotMachO;

        const slice = try range(data, offset, size);
        _ = try range(slice, 0, 32);
        if (try read32(slice, 0, .little) != 0xfeedfacf) return error.NotMachO;
        if (try read32(slice, 4, .little) != 0x0100000c) return error.NoArm64Slice;
        // arm64e uses a different authenticated-pointer ABI.
        if ((try read32(slice, 8, .little)) & 0x00ffffff != 0) return error.UnsupportedArm64Subtype;
        const count = try read32(slice, 16, .little);
        const command_size = try read32(slice, 20, .little);
        _ = try range(slice, 32, command_size);
        if (count > command_size / 8) return error.InvalidMachO;
        var cursor: usize = 32;
        for (0..count) |_| {
            const length = try read32(slice, cursor + 4, .little);
            if (length < 8 or length % 8 != 0 or length > 32 + command_size - cursor) return error.InvalidMachO;
            if (try read32(slice, cursor, .little) == 0x19) {
                if (length < 72) return error.InvalidMachO;
                const section_count = try read32(slice, cursor + 64, .little);
                if (section_count > (length - 72) / 80) return error.InvalidMachO;
                const off = try read64(slice, cursor + 40, .little);
                const len = try read64(slice, cursor + 48, .little);
                _ = try range(slice, @intCast(off), @intCast(len));
            }
            cursor += length;
        }
        if (cursor != 32 + command_size) return error.InvalidMachO;
        return .{ .data = data, .slice_offset = offset, .slice_size = size, .command_count = count, .command_size = command_size };
    }

    pub fn virtualAddress(self: Image, offset: usize, length: usize) !u64 {
        const data = self.bytes();
        var cursor: usize = 32;
        for (0..self.command_count) |_| {
            if (try read32(data, cursor, .little) == 0x19) {
                const fileoff = try read64(data, cursor + 40, .little);
                const filesize = try read64(data, cursor + 48, .little);
                const prot = try read32(data, cursor + 60, .little);
                if (offset >= fileoff and offset - fileoff <= filesize and length <= filesize - (offset - fileoff) and prot & 4 != 0) {
                    return (try read64(data, cursor + 24, .little)) + offset - fileoff;
                }
            }
            cursor += try read32(data, cursor + 4, .little);
        }
        return error.NonExecutablePatchRange;
    }

    pub fn requireSupported(self: Image) !void {
        if (!std.mem.eql(u8, &digest(self.bytes()), supported_sha256)) return error.UnsupportedMacBinary;
        const address = try self.virtualAddress(function_offset, patch_len);
        if (address != function_offset) return error.UnsupportedMacBinary;
        _ = try self.virtualAddress(@intCast(storage_function), 32);
    }
};

pub fn digest(data: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return std.fmt.bytesToHex(&hash, .lower);
}

pub fn branchLink(from: u64, to: u64) !u32 {
    if (from > std.math.maxInt(i64) or to > std.math.maxInt(i64)) return error.BranchOutOfRange;
    const delta = @as(i64, @intCast(to)) - @as(i64, @intCast(from));
    if (@mod(delta, 4) != 0 or delta < -0x8000000 or delta >= 0x8000000) return error.BranchOutOfRange;
    const signed: i32 = @intCast(@divExact(delta, 4));
    return 0x94000000 | (@as(u32, @bitCast(signed)) & 0x03ffffff);
}

// Apple ARM64 ABI: x8 points to the caller's libc++ return object. The existing
// string storage helper constructs that object and returns its writable buffer.
// Only caller-saved registers are used; sp stays 16-byte aligned across BL.
pub fn buildStub(key: []const u8, address: u64, helper: u64) ![patch_len]u8 {
    if (key.len != public_key_len) return error.InvalidPublicKey;
    for (key) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '/' and c != '=') return error.InvalidPublicKey;
    var result: [patch_len]u8 = undefined;
    const words = [_]u32{
        0xa9bf7bfd,                           0x910003fd, 0xaa0803e0, 0xd2803101,
        try branchLink(address + 16, helper), 0x10000121, 0xd2803102, 0x38401423,
        0x38001403,                           0xf1000442, 0x54ffffa1, 0x3900001f,
        0xa8c17bfd,                           0xd65f03c0,
    };
    for (words, 0..) |word, i| std.mem.writeInt(u32, result[i * 4 ..][0..4], word, .little);
    @memcpy(result[key_offset..], key);
    return result;
}

pub fn patch(allocator: std.mem.Allocator, data: []const u8, key: []const u8) ![]u8 {
    const image = try Image.parse(data);
    try image.requireSupported();
    const stub = try buildStub(key, function_offset, storage_function);
    const out = try allocator.dupe(u8, data);
    @memcpy(out[image.slice_offset + function_offset ..][0..patch_len], &stub);
    return out;
}

pub fn installedKey(image: Image) ?[]const u8 {
    const region = range(image.bytes(), function_offset, patch_len) catch return null;
    const key = region[key_offset..];
    const expected = buildStub(key, function_offset, storage_function) catch return null;
    if (!std.mem.eql(u8, region, &expected)) return null;
    return key;
}

fn fixture() [256]u8 {
    var data: [256]u8 = @splat(0);
    std.mem.writeInt(u32, data[0..4], 0xfeedfacf, .little);
    std.mem.writeInt(u32, data[4..8], 0x0100000c, .little);
    std.mem.writeInt(u32, data[16..20], 1, .little);
    std.mem.writeInt(u32, data[20..24], 72, .little);
    std.mem.writeInt(u32, data[32..36], 0x19, .little);
    std.mem.writeInt(u32, data[36..40], 72, .little);
    std.mem.writeInt(u64, data[80..88], 256, .little);
    std.mem.writeInt(u32, data[92..96], 5, .little);
    return data;
}

test "parse thin ARM64 and map executable ranges" {
    const data = fixture();
    const image = try Image.parse(&data);
    try std.testing.expectEqual(@as(u64, 120), try image.virtualAddress(120, 20));
    try std.testing.expectError(error.NonExecutablePatchRange, image.virtualAddress(250, 20));
    try std.testing.expectError(error.UnsupportedMacBinary, image.requireSupported());
}

test "universal ARM64 slice offsets are container relative" {
    var data: [512]u8 = @splat(0);
    std.mem.writeInt(u32, data[0..4], 0xcafebabe, .big);
    std.mem.writeInt(u32, data[4..8], 1, .big);
    std.mem.writeInt(u32, data[8..12], 0x0100000c, .big);
    std.mem.writeInt(u32, data[16..20], 256, .big);
    std.mem.writeInt(u32, data[20..24], 256, .big);
    @memcpy(data[256..], &fixture());
    const image = try Image.parse(&data);
    try std.testing.expectEqual(@as(usize, 256), image.slice_offset);
    std.mem.writeInt(u32, data[16..20], 0xfffffff0, .big);
    try std.testing.expectError(error.TruncatedMachO, Image.parse(&data));
}

test "malformed headers and foreign architectures fail closed" {
    var data = fixture();
    try std.testing.expectError(error.TruncatedMachO, Image.parse(data[0..12]));
    std.mem.writeInt(u32, data[36..40], 0, .little);
    try std.testing.expectError(error.InvalidMachO, Image.parse(&data));
    data = fixture();
    std.mem.writeInt(u32, data[4..8], 0x01000007, .little);
    try std.testing.expectError(error.NoArm64Slice, Image.parse(&data));
    data = fixture();
    std.mem.writeInt(u32, data[8..12], 2, .little);
    try std.testing.expectError(error.UnsupportedArm64Subtype, Image.parse(&data));
}

test "ARM64 BL signed range and stub buffer boundaries" {
    try std.testing.expectEqual(@as(u32, 0x94000002), try branchLink(0x1000, 0x1008));
    try std.testing.expectEqual(@as(u32, 0x97ffffff), try branchLink(0x1000, 0xffc));
    try std.testing.expectError(error.BranchOutOfRange, branchLink(0, 0x8000000));
    try std.testing.expectError(error.BranchOutOfRange, branchLink(0, 3));
    const key: [392]u8 = @splat('A');
    const stub = try buildStub(&key, function_offset, storage_function);
    try std.testing.expectEqualSlices(u8, &key, stub[key_offset..]);
    try std.testing.expectEqual(@as(u32, 0xd65f03c0), try read32(&stub, 52, .little));
    try std.testing.expectError(error.InvalidPublicKey, buildStub("short", 0, 0));
}
