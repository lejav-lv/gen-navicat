const std = @import("std");
const crypto = @import("crypto.zig");

pub const Error = error{
    UnsupportedVersion,
    InvalidSerial,
    OutOfMemory,
} || crypto.Error;

pub const Product = enum {
    DataModeler,
    Premium,
    MySQL,
    PostgreSQL,
    Oracle,
    SQLServer,
    SQLite,
    MariaDB,
    MongoDB,
    ReportViewer,
    ChartsCreator,
    ChartsViewer,

    pub fn value(self: Product) u8 {
        return switch (self) {
            .DataModeler => 0x84,
            .Premium => 0x65,
            .MySQL => 0x68,
            .PostgreSQL => 0x6C,
            .Oracle => 0x70,
            .SQLServer => 0x74,
            .SQLite => 0x78,
            .MariaDB => 0x7C,
            .MongoDB => 0x80,
            .ReportViewer => 0x0B,
            .ChartsCreator => 0x86,
            .ChartsViewer => 0x88,
        };
    }

    pub fn fromValue(product_value: u8) ?Product {
        return switch (product_value) {
            0x84 => .DataModeler,
            0x65 => .Premium,
            0x68 => .MySQL,
            0x6C => .PostgreSQL,
            0x70 => .Oracle,
            0x74 => .SQLServer,
            0x78 => .SQLite,
            0x7C => .MariaDB,
            0x80 => .MongoDB,
            0x0B => .ReportViewer,
            0x86 => .ChartsCreator,
            0x88 => .ChartsViewer,
            else => null,
        };
    }

    pub fn fromName(text: []const u8) ?Product {
        const info = @typeInfo(Product).@"enum";
        inline for (info.field_names, info.field_values) |field_name, field_value| {
            if (std.ascii.eqlIgnoreCase(text, field_name)) return @fromBackingInt(@intCast(field_value));
        }
        return null;
    }

    pub fn name(self: Product) []const u8 {
        return @tagName(self);
    }
};

pub const Language = enum(u16) {
    English = 0xAC88,
    SimplifiedChinese = 0xCE32,
    TraditionalChinese = 0xAA99,
    Japanese = 0xAD82,
    Polish = 0xBB55,
    Spanish = 0xAE10,
    French = 0xFA20,
    German = 0xB160,
    Korean = 0xB560,
    Russian = 0xEE16,
    Portuguese = 0xCD49,

    pub fn fromName(text: []const u8) ?Language {
        const info = @typeInfo(Language).@"enum";
        inline for (info.field_names, info.field_values) |field_name, field_value| {
            if (std.ascii.eqlIgnoreCase(text, field_name)) return @fromBackingInt(@intCast(field_value));
        }
        return null;
    }

    pub fn fromValue(language_value: u16) ?Language {
        const info = @typeInfo(Language).@"enum";
        inline for (info.field_names, info.field_values) |field_name, field_value| {
            _ = field_name;
            if (field_value == language_value) return @fromBackingInt(@intCast(field_value));
        }
        return null;
    }

    pub fn name(self: Language) []const u8 {
        return @tagName(self);
    }
};

pub const SerialInfo = struct {
    version: u8,
    product: u8,
    language: u16,
    raw: [10]u8,
};

const key_1 = [_]u8{ 0xE9, 0x7F, 0xB0, 0x60, 0x77, 0x45, 0x90, 0xAE };
const key_0 = [_]u8{ 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

pub fn keyForVersion(version: u8) ?[8]u8 {
    if (version >= 16 and version <= 31) return key_1;
    if (version >= 1 and version <= 15) return key_0;
    return null;
}

pub fn makeSerial(
    allocator: std.mem.Allocator,
    io: std.Io,
    version: u8,
    product: Product,
    language: Language,
) Error![16]u8 {
    const key = keyForVersion(version) orelse return error.UnsupportedVersion;
    var data: [10]u8 = undefined;
    data[0] = 0x68;
    data[1] = 0x2A;
    io.random(data[2..5]);
    const lang: u16 = @backingInt(language);
    data[5] = @intCast(lang >> 8);
    data[6] = @intCast(lang & 0xff);
    data[7] = product.value();
    data[8] = ((version - 16) << 4) & 0xff;
    data[9] = 0x32;

    const encrypted = try crypto.desEncrypt(allocator, key, data[2..10]);
    defer allocator.free(encrypted);
    var raw: [10]u8 = undefined;
    raw[0] = data[0];
    raw[1] = data[1];
    @memcpy(raw[2..10], encrypted);
    const result = crypto.base32Encode(&raw);
    const check = try decodeSerialAlloc(allocator, &result);
    if (check.version != version or check.product != product.value() or check.language != lang) {
        return error.InvalidSerial;
    }
    return result;
}

pub fn decodeSerialAlloc(allocator: std.mem.Allocator, serial: []const u8) Error!SerialInfo {
    const raw = crypto.base32Decode(serial) catch return error.InvalidSerial;
    // v16 的密钥是固定的；取不到说明表被改动过，按格式错误处理即可
    const key = keyForVersion(16) orelse return error.UnsupportedVersion;
    const encrypted = try crypto.desDecrypt(allocator, key, raw[2..10]);
    defer allocator.free(encrypted);
    var data: [10]u8 = undefined;
    data[0] = raw[0];
    data[1] = raw[1];
    @memcpy(data[2..10], encrypted);
    if (data[0] != 0x68 or data[1] != 0x2A or data[9] != 0x32) return error.InvalidSerial;
    const version = (data[8] >> 4) + 16;
    if (version < 16 or version > 31) return error.InvalidSerial;
    return .{
        .version = version,
        .product = data[7],
        .language = (@as(u16, data[5]) << 8) | data[6],
        .raw = data,
    };
}
