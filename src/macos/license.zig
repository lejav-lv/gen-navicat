//! macOS manual activation uses the K/DI/N/O/T request-response shape.
const std = @import("std");
const rsa = @import("../common/rsa.zig");

pub fn payload(allocator: std.mem.Allocator, request: []const u8, name: []const u8, org: []const u8, timestamp: i64) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, request, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidRequestCode;
    const key = parsed.value.object.get("K") orelse return error.MissingField;
    const device = parsed.value.object.get("DI") orelse return error.MissingField;
    if (key != .string or device != .string or key.string.len == 0 or device.string.len == 0) return error.InvalidRequestCode;
    if (parsed.value.object.get("P")) |platform| {
        if (platform != .string or !std.ascii.eqlIgnoreCase(platform.string, "MAC")) return error.NotMacRequest;
    }
    const result = try std.json.Stringify.valueAlloc(allocator, .{ .K = key.string, .DI = device.string, .N = name, .O = org, .T = timestamp }, .{});
    errdefer allocator.free(result);
    if (result.len > 240) return error.PayloadTooLarge;
    return result;
}

pub fn sign(allocator: std.mem.Allocator, key: rsa.PrivateKey, request_base64: []const u8, name: []const u8, org: []const u8, timestamp: i64) ![]u8 {
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(allocator);
    for (request_base64) |c| if (!std.ascii.isWhitespace(c)) try clean.append(allocator, c);
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(clean.items) catch return error.InvalidRequestCode;
    if (size != 256) return error.InvalidRequestCode;
    var cipher: [256]u8 = undefined;
    decoder.decode(&cipher, clean.items) catch return error.InvalidRequestCode;
    var clear: [256]u8 = undefined;
    const request = key.decryptRequest(&cipher, &clear) catch return error.SigningFailed;
    const response = try payload(allocator, request, name, org, timestamp);
    defer allocator.free(response);
    const signature = try key.sign(response);
    var recovered: [256]u8 = undefined;
    const verified = try rsa.verifySignature(&key.n, &signature, &recovered);
    if (!std.mem.eql(u8, verified, response)) return error.Signature;
    const encoder = std.base64.standard.Encoder;
    const result = try allocator.alloc(u8, encoder.calcSize(signature.len));
    _ = encoder.encode(result, &signature);
    return result;
}

test "Mac payload preserves device and escapes unicode names" {
    const allocator = std.testing.allocator;
    const result = try payload(allocator, "{\"K\":\"TEST\",\"DI\":\"device\",\"P\":\"MAC\"}", "张\"三", "公司", 123);
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("张\"三", parsed.value.object.get("N").?.string);
    try std.testing.expectEqualStrings("device", parsed.value.object.get("DI").?.string);
    try std.testing.expect(!parsed.value.object.contains("P"));
    try std.testing.expect(!parsed.value.object.contains("FA"));
    try std.testing.expect(!parsed.value.object.contains("M"));
    try std.testing.expectError(error.NotMacRequest, payload(allocator, "{\"K\":\"x\",\"DI\":\"y\",\"P\":\"WIN\"}", "n", "o", 1));
    try std.testing.expectError(error.MissingField, payload(allocator, "{\"K\":\"x\"}", "n", "o", 1));
    try std.testing.expectError(error.PayloadTooLarge, payload(allocator, "{\"K\":\"x\",\"DI\":\"y\"}", &@as([250]u8, @splat('x')), "o", 1));
}
