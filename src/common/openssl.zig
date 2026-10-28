const std = @import("std");

const BIO = opaque {};
const BIO_METHOD = opaque {};
const RSA = opaque {};
const BIGNUM = opaque {};
const BN_GENCB = opaque {};

extern fn BIO_new_mem_buf(buf: *const anyopaque, len: c_int) ?*BIO;
extern fn BIO_new(t: *const BIO_METHOD) ?*BIO;
extern fn BIO_s_mem() ?*const BIO_METHOD;
extern fn BIO_free(bio: *BIO) c_int;
extern fn BIO_read(bio: *BIO, data: [*]u8, len: c_int) c_int;
extern fn PEM_read_bio_RSAPrivateKey(bio: *BIO, rsa: ?*?*RSA, cb: ?*const anyopaque, u: ?*anyopaque) ?*RSA;
extern fn PEM_write_bio_RSA_PUBKEY(bio: *BIO, rsa: *RSA) c_int;
extern fn PEM_write_bio_RSAPrivateKey(bio: *BIO, rsa: *RSA, enc: ?*const anyopaque, kstr: ?[*]const u8, klen: c_int, cb: ?*const anyopaque, u: ?*anyopaque) c_int;
extern fn RSA_private_encrypt(flen: c_int, from: [*]const u8, to: [*]u8, rsa: *RSA, padding: c_int) c_int;
extern fn RSA_public_decrypt(flen: c_int, from: [*]const u8, to: [*]u8, rsa: *RSA, padding: c_int) c_int;
extern fn RSA_size(rsa: *const RSA) c_int;
extern fn RSA_free(rsa: *RSA) void;
extern fn RSA_new() ?*RSA;
extern fn RSA_generate_key_ex(rsa: *RSA, bits: c_int, e: *BIGNUM, cb: ?*BN_GENCB) c_int;
extern fn BN_new() ?*BIGNUM;
extern fn BN_set_word(bn: *BIGNUM, w: c_ulong) c_int;
extern fn BN_free(bn: *BIGNUM) void;

extern fn DES_set_key_unchecked(key: *const [8]u8, schedule: *[32]u32) void;
extern fn DES_ecb_encrypt(input: *const [8]u8, output: *[8]u8, schedule: *[32]u32, enc: c_int) void;

pub const Error = error{
    Bio,
    PrivateKey,
    Signature,
    PublicKey,
    KeyGeneration,
    OutOfMemory,
};

pub fn generatePrivateKey(allocator: std.mem.Allocator) Error![]u8 {
    const rsa = RSA_new() orelse return error.KeyGeneration;
    defer RSA_free(rsa);
    const e = BN_new() orelse return error.KeyGeneration;
    defer BN_free(e);
    if (BN_set_word(e, 65537) != 1) return error.KeyGeneration;
    if (RSA_generate_key_ex(rsa, 2048, e, null) != 1) return error.KeyGeneration;

    const method = BIO_s_mem() orelse return error.Bio;
    const bio = BIO_new(method) orelse return error.Bio;
    defer _ = BIO_free(bio);
    if (PEM_write_bio_RSAPrivateKey(bio, rsa, null, null, 0, null, null) != 1) return error.KeyGeneration;

    const out = allocator.alloc(u8, 4096) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    const pem_len = BIO_read(bio, out.ptr, @intCast(out.len));
    if (pem_len <= 0) return error.KeyGeneration;
    return allocator.realloc(out, @intCast(pem_len)) catch {
        allocator.free(out);
        return error.OutOfMemory;
    };
}

pub const Rsa = struct {
    ptr: *RSA,

    pub fn fromPem(pem: []const u8) Error!Rsa {
        const bio = BIO_new_mem_buf(@ptrCast(pem.ptr), @intCast(pem.len)) orelse return error.Bio;
        defer _ = BIO_free(bio);
        const rsa = PEM_read_bio_RSAPrivateKey(bio, null, null, null) orelse return error.PrivateKey;
        return .{ .ptr = rsa };
    }

    pub fn deinit(self: Rsa) void {
        RSA_free(self.ptr);
    }

    pub fn sign(self: Rsa, allocator: std.mem.Allocator, payload: []const u8) Error![]u8 {
        const size: usize = @intCast(RSA_size(self.ptr));
        const out = allocator.alloc(u8, size) catch return error.OutOfMemory;
        errdefer allocator.free(out);
        const signed_len = RSA_private_encrypt(@intCast(payload.len), payload.ptr, out.ptr, self.ptr, 1);
        if (signed_len <= 0) return error.Signature;
        const n: usize = @intCast(signed_len);
        return allocator.realloc(out, n) catch {
            allocator.free(out);
            return error.OutOfMemory;
        };
    }

    pub fn recover(self: Rsa, allocator: std.mem.Allocator, signature: []const u8) Error![]u8 {
        const size: usize = @intCast(RSA_size(self.ptr));
        const out = allocator.alloc(u8, size) catch return error.OutOfMemory;
        errdefer allocator.free(out);
        const recovered_len = RSA_public_decrypt(@intCast(signature.len), signature.ptr, out.ptr, self.ptr, 1);
        if (recovered_len <= 0) return error.Signature;
        const n: usize = @intCast(recovered_len);
        return allocator.realloc(out, n) catch {
            allocator.free(out);
            return error.OutOfMemory;
        };
    }

    pub fn publicPem(self: Rsa, allocator: std.mem.Allocator) Error![]u8 {
        const bio = BIO_new(BIO_s_mem().?) orelse return error.Bio;
        defer _ = BIO_free(bio);
        if (PEM_write_bio_RSA_PUBKEY(bio, self.ptr) != 1) return error.PublicKey;
        const out = allocator.alloc(u8, 4096) catch return error.OutOfMemory;
        errdefer allocator.free(out);
        const pem_len = BIO_read(bio, out.ptr, @intCast(out.len));
        if (pem_len <= 0) return error.PublicKey;
        const n: usize = @intCast(pem_len);
        return allocator.realloc(out, n) catch {
            allocator.free(out);
            return error.OutOfMemory;
        };
    }

    pub fn publicBase64(self: Rsa, allocator: std.mem.Allocator) Error![]u8 {
        const pem = try self.publicPem(allocator);
        defer allocator.free(pem);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        var lines = std.mem.splitScalar(u8, pem, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "-----")) continue;
            out.appendSlice(allocator, trimmed) catch return error.OutOfMemory;
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }
};

pub fn desEncryptBlock(key: [8]u8, input: [8]u8) [8]u8 {
    var schedule: [32]u32 align(8) = undefined;
    DES_set_key_unchecked(&key, &schedule);
    var output: [8]u8 = undefined;
    DES_ecb_encrypt(&input, &output, &schedule, 1);
    return output;
}

pub fn desDecryptBlock(key: [8]u8, input: [8]u8) [8]u8 {
    var schedule: [32]u32 align(8) = undefined;
    DES_set_key_unchecked(&key, &schedule);
    var output: [8]u8 = undefined;
    DES_ecb_encrypt(&input, &output, &schedule, 0);
    return output;
}
