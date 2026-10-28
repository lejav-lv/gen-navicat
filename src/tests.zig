//! Tests for the macOS-only implementation and its shared cryptographic code.
test {
    _ = @import("common/der.zig");
    _ = @import("common/pem.zig");
    _ = @import("common/rsa.zig");
    _ = @import("common/crypto.zig");
    _ = @import("common/serial.zig");
    _ = @import("macos/macho.zig");
    _ = @import("macos/license.zig");
    _ = @import("macos/cli.zig");
}
