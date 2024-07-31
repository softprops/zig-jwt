const std = @import("std");

pub const decode = @import("decode.zig").decode;
pub const DecodingKey = @import("decode.zig").DecodingKey;
pub const Validation = @import("validation.zig").Validation;
pub const encode = @import("encode.zig").encode;
pub const EncodingKey = @import("encode.zig").EncodingKey;

pub const Algorithm = enum {
    HS256,
    HS384,
    HS512,
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,

    pub fn jsonStringify(
        self: @This(),
        out: anytype,
    ) !void {
        try out.write(@tagName(self));
    }
};

pub const Header = struct {
    alg: Algorithm,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    jku: ?[]const u8 = null,
    jwk: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    x5t: ?[]const u8 = null,
    @"x5t#S256": ?[]const u8 = null,

    // todo add others
    //
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var out = std.json.writeStream(writer, .{ .emit_null_optional_fields = false });
        defer out.deinit();
        try out.write(self);
    }
};

pub fn JWT(comptime ClaimSet: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        header: Header,
        claims: ClaimSet,

        pub fn deinit(self: *@This()) void {
            const child = self.arena.child_allocator;
            self.arena.deinit();
            child.destroy(self.arena);
        }
    };
}

test "EdDSA.roundtrip" {
    const allocator = std.testing.allocator;
    const validation: Validation = .{
        .now = struct {
            fn func() u64 {
                return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
            }
        }.func,
    };

    // predicable key generation
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(seed[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const pair = try std.crypto.sign.Ed25519.KeyPair.create(seed);

    const token = try encode(
        allocator,
        .{ .alg = .EdDSA },
        .{ .sub = "test", .exp = validation.now() + 60 },
        .{ .edsa = pair.secret_key },
    );
    defer allocator.free(token);
    try std.testing.expectEqualStrings("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzIyNDQxMzM0fQ.qV1oOiw9DmKfaxVv3_W6zn878ke6D-G70bzAMTtNB4-3dCk5reLaqrXEMluP-0vjgfdQaJc-J0XANMP2CVymDQ", token);

    var jwt = try decode(
        allocator,
        struct { sub: []const u8 },
        token,
        .{ .edsa = pair.public_key },
        validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test "HS256.roundtrip" {
    const allocator = std.testing.allocator;
    const validation: Validation = .{
        .now = struct {
            fn func() u64 {
                return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
            }
        }.func,
    };
    const token = try encode(allocator, .{ .alg = .HS256 }, .{ .sub = "test", .exp = validation.now() + 60 }, .{ .secret = "secret" });
    defer allocator.free(token);
    var jwt = try decode(
        std.testing.allocator,
        struct { sub: []const u8 },
        token,
        .{ .secret = "secret" },
        validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test {
    std.testing.refAllDecls(@This());
}
