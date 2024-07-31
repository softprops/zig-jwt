const std = @import("std");
const Algorithm = @import("root.zig").Algorithm;
const Header = @import("root.zig").Header;

/// Key used for encoding JWT token components
pub const EncodingKey = union(enum) {
    secret: []const u8,
    edsa: std.crypto.sign.Ed25519.SecretKey,
    es256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    es384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,

    /// create a new edsa encoding key from edsa secret key bytes
    pub fn fromEdsaBytes(bytes: [std.crypto.sign.Ed25519.SecretKey.encoded_length]u8) !@This() {
        return .{ .edsa = try std.crypto.sign.Ed25519.SecretKey.fromBytes(bytes) };
    }

    pub fn fromEs256Bytes(bytes: [std.crypto.ecdsa.EcdsaP256Sha256.SecretKey.encoded_length]u8) !@This() {
        return .{ .es256 = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(bytes) };
    }

    pub fn fromEs384Bytes(bytes: [std.crypto.ecdsa.EcdsaP384Sha384.SecretKey.encoded_length]u8) !@This() {
        return .{ .es384 = try std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(bytes) };
    }
};

test EncodingKey {
    const pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
    const key = try EncodingKey.fromEdsaBytes(pair.secret_key.toBytes());
    try std.testing.expectEqual(key.edsa.toBytes(), pair.secret_key.toBytes());
}

fn encodePart(
    allocator: std.mem.Allocator,
    part: anytype,
) ![]const u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const json = try std.json.stringifyAlloc(allocator, part, .{ .emit_null_optional_fields = false });
    defer allocator.free(json);
    const enc = try allocator.alloc(u8, encoder.calcSize(json.len));
    _ = encoder.encode(enc, json);
    return enc;
}

fn sign(
    allocator: std.mem.Allocator,
    msg: []const u8,
    algo: Algorithm,
    key: EncodingKey,
) ![]const u8 {
    return switch (algo) {
        .HS256 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidEncodingKey,
            });
            break :blk allocator.dupe(u8, &dest);
        },
        .HS384 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha384.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidEncodingKey,
            });
            break :blk allocator.dupe(u8, &dest);
        },
        .HS512 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidEncodingKey,
            });
            break :blk allocator.dupe(u8, &dest);
        },
        .ES256 => blk: {
            const pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(switch (key) {
                .es256 => |v| v,
                else => return error.InvalidEncodingKey,
            });
            const dest = (try pair.sign(msg, null)).toBytes();
            break :blk allocator.dupe(u8, &dest);
        },
        .ES384 => blk: {
            const pair = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.fromSecretKey(switch (key) {
                .es384 => |v| v,
                else => return error.InvalidEncodingKey,
            });
            const dest = (try pair.sign(msg, null)).toBytes();
            break :blk allocator.dupe(u8, &dest);
        },
        .EdDSA => blk: {
            const pair = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(switch (key) {
                .edsa => |v| v,
                else => return error.InvalidEncodingKey,
            });
            const dest = (try pair.sign(msg, null)).toBytes();
            break :blk allocator.dupe(u8, &dest);
        },
        else => return error.TODO,
    };
}

pub fn encode(
    allocator: std.mem.Allocator,
    header: Header,
    claims: anytype,
    key: EncodingKey,
) ![]const u8 {
    comptime {
        if (@typeInfo(@TypeOf(claims)) != .Struct) {
            @compileError("expected claims to be a struct but was a " ++ @typeName(@TypeOf(claims)));
        }
    }

    const encoder = std.base64.url_safe_no_pad.Encoder;

    const header_enc = try encodePart(allocator, header);
    defer allocator.free(header_enc);

    const claims_enc = try encodePart(allocator, claims);
    defer allocator.free(claims_enc);

    const msg = try std.mem.join(allocator, ".", &.{ header_enc, claims_enc });
    defer allocator.free(msg);

    const sig = try sign(allocator, msg, header.alg, key);
    defer allocator.free(sig);
    const sig_enc = try allocator.alloc(u8, encoder.calcSize(sig.len));
    defer allocator.free(sig_enc);
    _ = encoder.encode(sig_enc, sig);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try buf.appendSlice(msg);
    try buf.append('.');
    try buf.appendSlice(sig_enc);

    return try buf.toOwnedSlice();
}
