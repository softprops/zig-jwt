const std = @import("std");
const Validation = @import("validation.zig").Validation;
const Algorithm = @import("root.zig").Algorithm;
const JWT = @import("root.zig").JWT;
const Header = @import("root.zig").Header;

/// Key used for decoding JWT tokens
pub const DecodingKey = union(enum) {
    secret: []const u8,
    edsa: std.crypto.sign.Ed25519.PublicKey,

    fn fromEdsaBytes(bytes: [std.crypto.sign.Ed25519.SecretKey]u8) !@This() {
        return .{ .edsa = try std.crypto.sign.Ed25519.SecretKey.fromBytes(bytes) };
    }
};

fn decodePart(allocator: std.mem.Allocator, comptime T: type, encoded: []const u8) !T {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const dest = try allocator.alloc(u8, try decoder.calcSizeForSlice(encoded));
    _ = try decoder.decode(dest, encoded);
    return try std.json.parseFromSliceLeaky(T, allocator, dest, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

pub fn decode(
    allocator: std.mem.Allocator,
    comptime ClaimSet: type,
    str: []const u8,
    key: DecodingKey,
    validation: Validation,
) !JWT(ClaimSet) {
    var arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    if (std.mem.count(u8, str, ".") == 2) {
        const sigSplit = std.mem.lastIndexOfScalar(u8, str, '.').?;
        const messageEnc, const signatureEnc = .{ str[0..sigSplit], str[sigSplit + 1 ..] };

        const header = try decodePart(arena.allocator(), Header, messageEnc[0..std.mem.indexOfScalar(u8, messageEnc, '.').?]);
        const claims = try verify(arena.allocator(), header.alg, key, ClaimSet, messageEnc, signatureEnc, validation);

        return .{
            .arena = arena,
            .header = header,
            .claims = claims,
        };
    }
    return error.MalformedJWT;
}

pub fn verify(
    allocator: std.mem.Allocator,
    algo: Algorithm,
    key: DecodingKey,
    comptime ClaimSet: type,
    msg: []const u8,
    sigEnc: []const u8,
    validation: Validation,
) !ClaimSet {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const sig = try allocator.alloc(u8, try decoder.calcSizeForSlice(sigEnc));
    _ = try decoder.decode(sig, sigEnc);

    switch (algo) {
        .HS256 => {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
            var src: [dest.len]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidDecodingKey,
            });
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
        .HS384 => {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha384.mac_length]u8 = undefined;
            var src: [dest.len]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidDecodingKey,
            });
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
        .HS512 => {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
            var src: [dest.len]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&dest, msg, switch (key) {
                .secret => |v| v,
                else => return error.InvalidDecodingKey,
            });
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
        .EdDSA => {
            var src: [std.crypto.sign.Ed25519.Signature.encoded_length]u8 = undefined;
            @memcpy(&src, sig);
            std.crypto.sign.Ed25519.Signature.fromBytes(src).verify(msg, switch (key) {
                .edsa => |v| v,
                else => return error.InvalidDecodingKey,
            }) catch {
                return error.InvalidSignature;
            };
        },

        //
        //
        else => return error.TODO,
    }

    try validation.validate(
        try decodePart(allocator, Validation.RegisteredClaims, msg[std.mem.indexOfScalar(u8, msg, '.').? + 1 ..]),
    );

    const claims = try decodePart(
        allocator,
        ClaimSet,
        msg[std.mem.indexOfScalar(u8, msg, '.').? + 1 ..],
    );

    return claims;
}
