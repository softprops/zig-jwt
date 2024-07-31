const std = @import("std");

/// Key used for decoding JWT tokens
pub const DecodingKey = union(enum) {
    secret: []const u8,
};

/// Key used for encoding JWT token components
pub const EncodingKey = union(enum) {
    secret: []const u8,
};

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

/// Validation rules for registered claims
/// By default validation requires a `exp` claim to ensure the token has
/// not expired.
const Validation = struct {
    /// registered claims used for validation
    ///
    /// see also [rfc7519#section-4.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
    const RegisteredClaims = struct {
        exp: ?u64 = null,
        nbf: ?u64 = null,
        sub: ?[]const u8 = null,
        iss: ?[]const u8 = null,
        aud: ?[]const u8 = null,
    };

    const RegisteredClaim = enum { exp, sub, iss, aud, nbf };

    /// list of claims expected to have been provided
    required_claims: []const RegisteredClaim = &.{.exp},
    /// amount of clockskew, in seconds, permitted
    leeway: u64 = 60,
    /// buffered amount of time to adjust timestamp to account for probably network transit time
    /// after which this token would be expired
    reject_tokens_expiring_in_less_than: u64 = 0,
    /// validate token is not past expiration time
    validate_exp: bool = true,
    /// validate token is not used not before expected time
    validate_nbf: bool = false,
    /// validate audience is as expected
    validate_aud: bool = true,
    /// validate expected audience
    aud: ?[]const []const u8 = null,
    /// validate expected issuer
    iss: ?[]const []const u8 = null,
    /// validate expected subject
    sub: ?[]const u8 = null,
    /// validate supported algoritm
    algorithms: []const Algorithm = &.{.HS256},

    /// validate token meets baseline of registered claims rules
    fn validate(self: @This(), claims: RegisteredClaims) anyerror!void {
        // were all required registered claims provided?
        for (self.required_claims) |c| {
            switch (c) {
                .exp => if (claims.exp == null) return error.MissingExp,
                .sub => if (claims.sub == null) return error.MissingSub,
                .iss => if (claims.iss == null) return error.MissingIss,
                .aud => if (claims.aud == null) return error.MissingAud,
                .nbf => if (claims.nbf == null) return error.MissingNbf,
            }
        }

        // is this token being used before or after its intended window of usage?
        if (self.validate_exp or self.validate_nbf) {
            const nowSec: u64 = @intCast(@divTrunc(std.time.milliTimestamp(), 1_000));
            if (self.validate_exp) {
                if (claims.exp) |exp| {
                    if (exp - self.reject_tokens_expiring_in_less_than < nowSec - self.leeway) {
                        return error.TokenExpired;
                    }
                }
            }

            if (self.validate_nbf) {
                if (claims.nbf) |nbf| {
                    if (nbf > nowSec - self.leeway) {
                        return error.TokenEarly;
                    }
                }
            }
        }

        // is this token intended for the expected subject?
        if (claims.sub) |actual| {
            if (self.sub) |expected| {
                if (!std.mem.eql(u8, actual, expected)) {
                    return error.InvalidSubject;
                }
            }
        }

        // was this token issued by the expected party?
        if (claims.iss) |actual| {
            if (self.iss) |expected| {
                var found = false;
                for (expected) |exp| {
                    if (std.mem.eql(u8, actual, exp)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return error.InvalidIssuer;
                }
            }
        }

        // was this token intended for the expected audience?
        if (self.validate_aud) {
            if (claims.aud) |actual| {
                if (self.aud) |expected| {
                    var found = false;
                    for (expected) |exp| {
                        if (std.mem.eql(u8, exp, actual)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return error.InvalidAudience;
                    }
                }
            }
        }
    }
};

test Validation {
    for ([_]struct {
        desc: []const u8,
        claims: Validation.RegisteredClaims,
        validation: Validation,
        expect: ?anyerror,
    }{
        .{
            .desc = "default: missing exp",
            .claims = .{},
            .validation = .{},
            .expect = error.MissingExp,
        },
        .{
            .desc = "default: expired",
            .claims = .{
                .exp = 0,
            },
            .validation = .{},
            .expect = error.TokenExpired,
        },
        .{
            .desc = "default: expected aud",
            .claims = .{
                .exp = @intCast(@divTrunc(std.time.milliTimestamp(), 1000) * 10),
                .aud = "foo",
            },
            .validation = .{
                .aud = &.{"bar"},
            },
            .expect = error.InvalidAudience,
        },
    }) |case| {
        if (case.validation.validate(case.claims)) {
            std.testing.expect(case.expect != null) catch |err| {
                std.debug.print("error: {s}\n", .{case.desc});
                return err;
            };
        } else |err| {
            std.testing.expect(err == case.expect orelse return error.TestUnexpectedResult) catch |e| {
                std.debug.print("error: {s}", .{case.desc});
                return e;
            };
        }
    }
}

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

fn verify(
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
            std.crypto.auth.hmac.sha2.HmacSha256.create(&dest, msg, key.secret);
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
        .HS384 => {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha384.mac_length]u8 = undefined;
            var src: [dest.len]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&dest, msg, key.secret);
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
        .HS512 => {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
            var src: [dest.len]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&dest, msg, key.secret);
            @memcpy(&src, sig);
            if (!std.crypto.utils.timingSafeEql([dest.len]u8, src, dest)) {
                return error.InvalidSignature;
            }
        },
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

fn sign(
    allocator: std.mem.Allocator,
    msg: []const u8,
    algo: Algorithm,
    key: EncodingKey,
) ![]const u8 {
    return switch (algo) {
        .HS256 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&dest, msg, key.secret);
            break :blk allocator.dupe(u8, &dest);
        },
        .HS384 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha384.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&dest, msg, key.secret);
            break :blk allocator.dupe(u8, &dest);
        },
        .HS512 => blk: {
            var dest: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&dest, msg, key.secret);
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

test "roundtrip" {
    const allocator = std.testing.allocator;
    const token = try encode(allocator, .{ .alg = .HS256 }, .{ .sub = "test", .exp = @divTrunc(std.time.milliTimestamp(), 1000) * 10 }, .{ .secret = "secret" });
    defer allocator.free(token);
    var jwt = try decode(
        std.testing.allocator,
        struct { sub: []const u8 },
        token,
        .{ .secret = "secret" },
        .{},
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}
