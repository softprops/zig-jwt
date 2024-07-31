const std = @import("std");
const jwt = @import("jwt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 👇 encode as a token jwt from its components
    const token = try jwt.encode(
        allocator,
        // 👇 header, at a minimum declaring an algorithm
        .{ .alg = .HS256 },
        // 👇 claims
        .{
            .sub = "demo",
            .exp = @divTrunc(std.time.milliTimestamp(), 1000) * 10,
            .aud = "demo",
        },
        // 👇 encoding key used to sign token
        .{ .secret = "secret" },
    );
    defer allocator.free(token);

    // 👇 decode token in to its respective parts
    var decoded = try jwt.decode(
        allocator,
        // 👇 the claims set we expect
        struct { sub: []const u8 },
        // 👇 the raw encoded token
        token,
        // 👇 decoding key used to verify encoded token's signature
        .{ .secret = "secret" },
        // 👇 verification rules that must hold for the token to be successfully decoded
        .{},
    );
    defer decoded.deinit();
}
