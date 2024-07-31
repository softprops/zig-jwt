const std = @import("std");
const jwt = @import("root.zig");

const benchmark = @import("benchmark");

// bench hello world comparison
test "bench decode" {
    try benchmark.main(.{}, struct {
        pub fn benchDecode(b: *benchmark.B) !void {
            // Setup is not timed
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();

            const token = try jwt.encode(arena.allocator(), .{ .alg = .HS256 }, .{ .sub = "test", .exp = @divTrunc(std.time.milliTimestamp(), 1000) * 10 }, .{ .secret = "secret" });
            defer arena.allocator().free(token);

            while (b.step()) {
                var decoded = try jwt.decode(
                    arena.allocator(),
                    struct { sub: []const u8 },
                    token,
                    .{ .secret = "secret" },
                    .{},
                );
                defer decoded.deinit();

                // `use` is a helper that calls `std.mem.doNotOptimizeAway`
                b.use(decoded);
            }
        }
    })();
}

test "bench encode" {
    try benchmark.main(.{}, struct {
        // Benchmarks are just public functions
        pub fn benchEncode(b: *benchmark.B) !void {
            // Setup is not timed
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();

            while (b.step()) { // Number of iterations is automatically adjusted for accurate timing
                defer _ = arena.reset(.retain_capacity);

                const token = try jwt.encode(arena.allocator(), .{ .alg = .HS256 }, .{ .sub = "test", .exp = @divTrunc(std.time.milliTimestamp(), 1000) * 10 }, .{ .secret = "secret" });
                defer arena.allocator().free(token);

                // `use` is a helper that calls `std.mem.doNotOptimizeAway`
                b.use(token);
            }
        }
    })();
}
