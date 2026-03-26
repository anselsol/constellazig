const std = @import("std");
const types = @import("types.zig");
const scheduler = @import("scheduler.zig");
const erasure = @import("erasure.zig");

const Timer = std.time.Timer;
const print = std.debug.print;

pub fn main() !void {
    print("\n=== Constellazig Benchmarks ===\n\n", .{});

    try benchScheduler(100);
    try benchScheduler(1000);
    try benchScheduler(5000);

    try benchRsEncode(1024);
    try benchRsEncode(8 * 1024);
    try benchRsEncode(64 * 1024);

    try benchRsDecode(1024);
    try benchRsDecode(8 * 1024);
    try benchRsDecode(64 * 1024);

    print("\n", .{});
}

fn benchScheduler(num_txs: usize) !void {
    const iterations = 10;
    var total_ns: u64 = 0;

    for (0..iterations) |_| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const gpa = arena.allocator();

        const txs = try gpa.alloc(types.Transaction, num_txs);
        const accs = try gpa.alloc([1]types.Pubkey, num_txs);
        for (0..num_txs) |i| {
            var key: types.Pubkey = .{0} ** 32;
            std.mem.writeInt(u32, key[0..4], @intCast(i % 200), .little);
            accs[i] = [_]types.Pubkey{key};
            txs[i] = .{
                .cu = 10_000 + @as(u64, i % 100) * 1_000,
                .bid = @as(u64, num_txs - i),
                .acc = &accs[i],
                .hash = blk: {
                    var h: types.Hash = .{0} ** 32;
                    std.mem.writeInt(u32, h[0..4], @intCast(i), .little);
                    break :blk h;
                },
                .index = @intCast(i),
            };
        }

        const bitmap_words = (num_txs + 63) / 64;
        const bitmap = try gpa.alloc(u64, bitmap_words);
        @memset(bitmap, std.math.maxInt(u64));

        var timer = try Timer.start();
        _ = try scheduler.selectTxs(txs, bitmap, gpa);
        const elapsed = timer.read();
        total_ns += elapsed;
    }

    const avg_us = total_ns / iterations / 1_000;
    print("  scheduler  {d:>5} txs: {d:>7} us avg ({d} iters)\n", .{ num_txs, avg_us, iterations });
}

fn benchRsEncode(payload_size: usize) !void {
    const iterations = 5;
    var total_ns: u64 = 0;

    for (0..iterations) |_| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const gpa = arena.allocator();

        const payload = try gpa.alloc(u8, payload_size);
        for (payload, 0..) |*b, i| {
            b.* = @intCast(i % 256);
        }

        var timer = try Timer.start();
        _ = try erasure.encode(payload, gpa);
        const elapsed = timer.read();
        total_ns += elapsed;
    }

    const avg_us = total_ns / iterations / 1_000;
    const size_label = if (payload_size >= 1024) payload_size / 1024 else payload_size;
    const unit = if (payload_size >= 1024) "KB" else "B ";
    print("  rs_encode  {d:>5}{s}: {d:>7} us avg ({d} iters)\n", .{ size_label, unit, avg_us, iterations });
}

fn benchRsDecode(payload_size: usize) !void {
    const iterations = 5;
    var total_ns: u64 = 0;

    for (0..iterations) |_| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const gpa = arena.allocator();

        const payload = try gpa.alloc(u8, payload_size);
        for (payload, 0..) |*b, i| {
            b.* = @intCast(i % 256);
        }

        const encoded = try erasure.encode(payload, gpa);

        var timer = try Timer.start();
        _ = try erasure.decode(encoded.root, encoded.shreds[0..64], payload_size, gpa);
        const elapsed = timer.read();
        total_ns += elapsed;
    }

    const avg_us = total_ns / iterations / 1_000;
    const size_label = if (payload_size >= 1024) payload_size / 1024 else payload_size;
    const unit = if (payload_size >= 1024) "KB" else "B ";
    print("  rs_decode  {d:>5}{s}: {d:>7} us avg ({d} iters)\n", .{ size_label, unit, avg_us, iterations });
}
