const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

/// GF(2^8) finite field element.
pub const GF = u8;

/// Irreducible polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
const PRIMITIVE_POLY: u16 = 0x11D;

/// Comptime-generated exp table (α^i for i = 0..511).
/// Doubled for easy modular indexing without a branch.
const exp_table: [512]GF = blk: {
    var table: [512]GF = undefined;
    var val: u16 = 1;
    for (0..255) |i| {
        table[i] = @intCast(val);
        val <<= 1;
        if (val & 0x100 != 0) val ^= PRIMITIVE_POLY;
    }
    // Copy for wraparound: exp_table[255..510] mirrors [0..255]
    for (255..512) |i| {
        table[i] = table[i - 255];
    }
    break :blk table;
};

/// Comptime-generated log table: log_α(i) for i = 1..255.
/// log_table[0] is undefined (log of 0 doesn't exist).
const log_table: [256]u8 = blk: {
    var table: [256]u8 = .{0} ** 256;
    var val: u16 = 1;
    for (0..255) |i| {
        table[@intCast(val)] = @intCast(i);
        val <<= 1;
        if (val & 0x100 != 0) val ^= PRIMITIVE_POLY;
    }
    break :blk table;
};

/// Addition in GF(2^8) = XOR.
pub fn add(a: GF, b: GF) GF {
    return a ^ b;
}

/// Subtraction in GF(2^8) = XOR (same as addition).
pub fn sub(a: GF, b: GF) GF {
    return a ^ b;
}

/// Multiplication in GF(2^8) via log/exp tables.
pub fn mul(a: GF, b: GF) GF {
    if (a == 0 or b == 0) return 0;
    return exp_table[@as(u16, log_table[a]) + @as(u16, log_table[b])];
}

/// Division in GF(2^8).
pub fn div(a: GF, b: GF) GF {
    std.debug.assert(b != 0);
    if (a == 0) return 0;
    const log_a = @as(u16, log_table[a]);
    const log_b = @as(u16, log_table[b]);
    // Add 255 before subtracting to avoid underflow
    return exp_table[log_a + 255 - log_b];
}

/// Multiplicative inverse: a^(-1).
pub fn inv(a: GF) GF {
    std.debug.assert(a != 0);
    return exp_table[255 - @as(u16, log_table[a])];
}

/// Exponentiation: a^n in GF(2^8).
pub fn pow(a: GF, n: u8) GF {
    if (n == 0) return 1;
    if (a == 0) return 0;
    const log_a = @as(u16, log_table[a]);
    return exp_table[@intCast(@as(u32, log_a) * @as(u32, n) % 255)];
}

/// Invert a square matrix in-place using Gauss-Jordan elimination in GF(2^8).
/// `matrix` is n×n stored as a flat array, row-major.
/// On success, `matrix` contains the inverse. Returns error if singular.
pub fn matInvert(matrix: []GF, n: usize, gpa: Allocator) !void {
    // Augment with identity matrix
    var aug: ArrayList(GF) = .empty;
    try aug.ensureTotalCapacity(gpa, n * 2 * n);
    for (0..n) |row| {
        for (0..n) |col| {
            aug.appendAssumeCapacity(matrix[row * n + col]);
        }
        for (0..n) |col| {
            aug.appendAssumeCapacity(if (row == col) 1 else 0);
        }
    }

    const stride = 2 * n;

    // Forward elimination
    for (0..n) |col| {
        // Find pivot
        var pivot_row: ?usize = null;
        for (col..n) |row| {
            if (aug.items[row * stride + col] != 0) {
                pivot_row = row;
                break;
            }
        }
        const pr = pivot_row orelse return error.SingularMatrix;

        // Swap rows
        if (pr != col) {
            for (0..stride) |j| {
                const tmp = aug.items[col * stride + j];
                aug.items[col * stride + j] = aug.items[pr * stride + j];
                aug.items[pr * stride + j] = tmp;
            }
        }

        // Scale pivot row
        const pivot_val = aug.items[col * stride + col];
        const pivot_inv = inv(pivot_val);
        for (0..stride) |j| {
            aug.items[col * stride + j] = mul(aug.items[col * stride + j], pivot_inv);
        }

        // Eliminate column in all other rows
        for (0..n) |row| {
            if (row == col) continue;
            const factor = aug.items[row * stride + col];
            if (factor == 0) continue;
            for (0..stride) |j| {
                aug.items[row * stride + j] = sub(
                    aug.items[row * stride + j],
                    mul(factor, aug.items[col * stride + j]),
                );
            }
        }
    }

    // Extract inverse from right half
    for (0..n) |row| {
        for (0..n) |col| {
            matrix[row * n + col] = aug.items[row * stride + n + col];
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "exp/log table roundtrip" {
    for (1..256) |i| {
        const val: GF = @intCast(i);
        try std.testing.expectEqual(val, exp_table[log_table[val]]);
    }
}

test "mul(a, inv(a)) == 1 for all nonzero a" {
    for (1..256) |i| {
        const a: GF = @intCast(i);
        try std.testing.expectEqual(@as(GF, 1), mul(a, inv(a)));
    }
}

test "add(a, a) == 0 for all a" {
    for (0..256) |i| {
        const a: GF = @intCast(i);
        try std.testing.expectEqual(@as(GF, 0), add(a, a));
    }
}

test "mul identity" {
    for (0..256) |i| {
        const a: GF = @intCast(i);
        try std.testing.expectEqual(a, mul(a, 1));
        try std.testing.expectEqual(a, mul(1, a));
    }
}

test "mul zero" {
    for (0..256) |i| {
        const a: GF = @intCast(i);
        try std.testing.expectEqual(@as(GF, 0), mul(a, 0));
        try std.testing.expectEqual(@as(GF, 0), mul(0, a));
    }
}

test "div(a, a) == 1 for all nonzero a" {
    for (1..256) |i| {
        const a: GF = @intCast(i);
        try std.testing.expectEqual(@as(GF, 1), div(a, a));
    }
}

test "pow" {
    // α^0 = 1 for all nonzero α
    for (1..256) |i| {
        try std.testing.expectEqual(@as(GF, 1), pow(@intCast(i), 0));
    }
    // 2^8 in GF(2^8) with polynomial 0x11D
    // 2^8 = 0x100 XOR 0x11D = 0x1D = 29
    try std.testing.expectEqual(@as(GF, 0x1D), pow(2, 8));
}

test "matInvert 2x2" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Simple 2x2 matrix: [[1, 2], [3, 4]]
    var mat = [_]GF{ 1, 2, 3, 4 };
    const orig = mat;

    try matInvert(&mat, 2, gpa);

    // Verify: original × inverse = identity
    for (0..2) |i| {
        for (0..2) |j| {
            var sum: GF = 0;
            for (0..2) |k| {
                sum = add(sum, mul(orig[i * 2 + k], mat[k * 2 + j]));
            }
            const expected: GF = if (i == j) 1 else 0;
            try std.testing.expectEqual(expected, sum);
        }
    }
}

test "matInvert 3x3" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var mat = [_]GF{ 1, 0, 0, 0, 1, 0, 0, 0, 1 }; // identity
    try matInvert(&mat, 3, gpa);

    // Inverse of identity is identity
    const expected = [_]GF{ 1, 0, 0, 0, 1, 0, 0, 0, 1 };
    try std.testing.expectEqualSlices(GF, &expected, &mat);
}
