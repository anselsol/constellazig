const std = @import("std");
const types = @import("types.zig");
const gf = @import("galois.zig");
const merkle = @import("merkle.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const GF = gf.GF;
const Hash = types.Hash;

pub const RS_K: u16 = types.RS_DATA_SHREDS; // 64 data shreds
pub const RS_N: u16 = types.RS_TOTAL_SHREDS; // 256 total shreds

/// Precomputed 256×64 Vandermonde encoding matrix.
/// vander_matrix[i][j] = eval_point(i) ^ j where eval_point(i) = i.
/// Generated at comptime — zero runtime cost.
const vander_matrix: [RS_N][RS_K]GF = blk: {
    @setEvalBranchQuota(200_000);
    var mat: [RS_N][RS_K]GF = undefined;
    for (0..RS_N) |i| {
        const x: GF = @intCast(i);
        var x_power: GF = 1;
        for (0..RS_K) |j| {
            mat[i][j] = x_power;
            x_power = gf.mul(x_power, x);
        }
    }
    break :blk mat;
};

/// A single erasure-coded shred with its Merkle proof.
pub const Shred = struct {
    index: u16,
    data: []const u8,
    merkle_proof: []const Hash,
};

/// Result of RS encoding.
pub const EncodeResult = struct {
    root: Hash,
    shreds: []Shred,
};

/// RS encode with Merkle commitment per Section 2.2.
///
/// 1. Pad payload to multiple of RS_K
/// 2. Split into RS_K data chunks
/// 3. Vandermonde encoding: evaluate polynomial at RS_N points
/// 4. Build Merkle tree over SHA256(shred_i)
/// 5. Extract validation paths
pub fn encode(payload: []const u8, gpa: Allocator) !EncodeResult {
    // Pad to multiple of RS_K
    const chunk_size = if (payload.len == 0) 1 else std.math.divCeil(usize, payload.len, RS_K) catch unreachable;
    const padded_len = chunk_size * RS_K;

    // Create padded payload
    var padded: ArrayList(u8) = .empty;
    try padded.ensureTotalCapacity(gpa, padded_len);
    padded.appendSliceAssumeCapacity(payload);
    for (0..padded_len - payload.len) |_| {
        padded.appendAssumeCapacity(0);
    }

    // Allocate output shred data
    var shred_data: [RS_N][]u8 = undefined;
    for (0..RS_N) |i| {
        const buf = try gpa.alloc(u8, chunk_size);
        @memset(buf, 0);
        shred_data[i] = buf;
    }

    // Encode using precomputed Vandermonde matrix.
    // For each byte position, multiply matrix row by coefficient vector.
    for (0..chunk_size) |byte_pos| {
        for (0..RS_N) |i| {
            var acc: GF = 0;
            for (0..RS_K) |j| {
                const coeff = padded.items[j * chunk_size + byte_pos];
                acc = gf.add(acc, gf.mul(coeff, vander_matrix[i][j]));
            }
            shred_data[i][byte_pos] = acc;
        }
    }

    // Build Merkle tree over SHA256(shred_i)
    var leaf_hashes: [RS_N]Hash = undefined;
    for (0..RS_N) |i| {
        leaf_hashes[i] = merkle.hashLeaf(shred_data[i]);
    }

    const tree = try merkle.buildTreeFromHashes(&leaf_hashes, gpa);
    const root = tree.root();

    // Build shreds with Merkle proofs
    var shreds: ArrayList(Shred) = .empty;
    try shreds.ensureTotalCapacity(gpa, RS_N);
    for (0..RS_N) |i| {
        const proof = try merkle.getValidationPath(&tree, @intCast(i), gpa);
        shreds.appendAssumeCapacity(.{
            .index = @intCast(i),
            .data = shred_data[i],
            .merkle_proof = proof,
        });
    }

    return .{
        .root = root,
        .shreds = shreds.items,
    };
}

/// RS decode with roundtrip verification per Section 2.2.
///
/// 1. Verify each shred's Merkle proof
/// 2. Select RS_K shreds with valid proofs
/// 3. Build RS_K×RS_K Vandermonde submatrix, invert it
/// 4. Multiply inverse by received data to recover original chunks
/// 5. Re-encode, verify root matches (roundtrip check)
pub fn decode(
    root: Hash,
    shreds: []const Shred,
    original_len: usize,
    gpa: Allocator,
) ![]u8 {
    if (shreds.len < RS_K) return error.InsufficientShreds;

    const chunk_size = if (original_len == 0) 1 else std.math.divCeil(usize, original_len, RS_K) catch unreachable;

    // 1. Verify Merkle proofs and select RS_K valid shreds
    var valid_shreds: ArrayList(Shred) = .empty;
    for (shreds) |shred| {
        if (valid_shreds.items.len >= RS_K) break;
        const leaf_hash = merkle.hashLeaf(shred.data);
        if (merkle.verifyPathHash(root, leaf_hash, shred.merkle_proof, shred.index, RS_N)) {
            try valid_shreds.append(gpa, shred);
        }
    }

    if (valid_shreds.items.len < RS_K) return error.InsufficientValidShreds;

    // 2. Build RS_K×RS_K Vandermonde submatrix for the received shred indices
    var submatrix: ArrayList(GF) = .empty;
    try submatrix.ensureTotalCapacity(gpa, RS_K * RS_K);

    for (valid_shreds.items[0..RS_K]) |shred| {
        // Copy the precomputed Vandermonde row for this shred's index
        for (0..RS_K) |j| {
            submatrix.appendAssumeCapacity(vander_matrix[shred.index][j]);
        }
    }

    // 3. Invert the submatrix
    try gf.matInvert(submatrix.items, RS_K, gpa);

    // 4. Multiply inverse by received data to recover original chunks
    // Layout must match encode: data[j * chunk_size + byte_pos] (chunk-major)
    const recovered_buf = try gpa.alloc(u8, RS_K * chunk_size);
    @memset(recovered_buf, 0);

    for (0..chunk_size) |byte_pos| {
        // Build received vector for this byte position
        var received_vec: [RS_K]GF = undefined;
        for (valid_shreds.items[0..RS_K], 0..) |shred, i| {
            received_vec[i] = if (byte_pos < shred.data.len) shred.data[byte_pos] else 0;
        }

        // Multiply: original[j] = sum(inverse[j][i] * received[i])
        for (0..RS_K) |j| {
            var acc: GF = 0;
            for (0..RS_K) |i| {
                acc = gf.add(acc, gf.mul(submatrix.items[j * RS_K + i], received_vec[i]));
            }
            recovered_buf[j * chunk_size + byte_pos] = acc;
        }
    }

    // 5. Roundtrip verification: re-encode full padded data and check root
    const re_encoded = try encode(recovered_buf, gpa);
    if (!std.mem.eql(u8, &re_encoded.root, &root)) {
        return error.RoundtripVerificationFailed;
    }

    // Return original (unpadded) data
    return recovered_buf[0..@min(original_len, recovered_buf.len)];
}

// ============================================================================
// Tests
// ============================================================================

test "encode produces correct number of shreds" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Hello, Constellation!" ** 10;
    const result = try encode(payload, gpa);

    try std.testing.expectEqual(@as(usize, RS_N), result.shreds.len);
    // All shreds have Merkle proofs of depth log2(256) = 8
    for (result.shreds) |shred| {
        try std.testing.expectEqual(@as(usize, 8), shred.merkle_proof.len);
    }
}

test "encode/decode roundtrip with all shreds" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "The quick brown fox jumps over the lazy dog. " ** 20;
    const encoded = try encode(payload, gpa);

    const decoded = try decode(encoded.root, encoded.shreds, payload.len, gpa);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "encode/decode roundtrip with minimum shreds (64 of 256)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Erasure coding test data. " ** 30;
    const encoded = try encode(payload, gpa);

    // Take only the first 64 shreds (indices 0..63)
    const decoded = try decode(encoded.root, encoded.shreds[0..RS_K], payload.len, gpa);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "encode/decode with non-contiguous shred selection" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Testing non-contiguous recovery. " ** 25;
    const encoded = try encode(payload, gpa);

    // Take every 4th shred (indices 0, 4, 8, ... — exactly 64 shreds)
    var selected: ArrayList(Shred) = .empty;
    var i: usize = 0;
    while (i < RS_N) : (i += 4) {
        try selected.append(gpa, encoded.shreds[i]);
    }
    try std.testing.expectEqual(@as(usize, RS_K), selected.items.len);

    const decoded = try decode(encoded.root, selected.items, payload.len, gpa);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "decode fails with corrupted shred (Merkle proof invalid)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Corruption test. " ** 20;
    const encoded = try encode(payload, gpa);

    // Corrupt one shred's data — its Merkle proof won't match
    var corrupted = try ArrayList(Shred).initCapacity(gpa, RS_K + 1);
    for (encoded.shreds[0 .. RS_K + 1]) |shred| {
        corrupted.appendAssumeCapacity(shred);
    }
    // Corrupt the first shred's data
    const bad_data = try gpa.alloc(u8, corrupted.items[0].data.len);
    @memcpy(bad_data, corrupted.items[0].data);
    bad_data[0] ^= 0xFF;
    corrupted.items[0] = .{
        .index = corrupted.items[0].index,
        .data = bad_data,
        .merkle_proof = corrupted.items[0].merkle_proof,
    };

    // Should still succeed using the 64 remaining valid shreds (indices 1..64)
    const decoded = try decode(encoded.root, corrupted.items, payload.len, gpa);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "decode fails with insufficient shreds" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Short payload test.";
    const encoded = try encode(payload, gpa);

    // Only 63 shreds — should fail
    const result = decode(encoded.root, encoded.shreds[0..63], payload.len, gpa);
    try std.testing.expectError(error.InsufficientShreds, result);
}

test "B1 regression: decode with shreds 0 and 255 (eval point distinctness)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = "Eval point regression test. " ** 20;
    const encoded = try encode(payload, gpa);

    // Select 64 shreds including both index 0 and index 255.
    // Before fix: eval_points[0] == eval_points[255] == 1, matrix singular.
    var selected: ArrayList(Shred) = .empty;
    try selected.append(gpa, encoded.shreds[0]); // index 0
    try selected.append(gpa, encoded.shreds[255]); // index 255
    // Fill remaining 62 from indices 1..62
    for (1..63) |i| {
        try selected.append(gpa, encoded.shreds[i]);
    }
    try std.testing.expectEqual(@as(usize, RS_K), selected.items.len);

    const decoded = try decode(encoded.root, selected.items, payload.len, gpa);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "property: random payload + random shred selection roundtrips" {
    var prng = std.Random.DefaultPrng.init(0xCAFE_BABE);
    const rand = prng.random();

    for (0..3) |_| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const gpa = arena.allocator();

        const payload_size = rand.intRangeAtMost(usize, 100, 2000);
        const payload = try gpa.alloc(u8, payload_size);
        for (payload) |*b| b.* = rand.int(u8);

        const encoded = try encode(payload, gpa);

        // Fisher-Yates shuffle of indices, take first 64
        var indices: [RS_N]u16 = undefined;
        for (0..RS_N) |i| indices[i] = @intCast(i);
        var i: usize = RS_N - 1;
        while (i > 0) : (i -= 1) {
            const j = rand.intRangeAtMost(usize, 0, i);
            const tmp = indices[i];
            indices[i] = indices[j];
            indices[j] = tmp;
        }

        var sel: ArrayList(Shred) = .empty;
        for (indices[0..RS_K]) |idx| {
            try sel.append(gpa, encoded.shreds[idx]);
        }

        const dec = try decode(encoded.root, sel.items, payload_size, gpa);
        try std.testing.expectEqualSlices(u8, payload, dec);
    }
}
