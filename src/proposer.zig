const std = @import("std");
const types = @import("types.zig");
const erasure = @import("erasure.zig");
const merkle = @import("merkle.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Hash = types.Hash;
const Transaction = types.Transaction;
const Pshred = types.Pshred;
const Pslice = types.Pslice;
const Signature = types.Signature;

/// Result of creating pshreds from a transaction list.
pub const PshredSet = struct {
    pshreds: []Pshred,
    commitment_hash: Hash,
    merkle_root: Hash,
};

/// Algorithm 1: Create pshreds from a list of transactions.
///
/// newPshreds(e, c, j, t, h, T):
/// 1. Compute commitment hash h(T) per Definition 2
/// 2. Serialize transactions into payload
/// 3. RS encode payload into 256 pshreds with Merkle proofs
/// 4. Return pshreds ready for distribution to attesters
pub fn newPshreds(
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    pslice_index: u32,
    transactions: []const Transaction,
    signature: Signature,
    gpa: Allocator,
) !PshredSet {
    // 1. Compute commitment hash: h(T) = SHA256(SHA256(tx1) || ... || SHA256(txk))
    var tx_hashes: ArrayList(Hash) = .empty;
    for (transactions) |tx| {
        try tx_hashes.append(gpa, tx.hash);
    }
    const commitment_hash = merkle.transactionListHash(tx_hashes.items);

    // 2. Serialize transactions into payload (concatenate hashes for now)
    // In production, this would be the full serialized transaction data.
    const payload = try serializeTransactions(transactions, gpa);

    // 3. RS encode
    const encoded = try erasure.encode(payload, gpa);

    // 4. Wrap as Pshred structs
    var pshreds: ArrayList(Pshred) = .empty;
    try pshreds.ensureTotalCapacity(gpa, types.RS_TOTAL_SHREDS);
    for (encoded.shreds) |shred| {
        pshreds.appendAssumeCapacity(.{
            .epoch = epoch,
            .cycle = cycle,
            .proposer_index = proposer_index,
            .pslice_index = pslice_index,
            .shred_index = shred.index,
            .commitment_hash = commitment_hash,
            .merkle_root = encoded.root,
            .data = shred.data,
            .merkle_proof = shred.merkle_proof,
            .signature = signature,
        });
    }

    return .{
        .pshreds = pshreds.items,
        .commitment_hash = commitment_hash,
        .merkle_root = encoded.root,
    };
}

/// Decode a pslice from a set of pshreds (used by leader in BuildBatch).
/// Requires >= γp (64) valid pshreds with consistent metadata.
/// Returns null if decode fails (fault witness should be created).
pub fn decodePslice(
    pshreds: []const Pshred,
    expected_commitment: Hash,
    gpa: Allocator,
) !?Pslice {
    if (pshreds.len < types.RS_DATA_SHREDS) return null;

    // Build erasure shreds
    const shreds = try gpa.alloc(erasure.Shred, pshreds.len);
    for (pshreds, 0..) |ps, i| {
        shreds[i] = .{
            .index = ps.shred_index,
            .data = ps.data,
            .merkle_proof = ps.merkle_proof,
        };
    }

    const root = pshreds[0].merkle_root;
    const chunk_size = if (pshreds[0].data.len > 0) pshreds[0].data.len else return null;
    const payload_len = chunk_size * types.RS_DATA_SHREDS;

    const payload = erasure.decode(root, shreds, payload_len, gpa) catch return null;

    // Deserialize transactions from payload
    const transactions = try deserializeTransactions(payload, gpa);

    // Verify commitment hash matches
    var tx_hashes: ArrayList(Hash) = .empty;
    for (transactions) |tx| {
        try tx_hashes.append(gpa, tx.hash);
    }
    const computed_commitment = merkle.transactionListHash(tx_hashes.items);
    if (!std.mem.eql(u8, &computed_commitment, &expected_commitment)) return null;

    return Pslice{
        .epoch = pshreds[0].epoch,
        .cycle = pshreds[0].cycle,
        .proposer_index = pshreds[0].proposer_index,
        .pslice_index = pshreds[0].pslice_index,
        .commitment_hash = expected_commitment,
        .merkle_root = root,
        .transactions = transactions,
        .signature = pshreds[0].signature,
    };
}

/// Serialize transactions into a byte payload.
/// Format: [num_txs: u32][tx1_hash: 32][tx1_cu: u64][tx1_bid: u64]...
fn serializeTransactions(txs: []const Transaction, gpa: Allocator) ![]u8 {
    const tx_size = 32 + 8 + 8; // hash + cu + bid
    const total = 4 + txs.len * tx_size;
    const buf = try gpa.alloc(u8, total);

    std.mem.writeInt(u32, buf[0..4], @intCast(txs.len), .little);
    for (txs, 0..) |tx, i| {
        const off = 4 + i * tx_size;
        @memcpy(buf[off .. off + 32], &tx.hash);
        @memcpy(buf[off + 32 .. off + 40], &std.mem.toBytes(std.mem.nativeToLittle(u64, tx.cu)));
        @memcpy(buf[off + 40 .. off + 48], &std.mem.toBytes(std.mem.nativeToLittle(u64, tx.bid)));
    }
    return buf;
}

/// Deserialize transactions from a byte payload.
fn deserializeTransactions(payload: []const u8, gpa: Allocator) ![]Transaction {
    if (payload.len < 4) return &.{};
    const num_txs = std.mem.readInt(u32, payload[0..4], .little);
    const tx_size = 32 + 8 + 8;
    if (payload.len < 4 + @as(usize, num_txs) * tx_size) return &.{};

    const txs = try gpa.alloc(Transaction, num_txs);
    for (0..num_txs) |i| {
        const off = 4 + i * tx_size;
        var hash: Hash = undefined;
        @memcpy(&hash, payload[off .. off + 32]);
        var cu_bytes: [8]u8 = undefined;
        var bid_bytes: [8]u8 = undefined;
        @memcpy(&cu_bytes, payload[off + 32 .. off + 40]);
        @memcpy(&bid_bytes, payload[off + 40 .. off + 48]);
        txs[i] = .{
            .hash = hash,
            .cu = std.mem.littleToNative(u64, @bitCast(cu_bytes)),
            .bid = std.mem.littleToNative(u64, @bitCast(bid_bytes)),
            .acc = &.{},
            .index = @intCast(i),
        };
    }
    return txs;
}

// ============================================================================
// Tests
// ============================================================================

test "newPshreds: produces 256 pshreds with correct metadata" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const txs = [_]Transaction{
        .{ .cu = 100_000, .bid = 50, .acc = &.{}, .hash = .{1} ** 32, .index = 0 },
        .{ .cu = 200_000, .bid = 30, .acc = &.{}, .hash = .{2} ** 32, .index = 1 },
    };

    const result = try newPshreds(1, 10, 3, 42, &txs, .{0} ** 64, gpa);

    try std.testing.expectEqual(@as(usize, 256), result.pshreds.len);
    // All pshreds share the same metadata
    for (result.pshreds) |ps| {
        try std.testing.expectEqual(@as(u64, 1), ps.epoch);
        try std.testing.expectEqual(@as(u64, 10), ps.cycle);
        try std.testing.expectEqual(@as(u8, 3), ps.proposer_index);
        try std.testing.expectEqual(@as(u32, 42), ps.pslice_index);
        try std.testing.expect(std.mem.eql(u8, &ps.commitment_hash, &result.commitment_hash));
        try std.testing.expect(std.mem.eql(u8, &ps.merkle_root, &result.merkle_root));
    }
}

test "newPshreds → decodePslice roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const txs = [_]Transaction{
        .{ .cu = 100_000, .bid = 50, .acc = &.{}, .hash = .{1} ** 32, .index = 0 },
        .{ .cu = 200_000, .bid = 30, .acc = &.{}, .hash = .{2} ** 32, .index = 1 },
        .{ .cu = 300_000, .bid = 10, .acc = &.{}, .hash = .{3} ** 32, .index = 2 },
    };

    const created = try newPshreds(1, 10, 0, 1, &txs, .{0} ** 64, gpa);

    // Decode using first 64 pshreds
    const pslice = try decodePslice(created.pshreds[0..64], created.commitment_hash, gpa);
    try std.testing.expect(pslice != null);

    const ps = pslice.?;
    try std.testing.expectEqual(@as(usize, 3), ps.transactions.len);
    try std.testing.expectEqual(@as(u64, 100_000), ps.transactions[0].cu);
    try std.testing.expectEqual(@as(u64, 200_000), ps.transactions[1].cu);
    try std.testing.expectEqual(@as(u64, 300_000), ps.transactions[2].cu);
    try std.testing.expect(std.mem.eql(u8, &ps.commitment_hash, &created.commitment_hash));
}

test "serialize/deserialize roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const txs = [_]Transaction{
        .{ .cu = 42, .bid = 99, .acc = &.{}, .hash = .{0xAB} ** 32, .index = 0 },
    };

    const payload = try serializeTransactions(&txs, gpa);
    const recovered = try deserializeTransactions(payload, gpa);

    try std.testing.expectEqual(@as(usize, 1), recovered.len);
    try std.testing.expectEqual(@as(u64, 42), recovered[0].cu);
    try std.testing.expectEqual(@as(u64, 99), recovered[0].bid);
    try std.testing.expect(std.mem.eql(u8, &recovered[0].hash, &(.{0xAB} ** 32)));
}
