const std = @import("std");
pub const types = @import("types.zig");
pub const scheduler = @import("scheduler.zig");
pub const galois = @import("galois.zig");
pub const merkle = @import("merkle.zig");
pub const erasure = @import("erasure.zig");
pub const attester = @import("attester.zig");
pub const fault = @import("fault.zig");
pub const proposer = @import("proposer.zig");
pub const validator = @import("validator.zig");
pub const leader = @import("leader.zig");

const Allocator = std.mem.Allocator;
const CTransaction = types.CTransaction;
const Transaction = types.Transaction;

// ============================================================================
// C ABI exports
// ============================================================================

comptime {
    @export(&selectTxsC, .{ .name = "constellation_select_txs" });
    @export(&rsEncodeC, .{ .name = "constellation_rs_encode" });
    @export(&rsDecodeC, .{ .name = "constellation_rs_decode" });
    @export(&attesterCreateC, .{ .name = "constellation_attester_create" });
    @export(&attesterRecordC, .{ .name = "constellation_attester_record" });
    @export(&attesterShiftC, .{ .name = "constellation_attester_shift" });
    @export(&attesterBuildC, .{ .name = "constellation_attester_build" });
    @export(&attesterDestroyC, .{ .name = "constellation_attester_destroy" });
    @export(&checkBlockValidC, .{ .name = "constellation_check_block_valid" });
    @export(&detectFaultC, .{ .name = "constellation_detect_fault" });
}

/// Transaction scheduler (Algorithm 6).
///
/// Returns 0 on success, negative on error.
/// Output buffers must be pre-allocated by the caller with capacity >= txs_len.
fn selectTxsC(
    txs_ptr: [*]const CTransaction,
    txs_len: u32,
    fee_bitmap_ptr: [*]const u64,
    fee_bitmap_len: u32,
    out_indices_ptr: [*]u32,
    out_len: *u32,
) callconv(.c) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Convert CTransaction array to Transaction slice
    const txs = gpa.alloc(Transaction, txs_len) catch return -1;
    for (txs_ptr[0..txs_len], txs) |ct, *t| {
        t.* = .{
            .cu = ct.cu,
            .bid = ct.bid,
            .acc = ct.acc_ptr[0..ct.acc_len],
            .hash = ct.hash,
            .index = ct.index,
        };
    }

    const fee_bitmap = fee_bitmap_ptr[0..fee_bitmap_len];

    const result = scheduler.selectTxs(txs, fee_bitmap, gpa) catch return -2;

    // Copy indices of scheduled transactions to output buffer
    for (result, 0..) |tx, i| {
        out_indices_ptr[i] = tx.index;
    }
    out_len.* = @intCast(result.len);
    return 0;
}

/// Merkle proof depth for RS_N=256 leaves.
const PROOF_DEPTH: u32 = 8; // log2(256)
const PROOF_BYTES: u32 = PROOF_DEPTH * 32; // 256 bytes per shred

/// RS encode with Merkle proofs.
///
/// Outputs:
///   out_root:       32-byte Merkle root
///   out_shred_data: contiguous buffer, 256 * chunk_size bytes
///   out_proofs:     contiguous buffer, 256 * 8 * 32 = 65536 bytes
///   out_chunk_size: size of each shred's data
fn rsEncodeC(
    payload_ptr: [*]const u8,
    payload_len: u32,
    out_root: *types.Hash,
    out_shred_data: [*]u8,
    out_proofs: [*]u8,
    out_chunk_size: *u32,
) callconv(.c) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payload = payload_ptr[0..payload_len];
    const result = erasure.encode(payload, gpa) catch return -1;

    out_root.* = result.root;
    const chunk_size: u32 = @intCast(result.shreds[0].data.len);
    out_chunk_size.* = chunk_size;

    // Copy shred data and proofs into contiguous output buffers
    for (result.shreds, 0..) |shred, i| {
        // Data: shred_data[i * chunk_size .. (i+1) * chunk_size]
        const d_off = i * chunk_size;
        @memcpy(out_shred_data[d_off .. d_off + chunk_size], shred.data);

        // Proof: proofs[i * PROOF_BYTES .. (i+1) * PROOF_BYTES]
        const p_off = i * PROOF_BYTES;
        for (shred.merkle_proof, 0..) |hash, j| {
            const h_off = p_off + j * 32;
            @memcpy(out_proofs[h_off .. h_off + 32], &hash);
        }
    }

    return 0;
}

/// RS decode with Merkle proof verification + roundtrip check.
///
/// Inputs:
///   root:           32-byte Merkle root to verify against
///   shred_data:     contiguous buffer, shred_count * chunk_size bytes
///   shred_proofs:   contiguous buffer, shred_count * 8 * 32 bytes
///   shred_indices:  array of shred_count u16 indices (0..255)
///   shred_count:    number of shreds (must be >= 64)
///   chunk_size:     size of each shred's data
///   original_len:   original payload length (for unpadding)
/// Outputs:
///   out_payload:    pre-allocated buffer, at least original_len bytes
///   out_len:        receives actual decoded length
fn rsDecodeC(
    root: *const types.Hash,
    shred_data: [*]const u8,
    shred_proofs: [*]const u8,
    shred_indices: [*]const u16,
    shred_count: u32,
    chunk_size: u32,
    original_len: u32,
    out_payload: [*]u8,
    out_len: *u32,
) callconv(.c) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Reconstruct Shred structs from flat buffers
    const shreds = gpa.alloc(erasure.Shred, shred_count) catch return -1;
    for (0..shred_count) |i| {
        // Data slice
        const d_off = i * chunk_size;
        const data = shred_data[d_off .. d_off + chunk_size];

        // Proof: 8 hashes of 32 bytes each
        const p_off = i * PROOF_BYTES;
        const proof = gpa.alloc(types.Hash, PROOF_DEPTH) catch return -1;
        for (0..PROOF_DEPTH) |j| {
            const h_off = p_off + j * 32;
            @memcpy(&proof[j], shred_proofs[h_off .. h_off + 32]);
        }

        shreds[i] = .{
            .index = shred_indices[i],
            .data = data,
            .merkle_proof = proof,
        };
    }

    const decoded = erasure.decode(root.*, shreds, original_len, gpa) catch |err| {
        return switch (err) {
            error.InsufficientShreds => -2,
            error.InsufficientValidShreds => -3,
            error.RoundtripVerificationFailed => -4,
            else => -5,
        };
    };

    const len: u32 = @intCast(decoded.len);
    @memcpy(out_payload[0..len], decoded);
    out_len.* = len;
    return 0;
}

/// Create an attester buffer.
fn attesterCreateC(start_cycle: u32) callconv(.c) ?*attester.AttesterBuffer {
    const buf = std.heap.page_allocator.create(attester.AttesterBuffer) catch return null;
    buf.* = attester.AttesterBuffer.init(start_cycle);
    return buf;
}

/// Record a pshred in the attester buffer.
fn attesterRecordC(
    buf: *attester.AttesterBuffer,
    proposer_idx: u8,
    pslice_index: u32,
    commitment: *const types.Hash,
) callconv(.c) void {
    buf.recordPshred(proposer_idx, pslice_index, commitment.*);
}

/// Shift the attester buffer forward by one cycle.
fn attesterShiftC(buf: *attester.AttesterBuffer) callconv(.c) void {
    buf.shiftBuffers();
}

/// Build attestation list for a proposer.
/// Returns the count of entries written to out_entries.
fn attesterBuildC(
    buf: *const attester.AttesterBuffer,
    proposer_idx: u8,
    out_pslice_indices: [*]u32,
    out_hashes: [*]types.Hash,
    out_count: *u32,
) callconv(.c) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const list = buf.buildAttestationList(proposer_idx, gpa) catch return -1;
    for (list, 0..) |entry, i| {
        out_pslice_indices[i] = entry.pslice_index;
        out_hashes[i] = entry.commitment_hash;
    }
    out_count.* = @intCast(list.len);
    return 0;
}

/// Destroy an attester buffer.
fn attesterDestroyC(buf: *attester.AttesterBuffer) callconv(.c) void {
    std.heap.page_allocator.destroy(buf);
}

/// Check block validity (Algorithm 5 / Definition 12).
/// Returns 1 if valid, 0 if invalid.
fn checkBlockValidC(
    num_batches: u32,
    batch_cycles: [*]const u64,
    parent_highest_cycle: u64,
) callconv(.c) i32 {
    // Simplified C API: just validates cycle monotonicity (condition 3).
    // Full validation requires passing attestations and submissions which
    // is complex across FFI. The Zig-native API handles the full check.
    var max_cycle = parent_highest_cycle;
    for (0..num_batches) |i| {
        const cycle = batch_cycles[i];
        if (cycle <= max_cycle) return 0;
        if (i > 0 and cycle != max_cycle + 1) return 0;
        max_cycle = cycle;
    }
    return 1;
}

/// Detect proposer fault from pshred metadata.
/// Simplified C API: checks for conflicting commitment hashes.
/// Returns 1 if fault detected, 0 if no fault.
fn detectFaultC(
    commitment_hashes: [*]const types.Hash,
    merkle_roots: [*]const types.Hash,
    num_pshreds: u32,
) callconv(.c) i32 {
    // Check for any pair with mismatching commitment or root
    for (0..num_pshreds) |i| {
        for (i + 1..num_pshreds) |j| {
            if (!std.mem.eql(u8, &commitment_hashes[i], &commitment_hashes[j])) return 1;
            if (!std.mem.eql(u8, &merkle_roots[i], &merkle_roots[j])) return 1;
        }
    }
    return 0;
}

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}

test "C API: selectTxs smoke test" {
    const acc_a = [_]types.Pubkey{.{1} ** 32};
    const acc_b = [_]types.Pubkey{.{2} ** 32};

    var txs = [_]CTransaction{
        .{ .cu = 100_000, .bid = 100, .acc_ptr = &acc_a, .acc_len = 1, .hash = .{1} ** 32, .index = 0 },
        .{ .cu = 100_000, .bid = 50, .acc_ptr = &acc_b, .acc_len = 1, .hash = .{2} ** 32, .index = 1 },
    };
    const bitmap = [_]u64{0b11};
    var out_indices: [2]u32 = undefined;
    var out_len: u32 = 0;

    const rc = selectTxsC(&txs, 2, &bitmap, 1, &out_indices, &out_len);
    try std.testing.expectEqual(@as(i32, 0), rc);
    try std.testing.expectEqual(@as(u32, 2), out_len);
}

test "C API: attester lifecycle" {
    const buf = attesterCreateC(0) orelse return error.AllocationFailed;
    defer attesterDestroyC(buf);

    const commitment: types.Hash = .{0xAB} ** 32;
    attesterRecordC(buf, 0, 1, &commitment);

    var out_indices: [types.BUFFER_LENGTH]u32 = undefined;
    var out_hashes: [types.BUFFER_LENGTH]types.Hash = undefined;
    var out_count: u32 = 0;

    const rc = attesterBuildC(buf, 0, &out_indices, &out_hashes, &out_count);
    try std.testing.expectEqual(@as(i32, 0), rc);
    try std.testing.expectEqual(@as(u32, 1), out_count);
    try std.testing.expectEqual(@as(u32, 1), out_indices[0]);

    attesterShiftC(buf);
}

test "C API: rsEncode smoke test" {
    const payload = "Hello Constellation!" ** 5;
    var root: types.Hash = undefined;
    var shred_data: [256 * 64]u8 = undefined;
    var proofs: [256 * PROOF_BYTES]u8 = undefined;
    var chunk_size: u32 = 0;

    const rc = rsEncodeC(payload, payload.len, &root, &shred_data, &proofs, &chunk_size);
    try std.testing.expectEqual(@as(i32, 0), rc);
    try std.testing.expect(chunk_size > 0);
    try std.testing.expect(!std.mem.eql(u8, &root, &(.{0} ** 32)));
}

test "C API: rsEncode + rsDecode roundtrip" {
    const payload = "RS FFI roundtrip test data. " ** 10;
    var root: types.Hash = undefined;
    var shred_data: [256 * 64]u8 = undefined;
    var proofs: [256 * PROOF_BYTES]u8 = undefined;
    var chunk_size: u32 = 0;

    // Encode
    const enc_rc = rsEncodeC(payload, payload.len, &root, &shred_data, &proofs, &chunk_size);
    try std.testing.expectEqual(@as(i32, 0), enc_rc);

    // Decode using first 64 shreds (indices 0..63)
    var indices: [64]u16 = undefined;
    for (0..64) |i| {
        indices[i] = @intCast(i);
    }

    // Extract first 64 shreds' data and proofs
    const sub_data_len = 64 * chunk_size;
    const sub_proof_len = 64 * PROOF_BYTES;

    var decoded: [1024]u8 = undefined;
    var decoded_len: u32 = 0;

    const dec_rc = rsDecodeC(
        &root,
        &shred_data,
        &proofs,
        &indices,
        64,
        chunk_size,
        payload.len,
        &decoded,
        &decoded_len,
    );
    _ = sub_data_len;
    _ = sub_proof_len;
    try std.testing.expectEqual(@as(i32, 0), dec_rc);
    try std.testing.expectEqual(@as(u32, payload.len), decoded_len);
    try std.testing.expectEqualSlices(u8, payload, decoded[0..decoded_len]);
}

test "end-to-end: txs → schedule → pslice → RS encode → attester → RS decode → verify" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // 1. Create transactions
    const acc_a = [_]types.Pubkey{.{0x0A} ** 32};
    const acc_b = [_]types.Pubkey{.{0x0B} ** 32};
    const acc_c = [_]types.Pubkey{.{0x0C} ** 32};

    var txs = [_]types.Transaction{
        .{ .cu = 200_000, .bid = 100, .acc = &acc_a, .hash = .{1} ** 32, .index = 0 },
        .{ .cu = 300_000, .bid = 80, .acc = &acc_b, .hash = .{2} ** 32, .index = 1 },
        .{ .cu = 150_000, .bid = 60, .acc = &acc_c, .hash = .{3} ** 32, .index = 2 },
        .{ .cu = 250_000, .bid = 40, .acc = &acc_a, .hash = .{4} ** 32, .index = 3 }, // conflicts with tx0 on A
    };
    const bitmap = [_]u64{0b1111};

    // 2. Schedule (Algorithm 6)
    const scheduled = try scheduler.selectTxs(&txs, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 4), scheduled.len);

    // 3. Build pslice payload: serialize scheduled tx hashes
    var tx_hashes: [4]types.Hash = undefined;
    for (scheduled, 0..) |tx, i| {
        tx_hashes[i] = tx.hash;
    }
    const commitment = merkle.transactionListHash(&tx_hashes);

    // 4. Serialize pslice as payload (concat of tx hashes for simplicity)
    var payload_buf: [4 * 32]u8 = undefined;
    for (0..4) |i| {
        @memcpy(payload_buf[i * 32 .. (i + 1) * 32], &tx_hashes[i]);
    }

    // 5. RS encode the pslice payload
    const encoded = try erasure.encode(&payload_buf, gpa);
    try std.testing.expectEqual(@as(usize, 256), encoded.shreds.len);

    // 6. Simulate attester: record pshred commitments
    var att_buf = attester.AttesterBuffer.init(0);
    att_buf.recordPshred(0, 1, commitment);

    // Build attestation and verify commitment was recorded
    const att_list = try att_buf.buildAttestationList(0, gpa);
    try std.testing.expectEqual(@as(usize, 1), att_list.len);
    try std.testing.expect(std.mem.eql(u8, &att_list[0].commitment_hash, &commitment));

    // Hash attestation lists (for signing)
    const att_hashes = try att_buf.hashAllLists(gpa);
    // Proposer 0's hash should be non-empty
    const empty_hash = attester.AttesterBuffer.hashAttestationList(&.{});
    try std.testing.expect(!std.mem.eql(u8, &att_hashes[0], &empty_hash));

    // 7. RS decode (simulate leader receiving 64 pshreds)
    const decoded = try erasure.decode(encoded.root, encoded.shreds[0..64], payload_buf.len, gpa);
    try std.testing.expectEqualSlices(u8, &payload_buf, decoded);

    // 8. Verify: reconstruct commitment from decoded payload and compare
    var recovered_hashes: [4]types.Hash = undefined;
    for (0..4) |i| {
        @memcpy(&recovered_hashes[i], decoded[i * 32 .. (i + 1) * 32]);
    }
    const recovered_commitment = merkle.transactionListHash(&recovered_hashes);
    try std.testing.expect(std.mem.eql(u8, &recovered_commitment, &commitment));
}
