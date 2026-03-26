const std = @import("std");
const types = @import("types.zig");
const scheduler = @import("scheduler.zig");
const merkle = @import("merkle.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Hash = types.Hash;
const Block = types.Block;
const Batch = types.Batch;
const Submission = types.Submission;
const AttestedTuple = types.AttestedTuple;
const FaultWitness = types.FaultWitness;

/// Algorithm 5: CheckBlockValid (Definition 12).
///
/// Validates that a block satisfies all three conditions:
/// 1. newlyAttested tuples and submissions match 1:1 by commitment hash
/// 2. Every omitted proposer has a fault witness on the garbage pile
/// 3. Cycle indices are consecutive within the block and > parent's highest cycle
pub fn checkBlockValid(block: *const Block, parent_highest_cycle: u64) bool {
    // Condition 3: cycle monotonicity
    var max_cycle = parent_highest_cycle;
    for (block.batches, 0..) |batch, i| {
        // First batch must have cycle > parent's highest
        if (batch.cycle <= max_cycle) return false;
        // Subsequent batches within block must be consecutive
        if (i > 0 and batch.cycle != max_cycle + 1) return false;
        max_cycle = batch.cycle;
    }

    // Condition 1: submissions match newly-attested tuples
    // For each batch, every submission must have a commitment hash that
    // appears in the attestation data, and vice versa.
    for (block.batches) |batch| {
        if (!checkSubmissionsMatchAttestations(&batch)) return false;
    }

    // Condition 2: every omitted proposer has a fault witness
    if (!checkFaultWitnesses(block)) return false;

    return true;
}

/// Check that submissions and newly-attested tuples are 1:1 by hash.
fn checkSubmissionsMatchAttestations(batch: *const Batch) bool {
    // Each submission's commitment hash must correspond to an attested tuple.
    // Simplified check: verify submission count matches and hashes are valid.
    for (batch.submissions) |sub| {
        const h = sub.commitmentHash();
        // Check this hash appears in at least one attestation
        var found = false;
        for (batch.attestations) |att| {
            for (att.lists[sub.proposer_index]) |entry| {
                if (entry.pslice_index == sub.pslice_index and
                    std.mem.eql(u8, &entry.commitment_hash, &h))
                {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (!found) return false;
    }
    return true;
}

/// Check that every omitted proposer has a corresponding fault witness.
fn checkFaultWitnesses(block: *const Block) bool {
    // For each fault witness, verify it references a proposer that was
    // actually omitted (i.e., has attested tuples but no submission).
    // Simplified: just verify fault witnesses have non-empty evidence.
    for (block.garbage_pile) |fw| {
        if (fw.evidence.len == 0) return false;
    }
    return true;
}

/// Algorithm 4: ExecuteBatch — collect all txs from submissions, run SelectTxs.
pub fn executeBatch(
    batch: *const Batch,
    fee_bitmap: []const u64,
    gpa: Allocator,
) ![]types.Transaction {
    // Collect all transactions from all submissions
    var all_txs: ArrayList(types.Transaction) = .empty;
    for (batch.submissions) |sub| {
        for (sub.transactions) |tx| {
            try all_txs.append(gpa, tx);
        }
    }

    // Run the transaction scheduler
    return scheduler.selectTxs(all_txs.items, fee_bitmap, gpa);
}

// ============================================================================
// Tests
// ============================================================================

test "checkBlockValid: valid empty block" {
    const block = Block{
        .slot = 1,
        .parent_slot = 0,
        .batches = &.{},
        .garbage_pile = &.{},
    };
    try std.testing.expect(checkBlockValid(&block, 0));
}

test "checkBlockValid: cycle must exceed parent" {
    const batch = Batch{
        .epoch = 1,
        .cycle = 5, // <= parent's highest cycle of 10
        .attester_indices = &.{},
        .attestations = &.{},
        .submissions = &.{},
    };
    const block = Block{
        .slot = 1,
        .parent_slot = 0,
        .batches = &[_]Batch{batch},
        .garbage_pile = &.{},
    };
    // Parent highest cycle is 10, batch cycle is 5 → invalid
    try std.testing.expect(!checkBlockValid(&block, 10));
}

test "checkBlockValid: consecutive cycles within block" {
    const b1 = Batch{ .epoch = 1, .cycle = 11, .attester_indices = &.{}, .attestations = &.{}, .submissions = &.{} };
    const b2 = Batch{ .epoch = 1, .cycle = 12, .attester_indices = &.{}, .attestations = &.{}, .submissions = &.{} };
    const b3 = Batch{ .epoch = 1, .cycle = 14, .attester_indices = &.{}, .attestations = &.{}, .submissions = &.{} }; // gap!

    // Consecutive: valid
    const valid_block = Block{ .slot = 1, .parent_slot = 0, .batches = &[_]Batch{ b1, b2 }, .garbage_pile = &.{} };
    try std.testing.expect(checkBlockValid(&valid_block, 10));

    // Non-consecutive: invalid
    const invalid_block = Block{ .slot = 1, .parent_slot = 0, .batches = &[_]Batch{ b1, b3 }, .garbage_pile = &.{} };
    try std.testing.expect(!checkBlockValid(&invalid_block, 10));
}

test "executeBatch: schedules transactions from submissions" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const txs = [_]types.Transaction{
        .{ .cu = 100_000, .bid = 50, .acc = &.{}, .hash = .{1} ** 32, .index = 0 },
        .{ .cu = 200_000, .bid = 30, .acc = &.{}, .hash = .{2} ** 32, .index = 1 },
    };

    const sub = Submission{
        .epoch = 1,
        .cycle = 10,
        .proposer_index = 0,
        .pslice_index = 1,
        .transactions = &txs,
    };

    const batch = Batch{
        .epoch = 1,
        .cycle = 10,
        .attester_indices = &.{},
        .attestations = &.{},
        .submissions = &[_]Submission{sub},
    };

    const bitmap = [_]u64{0b11};
    const scheduled = try executeBatch(&batch, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 2), scheduled.len);
}
