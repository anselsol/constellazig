const std = @import("std");
const types = @import("types.zig");
const proposer_mod = @import("proposer.zig");
const fault_mod = @import("fault.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Hash = types.Hash;
const Pshred = types.Pshred;
const Attestation = types.Attestation;
const AttestedTuple = types.AttestedTuple;
const Batch = types.Batch;
const Submission = types.Submission;
const FaultWitness = types.FaultWitness;

/// Algorithm 3: BuildBatch.
///
/// Given attestations and corresponding pshreds for a cycle,
/// produces a batch (submissions) and any fault witnesses.
pub fn buildBatch(
    epoch: u64,
    cycle: u64,
    attestations: []const Attestation,
    pshreds: []const Pshred,
    prev_attested: []const AttestedTuple,
    gpa: Allocator,
) !BuildBatchResult {
    var submissions: ArrayList(Submission) = .empty;
    var fault_witnesses: ArrayList(FaultWitness) = .empty;

    // Collect newly attested tuples from attestations (not in prev_attested)
    const newly_attested = try collectNewlyAttested(attestations, prev_attested, gpa);

    for (newly_attested) |tuple| {
        // Gather pshreds matching this tuple
        var matching: ArrayList(Pshred) = .empty;
        for (pshreds) |ps| {
            if (ps.epoch == tuple.epoch and
                ps.cycle == tuple.cycle and
                ps.proposer_index == tuple.proposer_index and
                ps.pslice_index == tuple.pslice_index and
                std.mem.eql(u8, &ps.commitment_hash, &tuple.commitment_hash))
            {
                try matching.append(gpa, ps);
            }
        }

        // Attempt to decode the pslice
        const pslice = try proposer_mod.decodePslice(
            matching.items,
            tuple.commitment_hash,
            gpa,
        );

        if (pslice) |ps| {
            // Valid pslice — create submission
            try submissions.append(gpa, .{
                .epoch = ps.epoch,
                .cycle = ps.cycle,
                .proposer_index = ps.proposer_index,
                .pslice_index = ps.pslice_index,
                .transactions = ps.transactions,
            });
        } else {
            // Invalid — try to create fault witness
            if (try fault_mod.detectFault(
                matching.items,
                tuple.epoch,
                tuple.cycle,
                tuple.proposer_index,
                gpa,
            )) |fw| {
                try fault_witnesses.append(gpa, fw);
            }
        }
    }

    return .{
        .batch = .{
            .epoch = epoch,
            .cycle = cycle,
            .attester_indices = &.{},
            .attestations = attestations,
            .submissions = submissions.items,
        },
        .fault_witnesses = fault_witnesses.items,
    };
}

pub const BuildBatchResult = struct {
    batch: Batch,
    fault_witnesses: []FaultWitness,
};

/// Collect attested tuples from attestations that aren't in prev_attested.
/// A tuple is "attested" if >= γp (RS_DATA_SHREDS=64) attesters include it.
fn collectNewlyAttested(
    attestations: []const Attestation,
    prev_attested: []const AttestedTuple,
    gpa: Allocator,
) ![]AttestedTuple {
    // Count occurrences of each (proposer, pslice_index, commitment_hash) tuple
    const Key = struct { proposer_index: u8, pslice_index: u32, commitment_hash: Hash };

    // Simple approach: collect all unique tuples with their count
    var tuple_counts: ArrayList(struct { key: Key, epoch: u64, cycle: u64, count: u32 }) = .empty;

    for (attestations) |att| {
        for (att.lists, 0..) |list, prop_idx| {
            for (list) |entry| {
                // Find or insert
                var found = false;
                for (tuple_counts.items) |*tc| {
                    if (tc.key.proposer_index == @as(u8, @intCast(prop_idx)) and
                        tc.key.pslice_index == entry.pslice_index and
                        std.mem.eql(u8, &tc.key.commitment_hash, &entry.commitment_hash))
                    {
                        tc.count += 1;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try tuple_counts.append(gpa, .{
                        .key = .{
                            .proposer_index = @intCast(prop_idx),
                            .pslice_index = entry.pslice_index,
                            .commitment_hash = entry.commitment_hash,
                        },
                        .epoch = att.epoch,
                        .cycle = entry.cycle,
                        .count = 1,
                    });
                }
            }
        }
    }

    // Filter: >= γp attestations AND not in prev_attested
    var result: ArrayList(AttestedTuple) = .empty;
    for (tuple_counts.items) |tc| {
        if (tc.count < types.RS_DATA_SHREDS) continue;

        // Check not in prev_attested
        var already = false;
        for (prev_attested) |pa| {
            if (pa.proposer_index == tc.key.proposer_index and
                pa.pslice_index == tc.key.pslice_index and
                std.mem.eql(u8, &pa.commitment_hash, &tc.key.commitment_hash))
            {
                already = true;
                break;
            }
        }
        if (already) continue;

        try result.append(gpa, .{
            .epoch = tc.epoch,
            .cycle = tc.cycle,
            .proposer_index = tc.key.proposer_index,
            .pslice_index = tc.key.pslice_index,
            .commitment_hash = tc.key.commitment_hash,
        });
    }

    return result.items;
}

// ============================================================================
// Tests
// ============================================================================

test "buildBatch: empty attestations produce empty batch" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const result = try buildBatch(1, 10, &.{}, &.{}, &.{}, gpa);
    try std.testing.expectEqual(@as(usize, 0), result.batch.submissions.len);
    try std.testing.expectEqual(@as(usize, 0), result.fault_witnesses.len);
}

test "collectNewlyAttested: filters by quorum and prev_attested" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Create 64 attestations all attesting to the same tuple
    const entry = types.AttestationEntry{
        .cycle = 10,
        .pslice_index = 1,
        .commitment_hash = .{0xAA} ** 32,
    };
    const entry_list = [_]types.AttestationEntry{entry};

    const attestations = try gpa.alloc(Attestation, 64);
    for (attestations, 0..) |*att, i| {
        var lists: [types.NUM_PROPOSERS][]const types.AttestationEntry = undefined;
        for (&lists, 0..) |*l, j| {
            l.* = if (j == 0) &entry_list else &.{};
        }
        att.* = .{
            .epoch = 1,
            .cycle = 10,
            .attester_index = @intCast(i),
            .lists = lists,
            .signature = .{0} ** 64,
        };
    }

    // Should produce one newly-attested tuple (64 attesters = quorum)
    const newly = try collectNewlyAttested(attestations, &.{}, gpa);
    try std.testing.expectEqual(@as(usize, 1), newly.len);
    try std.testing.expectEqual(@as(u8, 0), newly[0].proposer_index);

    // Same tuple in prev_attested → filtered out
    const newly2 = try collectNewlyAttested(attestations, newly, gpa);
    try std.testing.expectEqual(@as(usize, 0), newly2.len);
}
