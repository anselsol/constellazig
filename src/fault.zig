const std = @import("std");
const types = @import("types.zig");
const erasure = @import("erasure.zig");
const merkle = @import("merkle.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Pshred = types.Pshred;
const FaultWitness = types.FaultWitness;
const Hash = types.Hash;

/// Definition 7: Detect proposer fault from a set of pshreds.
///
/// A fault exists if either:
/// (a) Two pshreds have different commitment_hash or merkle_root
///     for the same (epoch, cycle, proposer, pslice_index).
/// (b) γp (64) pshreds are present but RS decode fails.
///
/// Returns a FaultWitness if fault detected, null otherwise.
pub fn detectFault(
    pshreds: []const Pshred,
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    gpa: Allocator,
) !?FaultWitness {
    if (pshreds.len == 0) return null;

    // (a) Check for conflicting commitments or roots
    if (try detectConflictingPshreds(pshreds, gpa)) |evidence| {
        return FaultWitness{
            .epoch = epoch,
            .cycle = cycle,
            .proposer_index = proposer_index,
            .evidence = evidence,
        };
    }

    // (b) If we have >= γp pshreds, attempt decode. If it fails, that's a fault.
    if (pshreds.len >= types.RS_DATA_SHREDS) {
        if (try detectDecodeFailure(pshreds, gpa)) |evidence| {
            return FaultWitness{
                .epoch = epoch,
                .cycle = cycle,
                .proposer_index = proposer_index,
                .evidence = evidence,
            };
        }
    }

    return null;
}

/// Check for two pshreds with the same (e,c,j,t) but different h or rt.
fn detectConflictingPshreds(
    pshreds: []const Pshred,
    gpa: Allocator,
) !?[]const Pshred {
    // Group by pslice_index, check for inconsistencies
    for (pshreds, 0..) |a, i| {
        for (pshreds[i + 1 ..]) |b| {
            if (a.pslice_index != b.pslice_index) continue;

            const h_mismatch = !std.mem.eql(u8, &a.commitment_hash, &b.commitment_hash);
            const rt_mismatch = !std.mem.eql(u8, &a.merkle_root, &b.merkle_root);

            if (h_mismatch or rt_mismatch) {
                const evidence = try gpa.alloc(Pshred, 2);
                evidence[0] = a;
                evidence[1] = b;
                return evidence;
            }
        }
    }
    return null;
}

/// Given >= γp pshreds with consistent metadata, try RS decode.
/// If decode fails, the pshreds constitute a fault witness.
fn detectDecodeFailure(
    pshreds: []const Pshred,
    gpa: Allocator,
) !?[]const Pshred {
    // Build erasure Shred structs from pshreds
    const shred_count = @min(pshreds.len, @as(usize, types.RS_TOTAL_SHREDS));
    const shreds = try gpa.alloc(erasure.Shred, shred_count);
    for (pshreds[0..shred_count], 0..) |ps, i| {
        shreds[i] = .{
            .index = ps.shred_index,
            .data = ps.data,
            .merkle_proof = ps.merkle_proof,
        };
    }

    // Attempt decode — if it fails, we have a fault witness
    const root = pshreds[0].merkle_root;
    // Use a large original_len estimate (we don't know the exact size)
    const chunk_size = if (pshreds[0].data.len > 0) pshreds[0].data.len else 1;
    const estimated_len = chunk_size * types.RS_DATA_SHREDS;

    _ = erasure.decode(root, shreds, estimated_len, gpa) catch {
        // Decode failed — collect γp pshreds as evidence
        const count = @min(pshreds.len, @as(usize, types.RS_DATA_SHREDS));
        const evidence = try gpa.alloc(Pshred, count);
        @memcpy(evidence, pshreds[0..count]);
        return evidence;
    };

    return null; // Decode succeeded — no fault
}

// ============================================================================
// Tests
// ============================================================================

test "detectFault: no fault for consistent pshreds" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const ps = [_]Pshred{
        makePshred(0, 1, .{0xAA} ** 32, .{0xBB} ** 32),
        makePshred(1, 1, .{0xAA} ** 32, .{0xBB} ** 32),
    };

    const result = try detectFault(&ps, 1, 10, 0, gpa);
    try std.testing.expect(result == null);
}

test "detectFault: conflicting commitment hashes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const ps = [_]Pshred{
        makePshred(0, 1, .{0xAA} ** 32, .{0xBB} ** 32),
        makePshred(1, 1, .{0xCC} ** 32, .{0xBB} ** 32), // different h!
    };

    const result = try detectFault(&ps, 1, 10, 0, gpa);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 2), result.?.evidence.len);
}

test "detectFault: conflicting merkle roots" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const ps = [_]Pshred{
        makePshred(0, 1, .{0xAA} ** 32, .{0xBB} ** 32),
        makePshred(1, 1, .{0xAA} ** 32, .{0xDD} ** 32), // different rt!
    };

    const result = try detectFault(&ps, 1, 10, 0, gpa);
    try std.testing.expect(result != null);
}

fn makePshred(shred_idx: u16, pslice_idx: u32, commitment: Hash, mroot: Hash) Pshred {
    return .{
        .epoch = 1,
        .cycle = 10,
        .proposer_index = 0,
        .pslice_index = pslice_idx,
        .shred_index = shred_idx,
        .commitment_hash = commitment,
        .merkle_root = mroot,
        .data = &.{},
        .merkle_proof = &.{},
        .signature = .{0} ** 64,
    };
}
