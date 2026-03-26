const std = @import("std");

// Constellation Table 1 parameters
pub const NUM_PROPOSERS: u8 = 16;
pub const NUM_ATTESTERS: u16 = 256;
pub const NUM_LANES: u8 = 4;
pub const LANE_CU_CAPACITY: u64 = 2_000_000;
pub const TX_CU_LIMIT: u64 = 1_400_000;
pub const MU: u8 = 4;
pub const LAMBDA: u8 = 6;
pub const BUFFER_LENGTH: u8 = MU * LAMBDA; // 24
pub const RS_TOTAL_SHREDS: u16 = 256;
pub const RS_DATA_SHREDS: u16 = 64;
pub const CYCLE_NS: u64 = 50_000_000;
pub const FEE_RESERVE_LAMPORTS: u64 = 1_000_000; // 0.001 SOL
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;
pub const MERKLE_NODE_PREFIX: u8 = 0x01;
pub const NUM_NEXT_LEADERS: u8 = 2;
pub const SCHEDULE_REPLACEMENT_CYCLES: u8 = 32;

pub const Pubkey = [32]u8;
pub const Hash = [32]u8;

/// Zig-native transaction representation.
pub const Transaction = struct {
    cu: u64,
    bid: u64,
    acc: []const Pubkey,
    hash: Hash,
    index: u32,
};

/// C-ABI-compatible transaction for FFI with Rust.
pub const CTransaction = extern struct {
    cu: u64,
    bid: u64,
    acc_ptr: [*]const Pubkey,
    acc_len: u32,
    hash: Hash,
    index: u32,
    _padding: u32 = 0,
};

/// Free interval on an execution lane.
pub const Space = struct {
    start: u64,
    end: u64,
    lane: u8,
};

/// A transaction placed in the schedule.
pub const ScheduledTx = struct {
    tx_index: u32,
    pos: u64,
    lane: u8,
    cu: u64,
    acc: []const Pubkey,
};

/// Attester buffer entry (Algorithm 2).
pub const BufferEntry = struct {
    pslice_index: u32,
    commitment_hash: Hash,
};

// ============================================================================
// Wire types: Definitions 3-12 from the whitepaper
// ============================================================================

pub const Signature = [64]u8;

/// Definition 3: Pshred — an erasure-coded piece of a pslice.
pub const Pshred = struct {
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    pslice_index: u32,
    shred_index: u16,
    commitment_hash: Hash, // h(T) from Definition 2
    merkle_root: Hash, // rt
    data: []const u8, // di
    merkle_proof: []const Hash, // πi
    signature: Signature, // σt
};

/// Definition 4: Pslice — a set of transactions from one proposer, one time slot.
pub const Pslice = struct {
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    pslice_index: u32,
    commitment_hash: Hash,
    merkle_root: Hash,
    transactions: []const Transaction,
    signature: Signature,
};

/// Definition 5: Attestation — attester's signed statement about seen pslices.
pub const AttestationEntry = struct {
    cycle: u64,
    pslice_index: u32,
    commitment_hash: Hash,
};

pub const Attestation = struct {
    epoch: u64,
    cycle: u64,
    attester_index: u16,
    lists: [NUM_PROPOSERS][]const AttestationEntry, // (l1, ..., lp)
    signature: Signature,
};

/// Definition 6: Submission — an ordered list of transactions from one pslice.
pub const Submission = struct {
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    pslice_index: u32,
    transactions: []const Transaction,

    /// s.h() = hash(T) per Definition 2
    pub fn commitmentHash(self: *const Submission) Hash {
        // Hash all tx hashes concatenated
        const Sha256 = std.crypto.hash.sha2.Sha256;
        var h = Sha256.init(.{});
        for (self.transactions) |tx| {
            h.update(&tx.hash);
        }
        return h.finalResult();
    }
};

/// Definition 7: Fault witness — proof that a proposer misbehaved.
pub const FaultWitness = struct {
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    /// The pshreds constituting the proof.
    /// Either: two with different h/rt for same (e,c,j,t),
    /// or: γp pshreds that fail to decode.
    evidence: []const Pshred,
};

/// An attested tuple (e, c', j, t, h) that has enough attestation support.
pub const AttestedTuple = struct {
    epoch: u64,
    cycle: u64,
    proposer_index: u8,
    pslice_index: u32,
    commitment_hash: Hash,
};

/// Definition 9: Batch — one cycle's worth of submissions + attestation data.
pub const Batch = struct {
    epoch: u64,
    cycle: u64,
    attester_indices: []const u16, // Q: set of α attester indices
    attestations: []const Attestation, // A
    submissions: []const Submission, // S

    /// Returns all attested tuples from this batch's attestations.
    pub fn attestedTuples(self: *const Batch, gpa: std.mem.Allocator) ![]AttestedTuple {
        // Count attestations per (e,c,j,t,h) tuple, include if >= γp = RS_DATA_SHREDS
        // Simplified: collect all unique tuples attested by >= γp attesters
        _ = gpa;
        _ = self;
        // TODO: implement quorum counting
        return &.{};
    }
};

/// Definition 10: Block — extends Alpenglow block with batches + garbage pile.
pub const Block = struct {
    slot: u64,
    parent_slot: u64,
    batches: []const Batch,
    garbage_pile: []const FaultWitness,

    pub fn highestCycle(self: *const Block) u64 {
        if (self.batches.len == 0) return 0;
        return self.batches[self.batches.len - 1].cycle;
    }
};

test "CTransaction has stable layout" {
    // Verify the extern struct has expected alignment for C ABI
    try std.testing.expect(@alignOf(CTransaction) == 8);
    // Verify fields are at expected offsets
    try std.testing.expect(@offsetOf(CTransaction, "cu") == 0);
    try std.testing.expect(@offsetOf(CTransaction, "bid") == 8);
}

test "Table 1 parameter sanity" {
    try std.testing.expect(BUFFER_LENGTH == 24);
    try std.testing.expect(RS_DATA_SHREDS * 4 == RS_TOTAL_SHREDS);
    try std.testing.expect(NUM_LANES == 4);
}
