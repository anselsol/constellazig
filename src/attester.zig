const std = @import("std");
const types = @import("types.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Hash = types.Hash;

/// Algorithm 2: Attester buffer.
///
/// Manages p=16 proposer buffers, each of length µλ=24 entries.
/// Tracks pshred commitments within a sliding window of cycles.
/// Stack-allocated — no heap required for the buffer itself.
pub const AttesterBuffer = struct {
    /// Per-proposer buffers. Each entry is optional (null = no pshred received).
    buffers: [types.NUM_PROPOSERS][types.BUFFER_LENGTH]?types.BufferEntry,
    /// The pslice index at the start of the current window.
    window_base: u32,

    pub fn init(start_cycle: u32) AttesterBuffer {
        return .{
            .buffers = [_][types.BUFFER_LENGTH]?types.BufferEntry{
                [_]?types.BufferEntry{null} ** types.BUFFER_LENGTH,
            } ** types.NUM_PROPOSERS,
            .window_base = start_cycle *| types.MU -| (types.LAMBDA - 1) *| types.MU,
        };
    }

    /// SliceIdxToBufferIdx (Algorithm 2, line 20-23):
    /// Maps a pslice index t to a buffer position for cycle c.
    /// Returns null if t is outside the current window:
    ///   valid range: (c - λ)µ < t ≤ cµ
    pub fn sliceIdxToBufferIdx(self: *const AttesterBuffer, t: u32) ?u8 {
        if (t <= self.window_base) return null; // too old
        const offset = t - self.window_base - 1;
        if (offset >= types.BUFFER_LENGTH) return null; // in the future
        return @intCast(offset);
    }

    /// Record a received pshred commitment in the buffer.
    /// Silently ignores out-of-window indices.
    pub fn recordPshred(self: *AttesterBuffer, proposer: u8, pslice_index: u32, commitment: Hash) void {
        if (proposer >= types.NUM_PROPOSERS) return;
        const buf_idx = self.sliceIdxToBufferIdx(pslice_index) orelse return;
        self.buffers[proposer][buf_idx] = .{
            .pslice_index = pslice_index,
            .commitment_hash = commitment,
        };
    }

    /// ShiftBuffers (Algorithm 2, line 24-27):
    /// Slide each proposer's window forward by µ=4 positions.
    /// Drops the oldest cycle's entries, fills new slots with null.
    pub fn shiftBuffers(self: *AttesterBuffer) void {
        for (&self.buffers) |*buf| {
            // Shift left by MU: copy [MU..] to [0..]
            const mu = types.MU;
            const len = types.BUFFER_LENGTH;
            var i: u8 = 0;
            while (i < len - mu) : (i += 1) {
                buf[i] = buf[i + mu];
            }
            // Fill new slots with null
            while (i < len) : (i += 1) {
                buf[i] = null;
            }
        }
        self.window_base += types.MU;
    }

    /// BuildAttestation (Algorithm 2, line 15-19):
    /// Collect all non-null entries for a given proposer.
    pub fn buildAttestationList(
        self: *const AttesterBuffer,
        proposer: u8,
        gpa: Allocator,
    ) ![]types.BufferEntry {
        if (proposer >= types.NUM_PROPOSERS) return &.{};

        var result: ArrayList(types.BufferEntry) = .empty;
        for (self.buffers[proposer]) |entry| {
            if (entry) |e| {
                try result.append(gpa, e);
            }
        }
        return result.items;
    }

    /// Build the full attestation: lists for all proposers.
    pub fn buildFullAttestation(
        self: *const AttesterBuffer,
        gpa: Allocator,
    ) ![types.NUM_PROPOSERS][]types.BufferEntry {
        var lists: [types.NUM_PROPOSERS][]types.BufferEntry = undefined;
        for (0..types.NUM_PROPOSERS) |j| {
            lists[j] = try self.buildAttestationList(@intCast(j), gpa);
        }
        return lists;
    }

    /// Hash a proposer's attestation list per Definition 5:
    /// hash(li) = SHA256(concat of (c', t, h) tuples as raw bytes).
    /// Used for attestation signing: sign(Attestation(e, c, k, hash(l1)..hash(lp))).
    pub fn hashAttestationList(entries: []const types.BufferEntry) Hash {
        var h = Sha256.init(.{});
        for (entries) |entry| {
            // Each tuple: pslice_index (4 bytes LE) || commitment_hash (32 bytes)
            h.update(&std.mem.toBytes(entry.pslice_index));
            h.update(&entry.commitment_hash);
        }
        return h.finalResult();
    }

    /// Hash all proposer lists → [16]Hash for the attestation commitment.
    /// Attestation signature covers: Attestation(e, c, k, hash(l1), ..., hash(lp))
    pub fn hashAllLists(
        self: *const AttesterBuffer,
        gpa: Allocator,
    ) ![types.NUM_PROPOSERS]Hash {
        var hashes: [types.NUM_PROPOSERS]Hash = undefined;
        for (0..types.NUM_PROPOSERS) |j| {
            const list = try self.buildAttestationList(@intCast(j), gpa);
            hashes[j] = hashAttestationList(list);
        }
        return hashes;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "init: all buffers empty" {
    const buf = AttesterBuffer.init(10);
    for (buf.buffers) |proposer_buf| {
        for (proposer_buf) |entry| {
            try std.testing.expect(entry == null);
        }
    }
}

test "recordPshred and retrieve" {
    var buf = AttesterBuffer.init(0);
    const commitment: Hash = .{0xAB} ** 32;

    buf.recordPshred(0, 1, commitment);

    const idx = buf.sliceIdxToBufferIdx(1);
    try std.testing.expect(idx != null);

    const entry = buf.buffers[0][idx.?];
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u32, 1), entry.?.pslice_index);
    try std.testing.expect(std.mem.eql(u8, &commitment, &entry.?.commitment_hash));
}

test "out-of-window pslice rejected" {
    var buf = AttesterBuffer.init(10);

    // Should be within window
    const valid_t = buf.window_base + 1;
    try std.testing.expect(buf.sliceIdxToBufferIdx(valid_t) != null);

    // Too old
    try std.testing.expect(buf.sliceIdxToBufferIdx(buf.window_base) == null);

    // Too far in the future
    try std.testing.expect(buf.sliceIdxToBufferIdx(buf.window_base + types.BUFFER_LENGTH + 1) == null);
}

test "shiftBuffers drops oldest cycle" {
    var buf = AttesterBuffer.init(0);

    // Record in first MU slots
    for (1..types.MU + 1) |t| {
        const ti: u8 = @intCast(t);
        buf.recordPshred(0, @as(u32, ti), .{ti} ** 32);
    }

    // Record in second MU slots
    for (types.MU + 1..2 * types.MU + 1) |t| {
        const ti: u8 = @intCast(t);
        buf.recordPshred(0, @as(u32, ti), .{ti} ** 32);
    }

    // Verify first entries exist
    try std.testing.expect(buf.buffers[0][0] != null);

    // Shift
    buf.shiftBuffers();

    // First cycle's entries should be gone (shifted out)
    // What was in position MU should now be in position 0
    const entry = buf.buffers[0][0];
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u32, types.MU + 1), entry.?.pslice_index);

    // New slots should be null
    try std.testing.expect(buf.buffers[0][types.BUFFER_LENGTH - 1] == null);
}

test "buildAttestationList collects non-null entries" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var buf = AttesterBuffer.init(0);

    // Record 3 entries for proposer 0
    buf.recordPshred(0, 1, .{0x01} ** 32);
    buf.recordPshred(0, 3, .{0x03} ** 32);
    buf.recordPshred(0, 5, .{0x05} ** 32);

    const list = try buf.buildAttestationList(0, gpa);
    try std.testing.expectEqual(@as(usize, 3), list.len);

    // Proposer 1 has no entries
    const empty_list = try buf.buildAttestationList(1, gpa);
    try std.testing.expectEqual(@as(usize, 0), empty_list.len);
}

test "buildFullAttestation returns all proposers" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var buf = AttesterBuffer.init(0);
    buf.recordPshred(0, 1, .{0x01} ** 32);
    buf.recordPshred(5, 2, .{0x02} ** 32);
    buf.recordPshred(15, 3, .{0x03} ** 32);

    const lists = try buf.buildFullAttestation(gpa);
    try std.testing.expectEqual(@as(usize, 1), lists[0].len);
    try std.testing.expectEqual(@as(usize, 0), lists[1].len);
    try std.testing.expectEqual(@as(usize, 1), lists[5].len);
    try std.testing.expectEqual(@as(usize, 1), lists[15].len);
}

test "multiple shifts maintain window correctly" {
    var buf = AttesterBuffer.init(0);
    const initial_base = buf.window_base;

    buf.shiftBuffers();
    try std.testing.expectEqual(initial_base + types.MU, buf.window_base);

    buf.shiftBuffers();
    try std.testing.expectEqual(initial_base + 2 * types.MU, buf.window_base);

    // Record at the new window position
    const t = buf.window_base + 1;
    buf.recordPshred(0, t, .{0xFF} ** 32);
    try std.testing.expect(buf.sliceIdxToBufferIdx(t) != null);
}

test "hashAttestationList: deterministic and order-sensitive" {
    const e1 = types.BufferEntry{ .pslice_index = 1, .commitment_hash = .{0x01} ** 32 };
    const e2 = types.BufferEntry{ .pslice_index = 2, .commitment_hash = .{0x02} ** 32 };

    const h_12 = AttesterBuffer.hashAttestationList(&[_]types.BufferEntry{ e1, e2 });
    const h_21 = AttesterBuffer.hashAttestationList(&[_]types.BufferEntry{ e2, e1 });
    const h_12b = AttesterBuffer.hashAttestationList(&[_]types.BufferEntry{ e1, e2 });

    // Deterministic
    try std.testing.expect(std.mem.eql(u8, &h_12, &h_12b));
    // Order matters
    try std.testing.expect(!std.mem.eql(u8, &h_12, &h_21));
}

test "hashAllLists: empty list hashes to SHA256 of empty" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var buf = AttesterBuffer.init(0);
    buf.recordPshred(0, 1, .{0xAA} ** 32);

    const hashes = try buf.hashAllLists(gpa);

    // Proposer 0 has data — non-zero hash
    const empty_hash = AttesterBuffer.hashAttestationList(&.{});
    try std.testing.expect(!std.mem.eql(u8, &hashes[0], &empty_hash));

    // Proposer 1 is empty — should match empty hash
    try std.testing.expect(std.mem.eql(u8, &hashes[1], &empty_hash));
}
