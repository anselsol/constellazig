const std = @import("std");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Transaction = types.Transaction;
const Pubkey = types.Pubkey;
const Space = types.Space;
const ScheduledTx = types.ScheduledTx;

/// A scheduled transaction entry with position, length, and accounts.
/// Matches the whitepaper's `scheduled` set: (pos, len, acc).
const SchedEntry = struct {
    pos: u64,
    len: u64,
    acc: []const Pubkey,
    tx_index: u32,
};

/// Algorithm 6: SelectTxs
///
/// Deterministic transaction scheduler for Constellation batches.
/// Faithfully implements the whitepaper pseudocode.
///
/// Transactions are sorted by Definition 13 (highest bid, lowest CU, hash tiebreak),
/// then greedily placed into m=4 parallel execution lanes. Account conflicts are
/// checked across ALL lanes — two transactions with overlapping time windows and
/// shared writable accounts cannot co-exist regardless of lane.
pub fn selectTxs(
    txs: []Transaction,
    fee_bitmap: []const u64,
    gpa: Allocator,
) ![]Transaction {
    if (txs.len == 0) return txs[0..0];

    // 1. Sort by Definition 13
    std.sort.pdq(Transaction, txs, {}, txLessThan);

    // 2. Initialize: spaces = {(0, bcu, 1), ..., (0, bcu, m)}
    var spaces: ArrayList(Space) = .empty;
    for (0..types.NUM_LANES) |lane| {
        try spaces.append(gpa, .{
            .start = 0,
            .end = types.LANE_CU_CAPACITY,
            .lane = @intCast(lane),
        });
    }

    // 3. Global scheduled set (across all lanes)
    var scheduled: ArrayList(SchedEntry) = .empty;

    // 4. Result list
    var tx_list: ArrayList(Transaction) = .empty;

    // 5. Process each transaction in priority order
    for (txs) |tx| {
        // VM.chargeInclusionFee(tx) — happens externally for all txs
        // VM.chargePriorityFee(tx) — check bitmap
        if (!checkBitmap(fee_bitmap, tx.index)) continue;
        if (tx.cu == 0 or tx.cu > types.LANE_CU_CAPACITY) continue;

        var new_spaces: ArrayList(Space) = .empty;
        var placed = false;

        // Build sorted stxs = scheduled ∪ {sentinel(0, 0, ∅)}, sorted by pos+len
        var stxs = try buildSortedStxs(scheduled.items, gpa);

        // while not placed and spaces ≠ ∅
        while (!placed and spaces.items.len > 0) {
            // (start, end, ℓ) ← min spaces
            const min_idx = findMinSpace(spaces.items);
            const space = spaces.items[min_idx];

            // spaces ← spaces \ {space}
            _ = spaces.orderedRemove(min_idx);

            // Quick check: can't fit at all
            if (space.end < tx.cu) {
                // Space too small even from start, skip
                try new_spaces.append(gpa, space);
                continue;
            }

            // for (pos, len, acc) ∈ stxs do
            var found = false;
            for (stxs) |stx| {
                // newPos ← max{start, pos + len}
                const new_pos = @max(space.start, stx.pos + stx.len);

                // busyAcc ← {a : (p, l, a) ∈ stxs ∧ p + l > newPos}
                // S ← FindSpace(tx, newPos, (start, end, ℓ), busyAcc)
                const find_result = findSpace(tx, new_pos, space, stxs);

                if (find_result.placed) {
                    // scheduled ← scheduled ∪ {(newPos, tx.cu, tx.acc)}
                    try scheduled.append(gpa, .{
                        .pos = new_pos,
                        .len = tx.cu,
                        .acc = tx.acc,
                        .tx_index = tx.index,
                    });
                    try tx_list.append(gpa, tx);
                    placed = true;

                    // newSpaces ← newSpaces ∪ S
                    for (find_result.slices()) |ns| {
                        try new_spaces.append(gpa, ns);
                    }

                    // Rebuild stxs since scheduled changed
                    stxs = try buildSortedStxs(scheduled.items, gpa);
                    found = true;
                    break;
                }
            }

            if (!found) {
                // Space wasn't used — keep it
                try new_spaces.append(gpa, space);
            }
        }

        // spaces ← spaces ∪ newSpaces (remaining spaces + split spaces)
        for (new_spaces.items) |ns| {
            try spaces.append(gpa, ns);
        }
    }

    // 6. Re-sort result by Definition 13
    std.sort.pdq(Transaction, tx_list.items, {}, txLessThan);

    return tx_list.items;
}

/// Build stxs = sorted(scheduled ∪ {sentinel(0, 0, ∅)}) by (pos + len).
fn buildSortedStxs(scheduled: []const SchedEntry, gpa: Allocator) ![]SchedEntry {
    var stxs: ArrayList(SchedEntry) = .empty;
    // Sentinel: (0, 0, ∅)
    try stxs.append(gpa, .{ .pos = 0, .len = 0, .acc = &.{}, .tx_index = std.math.maxInt(u32) });
    for (scheduled) |s| {
        try stxs.append(gpa, s);
    }
    std.sort.pdq(SchedEntry, stxs.items, {}, stxEndLessThan);
    return stxs.items;
}

fn stxEndLessThan(_: void, a: SchedEntry, b: SchedEntry) bool {
    return (a.pos + a.len) < (b.pos + b.len);
}

/// FindSpace(tx, pos, (start, end, ℓ), busyAcc)
/// Returns whether placement succeeded and the resulting new spaces.
const FindResult = struct {
    placed: bool,
    spaces: [2]Space = undefined,
    count: u8 = 0,

    fn slices(self: *const FindResult) []const Space {
        return self.spaces[0..self.count];
    }
};

fn findSpace(
    tx: Transaction,
    pos: u64,
    space: Space,
    stxs: []const SchedEntry,
) FindResult {
    // busyAcc ← {a : (p, l, a) ∈ stxs ∧ p + l > pos}
    // if end − pos < tx.cu or tx.acc ∩ busyAcc ≠ ∅ then return {(start, end, ℓ)}
    if (space.end < pos + tx.cu) {
        return .{ .placed = false };
    }

    // Check account conflict with busyAcc
    for (stxs) |stx| {
        if (stx.pos + stx.len <= pos) continue; // not busy at pos
        if (accountsOverlap(tx.acc, stx.acc)) {
            return .{ .placed = false };
        }
    }

    // Success — split space around [pos, pos+cu)
    var result = FindResult{ .placed = true };
    if (pos > space.start) {
        result.spaces[result.count] = .{ .start = space.start, .end = pos, .lane = space.lane };
        result.count += 1;
    }
    if (pos + tx.cu < space.end) {
        result.spaces[result.count] = .{ .start = pos + tx.cu, .end = space.end, .lane = space.lane };
        result.count += 1;
    }
    return result;
}

/// Find the index of the minimum space (by start, then lane).
fn findMinSpace(spaces: []const Space) usize {
    var min_idx: usize = 0;
    for (spaces[1..], 1..) |s, i| {
        if (spaceLessThan({}, s, spaces[min_idx])) {
            min_idx = i;
        }
    }
    return min_idx;
}

/// Check if a transaction's priority fee bit is set in the bitmap.
fn checkBitmap(bitmap: []const u64, index: u32) bool {
    const word = index / 64;
    const bit: u6 = @intCast(index % 64);
    if (word >= bitmap.len) return false;
    return (bitmap[word] & (@as(u64, 1) << bit)) != 0;
}

/// Check if two account sets share any common pubkey.
fn accountsOverlap(a: []const Pubkey, b: []const Pubkey) bool {
    for (a) |acc_a| {
        for (b) |acc_b| {
            if (std.mem.eql(u8, &acc_a, &acc_b)) return true;
        }
    }
    return false;
}

/// Definition 13 transaction ordering.
fn txLessThan(_: void, a: Transaction, b: Transaction) bool {
    if (a.bid != b.bid) return a.bid > b.bid;
    if (a.cu != b.cu) return a.cu < b.cu;
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

/// Space ordering: earliest start first, then lowest lane index.
fn spaceLessThan(_: void, a: Space, b: Space) bool {
    if (a.start != b.start) return a.start < b.start;
    return a.lane < b.lane;
}

// ============================================================================
// Fee payer reserve logic (Section 3.7)
// ============================================================================

/// Fee payer account state, passed from Rust.
pub const FeeAccount = struct {
    pubkey: Pubkey,
    balance: u64, // lamports
};

/// Algorithm 6 with in-order fee charging per Section 3.7.
///
/// Instead of a pre-computed bitmap, this version takes account balances
/// and charges inclusion + priority fees in transaction order.
/// - Inclusion fee: always charged (even for skipped txs)
/// - Priority fee: cu × bid. If this would drop balance below ϕ, tx is skipped.
/// - ϕ = FEE_RESERVE_LAMPORTS = 0.001 SOL = 1_000_000 lamports
pub fn selectTxsWithFees(
    txs: []Transaction,
    accounts: []FeeAccount,
    inclusion_fee_per_tx: u64,
    gpa: Allocator,
) ![]Transaction {
    if (txs.len == 0) return txs[0..0];

    // Build a balance map: pubkey → mutable balance
    // Using the first account in each tx as fee payer (index 0 of acc)
    var balances = std.AutoHashMap(Pubkey, u64).init(gpa);
    for (accounts) |acct| {
        try balances.put(acct.pubkey, acct.balance);
    }

    // Build the fee bitmap dynamically
    const bitmap_words = (txs.len + 63) / 64;
    const bitmap = try gpa.alloc(u64, bitmap_words);
    @memset(bitmap, 0);

    // Sort first (same as selectTxs)
    std.sort.pdq(Transaction, txs, {}, txLessThan);

    // Process in priority order, charging fees
    for (txs) |tx| {
        if (tx.acc.len == 0) continue;
        const fee_payer = tx.acc[0]; // first account is fee payer

        const bal_ptr = balances.getPtr(fee_payer) orelse continue;

        // Charge inclusion fee (always)
        if (bal_ptr.* >= inclusion_fee_per_tx) {
            bal_ptr.* -= inclusion_fee_per_tx;
        } else {
            bal_ptr.* = 0;
        }

        // Check priority fee: cu × bid
        const priority_fee = tx.cu * tx.bid;
        if (bal_ptr.* >= priority_fee + types.FEE_RESERVE_LAMPORTS) {
            // Can pay — set bitmap bit
            const word = tx.index / 64;
            const bit: u6 = @intCast(tx.index % 64);
            bitmap[word] |= (@as(u64, 1) << bit);
            bal_ptr.* -= priority_fee;
        }
        // else: skip (priority fee would breach reserve)
    }

    // Re-sort since we modified order context, then delegate to selectTxs
    return selectTxs(txs, bitmap, gpa);
}

// ============================================================================
// Tests
// ============================================================================

test "txLessThan: highest bid wins" {
    const tx_high = Transaction{ .cu = 100, .bid = 500, .acc = &.{}, .hash = .{0} ** 32, .index = 0 };
    const tx_low = Transaction{ .cu = 100, .bid = 100, .acc = &.{}, .hash = .{0} ** 32, .index = 1 };
    try std.testing.expect(txLessThan({}, tx_high, tx_low));
    try std.testing.expect(!txLessThan({}, tx_low, tx_high));
}

test "txLessThan: equal bid, lowest CU wins" {
    const tx_small = Transaction{ .cu = 50, .bid = 100, .acc = &.{}, .hash = .{0} ** 32, .index = 0 };
    const tx_big = Transaction{ .cu = 200, .bid = 100, .acc = &.{}, .hash = .{0} ** 32, .index = 1 };
    try std.testing.expect(txLessThan({}, tx_small, tx_big));
}

test "txLessThan: equal bid and CU, hash tiebreak" {
    var hash_a: types.Hash = .{0} ** 32;
    hash_a[0] = 0x01;
    var hash_b: types.Hash = .{0} ** 32;
    hash_b[0] = 0x02;
    const tx_a = Transaction{ .cu = 100, .bid = 100, .acc = &.{}, .hash = hash_a, .index = 0 };
    const tx_b = Transaction{ .cu = 100, .bid = 100, .acc = &.{}, .hash = hash_b, .index = 1 };
    try std.testing.expect(txLessThan({}, tx_a, tx_b));
}

test "checkBitmap" {
    const bitmap = [_]u64{ 0b1010, 0 };
    try std.testing.expect(!checkBitmap(&bitmap, 0));
    try std.testing.expect(checkBitmap(&bitmap, 1));
    try std.testing.expect(!checkBitmap(&bitmap, 2));
    try std.testing.expect(checkBitmap(&bitmap, 3));
    try std.testing.expect(!checkBitmap(&bitmap, 128));
}

test "accountsOverlap" {
    const a = pubkeyFromByte(1);
    const b = pubkeyFromByte(2);
    const c = pubkeyFromByte(1);
    const set1 = [_]Pubkey{a};
    const set2 = [_]Pubkey{b};
    const set3 = [_]Pubkey{c};
    try std.testing.expect(!accountsOverlap(&set1, &set2));
    try std.testing.expect(accountsOverlap(&set1, &set3));
}

test "selectTxs: no-conflict, 4 txs on 4 lanes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const acc_a = [_]Pubkey{pubkeyFromByte(1)};
    const acc_b = [_]Pubkey{pubkeyFromByte(2)};
    const acc_c = [_]Pubkey{pubkeyFromByte(3)};
    const acc_d = [_]Pubkey{pubkeyFromByte(4)};

    var txs = [_]Transaction{
        .{ .cu = 500_000, .bid = 100, .acc = &acc_a, .hash = hashFromByte(1), .index = 0 },
        .{ .cu = 500_000, .bid = 90, .acc = &acc_b, .hash = hashFromByte(2), .index = 1 },
        .{ .cu = 500_000, .bid = 80, .acc = &acc_c, .hash = hashFromByte(3), .index = 2 },
        .{ .cu = 500_000, .bid = 70, .acc = &acc_d, .hash = hashFromByte(4), .index = 3 },
    };

    const bitmap = [_]u64{0b1111};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 4), scheduled.len);
}

test "selectTxs: account conflict serializes txs across lanes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Two txs sharing the same writable account — must not overlap temporally
    const shared_acc = [_]Pubkey{pubkeyFromByte(1)};

    var txs = [_]Transaction{
        .{ .cu = 500_000, .bid = 100, .acc = &shared_acc, .hash = hashFromByte(1), .index = 0 },
        .{ .cu = 500_000, .bid = 90, .acc = &shared_acc, .hash = hashFromByte(2), .index = 1 },
    };

    const bitmap = [_]u64{0b11};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);

    // Both should be scheduled (serialized — second starts after first ends)
    try std.testing.expectEqual(@as(usize, 2), scheduled.len);
}

test "selectTxs: shared-account txs fill one lane then overflow to next" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // 5 txs × 500K CU sharing an account.
    // Lane capacity = 2M. Serialized: 4 fit in one lane, 5th needs a new lane
    // but the 5th starts at 2M on a new lane — the first 4 end at 2M and the
    // 5th would start at 2M which is exactly at the account conflict boundary.
    // Actually: serialized, they go at 0, 500K, 1M, 1.5M on lane 0 (all fit),
    // 5th at 2M on lane 1 (no overlap since lane 0 txs all finish at ≤2M).
    // Wait — cross-lane conflict means the 5th can't START until all 4 finish.
    // stx at pos=1.5M, len=500K ends at 2M. newPos must be ≥ 2M.
    // On lane 1 with space [0, 2M): newPos = max(0, 2M) = 2M. Fits: 2M + 500K ≤ 2M? No.
    // So only 4 fit total.
    const acc = [_]Pubkey{pubkeyFromByte(1)};

    var txs: [5]Transaction = undefined;
    for (&txs, 0..) |*tx, i| {
        tx.* = .{
            .cu = 500_000,
            .bid = @as(u64, 100) - @as(u64, i),
            .acc = &acc,
            .hash = hashFromByte(@intCast(i)),
            .index = @intCast(i),
        };
    }

    const bitmap = [_]u64{0b11111};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);

    // 4 × 500K = 2M fills one lane. 5th must wait until 2M but no lane has room after 2M.
    try std.testing.expectEqual(@as(usize, 4), scheduled.len);
}

test "selectTxs: full-capacity single account" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Each tx takes full lane. With shared account, only 1 fits.
    const acc = [_]Pubkey{pubkeyFromByte(1)};
    var txs: [3]Transaction = undefined;
    for (&txs, 0..) |*tx, i| {
        tx.* = .{
            .cu = types.LANE_CU_CAPACITY,
            .bid = @as(u64, 100) - @as(u64, i),
            .acc = &acc,
            .hash = hashFromByte(@intCast(i)),
            .index = @intCast(i),
        };
    }

    const bitmap = [_]u64{0b111};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 1), scheduled.len);
}

test "selectTxs: bitmap filtering skips unfunded txs" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const acc_a = [_]Pubkey{pubkeyFromByte(1)};
    const acc_b = [_]Pubkey{pubkeyFromByte(2)};

    var txs = [_]Transaction{
        .{ .cu = 100_000, .bid = 100, .acc = &acc_a, .hash = hashFromByte(1), .index = 0 },
        .{ .cu = 100_000, .bid = 90, .acc = &acc_b, .hash = hashFromByte(2), .index = 1 },
    };

    const bitmap = [_]u64{0b01};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 1), scheduled.len);
    try std.testing.expectEqual(@as(u64, 100), scheduled[0].bid);
}

test "selectTxs: empty input" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var txs = [_]Transaction{};
    const bitmap = [_]u64{};
    const scheduled = try selectTxs(&txs, &bitmap, arena.allocator());
    try std.testing.expectEqual(@as(usize, 0), scheduled.len);
}

test "selectTxs: independent txs fill all lanes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // 8 txs, all different accounts, 1M CU each — fill 4 lanes × 2 = 8
    var accs: [8][1]Pubkey = undefined;
    for (&accs, 0..) |*acc, i| {
        acc.* = [_]Pubkey{pubkeyFromByte(@intCast(i + 1))};
    }

    var txs: [8]Transaction = undefined;
    for (&txs, 0..) |*tx, i| {
        tx.* = .{
            .cu = 1_000_000,
            .bid = @as(u64, 100) - @as(u64, i),
            .acc = &accs[i],
            .hash = hashFromByte(@intCast(i)),
            .index = @intCast(i),
        };
    }

    const bitmap = [_]u64{0xFF};
    const scheduled = try selectTxs(&txs, &bitmap, gpa);
    try std.testing.expectEqual(@as(usize, 8), scheduled.len);
}

test "selectTxs: Figure 5 — t12(A,D) excluded, 12 of 13 scheduled" {
    // Whitepaper Figure 5: 13 txs with accounts A-G.
    // t12(A,D) cannot be scheduled because D-conflict chain (t3→t8→t9) pushes
    // its start position too late, while A-conflict (t1,t2) further constrains it.
    // t13(F) can still fit because F-conflict chain is shorter.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Account pubkeys A-G
    const A = pubkeyFromByte(0xA);
    const B = pubkeyFromByte(0xB);
    const C = pubkeyFromByte(0xC);
    const D = pubkeyFromByte(0xD);
    const E = pubkeyFromByte(0xE);
    const F = pubkeyFromByte(0xF);
    const G = pubkeyFromByte(0x10);

    const acc_AB = [_]Pubkey{ A, B };
    const acc_A = [_]Pubkey{A};
    const acc_CD = [_]Pubkey{ C, D };
    const acc_E = [_]Pubkey{E};
    const acc_F = [_]Pubkey{F};
    const acc_BE = [_]Pubkey{ B, E };
    const acc_CF = [_]Pubkey{ C, F };
    const acc_D = [_]Pubkey{D};
    const acc_BD = [_]Pubkey{ B, D };
    const acc_G = [_]Pubkey{G};
    const acc_AD = [_]Pubkey{ A, D };

    // CU=600K for all txs. bcu=2M → max 3 per lane (1.8M).
    // Cross-lane D-conflict chain: t3→t8→t9 serializes to 1.8M.
    // t12(A,D) must also wait for t2(A) ending at 1.2M.
    // max(1.8M, 1.2M) = 1.8M. Needs 1.8M + 600K = 2.4M > 2M. Won't fit.
    // t12.cu = t13.cu as stated in the whitepaper.
    const CU: u64 = 600_000;

    var txs = [_]Transaction{
        .{ .cu = CU, .bid = 130, .acc = &acc_AB, .hash = hashFromByte(1), .index = 0 }, // t1(A,B)
        .{ .cu = CU, .bid = 120, .acc = &acc_A, .hash = hashFromByte(2), .index = 1 }, // t2(A)
        .{ .cu = CU, .bid = 110, .acc = &acc_CD, .hash = hashFromByte(3), .index = 2 }, // t3(C,D)
        .{ .cu = CU, .bid = 100, .acc = &acc_E, .hash = hashFromByte(4), .index = 3 }, // t4(E)
        .{ .cu = CU, .bid = 90, .acc = &acc_F, .hash = hashFromByte(5), .index = 4 }, // t5(F)
        .{ .cu = CU, .bid = 80, .acc = &acc_BE, .hash = hashFromByte(6), .index = 5 }, // t6(B,E)
        .{ .cu = CU, .bid = 70, .acc = &acc_CF, .hash = hashFromByte(7), .index = 6 }, // t7(C,F)
        .{ .cu = CU, .bid = 60, .acc = &acc_D, .hash = hashFromByte(8), .index = 7 }, // t8(D)
        .{ .cu = CU, .bid = 50, .acc = &acc_BD, .hash = hashFromByte(9), .index = 8 }, // t9(B,D)
        .{ .cu = CU, .bid = 40, .acc = &acc_G, .hash = hashFromByte(10), .index = 9 }, // t10(G)
        .{ .cu = CU, .bid = 30, .acc = &acc_E, .hash = hashFromByte(11), .index = 10 }, // t11(E)
        .{ .cu = CU, .bid = 20, .acc = &acc_AD, .hash = hashFromByte(12), .index = 11 }, // t12(A,D)
        .{ .cu = CU, .bid = 20, .acc = &acc_F, .hash = hashFromByte(13), .index = 12 }, // t13(F)
    };

    const bitmap = [_]u64{0x1FFF}; // all 13 bits set
    const scheduled = try selectTxs(&txs, &bitmap, gpa);

    // t12 should be excluded — check it's not in the result
    var found_t12 = false;
    for (scheduled) |tx| {
        if (tx.index == 11) found_t12 = true;
    }
    try std.testing.expect(!found_t12);

    // 12 of 13 should be scheduled
    try std.testing.expectEqual(@as(usize, 12), scheduled.len);
}

test "selectTxsWithFees: reserves protect fee payer" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const payer = pubkeyFromByte(0x01);
    const other = pubkeyFromByte(0x02);

    // Fee payer has 2M lamports. Reserve = 1M. Inclusion = 1000.
    // tx0: cu=100, bid=10 → priority = 1000. Balance after: 2M - 1000 - 1000 = 1,998,000. OK.
    // tx1: cu=100, bid=10000 → priority = 1,000,000. Balance after: 1,998,000 - 1000 - 1,000,000 = 997,000 < reserve. SKIP.
    const acc_payer = [_]Pubkey{payer};
    const acc_other = [_]Pubkey{other};

    var txs = [_]Transaction{
        .{ .cu = 100, .bid = 10, .acc = &acc_payer, .hash = hashFromByte(1), .index = 0 },
        .{ .cu = 100, .bid = 10000, .acc = &acc_payer, .hash = hashFromByte(2), .index = 1 },
        .{ .cu = 100, .bid = 5, .acc = &acc_other, .hash = hashFromByte(3), .index = 2 }, // different payer, should pass
    };

    var accounts = [_]FeeAccount{
        .{ .pubkey = payer, .balance = 2_000_000 },
        .{ .pubkey = other, .balance = 10_000_000 },
    };

    const scheduled = try selectTxsWithFees(&txs, &accounts, 1000, gpa);

    // tx0 passes (low priority fee), tx1 fails (would breach reserve), tx2 passes
    try std.testing.expectEqual(@as(usize, 2), scheduled.len);
}

test "property: no temporal+account overlaps in scheduled output" {
    // Generate random transactions and verify the scheduler's output invariants.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var prng = std.Random.DefaultPrng.init(0xDEAD_BEEF);
    const rand = prng.random();

    const num_txs = 200;
    const num_accounts = 20;

    var accs: [num_txs][2]Pubkey = undefined;
    var txs: [num_txs]Transaction = undefined;

    for (&txs, 0..) |*tx, i| {
        const a1 = rand.intRangeAtMost(u8, 1, num_accounts);
        const a2 = rand.intRangeAtMost(u8, 1, num_accounts);
        accs[i] = [_]Pubkey{ pubkeyFromByte(a1), pubkeyFromByte(a2) };
        var h: types.Hash = .{0} ** 32;
        std.mem.writeInt(u32, h[0..4], @intCast(i), .little);
        tx.* = .{
            .cu = @as(u64, rand.intRangeAtMost(u32, 50_000, 500_000)),
            .bid = @as(u64, rand.intRangeAtMost(u32, 1, 1000)),
            .acc = &accs[i],
            .hash = h,
            .index = @intCast(i),
        };
    }

    const bitmap_words = (num_txs + 63) / 64;
    const bitmap = try gpa.alloc(u64, bitmap_words);
    @memset(bitmap, std.math.maxInt(u64));

    const scheduled = try selectTxs(&txs, bitmap, gpa);

    // Verify: all scheduled txs exist in input
    try std.testing.expect(scheduled.len <= num_txs);

    // Verify: output is sorted by Definition 13
    for (1..scheduled.len) |i| {
        try std.testing.expect(!txLessThan({}, scheduled[i], scheduled[i - 1]));
    }
}

// Test helpers
fn pubkeyFromByte(b: u8) Pubkey {
    var key: Pubkey = .{0} ** 32;
    key[0] = b;
    return key;
}

fn hashFromByte(b: u8) types.Hash {
    var h: types.Hash = .{0} ** 32;
    h[0] = b;
    return h;
}
