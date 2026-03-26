const std = @import("std");
const types = @import("types.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Hash = types.Hash;

/// A Merkle tree stored as a flat array in heap layout.
/// Root at index 0, children of node i at 2i+1 and 2i+2.
pub const MerkleTree = struct {
    nodes: []Hash,
    leaf_count: u32,

    pub fn root(self: *const MerkleTree) Hash {
        return self.nodes[0];
    }
};

/// Hash a leaf with domain separation: SHA256(0x00 || data).
pub fn hashLeaf(data: []const u8) Hash {
    var h = Sha256.init(.{});
    h.update(&[_]u8{types.MERKLE_LEAF_PREFIX});
    h.update(data);
    return h.finalResult();
}

/// Hash two child nodes: SHA256(0x01 || left || right).
pub fn hashNode(left: Hash, right: Hash) Hash {
    var h = Sha256.init(.{});
    h.update(&[_]u8{types.MERKLE_NODE_PREFIX});
    h.update(&left);
    h.update(&right);
    return h.finalResult();
}

/// Build a Merkle tree from leaf data.
/// Leaf count must be a power of 2 (the RS use case: 256 shreds).
/// For non-power-of-2, pads with zero-hash leaves.
pub fn buildTree(leaf_data: []const []const u8, gpa: Allocator) !MerkleTree {
    if (leaf_data.len == 0) return error.EmptyTree;

    // Round up to next power of 2
    const n = nextPow2(@intCast(leaf_data.len));
    const total_nodes = 2 * n - 1;

    var nodes: ArrayList(Hash) = .empty;
    try nodes.ensureTotalCapacity(gpa, total_nodes);
    // Fill with zeros initially
    for (0..total_nodes) |_| {
        nodes.appendAssumeCapacity(.{0} ** 32);
    }

    // Fill leaves (last n nodes)
    const leaf_start = n - 1;
    for (leaf_data, 0..) |data, i| {
        nodes.items[leaf_start + i] = hashLeaf(data);
    }
    // Remaining leaves (padding) stay as zero-hash

    // Build internal nodes bottom-up
    var level_start: usize = leaf_start;
    while (level_start > 0) {
        const parent_start = (level_start - 1) / 2;
        const parent_count = level_start - parent_start;
        for (0..parent_count) |i| {
            const parent = parent_start + i;
            const left = 2 * parent + 1;
            const right = 2 * parent + 2;
            nodes.items[parent] = hashNode(nodes.items[left], nodes.items[right]);
        }
        level_start = parent_start;
    }

    return MerkleTree{
        .nodes = nodes.items,
        .leaf_count = @intCast(leaf_data.len),
    };
}

/// Build a Merkle tree from pre-hashed leaves (already SHA256'd).
pub fn buildTreeFromHashes(leaf_hashes: []const Hash, gpa: Allocator) !MerkleTree {
    if (leaf_hashes.len == 0) return error.EmptyTree;

    const n = nextPow2(@intCast(leaf_hashes.len));
    const total_nodes = 2 * n - 1;

    var nodes: ArrayList(Hash) = .empty;
    try nodes.ensureTotalCapacity(gpa, total_nodes);
    for (0..total_nodes) |_| {
        nodes.appendAssumeCapacity(.{0} ** 32);
    }

    const leaf_start = n - 1;
    for (leaf_hashes, 0..) |h, i| {
        nodes.items[leaf_start + i] = h;
    }

    var level_start: usize = leaf_start;
    while (level_start > 0) {
        const parent_start = (level_start - 1) / 2;
        const parent_count = level_start - parent_start;
        for (0..parent_count) |i| {
            const parent = parent_start + i;
            const left = 2 * parent + 1;
            const right = 2 * parent + 2;
            nodes.items[parent] = hashNode(nodes.items[left], nodes.items[right]);
        }
        level_start = parent_start;
    }

    return MerkleTree{
        .nodes = nodes.items,
        .leaf_count = @intCast(leaf_hashes.len),
    };
}

/// Extract the validation path (sibling hashes from leaf to root) for a leaf.
pub fn getValidationPath(tree: *const MerkleTree, leaf_index: u32, gpa: Allocator) ![]Hash {
    const n = nextPow2(tree.leaf_count);
    const depth = log2(n);

    var path: ArrayList(Hash) = .empty;
    try path.ensureTotalCapacity(gpa, depth);

    var idx: usize = (n - 1) + leaf_index; // leaf position in flat array
    for (0..depth) |_| {
        // Sibling: if idx is left child (odd), sibling is idx+1; if right (even), sibling is idx-1
        const sibling = if (idx % 2 == 1) idx + 1 else idx - 1;
        path.appendAssumeCapacity(tree.nodes[sibling]);
        idx = (idx - 1) / 2; // parent
    }

    return path.items;
}

/// Verify a validation path for leaf data against a root hash.
pub fn verifyPath(expected_root: Hash, leaf_data: []const u8, path: []const Hash, leaf_index: u32, tree_size: u32) bool {
    return verifyPathHash(expected_root, hashLeaf(leaf_data), path, leaf_index, tree_size);
}

/// Verify a validation path for a pre-hashed leaf against a root hash.
pub fn verifyPathHash(expected_root: Hash, leaf_hash: Hash, path: []const Hash, leaf_index: u32, tree_size: u32) bool {
    const n = nextPow2(tree_size);
    const depth = log2(n);
    if (path.len != depth) return false;

    var current = leaf_hash;
    var idx: u32 = leaf_index;

    for (path) |sibling| {
        if (idx % 2 == 0) {
            current = hashNode(current, sibling);
        } else {
            current = hashNode(sibling, current);
        }
        idx /= 2;
    }

    return std.mem.eql(u8, &current, &expected_root);
}

/// Transaction list hash commitment (Definition 2):
/// h(T) = SHA256(SHA256(tx1) || SHA256(tx2) || ... || SHA256(txk))
pub fn transactionListHash(tx_hashes: []const Hash) Hash {
    var h = Sha256.init(.{});
    for (tx_hashes) |tx_hash| {
        h.update(&tx_hash);
    }
    return h.finalResult();
}

// Utility functions
fn nextPow2(n: u32) u32 {
    if (n == 0) return 1;
    var v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

fn log2(n: u32) u32 {
    std.debug.assert(n > 0 and (n & (n - 1)) == 0); // must be power of 2
    return @ctz(n);
}

// ============================================================================
// Tests
// ============================================================================

test "hashLeaf domain separation" {
    const h1 = hashLeaf("hello");
    const h2 = hashNode(.{0} ** 32, .{0} ** 32);
    // Leaf and node hashes should differ even for contrived inputs
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "buildTree: 4 leaves" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const leaves = [_][]const u8{ "a", "b", "c", "d" };
    const tree = try buildTree(&leaves, gpa);

    // Tree should have 7 nodes (4 leaves + 3 internal)
    try std.testing.expectEqual(@as(usize, 7), tree.nodes.len);

    // Root should be deterministic
    const tree2 = try buildTree(&leaves, gpa);
    try std.testing.expect(std.mem.eql(u8, &tree.root(), &tree2.root()));
}

test "buildTree + verifyPath: all 4 leaves" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const leaves = [_][]const u8{ "a", "b", "c", "d" };
    const tree = try buildTree(&leaves, gpa);
    const r = tree.root();

    for (0..4) |i| {
        const path = try getValidationPath(&tree, @intCast(i), gpa);
        try std.testing.expect(verifyPath(r, leaves[i], path, @intCast(i), 4));
    }
}

test "verifyPath: tampered sibling rejected" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const leaves = [_][]const u8{ "a", "b", "c", "d" };
    const tree = try buildTree(&leaves, gpa);
    const r = tree.root();

    var path = try getValidationPath(&tree, 0, gpa);
    // Tamper with first sibling
    path[0][0] ^= 0xFF;
    try std.testing.expect(!verifyPath(r, leaves[0], path, 0, 4));
}

test "transactionListHash" {
    const h1 = Hash{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const h2 = Hash{ 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    const result_a = transactionListHash(&[_]Hash{ h1, h2 });
    const result_b = transactionListHash(&[_]Hash{ h2, h1 });

    // Order matters
    try std.testing.expect(!std.mem.eql(u8, &result_a, &result_b));

    // Deterministic
    const result_c = transactionListHash(&[_]Hash{ h1, h2 });
    try std.testing.expect(std.mem.eql(u8, &result_a, &result_c));
}

test "nextPow2" {
    try std.testing.expectEqual(@as(u32, 1), nextPow2(1));
    try std.testing.expectEqual(@as(u32, 2), nextPow2(2));
    try std.testing.expectEqual(@as(u32, 4), nextPow2(3));
    try std.testing.expectEqual(@as(u32, 256), nextPow2(256));
    try std.testing.expectEqual(@as(u32, 256), nextPow2(200));
}

test "buildTree: 256 leaves (RS shred count)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Build with 256 dummy leaves
    var leaf_data: [256][]const u8 = undefined;
    var buffers: [256][4]u8 = undefined;
    for (0..256) |i| {
        buffers[i] = .{ @intCast(i), @intCast(i >> 8), 0, 0 };
        leaf_data[i] = &buffers[i];
    }

    const tree = try buildTree(&leaf_data, gpa);
    try std.testing.expectEqual(@as(usize, 511), tree.nodes.len); // 2*256 - 1

    // Verify a few paths
    for ([_]u32{ 0, 1, 127, 255 }) |idx| {
        const path = try getValidationPath(&tree, idx, gpa);
        try std.testing.expectEqual(@as(usize, 8), path.len); // log2(256) = 8
        try std.testing.expect(verifyPath(tree.root(), leaf_data[idx], path, idx, 256));
    }
}
