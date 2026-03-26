# Constellazig — Remaining Work

## Bugs

### B1: RS evaluation point collision (erasure.zig:55)
`eval_points[0] == eval_points[255]` — both map to 1 via `pow(2, i % 255)`.
Two identical Vandermonde rows means the matrix is singular if both shreds 0
and 255 are used in decoding. **Fix:** use raw field elements `0, 1, 2, ..., 255`
as evaluation points (all 256 GF(2^8) elements are distinct). Note: x=0 gives
Vandermonde row `[1, 0, 0, ..., 0]`, so shred 0 is just the first data chunk.
This also needs to be fixed in the decode path where the submatrix is built.

### B2: FindSpace static buffer (scheduler.zig:193)
`findSpace` returns a slice from a `struct { var buf: [2]Space }` — a file-level
mutable static. This is fine for single-threaded use, but if `selectTxs` is ever
called from multiple threads (or if Zig's test runner parallelizes), it's a data
race. **Fix:** return a small struct with inline array instead of a slice, or
allocate from the arena.

---

## Correctness / Protocol Fidelity

### C1: Writable vs readable accounts in scheduler
The scheduler treats all accounts in `tx.acc` as conflicting. The whitepaper
says "writable accounts" — if the Rust side passes both readable and writable
accounts, the scheduler would over-serialize. **Clarify:** ensure the Rust side
only passes writable accounts in `acc`, or add a read/write flag per account.

### C2: Scheduler sort stability
`std.sort.pdq` is not stable. Definition 13's ordering is total (hash tiebreaks
all ties), so instability doesn't affect correctness. But **verify** this is
always the case — if two txs have identical (bid, cu, hash), the sort order is
undefined. In practice, tx hashes are unique, so this is likely fine.

### C3: Fee payer reserve logic (Algorithm 6, lines 9-10)
The whitepaper interleaves fee charging within Algorithm 6:
- `chargeInclusionFee(tx)` happens for EVERY tx (even skipped ones)
- `chargePriorityFee(tx)` determines scheduling
- If priority fee would drop balance below ϕ=0.001 SOL, tx is skipped

Currently we treat this as a pre-computed bitmap from Rust. But the whitepaper
charges inclusion fees *in order*, which affects balances for later txs from the
same fee payer. **Decision needed:** either:
- (a) Rust pre-computes all of this (current approach, simpler), or
- (b) Zig implements the fee logic with account state access (more faithful)

Current approach (a) is correct IF the Rust side simulates Algorithm 6's fee
ordering when building the bitmap.

### C4: Attester window_base initialization
`AttesterBuffer.init(start_cycle)` uses saturating arithmetic for window_base:
`start_cycle *| MU -| (LAMBDA - 1) *| MU`. This should match the whitepaper's
`(c - λ)µ` formula. Needs test coverage for cycle 0 and epoch boundary cases.

---

## Missing Features

### F1: RS decode C FFI (root.zig)
Stubbed as `-100`. The challenge is serializing Merkle proofs across the FFI
boundary. Options:
- (a) Flat buffer: `proof_data[shred_idx * depth * 32]` — simple, fixed size
- (b) Opaque handle: Zig-side keeps the encoded result, Rust calls decode by handle
- (c) Combined encode/verify: Zig does both sides, Rust never sees raw proofs

Recommend (a) — proofs are fixed size (8 × 32 = 256 bytes per shred for 256
leaves), so a flat `[shred_count * 256]u8` buffer works.

### F2: Attestation signing & serialization
The attester buffer collects pshred commitments but doesn't:
- Sign attestations (Ed25519 signature over `Attestation(e, c, k, hash(l1)..hash(lp))`)
- Serialize attestation wire format (Definition 5)
- Hash the per-proposer lists

The signing should happen on the Rust side (Ed25519 is already in Agave). But
the Zig side should provide `hashAttestationLists()` → `[16]Hash` for the
attestation commitment.

### F3: Block validity checks (Algorithm 5)
`CheckBlockValid` verifies:
- Submissions match newly-attested pslices
- Fault witnesses present for omitted proposers
- Cycle indices are consecutive and monotonically increasing

This is a validator-side check. Could be implemented in Zig for performance, or
left to Rust since it touches Alpenglow state (parent block, attested set).

### F4: Proposer logic (Algorithm 1)
`selectTransactions()` and `newPshreds()` — proposer-side transaction selection
and pslice assembly. Currently not in scope (proposer logic is less
perf-critical than validator-side scheduling), but would complete the
Constellation protocol implementation.

### F5: Fault witness construction (Definition 7)
Leaders need to construct fraud proofs for misbehaving proposers:
- Two incompatible pshreds (different commitment hash for same (e,c,j,t))
- γp pshreds that fail to decode

The data structures exist (Shred, Merkle proofs), but no fault witness builder.

### F6: C header file
No `constellazig.h` for Rust/C consumers. Either:
- Auto-generate via `zig translate-c` (backwards), or
- Hand-write a header matching the `@export`ed symbols
- Or generate from Zig via a build step

---

## Performance

### P1: RS encoding speed
Current O(N×K×chunk_size) = O(256×64×chunk_size) per-byte polynomial evaluation.
For a 64KB payload: ~16M GF multiplications × ~5 cycles each = ~80M cycles ≈ 25ms
on 3GHz. This is tight for 50ms cycles.

Optimizations:
- **SIMD vectorization**: Process 16/32 bytes at once using `@Vector`
- **Matrix precomputation**: Cache the 256×64 encoding matrix instead of
  computing powers on the fly
- **FFT-based encoding**: Use Number Theoretic Transform for O(N log N) encoding

### P2: Scheduler with large transaction sets
The scheduler is O(T × S × K²) where T=transactions, S=spaces, K=scheduled txs.
For 5000+ transactions this could be slow. Profile and consider:
- Account conflict hash set for large batches
- Space tree instead of sorted array
- Early termination when all lanes full

### P3: Matrix inversion in decode
64×64 GF(2^8) Gauss-Jordan is O(K³) = O(262144) GF operations. This is fast
(~1.3M cycles ≈ 0.4ms). Not a bottleneck.

---

## Testing

### T1: RS codec with shred 255
Test that explicitly uses shreds {0, 255, ...} in decoding to verify evaluation
point distinctness. **Currently broken due to B1.**

### T2: Scheduler Figure 5 reproduction
The whitepaper Figure 5 shows 13 specific transactions with known accounts
(A through G) and their exact placement on 4 lanes. Implement this as a
golden test to verify Algorithm 6 correctness against the spec.

### T3: Property-based / fuzz testing
- Scheduler: random txs → verify no temporal+account overlaps in output
- RS: random payload + random shred selection → roundtrip matches
- Merkle: random trees → all paths verify

### T4: Benchmark suite
- `selectTxs` with 1K, 5K, 10K transactions
- RS encode/decode with 1KB, 64KB, 1MB payloads
- Target: scheduler < 5ms, RS encode < 10ms for 64KB

### T5: Cross-module integration test
Full pipeline: create transactions → schedule → build pslices → RS encode →
attester buffer → build attestation → (simulate leader) → RS decode → verify.

---

## Build / Integration

### I1: Rust build.rs integration
Write a `build.rs` that invokes `zig build -Doptimize=ReleaseFast` and links
`libconstellazig.a`. Include the C header and `extern "C"` declarations in Rust.

### I2: C header generation
Hand-write `include/constellazig.h` with all exported function signatures,
struct definitions, and documentation.

### I3: CI pipeline
- `zig build test` on every push
- `zig build -Doptimize=ReleaseFast` to verify release builds
- Benchmark regression tracking

---

## Priority Order

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | B1: Fix RS eval points | Small | Correctness bug |
| **P0** | T1: Test shred 255 | Small | Validates B1 fix |
| **P1** | F1: RS decode FFI | Medium | Enables Rust integration |
| **P1** | I1: Rust build.rs | Medium | Enables Rust integration |
| **P1** | I2: C header | Small | Enables Rust integration |
| **P1** | T2: Figure 5 golden test | Medium | Validates scheduler |
| **P2** | B2: FindSpace static buf | Small | Thread safety |
| **P2** | F2: Attestation hashing | Small | Protocol completeness |
| **P2** | P1: RS SIMD optimization | Large | Performance |
| **P2** | T4: Benchmarks | Medium | Performance tracking |
| **P3** | C3: Fee logic decision | Design | Protocol fidelity |
| **P3** | F3: Block validity | Large | Full validator |
| **P3** | F4: Proposer logic | Large | Full protocol |
| **P3** | F5: Fault witnesses | Medium | MEV resistance |
| **P3** | T3: Fuzz testing | Medium | Robustness |
| **P3** | T5: Integration test | Medium | End-to-end validation |
