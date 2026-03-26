# constellazig

Zig implementation of the hot-path components from [Solana Constellation v0.9](https://anza.xyz) — the Multiple Concurrent Proposers (MCP) layer that sits on top of Alpenglow consensus.

Compiles to a static library (`libconstellazig.a`) with a C ABI, designed to be linked into [Agave](https://github.com/anza-xyz/agave) via Rust FFI.

## What's here

| Module | Whitepaper ref | What it does |
|---|---|---|
| `scheduler.zig` | Algorithm 6 | Transaction selection with 4 parallel lanes, cross-lane account conflict detection, fee reserve logic |
| `erasure.zig` | Section 2.2 | RS(256,64) encode/decode with comptime Vandermonde matrix and Merkle roundtrip verification |
| `merkle.zig` | Definitions 2-4 | SHA256 Merkle tree with domain separation, validation paths |
| `galois.zig` | — | GF(2^8) finite field arithmetic with comptime lookup tables |
| `attester.zig` | Algorithm 2 | Sliding window pshred buffer, attestation list hashing |
| `proposer.zig` | Algorithm 1 | Pslice creation, pshred generation, pslice decoding |
| `leader.zig` | Algorithm 3 | Batch construction from attestations with quorum counting |
| `validator.zig` | Algorithm 5 | Block validity checks, batch execution via scheduler |
| `fault.zig` | Definition 7 | Fault witness detection (conflicting pshreds, decode failures) |
| `types.zig` | Table 1, Defs 3-12 | Constants and wire types |
| `root.zig` | — | C ABI exports (10 functions) |

## Building

Requires [Zig 0.15.2](https://ziglang.org/download/).

```sh
# Build static library
zig build

# Run tests (68 tests)
zig build test

# Run benchmarks
zig build bench -Doptimize=ReleaseFast

# Build release
zig build -Doptimize=ReleaseFast
```

Output: `zig-out/lib/libconstellazig.a`

## Rust FFI

The `ffi/` directory contains a Rust crate that links the Zig library and provides safe wrappers.

```sh
cd ffi
cargo test   # 5 tests — scheduler, RS roundtrip, attester, validator, fault detection
```

```rust
use constellazig::{select_txs, rs_encode, rs_decode, check_block_valid, detect_fault};

let indices = select_txs(&transactions, &fee_bitmap).unwrap();
let encoded = rs_encode(&payload).unwrap();
let decoded = rs_decode(&encoded.root, &encoded.shred_data, &encoded.proofs, &indices, encoded.chunk_size, payload.len() as u32).unwrap();
```

## Performance

Apple Silicon, ReleaseFast:

| Operation | Time |
|---|---|
| Schedule 1,000 txs | 3.1 ms |
| RS encode 64KB | 10.5 ms |
| RS decode 64KB | 13.7 ms |
| Cycle budget | 50 ms |

## Architecture

```
Constellation  <- this library (MCP layer)
     |
  Alpenglow    <- consensus (Votor + Rotor), handled by Agave/Rust
     |
    SVM        <- execution, unchanged
```

Zig handles the performance-critical, deterministic pure functions. Rust handles everything else (SVM, consensus, networking, storage). The FFI boundary is clean — arena-allocated, no shared mutable state, caller-provided output buffers.

## C API

See `include/constellazig.h` for the full API. Key exports:

```c
int32_t constellation_select_txs(...);
int32_t constellation_rs_encode(...);
int32_t constellation_rs_decode(...);
constellation_attester_buffer_t *constellation_attester_create(uint32_t start_cycle);
void    constellation_attester_record(...);
void    constellation_attester_shift(...);
int32_t constellation_attester_build(...);
void    constellation_attester_destroy(...);
int32_t constellation_check_block_valid(...);
int32_t constellation_detect_fault(...);
```

## References

- [Constellation v0.9 whitepaper](https://anza.xyz) — Kniep, Resnick, Sliwinski, Wattenhofer (Anza, March 2026)
- [Alpenglow](https://anza.xyz/alpenglow-1-1) — Kniep, Sliwinski, Wattenhofer (2025)
