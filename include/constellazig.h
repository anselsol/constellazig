/**
 * constellazig — Constellation v0.9 MCP hot-path components.
 *
 * Zig static library linked into Agave (Rust) via FFI.
 * All functions are thread-safe (use internal arena allocation).
 * Caller must pre-allocate output buffers.
 */

#ifndef CONSTELLAZIG_H
#define CONSTELLAZIG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Constants ===== */

#define CONSTELLATION_NUM_PROPOSERS    16
#define CONSTELLATION_NUM_ATTESTERS    256
#define CONSTELLATION_NUM_LANES        4
#define CONSTELLATION_LANE_CU_CAPACITY 2000000
#define CONSTELLATION_RS_TOTAL_SHREDS  256
#define CONSTELLATION_RS_DATA_SHREDS   64
#define CONSTELLATION_PROOF_DEPTH      8    /* log2(256) */
#define CONSTELLATION_PROOF_BYTES      256  /* PROOF_DEPTH * 32 */
#define CONSTELLATION_BUFFER_LENGTH    24   /* MU * LAMBDA */

/* ===== Types ===== */

typedef uint8_t constellation_pubkey_t[32];
typedef uint8_t constellation_hash_t[32];

/**
 * Transaction for the scheduler (C ABI layout).
 * Must match Zig CTransaction extern struct exactly.
 */
typedef struct {
    uint64_t cu;                          /* compute units */
    uint64_t bid;                         /* priority fee per CU (lamports/CU) */
    const constellation_pubkey_t *acc_ptr; /* writable account pubkeys */
    uint32_t acc_len;                     /* number of accounts */
    constellation_hash_t hash;            /* transaction hash */
    uint32_t index;                       /* original index for bitmap lookup */
    uint32_t _padding;
} constellation_transaction_t;

/* Opaque attester buffer handle */
typedef struct constellation_attester_buffer constellation_attester_buffer_t;

/* ===== Transaction Scheduler (Algorithm 6) ===== */

/**
 * Schedule transactions into m=4 parallel execution lanes.
 *
 * @param txs_ptr         Array of transactions (sorted in-place by Definition 13)
 * @param txs_len         Number of transactions
 * @param fee_bitmap_ptr  Packed bitmap: bit i set = tx i can pay priority fee
 * @param fee_bitmap_len  Number of u64 words in bitmap
 * @param out_indices_ptr Output: indices of scheduled transactions (pre-allocate txs_len)
 * @param out_len         Output: number of scheduled transactions
 * @return 0 on success, negative on error (-1=alloc, -2=scheduler)
 */
int32_t constellation_select_txs(
    const constellation_transaction_t *txs_ptr,
    uint32_t txs_len,
    const uint64_t *fee_bitmap_ptr,
    uint32_t fee_bitmap_len,
    uint32_t *out_indices_ptr,
    uint32_t *out_len
);

/* ===== Reed-Solomon Erasure Codec (256, 64) ===== */

/**
 * RS encode payload with Merkle commitment.
 *
 * @param payload_ptr    Input payload
 * @param payload_len    Payload length in bytes
 * @param out_root       Output: 32-byte Merkle root
 * @param out_shred_data Output: 256 * chunk_size bytes (pre-allocate 256 * ceil(payload_len/64))
 * @param out_proofs     Output: 256 * 256 bytes of Merkle proofs
 * @param out_chunk_size Output: size of each shred's data
 * @return 0 on success, negative on error
 */
int32_t constellation_rs_encode(
    const uint8_t *payload_ptr,
    uint32_t payload_len,
    constellation_hash_t *out_root,
    uint8_t *out_shred_data,
    uint8_t *out_proofs,
    uint32_t *out_chunk_size
);

/**
 * RS decode with Merkle verification + roundtrip check (Section 2.2).
 *
 * @param root            32-byte Merkle root to verify against
 * @param shred_data      shred_count * chunk_size bytes of shred data
 * @param shred_proofs    shred_count * 256 bytes of Merkle proofs
 * @param shred_indices   Array of shred_count indices (0..255)
 * @param shred_count     Number of shreds (must be >= 64)
 * @param chunk_size      Size of each shred's data
 * @param original_len    Original payload length (for unpadding)
 * @param out_payload     Output: decoded payload (pre-allocate original_len bytes)
 * @param out_len         Output: actual decoded length
 * @return 0 on success, -2=insufficient shreds, -3=insufficient valid, -4=roundtrip fail
 */
int32_t constellation_rs_decode(
    const constellation_hash_t *root,
    const uint8_t *shred_data,
    const uint8_t *shred_proofs,
    const uint16_t *shred_indices,
    uint32_t shred_count,
    uint32_t chunk_size,
    uint32_t original_len,
    uint8_t *out_payload,
    uint32_t *out_len
);

/* ===== Attester Buffer (Algorithm 2) ===== */

/**
 * Create an attester buffer initialized for the given cycle.
 * @return Opaque handle, or NULL on allocation failure. Free with constellation_attester_destroy.
 */
constellation_attester_buffer_t *constellation_attester_create(uint32_t start_cycle);

/**
 * Record a pshred commitment in the attester buffer.
 */
void constellation_attester_record(
    constellation_attester_buffer_t *buf,
    uint8_t proposer,
    uint32_t pslice_index,
    const constellation_hash_t *commitment
);

/**
 * Shift the attester buffer forward by one cycle (MU=4 slots).
 */
void constellation_attester_shift(constellation_attester_buffer_t *buf);

/**
 * Build attestation list for a proposer.
 *
 * @param buf               Attester buffer handle
 * @param proposer          Proposer index (0..15)
 * @param out_pslice_indices Output: pslice indices (pre-allocate BUFFER_LENGTH=24)
 * @param out_hashes        Output: commitment hashes (pre-allocate BUFFER_LENGTH=24)
 * @param out_count         Output: number of entries
 * @return 0 on success, negative on error
 */
int32_t constellation_attester_build(
    const constellation_attester_buffer_t *buf,
    uint8_t proposer,
    uint32_t *out_pslice_indices,
    constellation_hash_t *out_hashes,
    uint32_t *out_count
);

/**
 * Free an attester buffer.
 */
void constellation_attester_destroy(constellation_attester_buffer_t *buf);

/* ===== Validator (Algorithm 5) ===== */

/**
 * Check block cycle validity (Definition 12, condition 3).
 * @return 1 if valid, 0 if invalid
 */
int32_t constellation_check_block_valid(
    uint32_t num_batches,
    const uint64_t *batch_cycles,
    uint64_t parent_highest_cycle
);

/* ===== Fault Detection (Definition 7) ===== */

/**
 * Detect proposer fault from pshred metadata.
 * Checks for conflicting commitment hashes or Merkle roots.
 * @return 1 if fault detected, 0 if no fault
 */
int32_t constellation_detect_fault(
    const constellation_hash_t *commitment_hashes,
    const constellation_hash_t *merkle_roots,
    uint32_t num_pshreds
);

#ifdef __cplusplus
}
#endif

#endif /* CONSTELLAZIG_H */
