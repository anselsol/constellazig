//! Rust FFI bindings for the constellazig library.
//!
//! Safe wrappers around the C ABI exported by the Zig static library.

pub const NUM_PROPOSERS: usize = 16;
pub const NUM_LANES: usize = 4;
pub const LANE_CU_CAPACITY: u64 = 2_000_000;
pub const RS_TOTAL_SHREDS: usize = 256;
pub const RS_DATA_SHREDS: usize = 64;
pub const PROOF_DEPTH: usize = 8;
pub const PROOF_BYTES: usize = PROOF_DEPTH * 32;
pub const BUFFER_LENGTH: usize = 24;

pub type Pubkey = [u8; 32];
pub type Hash = [u8; 32];

/// C-ABI-compatible transaction struct. Must match Zig CTransaction layout.
#[repr(C)]
pub struct CTransaction {
    pub cu: u64,
    pub bid: u64,
    pub acc_ptr: *const Pubkey,
    pub acc_len: u32,
    pub hash: Hash,
    pub index: u32,
    _padding: u32,
}

/// Opaque attester buffer handle.
#[repr(C)]
pub struct AttesterBuffer {
    _opaque: [u8; 0],
}

extern "C" {
    pub fn constellation_select_txs(
        txs_ptr: *const CTransaction,
        txs_len: u32,
        fee_bitmap_ptr: *const u64,
        fee_bitmap_len: u32,
        out_indices_ptr: *mut u32,
        out_len: *mut u32,
    ) -> i32;

    pub fn constellation_rs_encode(
        payload_ptr: *const u8,
        payload_len: u32,
        out_root: *mut Hash,
        out_shred_data: *mut u8,
        out_proofs: *mut u8,
        out_chunk_size: *mut u32,
    ) -> i32;

    pub fn constellation_rs_decode(
        root: *const Hash,
        shred_data: *const u8,
        shred_proofs: *const u8,
        shred_indices: *const u16,
        shred_count: u32,
        chunk_size: u32,
        original_len: u32,
        out_payload: *mut u8,
        out_len: *mut u32,
    ) -> i32;

    pub fn constellation_attester_create(start_cycle: u32) -> *mut AttesterBuffer;
    pub fn constellation_attester_record(
        buf: *mut AttesterBuffer,
        proposer: u8,
        pslice_index: u32,
        commitment: *const Hash,
    );
    pub fn constellation_attester_shift(buf: *mut AttesterBuffer);
    pub fn constellation_attester_build(
        buf: *const AttesterBuffer,
        proposer: u8,
        out_pslice_indices: *mut u32,
        out_hashes: *mut Hash,
        out_count: *mut u32,
    ) -> i32;
    pub fn constellation_attester_destroy(buf: *mut AttesterBuffer);

    pub fn constellation_check_block_valid(
        num_batches: u32,
        batch_cycles: *const u64,
        parent_highest_cycle: u64,
    ) -> i32;

    pub fn constellation_detect_fault(
        commitment_hashes: *const Hash,
        merkle_roots: *const Hash,
        num_pshreds: u32,
    ) -> i32;
}

// ============================================================================
// Safe Rust wrappers
// ============================================================================

/// Schedule transactions into parallel execution lanes (Algorithm 6).
pub fn select_txs(txs: &[CTransaction], fee_bitmap: &[u64]) -> Result<Vec<u32>, i32> {
    let mut out_indices = vec![0u32; txs.len()];
    let mut out_len: u32 = 0;

    let rc = unsafe {
        constellation_select_txs(
            txs.as_ptr(),
            txs.len() as u32,
            fee_bitmap.as_ptr(),
            fee_bitmap.len() as u32,
            out_indices.as_mut_ptr(),
            &mut out_len,
        )
    };

    if rc != 0 {
        return Err(rc);
    }
    out_indices.truncate(out_len as usize);
    Ok(out_indices)
}

/// RS encode with Merkle commitment.
pub struct EncodeResult {
    pub root: Hash,
    pub shred_data: Vec<u8>,
    pub proofs: Vec<u8>,
    pub chunk_size: u32,
}

pub fn rs_encode(payload: &[u8]) -> Result<EncodeResult, i32> {
    let max_chunk = (payload.len() + RS_DATA_SHREDS - 1) / RS_DATA_SHREDS;
    let mut root = [0u8; 32];
    let mut shred_data = vec![0u8; RS_TOTAL_SHREDS * max_chunk];
    let mut proofs = vec![0u8; RS_TOTAL_SHREDS * PROOF_BYTES];
    let mut chunk_size: u32 = 0;

    let rc = unsafe {
        constellation_rs_encode(
            payload.as_ptr(),
            payload.len() as u32,
            &mut root,
            shred_data.as_mut_ptr(),
            proofs.as_mut_ptr(),
            &mut chunk_size,
        )
    };

    if rc != 0 {
        return Err(rc);
    }
    shred_data.truncate(RS_TOTAL_SHREDS * chunk_size as usize);
    proofs.truncate(RS_TOTAL_SHREDS * PROOF_BYTES);
    Ok(EncodeResult {
        root,
        shred_data,
        proofs,
        chunk_size,
    })
}

/// RS decode with Merkle verification.
pub fn rs_decode(
    root: &Hash,
    shred_data: &[u8],
    shred_proofs: &[u8],
    shred_indices: &[u16],
    chunk_size: u32,
    original_len: u32,
) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; original_len as usize];
    let mut out_len: u32 = 0;

    let rc = unsafe {
        constellation_rs_decode(
            root,
            shred_data.as_ptr(),
            shred_proofs.as_ptr(),
            shred_indices.as_ptr(),
            shred_indices.len() as u32,
            chunk_size,
            original_len,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };

    if rc != 0 {
        return Err(rc);
    }
    out.truncate(out_len as usize);
    Ok(out)
}

/// Check block cycle validity (Definition 12, condition 3).
pub fn check_block_valid(batch_cycles: &[u64], parent_highest_cycle: u64) -> bool {
    let rc = unsafe {
        constellation_check_block_valid(
            batch_cycles.len() as u32,
            batch_cycles.as_ptr(),
            parent_highest_cycle,
        )
    };
    rc == 1
}

/// Detect proposer fault from pshred metadata.
pub fn detect_fault(commitment_hashes: &[Hash], merkle_roots: &[Hash]) -> bool {
    assert_eq!(commitment_hashes.len(), merkle_roots.len());
    let rc = unsafe {
        constellation_detect_fault(
            commitment_hashes.as_ptr(),
            merkle_roots.as_ptr(),
            commitment_hashes.len() as u32,
        )
    };
    rc == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_txs() {
        let acc_a = [Pubkey::from([1u8; 32])];
        let acc_b = [Pubkey::from([2u8; 32])];

        let txs = [
            CTransaction {
                cu: 100_000,
                bid: 100,
                acc_ptr: acc_a.as_ptr(),
                acc_len: 1,
                hash: [1u8; 32],
                index: 0,
                _padding: 0,
            },
            CTransaction {
                cu: 100_000,
                bid: 50,
                acc_ptr: acc_b.as_ptr(),
                acc_len: 1,
                hash: [2u8; 32],
                index: 1,
                _padding: 0,
            },
        ];

        let bitmap = [0b11u64];
        let result = select_txs(&txs, &bitmap).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_rs_roundtrip() {
        let payload = b"Hello from Rust through Zig!".repeat(10);
        let encoded = rs_encode(&payload).unwrap();

        let indices: Vec<u16> = (0..64).collect();
        let decoded = rs_decode(
            &encoded.root,
            &encoded.shred_data,
            &encoded.proofs,
            &indices,
            encoded.chunk_size,
            payload.len() as u32,
        )
        .unwrap();

        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_attester_lifecycle() {
        unsafe {
            let buf = constellation_attester_create(0);
            assert!(!buf.is_null());

            let commitment = [0xABu8; 32];
            constellation_attester_record(buf, 0, 1, &commitment);

            let mut indices = [0u32; BUFFER_LENGTH];
            let mut hashes = [[0u8; 32]; BUFFER_LENGTH];
            let mut count: u32 = 0;

            let rc = constellation_attester_build(
                buf,
                0,
                indices.as_mut_ptr(),
                hashes.as_mut_ptr(),
                &mut count,
            );
            assert_eq!(rc, 0);
            assert_eq!(count, 1);
            assert_eq!(indices[0], 1);

            constellation_attester_shift(buf);
            constellation_attester_destroy(buf);
        }
    }

    #[test]
    fn test_check_block_valid() {
        // Valid: consecutive cycles after parent
        assert!(check_block_valid(&[11, 12, 13], 10));
        // Invalid: first cycle not > parent
        assert!(!check_block_valid(&[10], 10));
        // Invalid: non-consecutive
        assert!(!check_block_valid(&[11, 13], 10));
        // Empty block is valid
        assert!(check_block_valid(&[], 10));
    }

    #[test]
    fn test_detect_fault() {
        let h1 = [0xAAu8; 32];
        let h2 = [0xBBu8; 32];
        let r1 = [0xCCu8; 32];

        // No fault: consistent metadata
        assert!(!detect_fault(&[h1, h1], &[r1, r1]));
        // Fault: different commitment hashes
        assert!(detect_fault(&[h1, h2], &[r1, r1]));
        // Fault: different merkle roots
        assert!(detect_fault(&[h1, h1], &[r1, [0xDDu8; 32]]));
    }
}
