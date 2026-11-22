//! Chunked-16 range proofs on fastcrypto Bulletproofs++.
//!
//! One implementation for two consumers: the patched fastcrypto benchmark includes this
//! file through `#[path]` (see `patches/fastcrypto.patch`), and the Token-2022
//! end-to-end tests use it as the `token2022_chunked16` crate. It therefore depends only
//! on fastcrypto and std.
//!
//! A value committed at width `w` (16, 32, 48 or 64 bits) is split into `w / 16` chunks
//! of 16 bits. The prover publishes a commitment `H_i` for every high chunk; the verifier
//! derives the low-chunk commitment `C_0 = C - 2^16 * (H_1 + 2^16 * (H_2 + ...))` and
//! checks one 16-bit batch proof over `C_0, H_1, ...` for all values. The number of high
//! chunks is bound to the declared widths, since an extra chunk would widen the proven
//! range.

use fastcrypto::{
    bulletproofspp::{Range, RangeProof},
    error::{FastCryptoError, FastCryptoResult},
    groups::ristretto255::{RistrettoPoint, RistrettoScalar},
    pedersen::{Blinding, PedersenCommitment},
    serde_helpers::ToFromByteArray,
    traits::AllowedRng,
};

/// Bits per chunk.
pub const CHUNK_BITS: u32 = 16;

/// A chunked-16 proof as it would travel next to the original commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedProof {
    /// Serialized Bulletproofs++ batch proof over all 16-bit chunks.
    pub proof: Vec<u8>,
    /// Per original commitment, the commitments to its high chunks (`width / 16 - 1`).
    pub high_chunks: Vec<Vec<[u8; 32]>>,
}

impl ChunkedProof {
    /// Serialized batch proof size in bytes.
    pub fn proof_bytes(&self) -> usize {
        self.proof.len()
    }

    /// Size of the auxiliary high-chunk commitments in bytes.
    pub fn auxiliary_bytes(&self) -> usize {
        32 * self.high_chunks.iter().map(Vec::len).sum::<usize>()
    }
}

/// Number of high chunks for a declared width; only 16, 32, 48 and 64 are valid.
pub fn high_chunk_count(width: u32) -> FastCryptoResult<usize> {
    if width == 0 || width > 64 || width % CHUNK_BITS != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok((width / CHUNK_BITS - 1) as usize)
}

/// Decodes a public commitment as the verifier would at the instruction boundary.
pub fn decode_commitment(bytes: &[u8; 32]) -> FastCryptoResult<PedersenCommitment> {
    Ok(PedersenCommitment(RistrettoPoint::from_byte_array(bytes)?))
}

/// Multiplies a point by `2^bits` with repeated doubling.
pub fn scale_by_power_of_two(point: RistrettoPoint, bits: u32) -> RistrettoPoint {
    (0..bits).fold(point, |point, _| point + point)
}

/// Builds the 16-bit statement: for each original commitment, the derived low-chunk
/// commitment followed by its high-chunk commitments.
pub fn chunked_commitments(
    original: &[[u8; 32]],
    high_chunks: &[Vec<[u8; 32]>],
) -> FastCryptoResult<Vec<PedersenCommitment>> {
    let chunks = original.len() + high_chunks.iter().map(Vec::len).sum::<usize>();
    let mut statement = Vec::with_capacity(chunks);
    for (original, high) in original.iter().zip(high_chunks) {
        let original = decode_commitment(original)?.0;
        let first_high = statement.len() + 1;
        statement.push(PedersenCommitment(original));
        for chunk in high {
            statement.push(decode_commitment(chunk)?);
        }
        if let Some(weighted) = statement[first_high..]
            .iter()
            .rev()
            .map(|chunk| chunk.0)
            .reduce(|sum, point| scale_by_power_of_two(sum, CHUNK_BITS) + point)
        {
            statement[first_high - 1].0 = original - scale_by_power_of_two(weighted, CHUNK_BITS);
        }
    }
    Ok(statement)
}

/// Proves that every `values[i]` fits in `widths[i]` bits, given the blindings of the
/// existing commitments to those values.
pub fn prove<R: AllowedRng>(
    values: &[u64],
    blindings: &[Blinding],
    widths: &[u32],
    dst: &[u8],
    rng: &mut R,
) -> FastCryptoResult<ChunkedProof> {
    if values.len() != blindings.len() || values.len() != widths.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    let step = RistrettoScalar::from(1u64 << CHUNK_BITS);
    let mut chunk_values = Vec::new();
    let mut chunk_blindings = Vec::new();
    let mut high_chunks = Vec::with_capacity(values.len());
    for ((&value, blinding), &width) in values.iter().zip(blindings).zip(widths) {
        high_chunk_count(width)?;
        if width < 64 && value >> width != 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let high_values: Vec<u64> = (1..width / CHUNK_BITS)
            .map(|i| (value >> (i * CHUNK_BITS)) & 0xffff)
            .collect();
        let mut high_commitments = Vec::with_capacity(high_values.len());
        let mut high_blindings = Vec::with_capacity(high_values.len());
        for &high in &high_values {
            let (commitment, chunk_blinding) = PedersenCommitment::commit_u64(high, &mut *rng);
            high_commitments.push(commitment);
            high_blindings.push(chunk_blinding);
        }
        let high_blinding = high_blindings
            .iter()
            .rev()
            .fold(RistrettoScalar::from(0u64), |sum, chunk_blinding| {
                (sum + chunk_blinding.0) * step
            });
        chunk_values.push(value & 0xffff);
        chunk_values.extend(high_values);
        chunk_blindings.push(Blinding(blinding.0 - high_blinding));
        chunk_blindings.extend(high_blindings);
        high_chunks.push(
            high_commitments
                .iter()
                .map(|c| c.0.to_byte_array())
                .collect(),
        );
    }
    let proof = RangeProof::prove_batch(&chunk_values, &chunk_blindings, &Range::Bits16, dst, rng)?;
    Ok(ChunkedProof {
        proof: proof.to_bytes(),
        high_chunks,
    })
}

/// Verifies a chunked-16 proof for the original commitments at the declared widths.
pub fn verify(
    commitments: &[[u8; 32]],
    widths: &[u32],
    proof: &ChunkedProof,
    dst: &[u8],
) -> FastCryptoResult<()> {
    if commitments.len() != widths.len() || proof.high_chunks.len() != widths.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    for (high, &width) in proof.high_chunks.iter().zip(widths) {
        if high.len() != high_chunk_count(width)? {
            return Err(FastCryptoError::InvalidInput);
        }
    }
    let batch = RangeProof::from_bytes(&proof.proof)?;
    batch.verify_batch(
        &chunked_commitments(commitments, &proof.high_chunks)?,
        &Range::Bits16,
        dst,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DST: &[u8] = b"chunked16/unit";

    fn commit(values: &[u64]) -> (Vec<[u8; 32]>, Vec<Blinding>) {
        let mut rng = rand::thread_rng();
        values
            .iter()
            .map(|&v| {
                let (c, b) = PedersenCommitment::commit_u64(v, &mut rng);
                (c.0.to_byte_array(), b)
            })
            .unzip()
    }

    #[test]
    fn round_trip_at_token2022_widths() {
        let widths = [64, 16, 32, 16, 16, 16, 32, 64];
        let values = [
            u64::MAX,
            0xffff,
            u32::MAX as u64,
            0,
            9_999,
            1,
            1 << 31,
            1 << 48,
        ];
        let (commitments, blindings) = commit(&values);
        let proof = prove(&values, &blindings, &widths, DST, &mut rand::thread_rng()).unwrap();
        let counts: Vec<usize> = proof.high_chunks.iter().map(Vec::len).collect();
        assert_eq!(counts, [3, 0, 1, 0, 0, 0, 1, 3]);
        verify(&commitments, &widths, &proof, DST).unwrap();
    }

    #[test]
    fn rejects_value_wider_than_declared() {
        let (_, blindings) = commit(&[1 << 16]);
        assert!(prove(&[1 << 16], &blindings, &[16], DST, &mut rand::thread_rng()).is_err());
    }

    #[test]
    fn rejects_extra_high_chunks() {
        let (commitments, blindings) = commit(&[5]);
        let proof = prove(&[5], &blindings, &[64], DST, &mut rand::thread_rng()).unwrap();
        assert!(verify(&commitments, &[64], &proof, DST).is_ok());
        assert!(verify(&commitments, &[16], &proof, DST).is_err());
    }

    #[test]
    fn rejects_invalid_widths() {
        for width in [0, 8, 24, 80] {
            assert!(high_chunk_count(width).is_err());
        }
    }
}
