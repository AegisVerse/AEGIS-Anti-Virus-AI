//! Streaming hashing helpers.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Compute the SHA-256 of a reader, returning (hex digest, bytes read).
pub fn sha256_reader<R: Read>(mut r: R) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let f = std::fs::File::open(path)?;
    Ok(sha256_reader(std::io::BufReader::new(f))?.0)
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Shannon entropy (bits per byte, 0..=8).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }
}

