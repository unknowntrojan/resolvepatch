#![feature(portable_simd)]

use std::{
    ops::BitAnd,
    simd::{cmp::SimdPartialEq, Mask, Simd},
};

// we attempt to detect which instruction set rustc will make use of,
// as *for some reason* rust does not allow us to have the width
// automatically inferred. but it is what it is ¯\_(ツ)_/¯
#[cfg(all(
    not(target_feature = "sse2"),
    not(target_feature = "avx2"),
    not(target_feature = "avx512f"),
    not(target_feature = "neon")
))]
compile_error!("you have not selected a proper SIMD instruction set (SSE2/AVX2/AVX512/NEON)");

#[cfg(all(
    any(target_feature = "sse2", target_feature = "neon"),
    not(target_feature = "avx2"),
    not(target_feature = "avx512f")
))]
const BYTES: usize = 16;

#[cfg(all(target_feature = "avx2", not(target_feature = "avx512f")))]
const BYTES: usize = 32;

#[cfg(target_feature = "avx512f")]
const BYTES: usize = 64;

#[macro_export]
macro_rules! pattern {
    ($($elem:tt),+) => {
        &[$(pattern!(@el $elem)),+]
    };
    (@el $v:expr) => {
        Some($v as u8)
    };
    (@el $v:tt) => {
        None
    };
}

pub type OwnedPattern = Vec<Option<u8>>;
pub type Pattern<'a> = &'a [Option<u8>];

pub struct PatternChunk {
    pub first_byte: Simd<u8, BYTES>,
    pub mask: Mask<i8, BYTES>,
    pub bytes: Simd<u8, BYTES>,
}

pub struct PreparedPattern {
    pub chunks: Vec<PatternChunk>,
    pub orig_pat: OwnedPattern,
    pub size: usize,
    pub padded_size: usize,
    pub start_offset: usize,
}

impl<'a> From<Pattern<'a>> for PreparedPattern {
    fn from(pat: Pattern) -> Self {
        // remove trailing wildcard bytes
        let pat = &pat[0..=pat
            .iter()
            .rposition(|chr| matches!(chr, Some(_)))
            .expect("pattern should not be a wildcard!")];

        // don't include the first n wildcard bytes in the actual search pattern, saving valuable space
        // doing this naively would cause an unexpected shift in the returned matches, therefore
        // we simply re-apply the offset when returning pattern matches to the user.
        let start_offset = pat
            .iter()
            .position(|byte| byte.is_some())
            .expect("pattern should not be a wildcard!");

        let pat = &pat[start_offset..pat.len()];

        // get size extended to next chunk
        let size = if pat.len() % BYTES == 0 {
            pat.len()
        } else {
            pat.len() + (BYTES - (pat.len() % BYTES))
        };

        let bytes: Vec<u8> = pat
            .iter()
            .map(|x| match x {
                Some(x) => *x,
                None => 0u8,
            })
            .collect();

        let mask: Vec<bool> = pat.iter().map(|x| x.is_some()).collect();

        let mut bytes_extended = vec![0u8; size];

        bytes_extended[0..pat.len()].copy_from_slice(&bytes);

        let mut mask_extended = vec![false; size];

        mask_extended[0..pat.len()].copy_from_slice(&mask);

        let chunks: Vec<PatternChunk> = bytes_extended
            .chunks_exact(BYTES)
            .zip(mask_extended.chunks_exact(BYTES))
            .map(|(bytes, mask)| {
                let bytes: [u8; BYTES] = bytes.try_into().unwrap();
                let mask: [bool; BYTES] = mask.try_into().unwrap();
                PatternChunk {
                    first_byte: Simd::from_array([bytes[0]; BYTES]),
                    mask: Mask::from_array(mask),
                    bytes: Simd::from_array(bytes),
                }
            })
            .collect();

        Self {
            chunks,
            orig_pat: pat.to_owned(),
            size: pat.len(),
            padded_size: size,
            start_offset,
        }
    }
}

// precompute data for pattern in SIMD chunks.
// SIMD search binary

pub struct PatternSearcher<'data> {
    data: &'data [u8],
    remaining_data: &'data [u8],
    pattern: PreparedPattern,
}

impl<'data> PatternSearcher<'data> {
    pub fn new(data: &'data [u8], pattern: Pattern) -> Self {
        Self {
            data,
            remaining_data: data,
            pattern: pattern.into(),
        }
    }
}

impl<'data> Iterator for PatternSearcher<'data> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        'main: loop {
            if self.remaining_data.len() < self.pattern.size {
                // pattern is not findable anymore.
                break None;
            }

            if self.remaining_data.len() < self.pattern.padded_size {
                // pattern is no longer SIMD-findable. manually find.

                // this is a very cold path.
                #[cold]
                fn find_pattern(region: &[u8], pattern: Pattern) -> Option<usize> {
                    region.windows(pattern.len()).position(|wnd| {
                        wnd.iter().zip(pattern).all(|(v, p)| match p {
                            Some(x) => *v == *x,
                            None => true,
                        })
                    })
                }

                let result = find_pattern(self.remaining_data, &self.pattern.orig_pat);

                break match result {
                    Some(offset) => {
                        let result = offset - self.pattern.start_offset + self.data.len()
                            - self.remaining_data.len();
                        self.remaining_data = &self.remaining_data[offset + 1..];

                        Some(result)
                    }
                    None => None,
                };
            }

            let mut current_search = self.remaining_data;
            let mut current_offset = 0usize;
            let mut first_chunk = true;

            for chunk in &self.pattern.chunks {
                let search = Simd::from_slice(&current_search[..BYTES]);

                let first_byte = search.simd_eq(chunk.first_byte).to_bitmask();

                if first_byte == 0 {
                    if first_chunk {
                        // this is the first block. the next block may contain the first again
                        // advance current cursor to the next block and restart pattern verification
                        self.remaining_data = &self.remaining_data[BYTES..];
                    } else {
                        // this is a continuation block. the first pattern chunk might still be in this data chunk
                        // only this chunk has failed, we need to restart pattern verification in this same block, just this time with the first chunk
                        self.remaining_data = &self.remaining_data[current_offset..];
                    }

                    continue 'main;
                }

                // if this is the first chunk, allow advancing to the next occurrence of the first byte and restart check
                if first_chunk && first_byte.trailing_zeros() != 0 {
                    self.remaining_data =
                        &self.remaining_data[first_byte.trailing_zeros() as usize..];
                    continue 'main;
                } else if first_byte.trailing_zeros() != 0 {
                    // not the first chunk, but we are not aligned to the first byte.
                    // this means we did not match.
                    // restart pattern verification from the current data chunk.
                    self.remaining_data = &self.remaining_data[current_offset..];
                    continue 'main;
                }

                // we are now aligned to the first byte of the chunk
                let search = Simd::from_slice(current_search);

                let result = search.simd_eq(chunk.bytes);

                // filtered result is smaller than the mask
                let filtered_result = result.bitand(chunk.mask);

                if filtered_result != chunk.mask {
                    // we did not match. restart pattern scan in one byte

                    // increase index by one to avoid scanning the same chunk again
                    self.remaining_data = &self.remaining_data[1..];

                    continue 'main;
                }

                // we matched. go on to next chunk. if the remaining chunks also match, we gracefully leave the loop and return a match.

                first_chunk = false;
                current_search = &current_search[BYTES..];
                current_offset += BYTES;
            }

            let result = self.data.len() - self.remaining_data.len() - self.pattern.start_offset;

            self.remaining_data = &self.remaining_data[1..];

            return Some(result);
        }
    }
}

#[test]
fn test_scan_simple() {
    let mut buf = vec![0u8; 500];

    buf[6] = 0xDE;
    buf[7] = 0xAD;
    buf[8] = 0xBE;
    buf[9] = 0xEF;

    let pattern = pattern!(0xDE, 0xAD, 0xBE, 0xEF);
    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(6))
}

#[test]
fn test_scan_offset() {
    let mut buf = vec![0u8; 500];

    buf[6] = 0xDE;
    buf[7] = 0xAD;
    buf[8] = 0xBE;
    buf[9] = 0xEF;

    let pattern = pattern!(_, 0xDE, 0xAD, 0xBE, 0xEF);
    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(5))
}

#[test]
fn test_scan_simd_fallback() {
    let mut buf = vec![0u8; 500];

    buf[496] = 0xDE;
    buf[497] = 0xAD;
    buf[498] = 0xBE;
    buf[499] = 0xEF;

    let pattern = pattern!(0xDE, 0xAD, 0xBE, 0xEF);
    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(496))
}

#[test]
fn test_scan_simd_fallback_offset() {
    let mut buf = vec![0u8; 500];

    buf[496] = 0xDE;
    buf[497] = 0xAD;
    buf[498] = 0xBE;
    buf[499] = 0xEF;

    let pattern = pattern!(_, 0xDE, 0xAD, 0xBE, 0xEF);
    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(495))
}

#[test]
fn test_scan_wildcard() {
    let mut buf = vec![0u8; 500];

    buf[6] = 0xDE;
    buf[7] = 0xAD;
    buf[9] = 0xBE;
    buf[10] = 0xEF;

    let pattern = pattern!(0xDE, 0xAD, _, 0xBE, 0xEF);
    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(6))
}

#[test]
fn test_scan_large_sig() {
    let mut buf = vec![0u8; 500];

    buf[5] = 0xDE;
    buf[6] = 0xAD;
    buf[8] = 0xBE;
    buf[9] = 0xEF;

    buf[10] = 0xDE;
    buf[11] = 0xAD;
    buf[13] = 0xBE;
    buf[14] = 0xEF;

    buf[15] = 0xDE;
    buf[16] = 0xAD;
    buf[18] = 0xBE;
    buf[19] = 0xEF;

    buf[20] = 0xDE;
    buf[21] = 0xAD;
    buf[23] = 0xBE;
    buf[24] = 0xEF;

    buf[25] = 0xDE;
    buf[26] = 0xAD;
    buf[28] = 0xBE;
    buf[29] = 0xEF;

    buf[30] = 0xDE;
    buf[31] = 0xAD;
    buf[33] = 0xBE;
    buf[34] = 0xEF;

    buf[35] = 0xDE;
    buf[36] = 0xAD;
    buf[38] = 0xBE;
    buf[39] = 0xEF;

    buf[40] = 0xDE;
    buf[41] = 0xAD;
    buf[43] = 0xBE;
    buf[44] = 0xEF;

    buf[45] = 0xDE;
    buf[46] = 0xAD;
    buf[48] = 0xBE;
    buf[49] = 0xEF;

    let pattern = pattern!(
        0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE,
        0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _,
        0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF, 0xDE, 0xAD, _, 0xBE, 0xEF
    );

    let mut scanner = PatternSearcher::new(&buf, pattern);

    assert_eq!(scanner.next(), Some(5))
}
