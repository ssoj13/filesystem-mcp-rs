//! MurmurHash3 x64_128 implementation.
//!
//! Original algorithm by Austin Appleby.

/// Compute MurmurHash3 x64_128 hash.
/// Returns 128-bit hash as (h1, h2).
#[inline]
pub fn hash128(data: &[u8]) -> (u64, u64) {
    let len = data.len();
    let nblocks = len / 16;
    
    let mut h1: u64 = 0;
    let mut h2: u64 = 0;
    
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;
    
    // Body - process 16-byte blocks
    for i in 0..nblocks {
        let offset = i * 16;
        
        let k1 = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let k2 = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
        
        let mut k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);
        
        let mut k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
    }
    
    // Tail - process remaining bytes
    let tail = &data[nblocks * 16..];
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;
    
    match tail.len() {
        15 => { k2 ^= (tail[14] as u64) << 48; k2 ^= (tail[13] as u64) << 40; k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        14 => { k2 ^= (tail[13] as u64) << 40; k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        13 => { k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        12 => { k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        11 => { k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        10 => { k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        9 => { k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        8 => { k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        7 => { k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        6 => { k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        5 => { k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        4 => { k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        3 => { k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        2 => { k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        1 => { k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2); h1 ^= k1; }
        0 => {}
        _ => unreachable!(),
    }
    
    // Finalization
    h1 ^= len as u64;
    h2 ^= len as u64;
    
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    
    (h1, h2)
}

#[inline]
fn fmix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

/// Format as hex string (32 chars)
pub fn hash128_hex(data: &[u8]) -> String {
    let (h1, h2) = hash128(data);
    format!("{:016x}{:016x}", h1, h2)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty() {
        let h = hash128_hex(&[]);
        assert_eq!(h.len(), 32);
    }
    
    #[test]
    fn test_hello() {
        let h = hash128_hex(b"hello");
        assert_eq!(h.len(), 32);
    }
}
