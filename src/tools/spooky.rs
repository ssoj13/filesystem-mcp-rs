//! SpookyHash V2 - A 128-bit non-cryptographic hash function.
//!
//! Original algorithm by Bob Jenkins.

const SC_CONST: u64 = 0xdeadbeefdeadbeef;

#[inline(always)]
const fn rot64(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

#[inline(always)]
fn short_mix(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    *c = rot64(*c, 50); *c = c.wrapping_add(*d); *a ^= *c;
    *d = rot64(*d, 52); *d = d.wrapping_add(*a); *b ^= *d;
    *a = rot64(*a, 30); *a = a.wrapping_add(*b); *c ^= *a;
    *b = rot64(*b, 41); *b = b.wrapping_add(*c); *d ^= *b;
    *c = rot64(*c, 54); *c = c.wrapping_add(*d); *a ^= *c;
    *d = rot64(*d, 48); *d = d.wrapping_add(*a); *b ^= *d;
    *a = rot64(*a, 38); *a = a.wrapping_add(*b); *c ^= *a;
    *b = rot64(*b, 37); *b = b.wrapping_add(*c); *d ^= *b;
    *c = rot64(*c, 62); *c = c.wrapping_add(*d); *a ^= *c;
    *d = rot64(*d, 34); *d = d.wrapping_add(*a); *b ^= *d;
    *a = rot64(*a, 5);  *a = a.wrapping_add(*b); *c ^= *a;
    *b = rot64(*b, 36); *b = b.wrapping_add(*c); *d ^= *b;
}

#[inline(always)]
fn short_end(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    *d ^= *c; *c = rot64(*c, 15); *d = d.wrapping_add(*c);
    *a ^= *d; *d = rot64(*d, 52); *a = a.wrapping_add(*d);
    *b ^= *a; *a = rot64(*a, 26); *b = b.wrapping_add(*a);
    *c ^= *b; *b = rot64(*b, 51); *c = c.wrapping_add(*b);
    *d ^= *c; *c = rot64(*c, 28); *d = d.wrapping_add(*c);
    *a ^= *d; *d = rot64(*d, 9);  *a = a.wrapping_add(*d);
    *b ^= *a; *a = rot64(*a, 47); *b = b.wrapping_add(*a);
    *c ^= *b; *b = rot64(*b, 54); *c = c.wrapping_add(*b);
    *d ^= *c; *c = rot64(*c, 32); *d = d.wrapping_add(*c);
    *a ^= *d; *d = rot64(*d, 25); *a = a.wrapping_add(*d);
    *b ^= *a; *a = rot64(*a, 63); *b = b.wrapping_add(*a);
}

#[inline(always)]
fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

#[inline(always)]
fn read_u32_le(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let len = bytes.len().min(4);
    buf[..len].copy_from_slice(&bytes[..len]);
    u32::from_le_bytes(buf)
}

/// Hash a message, returning 128-bit hash as (h1, h2)
pub fn hash128(message: &[u8]) -> (u64, u64) {
    let length = message.len();
    
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut c = SC_CONST;
    let mut d = SC_CONST;
    
    let mut offset = 0;
    
    if length > 15 {
        let end = (length / 32) * 32;
        while offset < end {
            c = c.wrapping_add(read_u64_le(&message[offset..]));
            d = d.wrapping_add(read_u64_le(&message[offset + 8..]));
            short_mix(&mut a, &mut b, &mut c, &mut d);
            a = a.wrapping_add(read_u64_le(&message[offset + 16..]));
            b = b.wrapping_add(read_u64_le(&message[offset + 24..]));
            offset += 32;
        }
        
        let remaining = length - offset;
        if remaining >= 16 {
            c = c.wrapping_add(read_u64_le(&message[offset..]));
            d = d.wrapping_add(read_u64_le(&message[offset + 8..]));
            short_mix(&mut a, &mut b, &mut c, &mut d);
            offset += 16;
        }
    }
    
    d = d.wrapping_add((length as u64) << 56);
    let remaining = length - offset;
    let tail = &message[offset..];
    
    match remaining {
        15 => { d = d.wrapping_add((tail[14] as u64) << 48); d = d.wrapping_add((tail[13] as u64) << 40); d = d.wrapping_add((tail[12] as u64) << 32); d = d.wrapping_add(read_u32_le(&tail[8..]) as u64); c = c.wrapping_add(read_u64_le(tail)); }
        14 => { d = d.wrapping_add((tail[13] as u64) << 40); d = d.wrapping_add((tail[12] as u64) << 32); d = d.wrapping_add(read_u32_le(&tail[8..]) as u64); c = c.wrapping_add(read_u64_le(tail)); }
        13 => { d = d.wrapping_add((tail[12] as u64) << 32); d = d.wrapping_add(read_u32_le(&tail[8..]) as u64); c = c.wrapping_add(read_u64_le(tail)); }
        12 => { d = d.wrapping_add(read_u32_le(&tail[8..]) as u64); c = c.wrapping_add(read_u64_le(tail)); }
        11 => { d = d.wrapping_add((tail[10] as u64) << 16); d = d.wrapping_add((tail[9] as u64) << 8); d = d.wrapping_add(tail[8] as u64); c = c.wrapping_add(read_u64_le(tail)); }
        10 => { d = d.wrapping_add((tail[9] as u64) << 8); d = d.wrapping_add(tail[8] as u64); c = c.wrapping_add(read_u64_le(tail)); }
        9 => { d = d.wrapping_add(tail[8] as u64); c = c.wrapping_add(read_u64_le(tail)); }
        8 => { c = c.wrapping_add(read_u64_le(tail)); }
        7 => { c = c.wrapping_add((tail[6] as u64) << 48); c = c.wrapping_add((tail[5] as u64) << 40); c = c.wrapping_add((tail[4] as u64) << 32); c = c.wrapping_add(read_u32_le(tail) as u64); }
        6 => { c = c.wrapping_add((tail[5] as u64) << 40); c = c.wrapping_add((tail[4] as u64) << 32); c = c.wrapping_add(read_u32_le(tail) as u64); }
        5 => { c = c.wrapping_add((tail[4] as u64) << 32); c = c.wrapping_add(read_u32_le(tail) as u64); }
        4 => { c = c.wrapping_add(read_u32_le(tail) as u64); }
        3 => { c = c.wrapping_add((tail[2] as u64) << 16); c = c.wrapping_add((tail[1] as u64) << 8); c = c.wrapping_add(tail[0] as u64); }
        2 => { c = c.wrapping_add((tail[1] as u64) << 8); c = c.wrapping_add(tail[0] as u64); }
        1 => { c = c.wrapping_add(tail[0] as u64); }
        0 => { c = c.wrapping_add(SC_CONST); d = d.wrapping_add(SC_CONST); }
        _ => unreachable!(),
    }
    
    short_end(&mut a, &mut b, &mut c, &mut d);
    (a, b)
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
        let h = hash128_hex(b"hello world");
        assert_eq!(h.len(), 32);
    }
}
