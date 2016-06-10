use byteorder::{ BigEndian, ByteOrder };

pub type Endian = BigEndian;


#[inline]
pub fn u8_to_u64(input: &[u8], output: &mut [u64]) {
    for (i, b) in output.iter_mut().enumerate() {
        *b = Endian::read_u64(&input[(i * 8)..((i + 1) * 8)]);
    }
}

#[inline]
pub fn u64_to_u8(input: &[u64], output: &mut [u8]) {
    for (i, &b) in input.iter().enumerate() {
        Endian::write_u64(&mut output[(i * 8)..((i + 1) * 8)], b)
    }
}

#[inline]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false };

    let mut d = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }

    // NOTE ((1 & ((d - 1) >> 8)) - 1) != 0
    d == 0
}