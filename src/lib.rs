use std::convert::TryInto;

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[allow(non_snake_case)]
pub fn md5(message: &[u8]) -> String {
    let mut message = message
        .iter()
        .map(|byte| format!("{:0>8b}", byte))
        .collect::<String>();
    let message_len = (message.len() as u64)
        .to_le_bytes()
        .iter()
        .map(|byte| format!("{:0>8b}", byte))
        .collect::<String>();
    message.push('1');

    while (message.len() + 64) % 512 != 0 {
        message.push('0');
    }

    message.push_str(&message_len);
    let mut A: u32 = 0x67452301;
    let mut B: u32 = 0xefcdab89;
    let mut C: u32 = 0x98badcfe;
    let mut D: u32 = 0x10325476;

    for chunk_index in 0..message.len() / 512 {
        let chunk = &message[chunk_index * 512..chunk_index * 512 + 512];
        let bytes = (0..64)
            .map(|i| u8::from_str_radix(&chunk[i * 8..i * 8 + 8], 2).unwrap())
            .collect::<Vec<u8>>();
        let M = (0..16)
            .map(|i| {
                u32::from_le_bytes(
                    bytes[i * 4..i * 4 + 4].try_into().unwrap(),
                )
            })
            .collect::<Vec<u32>>();

        let (mut a, mut b, mut c, mut d) = (A, B, C, D);

        for i in 0..64 {
            let (F, g, s): (u32, usize, [u32; 4]);

            if i < 16 {
                F = (b & c) | (!b & d);
                g = i;
                s = [7, 12, 17, 22];
            } else if i >= 16 && i < 32 {
                F = (d & b) | (!d & c);
                g = (5 * i + 1) % 16;
                s = [5, 9, 14, 20];
            } else if i >= 32 && i < 48 {
                F = b ^ c ^ d;
                g = (3 * i + 5) % 16;
                s = [4, 11, 16, 23];
            } else {
                F = c ^ (b | !d);
                g = (7 * i) % 16;
                s = [6, 10, 15, 21];
            }

            a = a.wrapping_add(F);
            a = a.wrapping_add(M[g]);
            a = a.wrapping_add(K[i]);
            a = a.rotate_left(s[i % 4]);
            a = a.wrapping_add(b);
            let temp = a;
            a = d;
            d = c;
            c = b;
            b = temp;
        }

        A = A.wrapping_add(a);
        B = B.wrapping_add(b);
        C = C.wrapping_add(c);
        D = D.wrapping_add(d);
    }

    let mut digest = String::with_capacity(32);

    for register in &[A, B, C, D] {
        for byte in &register.to_le_bytes() {
            digest.push_str(&format!("{:0>2x}", byte));
        }
    }

    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_test() {
        assert_eq!(
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            md5("".as_bytes()),
        );
        assert_eq!(
            "9e107d9d372bb6826bd81d3542a419d6".to_string(),
            md5("The quick brown fox jumps over the lazy dog".as_bytes()),
        );
        assert_eq!(
            "e4d909c290d0fb1ca068ffaddf22cbd0".to_string(),
            md5("The quick brown fox jumps over the lazy dog.".as_bytes()),
        );
    }
}
