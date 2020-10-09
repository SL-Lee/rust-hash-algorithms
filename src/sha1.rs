use std::convert::TryInto;

pub fn sha1(message: &[u8]) -> String {
    let mut message = message.to_vec();
    let message_len = (message.len() as u64).wrapping_mul(8).to_be_bytes();
    message.push(0x80);

    // Pad message until it is 8 bytes (64 bits) less than a multiple of
    // 64 bytes (512 bits)
    while (message.len() + 8) % 64 != 0 {
        message.push(0);
    }

    message.extend(&message_len);
    let chunks = message.chunks_exact(64).collect::<Vec<&[u8]>>();
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    for chunk in chunks {
        let mut w = (0..16)
            .map(|i| {
                u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap())
            })
            .collect::<Vec<u32>>();

        for i in 16..80 {
            w.push(
                (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1),
            );
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k): (u32, u32);

            if i < 20 {
                f = (b & c) | (!b & d);
                k = 0x5a827999;
            } else if i >= 20 && i < 40 {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if i >= 40 && i < 60 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }

            e = e.wrapping_add(f);
            e = e.wrapping_add(a.rotate_left(5));
            e = e.wrapping_add(w[i]);
            e = e.wrapping_add(k);
            let temp = e;
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    [h0, h1, h2, h3, h4]
        .iter()
        .map(|word| format!("{:0>8x}", word))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_test() {
        assert_eq!(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha1("".as_bytes()),
        );
        assert_eq!(
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_string(),
            sha1("The quick brown fox jumps over the lazy dog".as_bytes()),
        );
        assert_eq!(
            "408d94384216f890ff7a0c3528e8bed1e0b01621".to_string(),
            sha1("The quick brown fox jumps over the lazy dog.".as_bytes()),
        );
    }
}
