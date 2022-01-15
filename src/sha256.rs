use std::convert::TryInto;

use crate::FixedLengthHasher;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct SHA256 {
    data: Vec<u8>,
}

impl FixedLengthHasher<32> for SHA256 {
    fn new() -> SHA256 {
        SHA256 { data: Vec::<u8>::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    #[allow(non_snake_case, clippy::many_single_char_names)]
    fn digest(&self) -> [u8; 32] {
        let mut data = self.data.to_vec();
        let data_len = (data.len() as u64).wrapping_mul(8).to_be_bytes();
        data.push(0x80);

        // Pad data until it is 8 bytes (64 bits) less than a multiple of
        // 64 bytes (512 bits)
        while (data.len() + 8) % 64 != 0 {
            data.push(0);
        }

        data.extend(&data_len);
        let chunks = data.chunks_exact(64).collect::<Vec<&[u8]>>();
        let mut h0: u32 = 0x6a09e667;
        let mut h1: u32 = 0xbb67ae85;
        let mut h2: u32 = 0x3c6ef372;
        let mut h3: u32 = 0xa54ff53a;
        let mut h4: u32 = 0x510e527f;
        let mut h5: u32 = 0x9b05688c;
        let mut h6: u32 = 0x1f83d9ab;
        let mut h7: u32 = 0x5be0cd19;

        for chunk in chunks {
            let mut w = chunk
                .chunks_exact(4)
                .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
                .collect::<Vec<u32>>();

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ w[i - 15] >> 3;
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ w[i - 2] >> 10;
                w.push(w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1));
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                (h0, h1, h2, h3, h4, h5, h6, h7);

            for i in 0..64 {
                let S1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let temp1 =
                    h.wrapping_add(S1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = S0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            h5 = h5.wrapping_add(f);
            h6 = h6.wrapping_add(g);
            h7 = h7.wrapping_add(h);
        }

        [h0, h1, h2, h3, h4, h5, h6, h7]
            .iter()
            .flat_map(|register| register.to_be_bytes().to_vec())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_test() {
        let mut hasher = SHA256::new();

        assert_eq!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c".to_string(),
            hasher.hexdigest(),
        );
    }
}
