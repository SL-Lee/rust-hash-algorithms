use std::convert::TryInto;

use crate::FixedLengthHasher;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub struct SHA512 {
    data: Vec<u8>,
}

impl FixedLengthHasher<64> for SHA512 {
    fn new() -> SHA512 {
        SHA512 { data: Vec::<u8>::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    #[allow(non_snake_case, clippy::many_single_char_names)]
    fn digest(&self) -> [u8; 64] {
        let mut data = self.data.to_vec();
        let data_len = (data.len() as u128).wrapping_mul(8).to_be_bytes();
        data.push(0x80);

        // Pad data until it is 16 bytes (128 bits) less than a multiple of
        // 128 bytes (1024 bits)
        while (data.len() + 16) % 128 != 0 {
            data.push(0);
        }

        data.extend(&data_len);
        let chunks = data.chunks_exact(128).collect::<Vec<&[u8]>>();
        let mut h0: u64 = 0x6a09e667f3bcc908;
        let mut h1: u64 = 0xbb67ae8584caa73b;
        let mut h2: u64 = 0x3c6ef372fe94f82b;
        let mut h3: u64 = 0xa54ff53a5f1d36f1;
        let mut h4: u64 = 0x510e527fade682d1;
        let mut h5: u64 = 0x9b05688c2b3e6c1f;
        let mut h6: u64 = 0x1f83d9abfb41bd6b;
        let mut h7: u64 = 0x5be0cd19137e2179;

        for chunk in chunks {
            let mut w = chunk
                .chunks_exact(8)
                .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
                .collect::<Vec<u64>>();

            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ w[i - 15] >> 7;
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ w[i - 2] >> 6;
                w.push(w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1));
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                (h0, h1, h2, h3, h4, h5, h6, h7);

            for i in 0..80 {
                let S1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ (!e & g);
                let temp1 =
                    h.wrapping_add(S1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let S0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
    fn sha512_test() {
        let mut hasher = SHA512::new();

        assert_eq!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318\
            d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d\
            1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8f\
            d4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed".to_string(),
            hasher.hexdigest(),
        );
    }
}
