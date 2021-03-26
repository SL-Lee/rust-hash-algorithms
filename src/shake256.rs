use std::convert::TryInto;

use crate::{keccak::keccak, VariableLengthHasher};

pub struct SHAKE256 {
    data: Vec<u8>,
}

impl VariableLengthHasher for SHAKE256 {
    fn new() -> SHAKE256 {
        SHAKE256 {
            data: Vec::<u8>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    fn digest(&self, length_in_bytes: usize) -> Vec<u8> {
        keccak(1088, 512, &self.data, 0x1f, length_in_bytes).unwrap()
    }

    fn digest_const<const DIGEST_BYTE_LENGTH: usize>(
        &self,
    ) -> [u8; DIGEST_BYTE_LENGTH] {
        keccak(1088, 512, &self.data, 0x1f, DIGEST_BYTE_LENGTH)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_test() {
        let mut hasher = SHAKE256::new();

        assert_eq!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd7\
            5dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
                .to_string(),
            hasher.hexdigest_const::<64>(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d\
            01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442"
                .to_string(),
            hasher.hexdigest_const::<64>(),
        );

        hasher.update(b".");

        assert_eq!(
            "bd225bfc8b255f3036f0c8866010ed0053b5163a3cae111e723c0c8e704eca4e5d\
            0f1e2a2fa18c8a219de6b88d5917ff5dd75b5fb345e7409a3b333b508a65fb"
                .to_string(),
            hasher.hexdigest_const::<64>(),
        );
    }
}
