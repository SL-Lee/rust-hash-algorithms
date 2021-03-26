use std::convert::TryInto;

use crate::{keccak::keccak, VariableLengthHasher};

pub struct SHAKE128 {
    data: Vec<u8>,
}

impl VariableLengthHasher for SHAKE128 {
    fn new() -> SHAKE128 {
        SHAKE128 {
            data: Vec::<u8>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    fn digest(&self, length_in_bytes: usize) -> Vec<u8> {
        keccak(1344, 256, &self.data, 0x1f, length_in_bytes).unwrap()
    }

    fn digest_const<const DIGEST_BYTE_LENGTH: usize>(
        &self,
    ) -> [u8; DIGEST_BYTE_LENGTH] {
        keccak(1344, 256, &self.data, 0x1f, DIGEST_BYTE_LENGTH)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake128_test() {
        let mut hasher = SHAKE128::new();

        assert_eq!(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
                .to_string(),
            hasher.hexdigest_const::<32>(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e"
                .to_string(),
            hasher.hexdigest_const::<32>(),
        );

        hasher.update(b".");

        assert_eq!(
            "634069e6b13c3af64c57f05babf5911b6acf1d309b9624fc92b0c0bd9f27f538"
                .to_string(),
            hasher.hexdigest_const::<32>(),
        );
    }
}
