use crate::keccak::keccak;
use std::convert::TryInto;

pub struct SHA3_256 {
    data: Vec<u8>,
}

impl SHA3_256 {
    pub fn new() -> SHA3_256 {
        SHA3_256 {
            data: Vec::<u8>::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    pub fn digest(&self) -> [u8; 32] {
        keccak(1088, 512, &self.data, 0x06, 32).unwrap()[..]
            .try_into()
            .unwrap()
    }

    pub fn hexdigest(&self) -> String {
        self.digest()
            .iter()
            .map(|byte| format!("{:0>2x}", byte))
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_test() {
        let mut hasher = SHA3_256::new();

        assert_eq!(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d"
                .to_string(),
            hasher.hexdigest(),
        )
    }
}
