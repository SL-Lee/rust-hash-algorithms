use crate::keccak::keccak;
use std::convert::TryInto;

pub struct SHA3_224 {
    data: Vec<u8>,
}

impl SHA3_224 {
    pub fn new() -> SHA3_224 {
        SHA3_224 {
            data: Vec::<u8>::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    pub fn digest(&self) -> [u8; 28] {
        keccak(1152, 448, &self.data, 0x06, 28).unwrap()[..]
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
    fn sha3_224_test() {
        let mut hasher = SHA3_224::new();

        assert_eq!(
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0"
                .to_string(),
            hasher.hexdigest(),
        );
    }
}
