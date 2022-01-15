use std::convert::TryInto;

use crate::{keccak::keccak, FixedLengthHasher};

pub struct SHA3_384 {
    data: Vec<u8>,
}

impl FixedLengthHasher<48> for SHA3_384 {
    fn new() -> SHA3_384 {
        SHA3_384 { data: Vec::<u8>::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    fn digest(&self) -> [u8; 48] {
        keccak(832, 768, &self.data, 0x06, 48).unwrap().try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_384_test() {
        let mut hasher = SHA3_384::new();

        assert_eq!(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1\
            e058d5f004".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a\
            9ebdf8be41".to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5\
            b965437fb9".to_string(),
            hasher.hexdigest(),
        );
    }
}
