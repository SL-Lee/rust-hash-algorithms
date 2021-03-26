use std::convert::TryInto;

use crate::{keccak::keccak, FixedLengthHasher};

pub struct SHA3_512 {
    data: Vec<u8>,
}

impl FixedLengthHasher<64> for SHA3_512 {
    fn new() -> SHA3_512 {
        SHA3_512 {
            data: Vec::<u8>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    fn digest(&self) -> [u8; 64] {
        keccak(576, 1024, &self.data, 0x06, 64)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_512_test() {
        let mut hasher = SHA3_512::new();

        assert_eq!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615\
            b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23\
            f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"
                .to_string(),
            hasher.hexdigest(),
        );

        hasher.update(b".");

        assert_eq!(
            "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597b\
            c9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8"
                .to_string(),
            hasher.hexdigest(),
        );
    }
}
