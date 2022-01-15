mod md5;
mod sha1;
// SHA-2
mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512_224;
mod sha512_256;
mod sha512_t_iv_generator;
// SHA-3
mod keccak;
mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
mod shake128;
mod shake256;

pub use md5::MD5;
pub use sha1::SHA1;
// SHA-2
pub use sha224::SHA224;
pub use sha256::SHA256;
pub use sha384::SHA384;
pub use sha512::SHA512;
pub use sha512_224::SHA512_224;
pub use sha512_256::SHA512_256;
// SHA-3
pub use sha3_224::SHA3_224;
pub use sha3_256::SHA3_256;
pub use sha3_384::SHA3_384;
pub use sha3_512::SHA3_512;
pub use shake128::SHAKE128;
pub use shake256::SHAKE256;

pub trait FixedLengthHasher<const DIGEST_BYTE_LENGTH: usize> {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn digest(&self) -> [u8; DIGEST_BYTE_LENGTH];

    fn hexdigest(&self) -> String {
        self.digest().iter().map(|byte| format!("{byte:0>2x}")).collect::<String>()
    }
}

pub trait VariableLengthHasher {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn digest(&self, length_in_bytes: usize) -> Vec<u8>;

    fn hexdigest(&self, length_in_bytes: usize) -> String {
        self.digest(length_in_bytes).iter().map(|byte| format!("{byte:0>2x}")).collect::<String>()
    }

    fn digest_const<const DIGEST_BYTE_LENGTH: usize>(&self) -> [u8; DIGEST_BYTE_LENGTH];

    fn hexdigest_const<const DIGEST_BYTE_LENGTH: usize>(&self) -> String {
        self.digest_const::<DIGEST_BYTE_LENGTH>()
            .iter()
            .map(|byte| format!("{byte:0>2x}"))
            .collect::<String>()
    }
}
