use blake2::{digest::{FixedOutput, typenum, KeyInit, Update}, Blake2bMac};
use curve25519_dalek::Scalar;

macro_rules! define_hash_bytes_x {
    ($f:ident, $outlen:expr, $outlentype:ident) => {
        pub fn $f(data: &[u8], key: &[u8]) -> [u8; $outlen] {
            type OutSizeLen = typenum::consts::$outlentype;
            let mut hasher = <Blake2bMac<OutSizeLen> as KeyInit>::new_from_slice(key).unwrap();
            hasher.update(data);
            hasher.finalize_fixed().into()
        }
    };
}

define_hash_bytes_x!{derive_bytes_3, 3, U3}
define_hash_bytes_x!{derive_bytes_8, 8, U8}
define_hash_bytes_x!{derive_bytes_16, 16, U16}
define_hash_bytes_x!{derive_bytes_32, 32, U32}
define_hash_bytes_x!{derive_bytes_64, 64, U64}

pub fn derive_scalar(data: &[u8], key: &[u8]) -> Scalar
{
    let unreduced64_scalar = derive_bytes_64(key, data);
    Scalar::from_bytes_mod_order_wide(&unreduced64_scalar)
}
