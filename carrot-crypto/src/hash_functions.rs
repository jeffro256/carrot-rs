use blake2::{digest, Blake2bVarCore};
use curve25519_dalek::Scalar;
use digest::core_api::{OutputSizeUser, TruncSide, UpdateCore, VariableOutputCore};
use typenum::Unsigned;

pub fn hash_base(data: &[u8], key: &[u8], out: &mut [u8]) {
    assert!(key.len() <= 64);
    assert!(out.len() <= <<Blake2bVarCore as OutputSizeUser>::OutputSize as Unsigned>::USIZE);
    const TRUNCS_LEFT: bool = match Blake2bVarCore::TRUNC_SIDE {
        TruncSide::Left => true,
        _ => false
    };
    assert!(TRUNCS_LEFT);

    let mut hasher = Blake2bVarCore::new_with_params(&[], &[], key.len(),
        out.len());

    let mut buffer = digest::core_api::Buffer::<Blake2bVarCore>::default();
    if !key.is_empty() {
        buffer.digest_blocks(key, |blocks| hasher.update_blocks(blocks));
        hasher.update_blocks(core::slice::from_ref(&buffer.pad_with_zeros()));
    }
    
    buffer.digest_blocks(data, |blocks| hasher.update_blocks(blocks));

    let mut full_out = Default::default(); 
    hasher.finalize_variable_core(&mut buffer, &mut full_out);
    out.copy_from_slice(&full_out[..(out.len())]);
}

macro_rules! define_hash_bytes_x {
    ($f:ident, $outlen:expr) => {
        pub fn $f(data: &[u8], key: &[u8]) -> [u8; $outlen] {
            let mut res = [0u8; $outlen];
            hash_base(data, key, &mut res);
            res
        }
    };
}

define_hash_bytes_x!{derive_bytes_3, 3}
define_hash_bytes_x!{derive_bytes_8, 8}
define_hash_bytes_x!{derive_bytes_16, 16}
define_hash_bytes_x!{derive_bytes_32, 32}
define_hash_bytes_x!{derive_bytes_64, 64}

pub fn derive_scalar(data: &[u8], key: &[u8]) -> Scalar
{
    let unreduced64_scalar = derive_bytes_64(data, key);
    Scalar::from_bytes_mod_order_wide(&unreduced64_scalar)
}
