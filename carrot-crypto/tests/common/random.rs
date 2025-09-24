use carrot_crypto::random::{Random, new_random};
use carrot_crypto::*;

use crate::common::keys::{SubaddressIndex, SubaddressIndexExtended};
use crate::common::{MAX_SUBADDRESS_MAJOR_INDEX, MAX_SUBADDRESS_MINOR_INDEX};

pub fn gen_random<R>() -> R
where
    R: Random<Params = ()>,
{
    new_random(&mut rand_core::OsRng)
}

pub fn gen_random_with_params<R>(p: R::Params) -> R
where
    R: Random,
{
    R::new_random_with_params(&mut rand_core::OsRng, p)
}

pub fn gen_subaddress_index_major() -> u32 {
    1 + gen_random::<u32>() % MAX_SUBADDRESS_MAJOR_INDEX
}

pub fn gen_subaddress_index_minor() -> u32 {
    1 + gen_random::<u32>() % MAX_SUBADDRESS_MINOR_INDEX
}

pub fn gen_subaddress_index() -> SubaddressIndexExtended {
    SubaddressIndexExtended {
        index: SubaddressIndex {
            major: gen_subaddress_index_major(),
            minor: gen_subaddress_index_minor(),
        },
        derive_type: None,
    }
}

pub fn gen_non_null_payment_id() -> PaymentId {
    loop {
        let res = gen_random();
        if res != NULL_PAYMENT_ID {
            return res;
        }
    }
}

pub fn gen_block_index() -> BlockIndex {
    1 + gen_random::<BlockIndex>() % 5000000
}
