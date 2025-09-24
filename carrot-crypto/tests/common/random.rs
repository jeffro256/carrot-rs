use carrot_crypto::random::{new_random, Random};

use crate::common::{MAX_SUBADDRESS_MAJOR_INDEX, MAX_SUBADDRESS_MINOR_INDEX};

pub fn gen_random<R>() -> R
    where R: Random<Params = ()>
{
    new_random(&mut rand_core::OsRng)
}

pub fn gen_random_with_params<R>(p: R::Params) -> R
    where R: Random
{
    R::new_random_with_params(&mut rand_core::OsRng, p)
}

pub fn gen_subaddress_index_major() -> u32 {
    gen_random::<u32>() % (MAX_SUBADDRESS_MAJOR_INDEX + 1)
}

pub fn gen_subaddress_index_minor() -> u32 {
    gen_random::<u32>() % (MAX_SUBADDRESS_MINOR_INDEX + 1)
}
