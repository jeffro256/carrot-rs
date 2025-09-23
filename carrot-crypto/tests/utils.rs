use carrot_crypto::random::{new_random, Random};

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
