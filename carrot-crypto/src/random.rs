pub trait Random {
    type Params;
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(
        rng: &mut R,
        p: Self::Params,
    ) -> Self;
}

pub fn new_random<T>(rng: &mut (impl rand_core::CryptoRngCore + ?Sized)) -> T
where
    T: Random<Params = ()>,
{
    T::new_random_with_params(rng, ())
}
