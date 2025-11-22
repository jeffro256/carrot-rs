pub trait Random {
    type Params;
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(
        rng: &mut R,
        p: Self::Params,
    ) -> Self;
}

pub fn new_random<R, T>(rng: &mut R) -> T
where
    R: rand_core::CryptoRngCore + ?Sized,
    T: Random<Params = ()>,
{
    T::new_random_with_params(rng, ())
}
