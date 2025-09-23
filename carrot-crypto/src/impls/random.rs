use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, MontgomeryPoint, Scalar};

use crate::random::Random;

macro_rules! impl_random_uint {
    ($t:ident) => {
        impl Random for $t {
            type Params = ();
            fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
                const N_BYTES: usize = core::mem::size_of::<$t>();
                Self::from_le_bytes(<[u8; N_BYTES] as Random>::new_random_with_params(rng, ()))
            }
        }
    };
}

impl_random_uint!{u8}
impl_random_uint!{u16}
impl_random_uint!{u32}
impl_random_uint!{u64}

impl<const N: usize> Random for [u8; N] {
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        let mut v = [0u8; N];
        rng.fill_bytes(&mut v);
        v
    }
}

impl Random for CompressedEdwardsY
{
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        EdwardsPoint::new_random_with_params(rng, ()).compress()
    }
}

impl Random for EdwardsPoint
{
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        EdwardsPoint::mul_base(&Scalar::new_random_with_params(rng, ()))
    }
}

impl Random for MontgomeryPoint {
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        EdwardsPoint::new_random_with_params(rng, ()).to_montgomery()
    }
}

impl Random for Scalar
{
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        Scalar::random(rng)
    }
}
