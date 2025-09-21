use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, MontgomeryPoint, Scalar};
use group::Group;

use crate::random::Random;

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
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
        EdwardsPoint::random(rng).compress()
    }
}

impl Random for EdwardsPoint
{
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
        EdwardsPoint::random(rng)
    }
}

impl Random for MontgomeryPoint {
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, _: Self::Params) -> Self {
        MontgomeryPoint(<[u8; 32]>::new_random_with_params(rng, ()))
    }
}

impl Random for Scalar
{
    type Params = ();
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
        Scalar::random(rng)
    }
}
