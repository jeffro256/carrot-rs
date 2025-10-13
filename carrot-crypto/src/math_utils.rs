use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar, edwards::CompressedEdwardsY};
use group::GroupEncoding;

use crate::as_crypto::{AsEdwardsPoint, AsMontgomeryPoint, AsScalar};

pub fn scalar_mul_gt<S1, S2>(x: &S1, y: &S2) -> CompressedEdwardsY
where
    S1: AsScalar,
    S2: AsScalar,
{
    // x G + y T
    (EdwardsPoint::mul_base(x.as_scalar_ref()) + y.as_scalar_ref() * &*monero_generators::T)
        .compress()
}

#[allow(non_snake_case)]
pub fn convert_to_montgomery_vartime<E>(P: &E) -> Option<MontgomeryPoint>
where
    E: AsEdwardsPoint,
{
    // ConvertPointE(P)
    EdwardsPoint::from_bytes(&P.as_edwards_ref().0)
        .into_option()
        .map(|x| x.to_montgomery())
}

#[allow(non_snake_case)]
pub fn add_edwards<E1, E2>(A: &E1, B: &E2) -> Option<CompressedEdwardsY>
where
    E1: AsEdwardsPoint,
    E2: AsEdwardsPoint,
{
    // A + B
    let A = EdwardsPoint::from_bytes(&A.as_edwards_ref().0).into_option()?;
    let B = EdwardsPoint::from_bytes(&B.as_edwards_ref().0).into_option()?;
    Some((A + B).compress())
}

#[allow(non_snake_case)]
pub fn sub_edwards<E1, E2>(A: &E1, B: &E2) -> Option<CompressedEdwardsY>
where
    E1: AsEdwardsPoint,
    E2: AsEdwardsPoint,
{
    // A - B
    let A = EdwardsPoint::from_bytes(&A.as_edwards_ref().0).into_option()?;
    let B = EdwardsPoint::from_bytes(&B.as_edwards_ref().0).into_option()?;
    Some((A - B).compress())
}

pub fn scalar_mul_base_montgomery<S>(a: &S) -> MontgomeryPoint
where
    S: AsScalar,
{
    MontgomeryPoint::mul_base(a.as_scalar_ref())
}

pub fn scalar_mul_base<S>(a: &S) -> CompressedEdwardsY
where
    S: AsScalar,
{
    // a G
    EdwardsPoint::mul_base(a.as_scalar_ref()).compress()
}

#[allow(non_snake_case)]
pub fn scalar_mul_key<S, E1>(a: &S, P: &E1) -> Option<CompressedEdwardsY>
where
    S: AsScalar,
    E1: AsEdwardsPoint,
{
    // a P
    EdwardsPoint::from_bytes(&P.as_edwards_ref().0)
        .into_option()
        .map(|x| (a.as_scalar_ref() * x).compress())
}

#[allow(non_snake_case)]
pub fn is_invalid_or_has_torsion<E>(P: &E) -> bool
where
    E: AsEdwardsPoint,
{
    // @TODO: this doesn't capture all bad cases, see monero primitive io crate
    let Some(P_decompressed) = EdwardsPoint::from_bytes(&P.as_edwards_ref().0).into_option() else {
        return true;
    };
    !P_decompressed.is_torsion_free()
}
