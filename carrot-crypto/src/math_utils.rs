use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, MontgomeryPoint, Scalar};
use group::GroupEncoding;

pub fn commit<S>(amount: S, amount_blinding_factor: &Scalar) -> CompressedEdwardsY
    where S: Into<Scalar>
{
    // z G + a H
    (EdwardsPoint::mul_base(amount_blinding_factor) + amount.into() * *monero_generators::H).compress()
}

pub fn zero_commit<S>(amount: S) -> CompressedEdwardsY
    where S: Into<Scalar>
{
    // G + a H
    (curve25519_dalek::constants::ED25519_BASEPOINT_POINT + amount.into() * *monero_generators::H).compress()
}

pub fn scalar_mul_gt(x: &Scalar, y: &Scalar) -> EdwardsPoint {
    // x G + y T
    EdwardsPoint::mul_base(x) + y * *monero_generators::T
}

#[allow(non_snake_case)]
pub fn convert_to_montgomery_vartime(P: &CompressedEdwardsY) -> Option<MontgomeryPoint> {
    // ConvertPointE(P)
    EdwardsPoint::from_bytes(&P.0).into_option().map(|x|x.to_montgomery())
}

#[allow(non_snake_case)]
pub fn scalar_mul_key_vartime(a: &Scalar, P: &CompressedEdwardsY) -> Option<CompressedEdwardsY> {
    // a P
    EdwardsPoint::from_bytes(&P.0).into_option().map(|x| (a * x).compress())
}

#[allow(non_snake_case)]
pub fn is_invalid_or_has_torsion(P: &CompressedEdwardsY) -> bool {
    let Some(P_decompressed) = EdwardsPoint::from_bytes(&P.0).into_option() else {
        return true;
    };
    !P_decompressed.is_torsion_free()
}