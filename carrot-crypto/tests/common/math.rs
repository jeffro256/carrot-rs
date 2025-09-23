use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};

pub fn scalar_mul_gt(x: &Scalar, y: &Scalar) -> CompressedEdwardsY {
    (curve25519_dalek::EdwardsPoint::mul_base(x) + y * *monero_generators::T).compress()
}
