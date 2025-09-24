use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};

pub fn scalar_mul_gt(x: &Scalar, y: &Scalar) -> CompressedEdwardsY {
    (curve25519_dalek::EdwardsPoint::mul_base(x) + y * *monero_generators::T).compress()
}
