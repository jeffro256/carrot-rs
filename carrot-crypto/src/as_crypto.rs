use curve25519_dalek::{MontgomeryPoint, Scalar, edwards::CompressedEdwardsY};

pub trait AsEdwardsPoint {
    fn as_edwards_ref(&self) -> &CompressedEdwardsY;
}

pub trait AsMontgomeryPoint {
    fn as_montgomery_ref(&self) -> &MontgomeryPoint;
}

pub trait AsScalar {
    fn as_scalar_ref(&self) -> &Scalar;
}
