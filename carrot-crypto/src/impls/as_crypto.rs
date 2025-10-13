use curve25519_dalek::{MontgomeryPoint, Scalar, edwards::CompressedEdwardsY};

use crate::as_crypto::*;

impl AsEdwardsPoint for CompressedEdwardsY {
    fn as_edwards_ref(&self) -> &CompressedEdwardsY {
        self
    }
}

impl AsMontgomeryPoint for MontgomeryPoint {
    fn as_montgomery_ref(&self) -> &MontgomeryPoint {
        self
    }
}

impl AsScalar for Scalar {
    fn as_scalar_ref(&self) -> &Scalar {
        self
    }
}
