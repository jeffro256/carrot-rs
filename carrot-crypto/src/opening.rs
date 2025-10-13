use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use zeroize::ZeroizeOnDrop;

use crate::as_crypto::{AsEdwardsPoint, AsScalar};
use crate::math_utils::{add_edwards, scalar_mul_gt};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OpeningScalarSecret(Scalar);

impl AsScalar for OpeningScalarSecret {
    fn as_scalar_ref(&self) -> &Scalar {
        &self.0
    }
}

impl OpeningScalarSecret {
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(bytes))
    }
}

pub struct OpenedPoint(CompressedEdwardsY);

impl OpenedPoint {
    pub fn scalar_mul_gt(x: &OpeningScalarSecret, y: &OpeningScalarSecret) -> Self {
        Self(scalar_mul_gt(x, y))
    }
}

impl AsEdwardsPoint for OpenedPoint {
    fn as_edwards_ref(&self) -> &CompressedEdwardsY {
        &self.0
    }
}

macro_rules! impl_opening_add {
    (ncomm ; $lhs:path, $rhs:path) => {
        impl core::ops::Add<$rhs> for $lhs {
            type Output = OpeningScalarSecret;
            fn add(self, rhs: $rhs) -> Self::Output {
                OpeningScalarSecret(self.as_scalar_ref() + rhs.as_scalar_ref())
            }
        }
        impl core::ops::Add<&$rhs> for &$lhs {
            type Output = OpeningScalarSecret;
            fn add(self, rhs: &$rhs) -> Self::Output {
                OpeningScalarSecret(self.as_scalar_ref() + rhs.as_scalar_ref())
            }
        }
    };
    ($lhs:path, $rhs:path) => {
        impl_opening_add!{ncomm; $lhs, $rhs}
        impl_opening_add!{ncomm; $rhs, $lhs}
    };
    ($bhs:path) => {
        impl_opening_add!{ncomm; $bhs, $bhs}
    };
}

macro_rules! impl_opening_mul {
    (ncomm ; $lhs:path, $rhs:path) => {
        impl core::ops::Mul<$rhs> for $lhs {
            type Output = OpeningScalarSecret;
            fn mul(self, rhs: $rhs) -> Self::Output {
                OpeningScalarSecret(self.as_scalar_ref() * rhs.as_scalar_ref())
            }
        }
        impl core::ops::Mul<&$rhs> for &$lhs {
            type Output = OpeningScalarSecret;
            fn mul(self, rhs: &$rhs) -> Self::Output {
                OpeningScalarSecret(self.as_scalar_ref() * rhs.as_scalar_ref())
            }
        }
    };
    ($lhs:path, $rhs:path) => {
        impl_opening_mul!{ncomm; $lhs, $rhs}
        impl_opening_mul!{ncomm; $rhs, $lhs}
    };
    ($bhs:path) => {
        impl_opening_mul!{ncomm; $bhs, $bhs}
    };
}

macro_rules! impl_opened_point_add {
    (ncomm ; $lhs:path, $rhs:path) => {
        impl core::ops::Add<$rhs> for $lhs {
            type Output = OpenedPoint;
            fn add(self, rhs: $rhs) -> Self::Output {
                OpenedPoint(add_edwards(self.as_edwards_ref(), rhs.as_edwards_ref()).unwrap())
            }
        }
        impl core::ops::Add<&$rhs> for &$lhs {
            type Output = OpenedPoint;
            fn add(self, rhs: &$rhs) -> Self::Output {
                OpenedPoint(add_edwards(self.as_edwards_ref(), rhs.as_edwards_ref()).unwrap())
            }
        }
    };
    ($lhs:path, $rhs:path) => {
        impl_opened_point_add!{ncomm; $lhs, $rhs}
        impl_opened_point_add!{ncomm; $rhs, $lhs}
    };
    ($bhs:path) => {
        impl_opened_point_add!{ncomm; $bhs, $bhs}
    };
}

macro_rules! impl_from_point {
    ($ptty:path) => {
        impl From<OpenedPoint> for $ptty {
            fn from(value: OpenedPoint) -> Self {
                <$ptty>::from_bytes(value.0.0)
            }
        }
    };
}

impl_opening_add!{crate::ProveSpendKey, OpeningScalarSecret}
impl_opening_add!{crate::OnetimeExtensionG, OpeningScalarSecret}
impl_opening_add!{crate::OnetimeExtensionT, OpeningScalarSecret}

impl_opening_mul!{crate::ProveSpendKey, crate::SubaddressScalarSecret}
impl_opening_mul!{crate::GenerateImageKey, crate::SubaddressScalarSecret}

impl_opened_point_add!{crate::AddressSpendPubkey, OpenedPoint}

impl_from_point!{crate::AddressSpendPubkey}
impl_from_point!{crate::OutputPubkey}
