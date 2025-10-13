pub use crate::as_crypto::{AsEdwardsPoint, AsMontgomeryPoint, AsScalar};
pub use crate::random::Random;
#[cfg(test)]
pub use crate::transcript::FromTranscriptBytes;
pub use crate::transcript::ToTranscriptBytes;

pub use curve25519_dalek::{MontgomeryPoint, Scalar, edwards::CompressedEdwardsY};
pub use generic_array::GenericArray;
pub use zeroize::Zeroize;

macro_rules! define_tiny_type {
    ($tiny:ident, $base:ty $(,$extra_derivs:ident)*) => {
        #[derive(Clone, Debug, Hash, PartialEq, Eq, Zeroize, $($extra_derivs),*)]
        pub struct $tiny($base);
        impl Random for $tiny {
            type Params = <$base as Random>::Params;
            fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
                $tiny(<$base>::new_random_with_params(rng, p))
            }
        }
        impl ToTranscriptBytes for $tiny {
            type Len = <$base as ToTranscriptBytes>::Len;
            fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
                self.0.to_transcript_bytes()
            }
        }
        #[cfg(test)]
        impl FromTranscriptBytes for $tiny {
            fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self> {
                Some($tiny(<$base>::from_transcript_bytes(bytes)?))
            }
        }
    };
}

macro_rules! define_tiny_edwards_type {
    ($tiny:ident) => {
        define_tiny_type! {$tiny, CompressedEdwardsY, Default}
        impl AsEdwardsPoint for $tiny {
            fn as_edwards_ref(&self) -> &CompressedEdwardsY {
                &self.0
            }
        }
        impl $tiny {
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(CompressedEdwardsY(bytes))
            }
        }
    };
}

macro_rules! define_tiny_montgomery_type {
    ($tiny:ident, $($extra_derivs:ident),*) => {
        define_tiny_type!{$tiny, MontgomeryPoint, Default $(,$extra_derivs)*}
        impl AsMontgomeryPoint for $tiny {
            fn as_montgomery_ref(&self) -> &MontgomeryPoint {
                &self.0
            }
        }
    };
}

macro_rules! define_tiny_scalar_type {
    ($tiny:ident) => {
        define_tiny_type! {$tiny, Scalar, Default, ZeroizeOnDrop}
        impl AsScalar for $tiny {
            fn as_scalar_ref(&self) -> &Scalar {
                &self.0
            }
        }
        impl From<u64> for $tiny {
            fn from(value: u64) -> Self {
                Self(Scalar::from(value))
            }
        }
        impl $tiny {
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
            pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
                Self(Scalar::from_bytes_mod_order(bytes))
            }
        }
    };
}

macro_rules! define_tiny_byte_type {
    ($tiny:ident, $size:expr $(,$extra_derivs:ident)*) => {
        define_tiny_type!{$tiny, [u8; $size] $(,$extra_derivs)*}
        impl Default for $tiny {
            fn default() -> Self {
                Self([0u8; $size])
            }
        }
        impl $tiny {
            pub(crate) fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
        impl From<[u8; $size]> for $tiny {
            fn from(value: [u8; $size]) -> Self {
                Self(value)
            }
        }
    };
}

pub(crate) use define_tiny_byte_type;
pub(crate) use define_tiny_edwards_type;
pub(crate) use define_tiny_montgomery_type;
pub(crate) use define_tiny_scalar_type;
pub(crate) use define_tiny_type;
