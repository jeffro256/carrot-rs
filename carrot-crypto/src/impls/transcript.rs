use core::mem::size_of;
use curve25519_dalek::{MontgomeryPoint, Scalar, edwards::CompressedEdwardsY};
use generic_array::{ArrayLength, GenericArray};
use typenum::{Const, ToUInt, U32};

use crate::as_crypto::{AsEdwardsPoint, AsMontgomeryPoint, AsScalar};
use crate::transcript::*;

macro_rules! impl_transcript_uint {
    ($t:ident) => {
        impl ToTranscriptBytes for $t {
            type Len = <Const<{ size_of::<$t>() }> as ToUInt>::Output;
            fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
                self.to_le_bytes().into()
            }
        }
    };
}

impl_transcript_uint! {u8}
impl_transcript_uint! {u16}
impl_transcript_uint! {u32}
impl_transcript_uint! {u64}

impl<const N: usize> ToTranscriptBytes for [u8; N]
where
    Const<N>: ToUInt,
    <Const<N> as ToUInt>::Output: ArrayLength<u8>,
    GenericArray<u8, <Const<N> as ToUInt>::Output>: From<[u8; N]>,
{
    type Len = <Const<N> as ToUInt>::Output;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.clone().into()
    }
}

#[cfg(test)]
impl<const N: usize> FromTranscriptBytes for [u8; N]
where
    Const<N>: ToUInt,
    <Const<N> as ToUInt>::Output: ArrayLength<u8>,
    GenericArray<u8, <Const<N> as ToUInt>::Output>: From<[u8; N]>,
    [u8; N]: From<GenericArray<u8, <Const<N> as ToUInt>::Output>>,
{
    fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self> {
        Some(bytes.into())
    }
}

impl ToTranscriptBytes for Scalar {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}

#[cfg(test)]
impl FromTranscriptBytes for Scalar {
    fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self> {
        Self::from_canonical_bytes(bytes.into()).into_option()
    }
}

impl ToTranscriptBytes for CompressedEdwardsY {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}

#[cfg(test)]
impl FromTranscriptBytes for CompressedEdwardsY {
    fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self> {
        Some(CompressedEdwardsY(bytes.into()))
    }
}

impl ToTranscriptBytes for MontgomeryPoint {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}

#[cfg(test)]
impl FromTranscriptBytes for MontgomeryPoint {
    fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self> {
        Some(MontgomeryPoint(bytes.into()))
    }
}
