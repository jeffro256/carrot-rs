use core::mem::size_of;
use curve25519_dalek::{edwards::CompressedEdwardsY, MontgomeryPoint, Scalar};
use generic_array::{ArrayLength, GenericArray};
use typenum::{Const, ToUInt, U32};

use crate::transcript::ToTranscriptBytes;

macro_rules! impl_transcript_uint {
    ($t:ident) => {
        impl ToTranscriptBytes for $t {
            type Len = <Const<{size_of::<$t>()}> as ToUInt>::Output;
            fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
                self.to_le_bytes().into()
            }
        }
    };
}

impl_transcript_uint!{u8}
impl_transcript_uint!{u16}
impl_transcript_uint!{u32}
impl_transcript_uint!{u64}

impl<const N: usize> ToTranscriptBytes for [u8; N]
    where
        Const<N>: ToUInt,
        <Const<N> as ToUInt>::Output: ArrayLength<u8>,
        GenericArray<u8, <Const<N> as ToUInt>::Output>: From<[u8; N]>
{
    type Len = <Const<N> as ToUInt>::Output; 
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.clone().into()
    }
}

impl ToTranscriptBytes for Scalar {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}

impl ToTranscriptBytes for CompressedEdwardsY {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}

impl ToTranscriptBytes for MontgomeryPoint {
    type Len = U32;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
        self.to_bytes().into()
    }
}
