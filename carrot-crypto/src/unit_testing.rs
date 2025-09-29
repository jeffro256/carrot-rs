use generic_array::GenericArray;
pub use hex_literal::hex;

use crate::transcript::FromTranscriptBytes;

pub fn transcript_bytes_into<T: FromTranscriptBytes>(bytes: GenericArray<u8, T::Len>) -> T {
    T::from_transcript_bytes(bytes).expect("from_transcript_bytes()")
}

macro_rules! assert_eq_hex {
    ($($exphex:literal)*, $e:expr) => {
        assert_eq!(hex!($($exphex)*).as_slice(), ($e).to_transcript_bytes().as_slice());
    };
}

macro_rules! hex_into {
    ($($hex:literal)*) => {
        transcript_bytes_into(hex!($($hex)*).into())
    };
}

pub(crate) use assert_eq_hex;
pub(crate) use hex_into;
