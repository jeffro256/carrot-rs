use generic_array::{ArrayLength, GenericArray};

pub trait ToTranscriptBytes {
    type Len: ArrayLength<u8>;
    fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len>;
}

#[cfg(test)]
pub trait FromTranscriptBytes: ToTranscriptBytes + Sized {
    fn from_transcript_bytes(bytes: GenericArray<u8, Self::Len>) -> Option<Self>;
}

macro_rules! calculate_carrot_transcript_len_types_only {
    () => { typenum::U0 };
    ($trans_type:path) => { <$trans_type as ToTranscriptBytes>::Len };
    ($trans_type:path, $($trans_types:path),+) => {
        typenum::Sum<
            calculate_carrot_transcript_len_types_only!($trans_type),
            calculate_carrot_transcript_len_types_only!($($trans_types),+)
        >
    };
}

macro_rules! calculate_carrot_transcript_len {
    ($domain_sep:path, $($trans_types:path),*) => {
        1usize
            + $domain_sep.len()
            + <calculate_carrot_transcript_len_types_only!($($trans_types),*) as typenum::Unsigned>::USIZE
    };
}

macro_rules! make_carrot_transcript {
    ($domain_sep:path, $($trans_type:path : $es:expr),*) => {
        {
            assert!($domain_sep.len() < 256);
            assert!($domain_sep.is_ascii());
            const TRANSCRIPT_LEN: usize = calculate_carrot_transcript_len!($domain_sep, $($trans_type),*);
            let mut transcript = [0u8; TRANSCRIPT_LEN];
            transcript[0] = ($domain_sep.len()) as u8;
            transcript[1..($domain_sep.len()+1)].copy_from_slice($domain_sep.as_bytes());
            {
                #![allow(unused_mut)]
                let mut transcript_idx = 1 + $domain_sep.len();
                $(
                    let es_bytes = ($es as &$trans_type).to_transcript_bytes();
                    let es_slice = es_bytes.as_slice();
                    transcript[transcript_idx..(transcript_idx+es_slice.len())].copy_from_slice(es_slice);
                    transcript_idx += es_slice.len();
                )*
                assert_eq!(transcript_idx, TRANSCRIPT_LEN);
            }
            transcript
        }
    };
}

pub(crate) use calculate_carrot_transcript_len;
pub(crate) use calculate_carrot_transcript_len_types_only;
pub(crate) use make_carrot_transcript;
