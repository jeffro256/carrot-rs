use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, MontgomeryPoint, Scalar};
use std::io::Write;

use crate::core_types::*;

pub trait Transcriptable {
    fn write_transcript_bytes<W: Write>(&self, writer: W) -> std::io::Result<usize>;
}

macro_rules! impl_transcript_uint {
    ($t:ident) => {
        impl Transcriptable for $t {
            fn write_transcript_bytes<W: Write>(&self, mut writer: W) -> std::io::Result<usize> {
                writer.write(&self.to_le_bytes())
            }
        }
    };
}

impl_transcript_uint!{u8}
impl_transcript_uint!{u16}
impl_transcript_uint!{u32}
impl_transcript_uint!{u64}

impl<const N: usize> Transcriptable for [u8; N] {
    fn write_transcript_bytes<W: Write>(&self, mut writer: W) -> std::io::Result<usize> {
        writer.write(self)
    }
}

impl Transcriptable for &str {
    fn write_transcript_bytes<W: Write>(&self, mut writer: W) -> std::io::Result<usize> {
        writer.write(self.as_bytes())
    }
}

impl Transcriptable for Scalar {
    fn write_transcript_bytes<W: Write>(&self, mut writer: W) -> std::io::Result<usize> {
        writer.write(&self.to_bytes())
    }
}

impl Transcriptable for CompressedEdwardsY {
    fn write_transcript_bytes<W: Write>(&self, mut writer: W) -> std::io::Result<usize> {
        writer.write(&self.0)
    }
}

impl Transcriptable for EdwardsPoint {
    fn write_transcript_bytes<W: Write>(&self, writer: W) -> std::io::Result<usize> {
        self.compress().write_transcript_bytes(writer)
    }
}

impl Transcriptable for MontgomeryPoint {
    fn write_transcript_bytes<W: Write>(&self, writer: W) -> std::io::Result<usize> {
        self.to_bytes().write_transcript_bytes(writer)
    }
}

macro_rules! impl_transcript_tiny_type {
    ($t:ident) => {
        impl Transcriptable for $t {
            fn write_transcript_bytes<W: Write>(&self, writer: W) -> std::io::Result<usize> {
                self.0.write_transcript_bytes(writer)
            }
        }
    };
}

impl_transcript_tiny_type!{AddressSpendPubkey}
impl_transcript_tiny_type!{AddressViewPubkey}
impl_transcript_tiny_type!{OutputPubkey}
impl_transcript_tiny_type!{AmountCommitment}
impl_transcript_tiny_type!{KeyImage}
impl_transcript_tiny_type!{EnoteEphemeralPubkey}
impl_transcript_tiny_type!{MontgomeryECDH}
impl_transcript_tiny_type!{JanusAnchor}
impl_transcript_tiny_type!{PaymentId}
impl_transcript_tiny_type!{InputContext}

macro_rules! make_carrot_transcript {
    ( $domain_sep:expr, $($es:expr),* ) => {
        {
            assert!($domain_sep.len() < 256);
            assert!($domain_sep.is_ascii());
            let mut transcript_ = vec![($domain_sep.len() as u8)];
            let _ = $domain_sep.write_transcript_bytes(&mut transcript_);
            $(
                let _ = $es.write_transcript_bytes(&mut transcript_);
            )*
            transcript_
        }
    };
}

pub(crate) use make_carrot_transcript;
