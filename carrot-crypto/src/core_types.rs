use core::ops::BitXor;
use curve25519_dalek::{edwards::CompressedEdwardsY, MontgomeryPoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::Random;
use crate::transcript::ToTranscriptBytes;

pub const JANUS_ANCHOR_BYTES: usize = 16;
pub const ENCRYPTED_AMOUNT_BYTES: usize = 8;
pub const PAYMENT_ID_BYTES: usize = 8;
pub const VIEW_TAG_BYTES: usize = 3;
pub const INPUT_CONTEXT_BYTES: usize = 1 + 32;

macro_rules! define_tiny_type {
    ($tiny:ident, $base:ty, $($extra_derivs:ident),*) => {
        #[derive(Clone, Debug, PartialEq, Eq, Zeroize, $($extra_derivs),*)]
        pub struct $tiny(pub $base);
        impl Random for $tiny {
            type Params = <$base as Random>::Params;
            fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
                $tiny(<$base>::new_random_with_params(rng, p))
            }
        }
        impl ToTranscriptBytes for $tiny {
            type Len = <$base as ToTranscriptBytes>::Len;
            fn to_transcript_bytes(&self) -> generic_array::GenericArray<u8, Self::Len> {
                self.0.to_transcript_bytes()
            }
        }
    };
}

define_tiny_type!{AddressSpendPubkey, CompressedEdwardsY, Default}
define_tiny_type!{AddressViewPubkey, CompressedEdwardsY, Default}
define_tiny_type!{OutputPubkey, CompressedEdwardsY, Default}
define_tiny_type!{AmountCommitment, CompressedEdwardsY, Default}
define_tiny_type!{KeyImageGenerator, CompressedEdwardsY, Default}
define_tiny_type!{KeyImage, CompressedEdwardsY, Default}
define_tiny_type!{EnoteEphemeralPubkey, MontgomeryPoint, Default}
define_tiny_type!{OnetimeExtension, CompressedEdwardsY, Default}

macro_rules! define_tiny_byte_type {
    ($tiny:ident, $size:expr, $($extra_derivs:ident),*) => {
        define_tiny_type!{$tiny, [u8; $size], $($extra_derivs),*}
    };
}

/// X25519 ECDH point secret
define_tiny_type!{MontgomeryECDH, MontgomeryPoint, ZeroizeOnDrop}

/// Field25519 scalar secret
define_tiny_type!{ScalarSecret, Scalar, Default, ZeroizeOnDrop}

/// Unbiased 32-byte secret
define_tiny_byte_type!{Uniform32Secret, 32, Default, ZeroizeOnDrop}

define_tiny_type!{ProveSpendKey, ScalarSecret, Default}
define_tiny_type!{ViewBalanceSecret, Uniform32Secret, Default}
define_tiny_type!{GenerateImageKey, ScalarSecret, Default}
define_tiny_type!{ViewIncomingKey, ScalarSecret, Default}
define_tiny_type!{GenerateAddressSecret, Uniform32Secret, Default}
define_tiny_type!{AddressIndexGeneratorSecret, Uniform32Secret, Default}
define_tiny_type!{SubaddressScalarSecret, ScalarSecret, Default}
define_tiny_type!{AmountBlindingKey, ScalarSecret, Default}
define_tiny_type!{EnoteEphemeralKey, ScalarSecret, Default}
define_tiny_type!{OnetimeExtensionG, ScalarSecret, Default}
define_tiny_type!{OnetimeExtensionT, ScalarSecret, Default}
define_tiny_type!{SenderReceiverSecret, Uniform32Secret, Default}

/// either encodes randomness the private key of, or an HMAC of, the ephemeral pubkey 
define_tiny_byte_type!{JanusAnchor, JANUS_ANCHOR_BYTES, Default}
/// carrot janus anchor XORd with a user-defined secret
define_tiny_byte_type!{EncryptedJanusAnchor, JANUS_ANCHOR_BYTES, Default}

/// carrot amount
pub type Amount = u64;
/// carrot encrypted amount
define_tiny_byte_type!{EncryptedAmount, ENCRYPTED_AMOUNT_BYTES, Default}

/// block index
pub type BlockIndex = u64;

/// legacy payment ID
define_tiny_byte_type!{PaymentId, PAYMENT_ID_BYTES, Default}
/// legacy encrypted payment ID
define_tiny_byte_type!{EncryptedPaymentId, PAYMENT_ID_BYTES, Default}

/// carrot view tags
define_tiny_byte_type!{ViewTag, VIEW_TAG_BYTES, Default}

/// carrot input context
define_tiny_byte_type!{InputContext, INPUT_CONTEXT_BYTES,}

/// carrot enote types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrotEnoteType {
    Payment,
    Change
}

pub const NULL_JANUS_ANCHOR: JanusAnchor = JanusAnchor([0u8; JANUS_ANCHOR_BYTES]);
pub const NULL_PAYMENT_ID: PaymentId = PaymentId([0u8; PAYMENT_ID_BYTES]);

////////////////////////////////////////////////////////////////////////////////

impl Default for InputContext {
    fn default() -> Self {
        InputContext([0u8; INPUT_CONTEXT_BYTES])
    }
}

////////////////////////////////////////////////////////////////////////////////

fn xor_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut c = a.clone();
    for i in 0..N {
        c[i] ^= b[i];
    }
    c
}

macro_rules! impl_tiny_byte_type_xor {
    ($t:ident, $enc_t:ident) => {
        impl BitXor<&$enc_t> for &$t {
            type Output = $enc_t;
            fn bitxor(self, rhs: &$enc_t) -> Self::Output {
                $enc_t(xor_bytes(&self.0, &rhs.0))
            }
        }
        impl BitXor<&$enc_t> for &$enc_t {
            type Output = $t;
            fn bitxor(self, rhs: &$enc_t) -> Self::Output {
                $t(xor_bytes(&self.0, &rhs.0))
            }
        }
    };
}

impl_tiny_byte_type_xor!{JanusAnchor, EncryptedJanusAnchor}
impl_tiny_byte_type_xor!{PaymentId, EncryptedPaymentId}

impl BitXor<&EncryptedAmount> for &Amount {
    type Output = EncryptedAmount;
    fn bitxor(self, rhs: &EncryptedAmount) -> Self::Output {
        EncryptedAmount(xor_bytes(&self.to_le_bytes(), &rhs.0))
    }
}

impl BitXor<&EncryptedAmount> for &EncryptedAmount {
    type Output = Amount;
    fn bitxor(self, rhs: &EncryptedAmount) -> Self::Output {
        Amount::from_le_bytes(xor_bytes(&self.0, &rhs.0))
    }
}
