use curve25519_dalek::MontgomeryPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use zeroize::ZeroizeOnDrop;

use crate::as_crypto::AsEdwardsPoint;
use crate::as_crypto::AsMontgomeryPoint;
use crate::as_crypto::AsScalar;
use crate::consts::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::random::Random;
use crate::transcript::*;
use crate::type_macros::*;
use crate::*;

define_tiny_edwards_type! {OutputPubkey, "ReRingCT transaction output pubkey / one-time address"}
define_tiny_edwards_type! {AmountCommitment, "ReRingCT transaction output amount commitment"}
define_tiny_edwards_type! {KeyImageGenerator, "ReRingCT key image generator, result of hash-to-point of an output pubkey"}
define_tiny_edwards_type! {KeyImage, "ReRingCT key image"}
define_tiny_edwards_type! {OnetimeExtension, "Difference between one-time address and address spend pubkey"}

define_tiny_montgomery_type! {MontgomeryECDH, "External sender-receiver uncontextualized ECDH exchange", ZeroizeOnDrop}
define_tiny_montgomery_type! {EnoteEphemeralPubkey, "Enote ephemeral pubkey",}

define_tiny_scalar_type! {AmountBlindingKey, "Blinding factor for an amount commitment"}
define_tiny_scalar_type! {EnoteEphemeralKey, "Private key for an enote ephemeral pubkey"}
define_tiny_scalar_type! {OnetimeExtensionG, "Opening for a one-time extension against the G generator"}
define_tiny_scalar_type! {OnetimeExtensionT, "Opening for a one-time extension against the T generator"}

define_tiny_byte_type! {SenderReceiverSecret, "Contextualized sender-receiver uniform byte secret", 32, ZeroizeOnDrop}

define_tiny_byte_type! {JanusAnchor,
    "Janus anchor holds normal enote ephemeral private key randomness or special HMAC of enote ephemeral pubkey",
    JANUS_ANCHOR_BYTES}
define_tiny_byte_type! {EncryptedJanusAnchor,
    "Enote janus anchor, encrypted", JANUS_ANCHOR_BYTES}

/// ReRingCT amount, 64-bit
pub type Amount = u64;
define_tiny_byte_type! {EncryptedAmount, "Encrypted amount", ENCRYPTED_AMOUNT_BYTES}

define_tiny_byte_type! {EncryptedPaymentId, "Encrypted payment ID", PAYMENT_ID_BYTES}

define_tiny_byte_type! {ViewTag, "Carrot view tag", VIEW_TAG_BYTES}

define_tiny_byte_type! {InputContext, "Carrot input context", INPUT_CONTEXT_BYTES}

/// Block index for coinbase enote input contexts
pub type BlockIndex = u64;

/// carrot enote types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrotEnoteType {
    Payment,
    Change,
}

impl EnoteEphemeralKey {
    pub fn derive(
        anchor_norm: &JanusAnchor,
        input_context: &InputContext,
        address_spend_pubkey: &AddressSpendPubkey,
        payment_id: &PaymentId,
    ) -> Self {
        // k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
        let transcript = make_carrot_transcript!(domain_separators::EPHEMERAL_PRIVKEY,
            JanusAnchor : anchor_norm, InputContext : input_context, AddressSpendPubkey : address_spend_pubkey,
            PaymentId : payment_id);
        EnoteEphemeralKey(derive_scalar(&transcript, &[]))
    }
}

impl EnoteEphemeralPubkey {
    pub fn derive_to_cryptonote_address(enote_ephemeral_privkey: &EnoteEphemeralKey) -> Self {
        // D_e = d_e B
        Self(scalar_mul_base_montgomery(enote_ephemeral_privkey))
    }

    pub fn derive_to_subaddress(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_spend_pubkey: &AddressSpendPubkey,
    ) -> Option<Self> {
        // D_e = ConvertPointE(d_e K^j_s)
        #[allow(non_snake_case)]
        let K_e: CompressedEdwardsY =
            scalar_mul_key(enote_ephemeral_privkey, address_spend_pubkey)?;
        Some(Self(convert_to_montgomery_vartime(&K_e)?))
    }

    pub fn derive_to(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_spend_pubkey: &AddressSpendPubkey,
        is_subaddress: bool,
    ) -> Option<Self> {
        if is_subaddress {
            // D_e = d_e ConvertPointE(K^j_s)
            Self::derive_to_subaddress(enote_ephemeral_privkey, address_spend_pubkey)
        } else {
            // D_e = d_e B
            Some(Self::derive_to_cryptonote_address(enote_ephemeral_privkey))
        }
    }
}

impl MontgomeryECDH {
    pub fn derive_as_receiver(
        k_view: &ViewIncomingKey,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    ) -> Self {
        // s_sr = k_v D_e
        Self(k_view.as_scalar_ref() * enote_ephemeral_pubkey.as_montgomery_ref())
    }

    pub fn derive_as_sender(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_view_pubkey: &AddressViewPubkey,
    ) -> Option<Self> {
        // if K^j_v not in prime order subgroup, then FAIL
        if is_invalid_or_has_torsion(address_view_pubkey) {
            return None;
        }

        // s_sr = d_e * ConvertPointE(K^j_v)
        Some(Self(
            enote_ephemeral_privkey.as_scalar_ref()
                * convert_to_montgomery_vartime(address_view_pubkey)?,
        ))
    }
}

impl InputContext {
    pub fn new_coinbase(block_index: BlockIndex) -> Self {
        // input_context = "C" || IntToBytes256(block_index)
        let mut input_context = [0u8; INPUT_CONTEXT_BYTES];
        input_context[0] = domain_separators::INPUT_CONTEXT_COINBASE;
        input_context[1..(1 + 8)].copy_from_slice(&block_index.to_le_bytes());
        Self::from(input_context)
    }

    pub fn new_ringct(first_rct_key_image: &KeyImage) -> Self {
        // input_context = "R" || KI_1
        let mut input_context = [0u8; INPUT_CONTEXT_BYTES];
        input_context[0] = domain_separators::INPUT_CONTEXT_RINGCT;
        input_context[1..].copy_from_slice(&first_rct_key_image.as_edwards_ref().0);
        Self::from(input_context)
    }
}

impl SenderReceiverSecret {
    pub fn derive(
        s_sender_receiver_unctx: &[u8; 32],
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
    ) -> Self {
        // s^ctx_sr = H_32(s_sr, D_e, input_context)
        let transcript = make_carrot_transcript!(domain_separators::SENDER_RECEIVER_SECRET,
            EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context);
        Self::from(derive_bytes_32(&transcript, s_sender_receiver_unctx))
    }
}

impl AmountBlindingKey {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        amount: Amount,
        address_spend_pubkey: &AddressSpendPubkey,
        enote_type: CarrotEnoteType,
    ) -> Self {
        let enote_type_u8: u8 = match enote_type {
            CarrotEnoteType::Payment => 0,
            CarrotEnoteType::Change => 1,
        };
        // k_a = H_n(s^ctx_sr, a, K^j_s, enote_type)
        let transcript = make_carrot_transcript!(domain_separators::AMOUNT_BLINDING_FACTOR,
            Amount: &amount, AddressSpendPubkey : address_spend_pubkey, u8 : &enote_type_u8);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl AmountCommitment {
    pub fn commit(amount: Amount, amount_blinding_factor: &AmountBlindingKey) -> Self {
        // z G + a H
        Self(
            (curve25519_dalek::EdwardsPoint::mul_base(amount_blinding_factor.as_scalar_ref())
                + curve25519_dalek::Scalar::from(amount) * *monero_generators::H)
                .compress(),
        )
    }

    pub fn clear_commit(amount: Amount) -> Self {
        // G + a H
        Self::commit(amount, &AmountBlindingKey::from(1u64))
    }
}

impl OnetimeExtensionG {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^o_g = H_n("..g..", s^ctx_sr, C_a)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_G,
            AmountCommitment : amount_commitment);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl OnetimeExtensionT {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^o_t = H_n("..t..", s^ctx_sr, C_a)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_T,
            AmountCommitment : amount_commitment);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl OnetimeExtension {
    pub fn derive_from_extension_scalars(
        onetime_ext_g: &OnetimeExtensionG,
        onetime_ext_t: &OnetimeExtensionT,
    ) -> Self {
        // K^o_ext = k^o_g G + k^o_t T
        Self(scalar_mul_gt(onetime_ext_g, onetime_ext_t))
    }

    pub fn derive_from_sender_receiver_secret(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^o_g = H_n("..g..", s^ctx_sr, C_a)
        let onetime_ext_g = OnetimeExtensionG::derive(s_sender_receiver, amount_commitment);

        // k^o_t = H_n("..t..", s^ctx_sr, C_a)
        let onetime_ext_t = OnetimeExtensionT::derive(s_sender_receiver, amount_commitment);

        // K^o_ext = k^o_g G + k^o_t T
        Self::derive_from_extension_scalars(&onetime_ext_g, &onetime_ext_t)
    }
}

impl OutputPubkey {
    pub fn derive_from_extension(
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_pubkey: OnetimeExtension,
    ) -> Option<Self> {
        // Ko = K^j_s + K^o_ext
        Some(Self(add_edwards(
            address_spend_pubkey,
            &sender_extension_pubkey,
        )?))
    }

    pub fn derive_from_sender_receiver_secret(
        address_spend_pubkey: &AddressSpendPubkey,
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Option<Self> {
        // K^o_ext = k^o_g G + k^o_t T
        let sender_extension_pubkey = OnetimeExtension::derive_from_sender_receiver_secret(
            s_sender_receiver,
            amount_commitment,
        );

        // Ko = K^j_s + K^o_ext
        Some(Self(add_edwards(
            address_spend_pubkey,
            &sender_extension_pubkey,
        )?))
    }
}

impl AddressSpendPubkey {
    pub fn recover_from_onetime_address(
        onetime_address: &OutputPubkey,
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Option<Self> {
        // K^o_ext = k^o_g G + k^o_t T
        let sender_extension_pubkey = OnetimeExtension::derive_from_sender_receiver_secret(
            s_sender_receiver,
            amount_commitment,
        );

        // K^j_s = Ko - K^o_ext
        Some(Self::from_inner(sub_edwards(
            onetime_address,
            &sender_extension_pubkey,
        )?))
    }
}

impl ViewTag {
    pub fn derive(
        s_sender_receiver_unctx: &[u8; 32],
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // vt = H_3(s_sr || input_context || Ko)
        let transcript = make_carrot_transcript!(domain_separators::VIEW_TAG,
            InputContext : input_context, OutputPubkey : onetime_address);
        Self::from(derive_bytes_3(&transcript, s_sender_receiver_unctx))
    }

    pub fn derive_and_test(
        &self,
        s_sender_receiver_unctx: &[u8; 32],
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> bool {
        // vt' = H_3(s_sr || input_context || Ko)
        let nominal_view_tag =
            Self::derive(s_sender_receiver_unctx, input_context, onetime_address);

        // vt' ?= vt
        &nominal_view_tag == self
    }
}

fn xor_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut c = a.clone();
    for i in 0..N {
        c[i] ^= b[i];
    }
    c
}

struct AnchorEncryptionMask([u8; JANUS_ANCHOR_BYTES]);
struct AmountEncryptionMask([u8; ENCRYPTED_AMOUNT_BYTES]);
struct PaymentIdEncryptionMask([u8; PAYMENT_ID_BYTES]);

impl AnchorEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_ANCHOR,
            OutputPubkey : onetime_address);
        Self(derive_bytes_16(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedJanusAnchor {
    pub fn encrypt(
        anchor: &JanusAnchor,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let mask = AnchorEncryptionMask::derive(s_sender_receiver, onetime_address);

        // anchor_enc = anchor XOR m_anchor
        Self::from(xor_bytes(anchor.as_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> JanusAnchor {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let mask = AnchorEncryptionMask::derive(s_sender_receiver, onetime_address);

        // anchor = anchor_enc XOR m_anchor
        JanusAnchor::from(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl AmountEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_a = H_8(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_AMOUNT,
            OutputPubkey : onetime_address);
        Self(derive_bytes_8(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedAmount {
    pub fn encrypt(
        amount: Amount,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_a = H_8(s^ctx_sr, Ko)
        let mask = AmountEncryptionMask::derive(s_sender_receiver, onetime_address);

        // a_enc = a XOR m_a  [paying attention to system endianness]
        Self::from(xor_bytes(&amount.to_le_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Amount {
        // m_a = H_8(s^ctx_sr, Ko)
        let mask = AmountEncryptionMask::derive(s_sender_receiver, onetime_address);

        // a = a_enc XOR m_a  [paying attention to system endianness]
        Amount::from_le_bytes(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl PaymentIdEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_pid = H_8(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_PAYMENT_ID,
            OutputPubkey : onetime_address);
        Self(derive_bytes_8(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedPaymentId {
    pub fn encrypt(
        payment_id: &PaymentId,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> EncryptedPaymentId {
        // m_pid = H_8(s^ctx_sr, Ko)
        let mask = PaymentIdEncryptionMask::derive(s_sender_receiver, onetime_address);

        // pid_enc = pid XOR m_pid
        Self::from(xor_bytes(payment_id.as_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> PaymentId {
        // m_pid = H_8(s^ctx_sr, Ko)
        let mask = PaymentIdEncryptionMask::derive(s_sender_receiver, onetime_address);

        // pid = pid_enc XOR m_pid
        PaymentId::from(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl JanusAnchor {
    pub fn new_randomness<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRngCore + ?Sized,
    {
        Self::new_random_with_params(rng, ())
    }

    pub fn derive_special(
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
        k_view: &ViewIncomingKey,
    ) -> Self {
        // anchor_sp = H_16(D_e, input_context, Ko, k_v)
        let transcript = make_carrot_transcript!(domain_separators::JANUS_ANCHOR_SPECIAL,
            EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context, OutputPubkey : onetime_address);
        Self::from(derive_bytes_16(
            &transcript,
            k_view.as_scalar_ref().as_bytes(),
        ))
    }
}

pub fn try_recompute_carrot_amount_commitment(
    s_sender_receiver: &SenderReceiverSecret,
    nominal_amount: Amount,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    nominal_enote_type: CarrotEnoteType,
    amount_commitment: &AmountCommitment,
) -> Option<AmountBlindingKey> {
    // k_a' = H_n(s^ctx_sr, a', K^j_s', enote_type')
    let amount_blinding_factor = AmountBlindingKey::derive(
        s_sender_receiver,
        nominal_amount,
        nominal_address_spend_pubkey,
        nominal_enote_type,
    );

    // C_a' = k_a' G + a' H
    let nominal_amount_commitment =
        AmountCommitment::commit(nominal_amount, &amount_blinding_factor);

    // C_a' ?= C_a
    if &nominal_amount_commitment == amount_commitment {
        Some(amount_blinding_factor)
    } else {
        None
    }
}

pub fn try_get_carrot_amount(
    s_sender_receiver: &SenderReceiverSecret,
    encrypted_amount: &EncryptedAmount,
    onetime_address: &OutputPubkey,
    address_spend_pubkey: &AddressSpendPubkey,
    amount_commitment: &AmountCommitment,
) -> Option<(Amount, AmountBlindingKey, CarrotEnoteType)> {
    // a' = a_enc XOR m_a
    let amount = encrypted_amount.decrypt(s_sender_receiver, onetime_address);

    // set enote_type <- "payment"
    let enote_type = CarrotEnoteType::Payment;

    // if C_a ?= k_a' G + a' H, then PASS
    if let Some(amount_blinding_factor) = try_recompute_carrot_amount_commitment(
        s_sender_receiver,
        amount,
        address_spend_pubkey,
        enote_type,
        amount_commitment,
    ) {
        return Some((amount, amount_blinding_factor, enote_type));
    }

    // set enote_type <- "change"
    let enote_type = CarrotEnoteType::Change;

    // if C_a ?= k_a' G + a' H, then PASS
    if let Some(amount_blinding_factor) = try_recompute_carrot_amount_commitment(
        s_sender_receiver,
        amount,
        address_spend_pubkey,
        enote_type,
        amount_commitment,
    ) {
        return Some((amount, amount_blinding_factor, enote_type));
    }

    // neither attempt at recomputing passed: so FAIL
    None
}

pub fn verify_carrot_normal_janus_protection(
    nominal_anchor: &JanusAnchor,
    input_context: &InputContext,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    is_subaddress: bool,
    nominal_payment_id: &PaymentId,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
) -> bool {
    // d_e' = H_n(anchor_norm, input_context, K^j_s, pid))
    let nominal_enote_ephemeral_privkey = EnoteEphemeralKey::derive(
        nominal_anchor,
        input_context,
        nominal_address_spend_pubkey,
        nominal_payment_id,
    );

    // recompute D_e' for d_e' and address type
    let Some(nominal_enote_ephemeral_pubkey) = EnoteEphemeralPubkey::derive_to(
        &nominal_enote_ephemeral_privkey,
        nominal_address_spend_pubkey,
        is_subaddress,
    ) else {
        return false;
    };

    // D_e' ?= D_e
    &nominal_enote_ephemeral_pubkey == enote_ephemeral_pubkey
}

#[cfg(test)]
mod test {
    use crate::enote_components::*;
    use crate::unit_testing::*;

    impl ToTranscriptBytes for AnchorEncryptionMask {
        type Len = typenum::U16;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    impl ToTranscriptBytes for AmountEncryptionMask {
        type Len = typenum::U8;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    impl ToTranscriptBytes for PaymentIdEncryptionMask {
        type Len = typenum::U8;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_privkey() {
        assert_eq_hex!(
            "6d4645a0e398ff430f68eaa78240dd2c04051e9a50438cd9c9c3c0e12af68b0b",
            EnoteEphemeralKey::derive(
                &hex_into!("caee1381775487a0982557f0d2680b55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                &hex_into!("4321734f56621440")
            )
        );
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_cryptonote() {
        assert_eq_hex!(
            "2987777565c02409dfe871cc27b2334f5ade9d4ad014012c568367b80e99c666",
            EnoteEphemeralPubkey::derive_to_cryptonote_address(&hex_into!(
                "f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_subaddress() {
        assert_eq_hex!(
            "d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55",
            EnoteEphemeralPubkey::derive_to_subaddress(
                &hex_into!("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d"),
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_receiver() {
        assert_eq_hex!(
            "baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451",
            MontgomeryECDH::derive_as_receiver(
                &hex_into!("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200"),
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55")
            )
        );
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_sender() {
        assert_eq_hex!(
            "baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451",
            MontgomeryECDH::derive_as_sender(
                &hex_into!("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d"),
                &hex_into!("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_sender_receiver_secret() {
        assert_eq_hex!(
            "232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c",
            SenderReceiverSecret::derive(
                &hex_into!("baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451"),
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_payment() {
        assert_eq_hex!(
            "9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02",
            AmountBlindingKey::derive(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                23000000000000,
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                CarrotEnoteType::Payment
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_change() {
        assert_eq_hex!(
            "dda34eac46030e4084f5a2c808d0a82ffaa82cbf01d4a74d7ee0d4fe72c31a0f",
            AmountBlindingKey::derive(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                23000000000000,
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                CarrotEnoteType::Change
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_commitment() {
        assert_eq_hex!(
            "ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b",
            AmountCommitment::commit(
                23000000000000,
                &hex_into!("9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02"),
            )
        );
    }

    #[test]
    fn converge_make_carrot_onetime_address() {
        assert_eq_hex!(
            "4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92",
            OutputPubkey::derive_from_sender_receiver_secret(
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b")
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_view_tag() {
        assert_eq_hex!(
            "0176f6",
            ViewTag::derive(
                &hex_into!("baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            )
        );
    }

    #[test]
    fn converge_make_carrot_anchor_encryption_mask() {
        assert_eq_hex!(
            "52d95a8e441f26a056f55094938cbfa8",
            AnchorEncryptionMask::derive(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_encryption_mask() {
        assert_eq_hex!(
            "98d25d1db65b6a3e",
            AmountEncryptionMask::derive(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            )
        );
    }

    #[test]
    fn converge_make_carrot_payment_id_encryption_mask() {
        assert_eq_hex!(
            "b57a1560e82e2483",
            PaymentIdEncryptionMask::derive(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            )
        );
    }

    #[test]
    fn converge_make_carrot_janus_anchor_special() {
        assert_eq_hex!(
            "31afa8f580feaf736cd424ecc9ae5fd2",
            JanusAnchor::derive_special(
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
                &hex_into!("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200")
            )
        );
    }
}
