use core::fmt::{Debug, Display};
use curve25519_dalek::Scalar;

use crate::core_types::*;
use crate::destination::*;
use crate::device;
use crate::device::ViewBalanceSecretDevice;
use crate::device::ViewIncomingKeyDevice;
use crate::enote::*;
use crate::enote_utils::*;
use crate::math_utils::commit;

////
// CarrotPaymentProposalV1
// - for creating an output proposal to send an amount to someone
///
pub struct CarrotPaymentProposalV1 {
    /// user address
    pub destination: CarrotDestinationV1,
    /// b
    pub amount: Amount,
    /// anchor_norm: secret 16-byte randomness for Janus anchor
    pub randomness: JanusAnchor,
}

////
// CarrotPaymentProposalSelfSendV1
// - for creating an output proposal to send an change to yourself
///
pub struct CarrotPaymentProposalSelfSendV1 {
    /// one of our own address spend pubkeys: K^j_s
    pub destination_address_spend_pubkey: AddressSpendPubkey,
    /// a
    pub amount: Amount,

    /// enote_type
    pub enote_type: CarrotEnoteType,
    /// enote ephemeral pubkey: D_e
    pub enote_ephemeral_pubkey: Option<EnoteEphemeralPubkey>,
    /// anchor: arbitrary, pre-encrypted message for _internal_ selfsends
    pub internal_message: Option<JanusAnchor>,
}

pub struct RCTOutputEnoteProposal {
    pub enote: CarrotEnoteV1,

    // we need this opening information to make amount range proofs
    pub amount: Amount,
    pub amount_blinding_factor: AmountBlindingKey,
}

#[derive(Debug)]
pub enum ErrorKind {
    BadAddressPoints,
    DeviceError,
    InvalidInternalMessage,
    MismatchedEnoteEphemeralPubkey,
    MissingEnoteEphemeralPubkey,
    MissingPaymentId,
    MissingRandomness,
    WrongAddressType,
    WrongOutputNumber,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

/// @TODO: real display
impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.kind, f)
    }
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

fn get_normal_proposal_ecdh_parts(
    proposal: &CarrotPaymentProposalV1,
    input_context: &InputContext,
) -> Result<(EnoteEphemeralPubkey, MontgomeryECDH)> {
    // 1. d_e = H_n(anchor_norm, input_context, K^j_s, pid))
    let enote_ephemeral_privkey = get_enote_ephemeral_privkey(proposal, input_context);

    // 2. make D_e
    let enote_ephemeral_pubkey = proposal.get_enote_ephemeral_pubkey(input_context)?;

    // 3. s_sr = d_e ConvertPointE(K^j_v)
    match make_carrot_uncontextualized_shared_key_sender(
        &enote_ephemeral_privkey,
        &proposal.destination.address_view_pubkey,
    ) {
        Some(s_sender_receiver_unctx) => Ok((enote_ephemeral_pubkey, s_sender_receiver_unctx)),
        None => Err(Error::new(ErrorKind::BadAddressPoints)),
    }
}

fn get_output_proposal_parts(
    s_sender_receiver: &SenderReceiverSecret,
    destination_spend_pubkey: &AddressSpendPubkey,
    payment_id: &PaymentId,
    amount: Amount,
    enote_type: CarrotEnoteType,
    coinbase_amount_commitment: bool,
) -> Result<(
    AmountBlindingKey,
    AmountCommitment,
    OutputPubkey,
    EncryptedAmount,
    EncryptedPaymentId,
)> {
    // 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
    let amount_blinding_factor = if coinbase_amount_commitment {
        AmountBlindingKey(ScalarSecret(Scalar::from(1u32)))
    } else {
        make_carrot_amount_blinding_factor(
            s_sender_receiver,
            amount,
            destination_spend_pubkey,
            enote_type,
        )
    };

    // 2. C_a = k_a G + a H
    let amount_commitment = AmountCommitment(commit(amount, &amount_blinding_factor.0.0));

    // 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
    let onetime_address = make_carrot_onetime_address(
        destination_spend_pubkey,
        s_sender_receiver,
        &amount_commitment,
    )
    .ok_or(Error::new(ErrorKind::BadAddressPoints))?;

    // 4. a_enc = a XOR m_a
    let encrypted_amount = encrypt_carrot_amount(amount, s_sender_receiver, &onetime_address);

    // 5. pid_enc = pid XOR m_pid
    let encrypted_payment_id =
        encrypt_legacy_payment_id(payment_id, s_sender_receiver, &onetime_address);

    Ok((
        amount_blinding_factor,
        amount_commitment,
        onetime_address,
        encrypted_amount,
        encrypted_payment_id,
    ))
}

fn get_external_output_proposal_parts(
    s_sender_receiver_unctx: &MontgomeryECDH,
    destination_spend_pubkey: &AddressSpendPubkey,
    payment_id: &PaymentId,
    amount: Amount,
    enote_type: CarrotEnoteType,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    input_context: &InputContext,
    coinbase_amount_commitment: bool,
) -> Result<(
    SenderReceiverSecret,
    AmountBlindingKey,
    AmountCommitment,
    OutputPubkey,
    EncryptedAmount,
    EncryptedPaymentId,
    ViewTag,
)> {
    // 1. s^ctx_sr = H_32(s_sr, D_e, input_context)
    let s_sender_receiver = make_carrot_sender_receiver_secret(
        s_sender_receiver_unctx.0.as_bytes(),
        enote_ephemeral_pubkey,
        input_context,
    );

    // 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
    let (
        amount_blinding_factor,
        amount_commitment,
        onetime_address,
        encrypted_amount,
        encrypted_payment_id,
    ) = get_output_proposal_parts(
        &s_sender_receiver,
        destination_spend_pubkey,
        payment_id,
        amount,
        enote_type,
        coinbase_amount_commitment,
    )?;

    // 3. vt = H_3(s_sr || input_context || Ko)
    let view_tag = make_carrot_view_tag(
        s_sender_receiver_unctx.0.as_bytes(),
        input_context,
        &onetime_address,
    );

    Ok((
        s_sender_receiver,
        amount_blinding_factor,
        amount_commitment,
        onetime_address,
        encrypted_amount,
        encrypted_payment_id,
        view_tag,
    ))
}

fn get_enote_ephemeral_privkey(
    proposal: &CarrotPaymentProposalV1,
    input_context: &InputContext,
) -> EnoteEphemeralKey {
    make_carrot_enote_ephemeral_privkey(
        &proposal.randomness,
        input_context,
        &proposal.destination.address_spend_pubkey,
        &proposal.destination.payment_id,
    )
}

fn try_resolve_selfsend_enote_ephemeral_pubkey<'a>(
    proposal: &'a CarrotPaymentProposalSelfSendV1,
    other_enote_ephemeral_pubkey: &'a Option<EnoteEphemeralPubkey>,
) -> Result<&'a EnoteEphemeralPubkey> {
    match &proposal.enote_ephemeral_pubkey {
        Some(a) => match other_enote_ephemeral_pubkey {
            Some(b) => {
                if a == b {
                    Ok(a)
                } else {
                    Err(Error::new(ErrorKind::MismatchedEnoteEphemeralPubkey))
                }
            }
            None => Ok(a),
        },
        None => match other_enote_ephemeral_pubkey {
            Some(b) => Ok(b),
            None => Err(Error::new(ErrorKind::MissingEnoteEphemeralPubkey)),
        },
    }
}

fn coerce_device_result<T>(result: device::Result<T>) -> Result<T> {
    match result {
        Ok(v) => Ok(v),
        Err(_) => Err(Error::new(ErrorKind::DeviceError)),
    }
}

impl CarrotPaymentProposalV1 {
    pub fn get_enote_ephemeral_pubkey(
        &self,
        input_context: &InputContext,
    ) -> Result<EnoteEphemeralPubkey> {
        // d_e = H_n(anchor_norm, input_context, K^j_s, pid))
        let enote_ephemeral_privkey = get_enote_ephemeral_privkey(self, input_context);

        if self.destination.is_subaddress {
            // D_e = d_e ConvertPointE(K^j_s)
            make_carrot_enote_ephemeral_pubkey_subaddress(
                &enote_ephemeral_privkey,
                &self.destination.address_spend_pubkey,
            )
            .ok_or(Error::new(ErrorKind::BadAddressPoints))
        } else {
            // D_e = d_e B
            Ok(make_carrot_enote_ephemeral_pubkey_cryptonote(
                &enote_ephemeral_privkey,
            ))
        }
    }

    pub fn get_coinbase_output_proposal(
        &self,
        block_index: BlockIndex,
    ) -> Result<CarrotCoinbaseEnoteV1> {
        // 1. sanity checks
        if self.randomness == NULL_JANUS_ANCHOR {
            return Err(Error::new(ErrorKind::MissingRandomness));
        } else if self.destination.is_subaddress || self.destination.payment_id != NULL_PAYMENT_ID {
            return Err(Error::new(ErrorKind::WrongAddressType));
        }

        // 2. coinbase input context
        let input_context = make_carrot_input_context_coinbase(block_index);

        // 3. make D_e and do external ECDH
        let (enote_ephemeral_pubkey, s_sender_receiver_unctx) =
            get_normal_proposal_ecdh_parts(self, &input_context)?;

        // 4. build the output enote address pieces
        let (s_sender_receiver, _, _, onetime_address, _, _, view_tag) =
            get_external_output_proposal_parts(
                &s_sender_receiver_unctx,
                &self.destination.address_spend_pubkey,
                &NULL_PAYMENT_ID,
                self.amount,
                CarrotEnoteType::Payment,
                &enote_ephemeral_pubkey,
                &input_context,
                true,
            )?;

        // 5. anchor_enc = anchor XOR m_anchor
        let anchor_enc =
            encrypt_carrot_anchor(&self.randomness, &s_sender_receiver, &onetime_address);

        // 6. save the amount and block index
        Ok(CarrotCoinbaseEnoteV1 {
            onetime_address: onetime_address,
            amount: self.amount,
            anchor_enc: anchor_enc,
            view_tag: view_tag,
            enote_ephemeral_pubkey: enote_ephemeral_pubkey,
            block_index: block_index,
        })
    }

    pub fn get_normal_output_proposal(
        &self,
        tx_first_key_image: KeyImage,
    ) -> Result<(RCTOutputEnoteProposal, EncryptedPaymentId)> {
        // 1. sanity checks
        if self.randomness == NULL_JANUS_ANCHOR {
            return Err(Error::new(ErrorKind::MissingRandomness));
        }

        // 2. input context: input_context = "R" || KI_1
        let input_context = make_carrot_input_context(&tx_first_key_image);

        // 3. make D_e and do external ECDH
        let (enote_ephemeral_pubkey, s_sender_receiver_unctx) =
            get_normal_proposal_ecdh_parts(self, &input_context)?;

        // 4. build the output enote address pieces
        let (
            s_sender_receiver,
            amount_blinding_factor,
            amount_commitment,
            onetime_address,
            amount_enc,
            encrypted_payment_id,
            view_tag,
        ) = get_external_output_proposal_parts(
            &s_sender_receiver_unctx,
            &self.destination.address_spend_pubkey,
            &self.destination.payment_id,
            self.amount,
            CarrotEnoteType::Payment,
            &enote_ephemeral_pubkey,
            &input_context,
            false,
        )?;

        // 5. anchor_enc = anchor XOR m_anchor
        let anchor_enc =
            encrypt_carrot_anchor(&self.randomness, &s_sender_receiver, &onetime_address);

        // 6. save the amount and first key image
        Ok((
            RCTOutputEnoteProposal {
                enote: CarrotEnoteV1 {
                    onetime_address: onetime_address,
                    amount_commitment: amount_commitment,
                    amount_enc: amount_enc,
                    anchor_enc: anchor_enc,
                    view_tag: view_tag,
                    enote_ephemeral_pubkey: enote_ephemeral_pubkey,
                    tx_first_key_image: tx_first_key_image,
                },
                amount: self.amount,
                amount_blinding_factor: amount_blinding_factor,
            },
            encrypted_payment_id,
        ))
    }
}

impl CarrotPaymentProposalSelfSendV1 {
    pub fn get_special_output_proposal<VI: ViewIncomingKeyDevice>(
        &self,
        k_view_dev: &VI,
        tx_first_key_image: KeyImage,
        other_enote_ephemeral_pubkey: &Option<EnoteEphemeralPubkey>,
    ) -> Result<RCTOutputEnoteProposal> {
        // 1. sanity checks
        if self.internal_message.is_some() {
            return Err(Error::new(ErrorKind::InvalidInternalMessage));
        }

        // 2. input context: input_context = "R" || KI_1
        let input_context = make_carrot_input_context(&tx_first_key_image);

        // 3. D_e
        let enote_ephemeral_pubkey =
            try_resolve_selfsend_enote_ephemeral_pubkey(self, other_enote_ephemeral_pubkey)?;

        // 4. s_sr = k_v D_e
        let s_sender_receiver_unctx = coerce_device_result(
            k_view_dev.view_key_scalar_mult_x25519(&enote_ephemeral_pubkey.0),
        )?;

        // 5. build the output enote address pieces
        let (
            s_sender_receiver,
            amount_blinding_factor,
            amount_commitment,
            onetime_address,
            amount_enc,
            _,
            view_tag,
        ) = get_external_output_proposal_parts(
            &s_sender_receiver_unctx,
            &self.destination_address_spend_pubkey,
            &NULL_PAYMENT_ID,
            self.amount,
            self.enote_type,
            &enote_ephemeral_pubkey,
            &input_context,
            false,
        )?;

        // 6. make special janus anchor: anchor_sp = H_16(D_e, input_context, Ko, k_v)
        let janus_anchor_special = coerce_device_result(k_view_dev.make_janus_anchor_special(
            &enote_ephemeral_pubkey,
            &input_context,
            &onetime_address,
        ))?;

        // 7. encrypt special anchor: anchor_enc = anchor XOR m_anchor
        let anchor_enc =
            encrypt_carrot_anchor(&janus_anchor_special, &s_sender_receiver, &onetime_address);

        // 8. save the enote ephemeral pubkey, first tx key image, and amount
        Ok(RCTOutputEnoteProposal {
            enote: CarrotEnoteV1 {
                onetime_address: onetime_address,
                amount_commitment: amount_commitment,
                amount_enc: amount_enc,
                anchor_enc: anchor_enc,
                view_tag: view_tag,
                enote_ephemeral_pubkey: enote_ephemeral_pubkey.clone(),
                tx_first_key_image: tx_first_key_image,
            },
            amount: self.amount,
            amount_blinding_factor: amount_blinding_factor,
        })
    }

    pub fn get_internal_output_proposal<VB: ViewBalanceSecretDevice>(
        &self,
        s_view_balance_dev: &VB,
        tx_first_key_image: KeyImage,
        other_enote_ephemeral_pubkey: &Option<EnoteEphemeralPubkey>,
    ) -> Result<RCTOutputEnoteProposal> {
        // 1. sanity checks
        // @TODO

        // 2. input_context = "R" || KI_1
        let input_context = make_carrot_input_context(&tx_first_key_image);

        // 3. D_e
        let enote_ephemeral_pubkey =
            try_resolve_selfsend_enote_ephemeral_pubkey(self, other_enote_ephemeral_pubkey)?;

        // 4. s^ctx_sr = H_32(s_vb, D_e, input_context)
        let s_sender_receiver = coerce_device_result(
            s_view_balance_dev
                .make_internal_sender_receiver_secret(&enote_ephemeral_pubkey, &input_context),
        )?;

        // 5. build the output enote address pieces
        let (amount_blinding_factor, amount_commitment, onetime_address, amount_enc, _) =
            get_output_proposal_parts(
                &s_sender_receiver,
                &self.destination_address_spend_pubkey,
                &NULL_PAYMENT_ID,
                self.amount,
                self.enote_type,
                false,
            )?;

        // 6. vt = H_3(s_vb || input_context || Ko)
        let view_tag = coerce_device_result(
            s_view_balance_dev.make_internal_view_tag(&input_context, &onetime_address),
        )?;

        // 7. anchor = given message OR 0s, if not available
        let anchor = self.internal_message.clone().unwrap_or_default();

        // 8. encrypt anchor: anchor_enc = anchor XOR m_anchor
        let anchor_enc = encrypt_carrot_anchor(&anchor, &s_sender_receiver, &onetime_address);

        // 9. save the enote ephemeral pubkey, first tx key image, and amount
        Ok(RCTOutputEnoteProposal {
            enote: CarrotEnoteV1 {
                onetime_address: onetime_address,
                amount_commitment: amount_commitment,
                amount_enc: amount_enc,
                anchor_enc: anchor_enc,
                view_tag: view_tag,
                enote_ephemeral_pubkey: enote_ephemeral_pubkey.clone(),
                tx_first_key_image: tx_first_key_image,
            },
            amount: self.amount,
            amount_blinding_factor: amount_blinding_factor,
        })
    }
}
