use core::ops::{Index, IndexMut};

use crate::consts::*;
use crate::core_types::*;
use crate::destination::CarrotDestinationV1;
use crate::device::ViewBalanceSecretDevice;
use crate::device::ViewIncomingKeyDevice;
use crate::enote::CarrotCoinbaseEnoteV1;
use crate::math_utils::is_invalid_or_has_torsion;
use crate::payments::*;
use crate::permutate::apply_permutation_backwards;
use crate::random::new_random;
use crate::random::Random;

pub enum AdditionalOutputType
{
    PaymentShared, // self-send proposal with enote_type="payment" with a shared D_e
    ChangeShared,  // self-send proposal with enote_type="change" with a shared D_e
    ChangeUnique,  // self-send proposal with enote_type="change" with a unique D_e
    Dummy,         // outgoing proposal to a random address
}

pub enum AdditionalOutputProposal {
    None,
    Normal(CarrotPaymentProposalV1),
    Selfsend(CarrotPaymentProposalSelfSendV1)
}

pub fn get_additional_output_type(num_outgoing: usize,
    num_selfsend: usize,
    need_change_output: bool,
    have_payment_type_selfsend: bool) -> Option<AdditionalOutputType>
{
    let num_outputs = num_outgoing + num_selfsend;
    let already_completed = num_outputs >= 2 && num_selfsend >= 1 && !need_change_output;
    if already_completed
    {
        None
    }
    else if num_outputs < 2
    {
        if num_selfsend == 0
        {
            Some(AdditionalOutputType::ChangeShared)
        }
        else if !need_change_output
        {
            Some(AdditionalOutputType::Dummy)
        }
        else // num_selfsend == 1 && need_change_output
        {
            if have_payment_type_selfsend
            {
                Some(AdditionalOutputType::ChangeShared)
            }
            else
            {
                Some(AdditionalOutputType::PaymentShared)
            }
        }
    }
    else
    {
        Some(AdditionalOutputType::ChangeUnique)
    }
}

pub fn get_additional_output_proposal<R>(
        num_outgoing: usize,
        num_selfsend: usize,
        needed_change_amount: Amount,
        have_payment_type_selfsend: bool,
        change_address_spend_pubkey: &AddressSpendPubkey,
        rng: &mut R) -> AdditionalOutputProposal
    where R: rand_core::CryptoRngCore
{
    let additional_output_type = get_additional_output_type(
        num_outgoing,
        num_selfsend,
        needed_change_amount != 0,
        have_payment_type_selfsend);

    let Some(additional_output_type) = additional_output_type else {
        return AdditionalOutputProposal::None;
    };

    match additional_output_type {
        AdditionalOutputType::PaymentShared => AdditionalOutputProposal::Selfsend(CarrotPaymentProposalSelfSendV1{
            destination_address_spend_pubkey: change_address_spend_pubkey.clone(),
            amount: needed_change_amount,
            enote_type: CarrotEnoteType::Payment,
            enote_ephemeral_pubkey: None,
            internal_message: None,
        }),
        AdditionalOutputType::ChangeShared => AdditionalOutputProposal::Selfsend(CarrotPaymentProposalSelfSendV1{
            destination_address_spend_pubkey: change_address_spend_pubkey.clone(),
            amount: needed_change_amount,
            enote_type: CarrotEnoteType::Change,
            enote_ephemeral_pubkey: None,
            internal_message: None,
        }),
        AdditionalOutputType::ChangeUnique => AdditionalOutputProposal::Selfsend(CarrotPaymentProposalSelfSendV1{
            destination_address_spend_pubkey: change_address_spend_pubkey.clone(),
            amount: needed_change_amount,
            enote_type: CarrotEnoteType::Change,
            enote_ephemeral_pubkey: None,
            internal_message: None,
        }),
        AdditionalOutputType::Dummy => AdditionalOutputProposal::Normal(CarrotPaymentProposalV1{
            destination: CarrotDestinationV1::new_random_with_params(rng, (false, false)),
            amount: 0,
            randomness: new_random(rng)
        })
    }
}

struct PaymentProposalOrderSlice<'a>(&'a mut [(bool, usize)]);

impl<'a> Index<usize> for PaymentProposalOrderSlice<'a> {
    type Output = usize;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index].1
    }
}

impl<'a> IndexMut<usize> for PaymentProposalOrderSlice<'a> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index].1
    }
}

#[must_use]
fn check_normal_proposals_randomness(normal_payment_proposals: &[CarrotPaymentProposalV1]) -> Result<()> {
    // assert anchor_norm != 0 for payments
    for normal_payment_proposal in normal_payment_proposals.iter() {
        if normal_payment_proposal.randomness == NULL_JANUS_ANCHOR {
            return Err(Error::new(ErrorKind::MissingRandomness));
        }
    }

    // assert uniqueness of randomness for each payment
    for i in 0..normal_payment_proposals.len() {
        for j in 0..normal_payment_proposals.len() {
            if i == j {
                continue;
            } else if normal_payment_proposals[i].randomness == normal_payment_proposals[j].randomness {
                return Err(Error::new(ErrorKind::MissingRandomness));
            }
        }
    }

    Ok(())
}

pub fn get_output_enote_proposals<VB, VI>(normal_payment_proposals: &[CarrotPaymentProposalV1],
    selfsend_payment_proposals: &[CarrotPaymentProposalSelfSendV1],
    dummy_encrypted_payment_id: &Option<EncryptedPaymentId>,
    s_view_balance_dev: Option<&VB>,
    k_view_dev: Option<&VI>,
    tx_first_key_image: KeyImage,
    output_enote_proposals_out: &mut [RCTOutputEnoteProposal],
    encrypted_payment_id_out: &mut EncryptedPaymentId,
    payment_proposal_order_out: &mut [(bool, usize)]
) -> Result<()>
    where
        VB: ViewBalanceSecretDevice,
        VI: ViewIncomingKeyDevice
{
    // assert payment proposals numbers
    let num_selfsend_proposals = selfsend_payment_proposals.len();
    let num_proposals = normal_payment_proposals.len() + num_selfsend_proposals;
    if num_proposals < MIN_OUTPUT_SET_SIZE || num_selfsend_proposals == 0 {
        return Err(Error::new(ErrorKind::WrongOutputNumber));
    }

    // assert output sizes
    if output_enote_proposals_out.len() != num_proposals || payment_proposal_order_out.len() != num_proposals {
        return Err(Error::new(ErrorKind::WrongOutputNumber));
    }

    // assert there is a max of 1 integrated address payment proposals
    let mut num_integrated = 0;
    for normal_payment_proposal in normal_payment_proposals.iter() {
        if normal_payment_proposal.destination.payment_id != NULL_PAYMENT_ID {
            num_integrated += 1;
        }
    }
    if num_integrated > 1 {
        return Err(Error::new(ErrorKind::WrongAddressType));
    }

    check_normal_proposals_randomness(normal_payment_proposals)?;

    // D^other_e
    let mut other_enote_ephemeral_pubkey = None;

    // construct normal enotes
    for i in 0..normal_payment_proposals.len()
    {
        payment_proposal_order_out[i] = (false, i);

        let (output_enote_proposal, encrypted_payment_id) = 
            normal_payment_proposals[i].get_normal_output_proposal(tx_first_key_image.clone())?;

        // if 1 normal, and 2 self-send, set D^other_e equal to this D_e
        if num_proposals == 2 {
            other_enote_ephemeral_pubkey = Some(output_enote_proposal.enote.enote_ephemeral_pubkey.clone());
        }

        output_enote_proposals_out[i] = output_enote_proposal;

        // set pid_enc from integrated address proposal pic_enc
        if normal_payment_proposals[i].destination.payment_id != NULL_PAYMENT_ID {
            *encrypted_payment_id_out = encrypted_payment_id;
        }
    }

    // in the case that there is no required pid_enc, set it to the provided dummy
    if num_integrated == 0
    {
        match dummy_encrypted_payment_id {
            Some(dummy_encrypted_payment_id) => 
                *encrypted_payment_id_out = dummy_encrypted_payment_id.clone(),
            None => return Err(Error::new(ErrorKind::MissingPaymentId))
        }
    }

    // if 0 normal, and 2 self-send, set D^other_e equal to whichever *has* a D_e
    if num_proposals == 2 && num_selfsend_proposals == 2
    {
        let use_ephem_pk_idx = if selfsend_payment_proposals[0].enote_ephemeral_pubkey.is_some() { 0 } else { 1 };
        other_enote_ephemeral_pubkey = selfsend_payment_proposals[use_ephem_pk_idx].enote_ephemeral_pubkey.clone();
    }

    // construct selfsend enotes, preferring internal enotes over special enotes when possible
    for i in 0..selfsend_payment_proposals.len()
    {
        let selfsend_payment_proposal = &selfsend_payment_proposals[i];
        let output_idx = normal_payment_proposals.len() + i;

        payment_proposal_order_out[output_idx] = (true, i);

        output_enote_proposals_out[output_idx] = match s_view_balance_dev {
            Some(s_view_balance_dev) =>  
                selfsend_payment_proposal.get_internal_output_proposal(s_view_balance_dev,
                    tx_first_key_image.clone(),
                    &other_enote_ephemeral_pubkey)?,
            None => match k_view_dev {
                Some(k_view_dev) => selfsend_payment_proposal.get_special_output_proposal(k_view_dev,
                    tx_first_key_image.clone(),
                    &other_enote_ephemeral_pubkey)?,
                None => return Err(Error::new(ErrorKind::DeviceError))
            }
        };
    }

    // sort enotes by K_o
    payment_proposal_order_out.sort_by(|a, b| {
        let a_output_idx = a.1 + if a.0 { normal_payment_proposals.len() } else { 0 };
        let b_output_idx = b.1 + if b.0 { normal_payment_proposals.len() } else { 0 };
        let a_pk_bytes = &output_enote_proposals_out[a_output_idx].
            enote.onetime_address.0.0;
        let b_pk_bytes = &output_enote_proposals_out[b_output_idx].
            enote.onetime_address.0.0;
        a_pk_bytes.cmp(b_pk_bytes)
    });

    // reorder output_enote_proposals_out according to payment_proposal_order_out
    apply_permutation_backwards(&mut PaymentProposalOrderSlice(payment_proposal_order_out),
        output_enote_proposals_out);

    // assert uniqueness of D_e if >2-out, shared otherwise. also check D_e is not trivial
    let mut has_unique_ephemeral_pubkeys = true;
    for i in 0..output_enote_proposals_out.len() {
        let pk_i = &output_enote_proposals_out[i].enote.enote_ephemeral_pubkey;
        for j in 0..output_enote_proposals_out.len() {
            let pk_j = &output_enote_proposals_out[j].enote.enote_ephemeral_pubkey;
            if i == j {
                continue;
            } else if pk_i == pk_j {
                has_unique_ephemeral_pubkeys = false;
                break;
            }
        }
    }
    if num_proposals > 2 && !has_unique_ephemeral_pubkeys {
        return Err(Error::new(ErrorKind::MissingRandomness));
    }
    else if num_proposals == 2 && has_unique_ephemeral_pubkeys {
        return Err(Error::new(ErrorKind::MismatchedEnoteEphemeralPubkey));
    }

    // assert a) uniqueness of K_o, b) all K_o lie in prime order subgroup, and c) K_o is sorted
    for i in 0..output_enote_proposals_out.len() {
        let i_out_pk = &output_enote_proposals_out[i].enote.onetime_address;
        if is_invalid_or_has_torsion(&i_out_pk.0) {
            return Err(Error::new(ErrorKind::BadAddressPoints));
        } else if i > 0 {
            let prev_out_pk = &output_enote_proposals_out[i - 1].enote.onetime_address;
            if &prev_out_pk.0.0 >= &i_out_pk.0.0 {
                return Err(Error::new(ErrorKind::MissingRandomness)); 
            }
        }
    }

    // assert unique and non-trivial k_a
    for i in 0..output_enote_proposals_out.len() {
        let k_a_i = &output_enote_proposals_out[i].amount_blinding_factor;
        if k_a_i == &AmountBlindingKey::default() {
            return Err(Error::new(ErrorKind::MissingRandomness));
        }
        for j in 0..output_enote_proposals_out.len() {
            if i == j {
                continue;
            } else if &output_enote_proposals_out[j].amount_blinding_factor == k_a_i {
                return Err(Error::new(ErrorKind::MissingRandomness));
            }
        }
    }

    Ok(())
}

pub fn get_coinbase_output_enotes(normal_payment_proposals: &[CarrotPaymentProposalV1],
    block_index: BlockIndex,
    output_coinbase_enotes_out: &mut [CarrotCoinbaseEnoteV1],
    payment_proposal_order_out: &mut [usize]) -> Result<()>
{
    // assert payment proposals numbers
    let num_proposals = normal_payment_proposals.len();
    if num_proposals == 0 {
        return Err(Error::new(ErrorKind::WrongOutputNumber));
    }

    // assert output sizes
    if output_coinbase_enotes_out.len() != num_proposals || payment_proposal_order_out.len() != num_proposals {
        return Err(Error::new(ErrorKind::WrongOutputNumber));
    }

    // assert there are no integrated address payment proposals
    for normal_payment_proposal in normal_payment_proposals.iter() {
        let destination = &normal_payment_proposal.destination;
        if destination.is_subaddress || destination.is_integrated() {
            return Err(Error::new(ErrorKind::WrongAddressType));
        }
    }

    check_normal_proposals_randomness(normal_payment_proposals)?;

    // construct normal enotes
    for i in 0..num_proposals {
        payment_proposal_order_out[i] = i;
        output_coinbase_enotes_out[i] = normal_payment_proposals[i].get_coinbase_output_proposal(block_index)?;
    }

    // assert uniqueness of D_e and check D_e is not trivial
    for i in 0..output_coinbase_enotes_out.len() {
        let pk_i = &output_coinbase_enotes_out[i].enote_ephemeral_pubkey;
        for j in 0..output_coinbase_enotes_out.len() {
            let pk_j = &output_coinbase_enotes_out[j].enote_ephemeral_pubkey;
            if i == j {
                continue;
            } else if pk_i == pk_j {
                return Err(Error::new(ErrorKind::MissingRandomness));
            }
        }
    }

    // sort enotes by K_o
    payment_proposal_order_out.sort_by(|a_idx, b_idx| {
        let a_pk_bytes = &output_coinbase_enotes_out[*a_idx].onetime_address.0.0;
        let b_pk_bytes = &output_coinbase_enotes_out[*b_idx].onetime_address.0.0;
        a_pk_bytes.cmp(&b_pk_bytes)
    });

    // assert a) uniqueness of K_o, b) all K_o lie in prime order subgroup, and c) K_o is sorted
    for i in 0..output_coinbase_enotes_out.len() {
        let i_out_pk = &output_coinbase_enotes_out[i].onetime_address;
        if is_invalid_or_has_torsion(&i_out_pk.0) {
            return Err(Error::new(ErrorKind::BadAddressPoints));
        } else if i > 0 {
            let prev_out_pk = &output_coinbase_enotes_out[i - 1].onetime_address;
            if &prev_out_pk.0.0 >= &i_out_pk.0.0 {
                return Err(Error::new(ErrorKind::MissingRandomness)); 
            }
        }
    }

    Ok(())
}
