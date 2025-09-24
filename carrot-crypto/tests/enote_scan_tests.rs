mod common;
use crate::common::keys::{AddressDeriveType, MockKeys, SubaddressIndex, SubaddressIndexExtended};
use crate::common::random::{gen_random, gen_random_with_params, gen_subaddress_index_major, gen_subaddress_index_minor};

use carrot_crypto::*;

#[test]
fn main_address_normal_scan_completeness() {
    let keys: MockKeys = gen_random_with_params(AddressDeriveType::Carrot);

    let main_address = keys.main_address(None);

    let proposal = payments::CarrotPaymentProposalV1{
        destination: main_address,
        amount: gen_random(),
        randomness: gen_random()
    };

    let tx_first_key_image = gen_random(); 

    let (enote_proposal, encrypted_payment_id)
        = proposal.get_normal_output_proposal(tx_first_key_image).expect("get_normal_output_proposal");

    assert_eq!(proposal.amount, enote_proposal.amount);
    let recomputed_amount_commitment = enote_utils::make_carrot_amount_commitment(
        enote_proposal.amount, &enote_proposal.amount_blinding_factor);
    assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

    let s_sender_receiver_unctx = scan::make_carrot_uncontextualized_shared_key_receiver(
        &keys.k_view_incoming,
        &enote_proposal.enote.enote_ephemeral_pubkey).expect("make_carrot_uncontextualized_shared_key_receiver");

    let (recovered_sender_extension_g, recovered_sender_extension_t,
            recovered_address_spend_pubkey, recovered_amount,
            recovered_amount_blinding_factor, recovered_payment_id,
            recovered_enote_type)
        = scan::try_scan_carrot_enote_external_receiver(&enote_proposal.enote,
            Some(&encrypted_payment_id),
            &s_sender_receiver_unctx,
            core::slice::from_ref(&keys.carrot_account_spend_pubkey),
            &keys.k_view_incoming)
        .expect("try_scan_carrot_enote_external_receiver");

    // check recovered data
    assert_eq!(proposal.destination.address_spend_pubkey, recovered_address_spend_pubkey);
    assert_eq!(proposal.amount, recovered_amount);
    assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
    assert_eq!(NULL_PAYMENT_ID, recovered_payment_id);
    assert_eq!(CarrotEnoteType::Payment, recovered_enote_type);

    // check spendability
    assert!(keys.can_open_fcmp_onetime_address(&recovered_address_spend_pubkey,
        &recovered_sender_extension_g,
        &recovered_sender_extension_t,
        &enote_proposal.enote.onetime_address));
}

#[test]
fn subaddress_normal_scan_completeness() {
    let keys: MockKeys = gen_random_with_params(AddressDeriveType::Carrot);

    let j_major = gen_subaddress_index_major();
    let j_minor = gen_subaddress_index_minor();
    let subaddr_index = SubaddressIndexExtended{
        index: SubaddressIndex{major: j_major, minor: j_minor},
        derive_type: None
    };

    let subaddress = keys.subaddress(&subaddr_index);

    let proposal = payments::CarrotPaymentProposalV1{
        destination: subaddress,
        amount: gen_random(),
        randomness: gen_random()
    };

    let tx_first_key_image = gen_random();

    let (enote_proposal, encrypted_payment_id) = 
        proposal.get_normal_output_proposal(tx_first_key_image).expect("get_output_proposal_normal_v1");

    assert_eq!(proposal.amount, enote_proposal.amount);
    let recomputed_amount_commitment = enote_utils::make_carrot_amount_commitment(
        enote_proposal.amount, &enote_proposal.amount_blinding_factor);
    assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

    let s_sender_receiver_unctx = scan::make_carrot_uncontextualized_shared_key_receiver(
        &keys.k_view_incoming,
        &enote_proposal.enote.enote_ephemeral_pubkey).expect("make_carrot_uncontextualized_shared_key_receiver");

    let (recovered_sender_extension_g, recovered_sender_extension_t, recovered_address_spend_pubkey,
        recovered_amount, recovered_amount_blinding_factor, recovered_payment_id, recovered_enote_type) =
            scan::try_scan_carrot_enote_external_receiver(&enote_proposal.enote,
                Some(&encrypted_payment_id),
                &s_sender_receiver_unctx,
                core::slice::from_ref(&keys.carrot_account_spend_pubkey),
                &keys.k_view_incoming).expect("try_scan_carrot_enote_external_receiver");

    // check recovered data
    assert_eq!(proposal.destination.address_spend_pubkey, recovered_address_spend_pubkey);
    assert_eq!(proposal.amount, recovered_amount);
    assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
    assert_eq!(NULL_PAYMENT_ID, recovered_payment_id);
    assert_eq!(CarrotEnoteType::Payment, recovered_enote_type);

    // check spendability
    assert!(keys.can_open_fcmp_onetime_address(&recovered_address_spend_pubkey,
        &recovered_sender_extension_g,
        &recovered_sender_extension_t,
        &enote_proposal.enote.onetime_address));
}

/*
TEST(carrot_core, integrated_address_normal_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    const CarrotDestinationV1 integrated_address = keys.cryptonote_address(gen_payment_id());

    const CarrotPaymentProposalV1 proposal = CarrotPaymentProposalV1{
        .destination = integrated_address,
        .amount = crypto::rand<rct::xmr_amount>(),
        .randomness = gen_janus_anchor()
    };

    const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

    RCTOutputEnoteProposal enote_proposal;
    encrypted_payment_id_t encrypted_payment_id;
    get_output_proposal_normal_v1(proposal,
        tx_first_key_image,
        enote_proposal,
        encrypted_payment_id);

    assert_eq!(proposal.amount, enote_proposal.amount);
    const rct::key recomputed_amount_commitment = rct::commit(enote_proposal.amount, rct::sk2rct(enote_proposal.amount_blinding_factor));
    assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

    mx25519_pubkey s_sender_receiver_unctx;
    make_carrot_uncontextualized_shared_key_receiver(keys.legacy_acb.get_keys().m_view_secret_key,
        enote_proposal.enote.enote_ephemeral_pubkey,
        s_sender_receiver_unctx);

    crypto::secret_key recovered_sender_extension_g;
    crypto::secret_key recovered_sender_extension_t;
    crypto::public_key recovered_address_spend_pubkey;
    rct::xmr_amount recovered_amount;
    crypto::secret_key recovered_amount_blinding_factor;
    payment_id_t recovered_payment_id;
    CarrotEnoteType recovered_enote_type;
    const bool scan_success = try_scan_carrot_enote_external_receiver(enote_proposal.enote,
        encrypted_payment_id,
        s_sender_receiver_unctx,
        {&keys.carrot_account_spend_pubkey, 1},
        keys.k_view_incoming_dev,
        recovered_sender_extension_g,
        recovered_sender_extension_t,
        recovered_address_spend_pubkey,
        recovered_amount,
        recovered_amount_blinding_factor,
        recovered_payment_id,
        recovered_enote_type);
    
    assert!(scan_success);

    // check recovered data
    assert_eq!(proposal.destination.address_spend_pubkey, recovered_address_spend_pubkey);
    assert_eq!(proposal.amount, recovered_amount);
    assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
    assert_eq!(integrated_address.payment_id, recovered_payment_id);
    assert_eq!(CarrotEnoteType::PAYMENT, recovered_enote_type);

    // check spendability
    assert!(keys.can_open_fcmp_onetime_address(recovered_address_spend_pubkey,
        recovered_sender_extension_g,
        recovered_sender_extension_t,
        enote_proposal.enote.onetime_address));
}

TEST(carrot_core, main_address_special_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    // try once with PAYMENT, once with CHANGE
    for (int i = 0; i < 2; ++i)
    {
        const CarrotEnoteType enote_type = i ? CarrotEnoteType::PAYMENT : CarrotEnoteType::CHANGE;

        const CarrotPaymentProposalSelfSendV1 proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = keys.carrot_account_spend_pubkey,
            .amount = crypto::rand<rct::xmr_amount>(),
            .enote_type = enote_type,
            .enote_ephemeral_pubkey = gen_x25519_pubkey(),
        };

        const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

        RCTOutputEnoteProposal enote_proposal;
        get_output_proposal_special_v1(proposal,
            keys.k_view_incoming_dev,
            tx_first_key_image,
            std::nullopt,
            enote_proposal);

        assert_eq!(proposal.amount, enote_proposal.amount);
        const rct::key recomputed_amount_commitment = rct::commit(enote_proposal.amount, rct::sk2rct(enote_proposal.amount_blinding_factor));
        assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

        mx25519_pubkey s_sender_receiver_unctx;
        make_carrot_uncontextualized_shared_key_receiver(keys.legacy_acb.get_keys().m_view_secret_key,
            enote_proposal.enote.enote_ephemeral_pubkey,
            s_sender_receiver_unctx);

        crypto::secret_key recovered_sender_extension_g;
        crypto::secret_key recovered_sender_extension_t;
        crypto::public_key recovered_address_spend_pubkey;
        rct::xmr_amount recovered_amount;
        crypto::secret_key recovered_amount_blinding_factor;
        payment_id_t recovered_payment_id;
        CarrotEnoteType recovered_enote_type;
        const bool scan_success = try_scan_carrot_enote_external_receiver(enote_proposal.enote,
            std::nullopt,
            s_sender_receiver_unctx,
            {&keys.carrot_account_spend_pubkey, 1},
            keys.k_view_incoming_dev,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            recovered_address_spend_pubkey,
            recovered_amount,
            recovered_amount_blinding_factor,
            recovered_payment_id,
            recovered_enote_type);
        
        assert!(scan_success);

        // check recovered data
        assert_eq!(proposal.destination_address_spend_pubkey, recovered_address_spend_pubkey);
        assert_eq!(proposal.amount, recovered_amount);
        assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
        assert_eq!(null_payment_id, recovered_payment_id);
        assert_eq!(enote_type, recovered_enote_type);

        // check spendability
        assert!(keys.can_open_fcmp_onetime_address(recovered_address_spend_pubkey,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            enote_proposal.enote.onetime_address));
    }
}

TEST(carrot_core, subaddress_special_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    const uint32_t j_major = crypto::rand_idx(mock::MAX_SUBADDRESS_MAJOR_INDEX);
    const uint32_t j_minor = crypto::rand_idx(mock::MAX_SUBADDRESS_MINOR_INDEX);

    const CarrotDestinationV1 subaddress = keys.subaddress({{j_major, j_minor}});

    // try once with PAYMENT, once with CHANGE
    for (int i = 0; i < 2; ++i)
    {
        const CarrotEnoteType enote_type = i ? CarrotEnoteType::PAYMENT : CarrotEnoteType::CHANGE;

        const CarrotPaymentProposalSelfSendV1 proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = subaddress.address_spend_pubkey,
            .amount = crypto::rand<rct::xmr_amount>(),
            .enote_type = enote_type,
            .enote_ephemeral_pubkey = gen_x25519_pubkey(),
        };

        const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

        RCTOutputEnoteProposal enote_proposal;
        get_output_proposal_special_v1(proposal,
            keys.k_view_incoming_dev,
            tx_first_key_image,
            std::nullopt,
            enote_proposal);

        assert_eq!(proposal.amount, enote_proposal.amount);
        const rct::key recomputed_amount_commitment = rct::commit(enote_proposal.amount, rct::sk2rct(enote_proposal.amount_blinding_factor));
        assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

        mx25519_pubkey s_sender_receiver_unctx;
        make_carrot_uncontextualized_shared_key_receiver(keys.legacy_acb.get_keys().m_view_secret_key,
            enote_proposal.enote.enote_ephemeral_pubkey,
            s_sender_receiver_unctx);

        crypto::secret_key recovered_sender_extension_g;
        crypto::secret_key recovered_sender_extension_t;
        crypto::public_key recovered_address_spend_pubkey;
        rct::xmr_amount recovered_amount;
        crypto::secret_key recovered_amount_blinding_factor;
        payment_id_t recovered_payment_id;
        CarrotEnoteType recovered_enote_type;
        const bool scan_success = try_scan_carrot_enote_external_receiver(enote_proposal.enote,
            std::nullopt,
            s_sender_receiver_unctx,
            {&keys.carrot_account_spend_pubkey, 1},
            keys.k_view_incoming_dev,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            recovered_address_spend_pubkey,
            recovered_amount,
            recovered_amount_blinding_factor,
            recovered_payment_id,
            recovered_enote_type);
        
        assert!(scan_success);

        // check recovered data
        assert_eq!(proposal.destination_address_spend_pubkey, recovered_address_spend_pubkey);
        assert_eq!(proposal.amount, recovered_amount);
        assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
        assert_eq!(null_payment_id, recovered_payment_id);
        assert_eq!(enote_type, recovered_enote_type);

        // check spendability
        assert!(keys.can_open_fcmp_onetime_address(recovered_address_spend_pubkey,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            enote_proposal.enote.onetime_address));
    }
}

TEST(carrot_core, main_address_internal_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    const CarrotDestinationV1 main_address = keys.cryptonote_address();

    // try once with PAYMENT, once with CHANGE
    for (int i = 0; i < 2; ++i)
    {
        const CarrotEnoteType enote_type = i ? CarrotEnoteType::PAYMENT : CarrotEnoteType::CHANGE;

        const CarrotPaymentProposalSelfSendV1 proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = main_address.address_spend_pubkey,
            .amount = crypto::rand<rct::xmr_amount>(),
            .enote_type = enote_type,
            .enote_ephemeral_pubkey = gen_x25519_pubkey(),
            .internal_message = gen_janus_anchor()
        };

        const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

        RCTOutputEnoteProposal enote_proposal;
        get_output_proposal_internal_v1(proposal,
            keys.s_view_balance_dev,
            tx_first_key_image,
            std::nullopt,
            enote_proposal);

        assert_eq!(proposal.amount, enote_proposal.amount);
        const rct::key recomputed_amount_commitment = rct::commit(enote_proposal.amount, rct::sk2rct(enote_proposal.amount_blinding_factor));
        assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

        crypto::secret_key recovered_sender_extension_g;
        crypto::secret_key recovered_sender_extension_t;
        crypto::public_key recovered_address_spend_pubkey;
        rct::xmr_amount recovered_amount;
        crypto::secret_key recovered_amount_blinding_factor;
        CarrotEnoteType recovered_enote_type;
        janus_anchor_t recovered_internal_message;
        const bool scan_success = try_scan_carrot_enote_internal_receiver(enote_proposal.enote,
            keys.s_view_balance_dev,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            recovered_address_spend_pubkey,
            recovered_amount,
            recovered_amount_blinding_factor,
            recovered_enote_type,
            recovered_internal_message);

        assert!(scan_success);

        // check recovered data
        assert_eq!(proposal.destination_address_spend_pubkey, recovered_address_spend_pubkey);
        assert_eq!(proposal.amount, recovered_amount);
        assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
        assert_eq!(enote_type, recovered_enote_type);
        assert_eq!(proposal.internal_message, recovered_internal_message);

        // check spendability
        assert!(keys.can_open_fcmp_onetime_address(recovered_address_spend_pubkey,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            enote_proposal.enote.onetime_address));
    }
}

TEST(carrot_core, subaddress_internal_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    const uint32_t j_major = crypto::rand_idx(mock::MAX_SUBADDRESS_MAJOR_INDEX);
    const uint32_t j_minor = crypto::rand_idx(mock::MAX_SUBADDRESS_MINOR_INDEX);

    const CarrotDestinationV1 subaddress = keys.subaddress({{j_major, j_minor}});

    // try once with PAYMENT, once with CHANGE
    for (int i = 0; i < 2; ++i)
    {
        const CarrotEnoteType enote_type = i ? CarrotEnoteType::PAYMENT : CarrotEnoteType::CHANGE;

        const CarrotPaymentProposalSelfSendV1 proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = subaddress.address_spend_pubkey,
            .amount = crypto::rand<rct::xmr_amount>(),
            .enote_type = enote_type,
            .enote_ephemeral_pubkey = gen_x25519_pubkey(),
            .internal_message = gen_janus_anchor()
        };

        const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

        RCTOutputEnoteProposal enote_proposal;
        get_output_proposal_internal_v1(proposal,
            keys.s_view_balance_dev,
            tx_first_key_image,
            std::nullopt,
            enote_proposal);

        assert_eq!(proposal.amount, enote_proposal.amount);
        const rct::key recomputed_amount_commitment = rct::commit(enote_proposal.amount, rct::sk2rct(enote_proposal.amount_blinding_factor));
        assert_eq!(enote_proposal.enote.amount_commitment, recomputed_amount_commitment);

        crypto::secret_key recovered_sender_extension_g;
        crypto::secret_key recovered_sender_extension_t;
        crypto::public_key recovered_address_spend_pubkey;
        rct::xmr_amount recovered_amount;
        crypto::secret_key recovered_amount_blinding_factor;
        CarrotEnoteType recovered_enote_type;
        janus_anchor_t recovered_internal_message;
        const bool scan_success = try_scan_carrot_enote_internal_receiver(enote_proposal.enote,
            keys.s_view_balance_dev,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            recovered_address_spend_pubkey,
            recovered_amount,
            recovered_amount_blinding_factor,
            recovered_enote_type,
            recovered_internal_message);

        assert!(scan_success);

        // check recovered data
        assert_eq!(proposal.destination_address_spend_pubkey, recovered_address_spend_pubkey);
        assert_eq!(proposal.amount, recovered_amount);
        assert_eq!(enote_proposal.amount_blinding_factor, recovered_amount_blinding_factor);
        assert_eq!(enote_type, recovered_enote_type);
        assert_eq!(proposal.internal_message, recovered_internal_message);

        // check spendability
        assert!(keys.can_open_fcmp_onetime_address(recovered_address_spend_pubkey,
            recovered_sender_extension_g,
            recovered_sender_extension_t,
            enote_proposal.enote.onetime_address));
    }
}

TEST(carrot_core, main_address_coinbase_scan_completeness)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate();

    const CarrotDestinationV1 main_address = keys.cryptonote_address();

    const CarrotPaymentProposalV1 proposal = CarrotPaymentProposalV1{
        .destination = main_address,
        .amount = crypto::rand<rct::xmr_amount>(),
        .randomness = gen_janus_anchor()
    };

    const uint64_t block_index = crypto::rand<uint64_t>();

    CarrotCoinbaseEnoteV1 enote;
    get_coinbase_output_proposal_v1(proposal,
        block_index,
        enote);

    assert_eq!(proposal.amount, enote.amount);

    mx25519_pubkey s_sender_receiver_unctx;
    make_carrot_uncontextualized_shared_key_receiver(keys.k_view_incoming_dev,
        enote.enote_ephemeral_pubkey,
        s_sender_receiver_unctx);

    crypto::secret_key recovered_sender_extension_g;
    crypto::secret_key recovered_sender_extension_t;
    const bool scan_success = try_scan_carrot_coinbase_enote_receiver(enote,
        s_sender_receiver_unctx,
        keys.carrot_account_spend_pubkey,
        recovered_sender_extension_g,
        recovered_sender_extension_t);

    assert!(scan_success);

    // check spendability
    assert!(keys.can_open_fcmp_onetime_address(
        keys.carrot_account_spend_pubkey,
        recovered_sender_extension_g,
        recovered_sender_extension_t,
        enote.onetime_address));
}

        */
