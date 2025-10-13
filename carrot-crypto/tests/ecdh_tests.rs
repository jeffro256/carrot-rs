mod common;
use crate::common::random::gen_random;

use carrot_crypto::*;

#[test]
fn ecdh_cryptonote_completeness() {
    let k_view = gen_random();
    let primary_address_view_pubkey =
        AddressViewPubkey::derive_primary_address_view_pubkey(&k_view);
    let k_ephem: EnoteEphemeralKey = gen_random();
    assert_ne!(k_view.as_bytes(), k_ephem.as_bytes());

    let enote_ephemeral_pubkey = EnoteEphemeralPubkey::derive_to_cryptonote_address(&k_ephem);

    let s_sr_sender = MontgomeryECDH::derive_as_sender(&k_ephem, &primary_address_view_pubkey)
        .expect("make_carrot_uncontextualized_shared_key_sender");

    let s_sr_receiver = MontgomeryECDH::derive_as_receiver(&k_view, &enote_ephemeral_pubkey);

    assert_eq!(s_sr_sender, s_sr_receiver);
}

#[test]
fn ecdh_subaddress_completeness() {
    let k_view = gen_random();
    let spend_pubkey: AddressSpendPubkey = gen_random();
    /*
    assert!(
        EdwardsPoint::from_bytes(spend_pubkey.as_bytes())
            .unwrap()
            .is_torsion_free()
    );
    */
    let view_pubkey = AddressViewPubkey::derive_carrot_account_view_pubkey(&k_view, &spend_pubkey)
        .expect("derive_carrot_account_view_pubkey");
    let k_ephem: EnoteEphemeralKey = gen_random();
    assert_ne!(k_view.as_bytes(), k_ephem.as_bytes());

    let enote_ephemeral_pubkey =
        EnoteEphemeralPubkey::derive_to_subaddress(&k_ephem, &spend_pubkey)
            .expect("make_carrot_enote_ephemeral_pubkey_subaddress");

    let s_sr_sender = MontgomeryECDH::derive_as_sender(&k_ephem, &view_pubkey)
        .expect("make_carrot_uncontextualized_shared_key_sender");

    let s_sr_receiver = MontgomeryECDH::derive_as_receiver(&k_view, &enote_ephemeral_pubkey);

    assert_eq!(s_sr_sender, s_sr_receiver);
}
