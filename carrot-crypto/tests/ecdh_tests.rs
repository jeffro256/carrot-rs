use carrot_crypto::account::make_carrot_account_view_pubkey;
use carrot_crypto::*;
use carrot_crypto::random::{new_random, Random};

fn gen_random<R>() -> R
    where R: Random<Params = ()>
{
    new_random(&mut rand_core::OsRng)
}

#[test]
fn ecdh_cryptonote_completeness() {
    let k_view = gen_random();
    let primary_address_view_pubkey = account::make_carrot_primary_address_view_pubkey(&k_view);
    let k_ephem: EnoteEphemeralKey = gen_random();
    assert_ne!(&k_view.0.0, &k_ephem.0.0);

    let enote_ephemeral_pubkey = enote_utils::make_carrot_enote_ephemeral_pubkey_cryptonote(
        &k_ephem);

    let s_sr_sender = enote_utils::make_carrot_uncontextualized_shared_key_sender(&k_ephem,
        &primary_address_view_pubkey).expect("make_carrot_uncontextualized_shared_key_sender");

    let s_sr_receiver = enote_utils::make_carrot_uncontextualized_shared_key_receiver(&k_view,
        &enote_ephemeral_pubkey);

    assert_eq!(s_sr_sender, s_sr_receiver);
}

#[test]
fn ecdh_subaddress_completeness() {
    let k_view = gen_random();
    let spend_pubkey = gen_random();
    let view_pubkey = make_carrot_account_view_pubkey(&k_view, &spend_pubkey);
    let k_ephem: EnoteEphemeralKey = gen_random();
    assert_ne!(&k_view.0.0, &k_ephem.0.0);

    let enote_ephemeral_pubkey
        = enote_utils::make_carrot_enote_ephemeral_pubkey_subaddress(&k_ephem, &spend_pubkey)
        .expect("make_carrot_enote_ephemeral_pubkey_subaddress");

    let s_sr_sender = enote_utils::make_carrot_uncontextualized_shared_key_sender(
        &k_ephem, &view_pubkey).expect("make_carrot_uncontextualized_shared_key_sender");

    let s_sr_receiver = enote_utils::make_carrot_uncontextualized_shared_key_receiver(&k_view,
        &enote_ephemeral_pubkey);

    assert_eq!(s_sr_sender, s_sr_receiver);
}
