use crate::account::make_carrot_subaddress_scalar;
use crate::core_types::*;
use crate::device::*;
use crate::math_utils::scalar_mul_key_vartime;
use crate::random::Random;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CarrotDestinationV1 {
    pub address_spend_pubkey: AddressSpendPubkey,
    pub address_view_pubkey: AddressViewPubkey,
    pub is_subaddress: bool,
    pub payment_id: PaymentId
}

impl CarrotDestinationV1 {
    pub fn make_main_address(account_spend_pubkey: AddressSpendPubkey,
        primary_address_view_pubkey: AddressViewPubkey) -> Self
    {
        Self{
            address_spend_pubkey: account_spend_pubkey,
            address_view_pubkey: primary_address_view_pubkey,
            is_subaddress: false,
            payment_id: NULL_PAYMENT_ID
        }
    }

    pub fn make_subaddress<G: GenerateAddressSecretDevice>(account_spend_pubkey: &AddressSpendPubkey,
        account_view_pubkey: &AddressViewPubkey,
        s_generate_address_dev: &G,
        major_index: u32,
        minor_index: u32) -> Option<Self>
    {
        if major_index == 0 && minor_index == 0 {
            return None;
        }

        // s^j_gen = H_32[s_ga](j_major, j_minor)
        let address_index_generator = s_generate_address_dev.make_index_extension_generator(
            major_index, minor_index).ok()?;

        // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
        let subaddress_scalar = &make_carrot_subaddress_scalar(&account_spend_pubkey,
            &address_index_generator, major_index, minor_index).0.0;

        // K^j_s = k^j_subscal * K_s
        let address_spend_pubkey = AddressSpendPubkey(scalar_mul_key_vartime(subaddress_scalar,
            &account_spend_pubkey.0)?);

        // K^j_v = k^j_subscal * K_v
        let address_view_pubkey = AddressViewPubkey(scalar_mul_key_vartime(subaddress_scalar,
            &account_view_pubkey.0)?);

        Some(Self{
            address_spend_pubkey: address_spend_pubkey,
            address_view_pubkey: address_view_pubkey,
            is_subaddress: true,
            payment_id: NULL_PAYMENT_ID
        })
    }

    pub fn make_integrated_address(account_spend_pubkey: AddressSpendPubkey,
        primary_address_view_pubkey: AddressViewPubkey,
        payment_id: PaymentId) -> Self
    {
        Self{
            address_spend_pubkey: account_spend_pubkey,
            address_view_pubkey: primary_address_view_pubkey,
            is_subaddress: false,
            payment_id: payment_id
        }
    }

    pub fn is_integrated(&self) -> bool {
        return self.payment_id != NULL_PAYMENT_ID;
    }
}

impl Random for CarrotDestinationV1 {
    type Params = (bool, bool);
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
        let (is_subaddress, is_integrated_address) = p;
        CarrotDestinationV1{
            address_spend_pubkey: AddressSpendPubkey::new_random_with_params(rng, ()),
            address_view_pubkey: AddressViewPubkey::new_random_with_params(rng, ()),
            is_subaddress: is_subaddress,
            payment_id: if is_integrated_address { PaymentId::new_random_with_params(rng, ()) } else { NULL_PAYMENT_ID }
        }
    }
}
