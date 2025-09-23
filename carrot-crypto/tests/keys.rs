use carrot_crypto::{account::make_carrot_viewincoming_key, *};
use curve25519_dalek::{EdwardsPoint, Scalar};
use group::GroupEncoding;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, ops::Add};

#[derive(Clone, Copy)]
pub enum AddressDeriveType {
    Carrot,
    Legacy
}

pub struct SubaddressIndex {
    pub major_index: u32,
    pub minor_index: u32
}

pub struct SubaddressIndexExtended {
    pub index: SubaddressIndex,
    pub derive_type: AddressDeriveType
}

pub struct MockKeys
{
    // legacy privkeys and pubkeys
    pub legacy_k_spend: ScalarSecret,
    pub legacy_account_spend_pubkey: AddressSpendPubkey,

    // carrot secret keys (minus k_v, which is shared with legacy k_v)
    pub s_master: Uniform32Secret,
    pub k_prove_spend: ProveSpendKey,
    pub s_view_balance: ViewBalanceSecret,
    pub k_generate_image: GenerateImageKey,
    pub s_generate_address: GenerateAddressSecret,

    // shared keys
    pub k_view_incoming: ViewIncomingKey,
    pub primary_address_view_pubkey: AddressViewPubkey,

    // carrot public keys (minus K^0_v, which is shared with legacy K^0_v)
    pub carrot_account_spend_pubkey: AddressSpendPubkey,
    pub carrot_account_view_pubkey: AddressViewPubkey,

    //pub subaddress_map: HashMap<AddressSpendPubkey, SubaddressIndexExtended>,

    pub default_derive_type: AddressDeriveType
}

impl MockKeys {
    pub fn main_address(&self, derive_type: Option<AddressDeriveType>) -> CarrotDestinationV1 {
        let account_spend_pubkey = match self.resolve_derive_type(derive_type) {
            AddressDeriveType::Carrot => &self.carrot_account_spend_pubkey,
            AddressDeriveType::Legacy => &self.legacy_account_spend_pubkey
        };

        CarrotDestinationV1::make_main_address(account_spend_pubkey.clone(),
            self.primary_address_view_pubkey.clone())
    }

    pub fn integrated_address(&self, payment_id: PaymentId, derive_type: Option<AddressDeriveType>) -> CarrotDestinationV1 {
        let account_spend_pubkey = match self.resolve_derive_type(derive_type) {
            AddressDeriveType::Carrot => &self.carrot_account_spend_pubkey,
            AddressDeriveType::Legacy => &self.legacy_account_spend_pubkey
        };

        CarrotDestinationV1::make_integrated_address(account_spend_pubkey.clone(),
            self.primary_address_view_pubkey.clone(), payment_id)
    }

    pub fn subaddress(&self, subaddr_index: SubaddressIndexExtended) -> CarrotDestinationV1 {
        match self.resolve_derive_type(Some(subaddr_index.derive_type)) {
            AddressDeriveType::Carrot => {
                CarrotDestinationV1::make_subaddress(&self.carrot_account_spend_pubkey,
                        &self.carrot_account_view_pubkey,
                        &self.s_generate_address,
                        subaddr_index.index.major_index,
                        subaddr_index.index.minor_index)
                    .expect("CarrotDestinationV1::make_subaddress")
            },
            AddressDeriveType::Legacy => {
                self.make_legacy_subaddress(subaddr_index.index.major_index, subaddr_index.index.minor_index)
            }
        }
    }

    fn resolve_derive_type(&self, derive_type: Option<AddressDeriveType>) -> AddressDeriveType {
        derive_type.unwrap_or(self.default_derive_type)
    }

    fn make_legacy_subaddress_extension(k_view: &ScalarSecret,
        major_index: u32,
        minor_index: u32) -> ScalarSecret
    {
        if major_index == 0 && minor_index == 0 {
            return ScalarSecret::default();
        }

        let mut data = [0u8; (8 + 32 + 4 + 4)];
        // "Subaddr" || IntToBytes(0)
        data[0..7].copy_from_slice("SubAddr".as_bytes());
        data[8] = 0;
        // ... || k_v
        data[8..40].copy_from_slice(k_view.0.as_bytes());
        // ... || IntToBytes32(j_major)
        data[40..44].copy_from_slice(&major_index.to_be_bytes());
        // ... || IntToBytes32(j_minor)
        data[44..48].copy_from_slice(&minor_index.to_be_bytes());

        // k^j_subext = ScalarDeriveLegacy("SubAddr" || IntToBytes8(0) || k_v || IntToBytes32(j_major) || IntToBytes32(j_minor))
        let mut hasher = Keccak256::default();
        hasher.update(&data);
        let hash = hasher.finalize();
        ScalarSecret(Scalar::from_bytes_mod_order(hash.into()))
    }

    fn make_legacy_view_key(legacy_k_spend: &ScalarSecret) -> ViewIncomingKey {
        let mut hasher = Keccak256::default();
        hasher.update(&legacy_k_spend.0.as_bytes());
        let hash = hasher.finalize();
        ViewIncomingKey(ScalarSecret(Scalar::from_bytes_mod_order(hash.into())))
    }

    fn make_legacy_subaddress(&self, major_index: u32, minor_index: u32) -> CarrotDestinationV1 {
        let subaddress_extension_scalar = Self::make_legacy_subaddress_extension(&self.k_view_incoming.0,
            major_index, minor_index);
        let subaddress_extension = EdwardsPoint::mul_base(&subaddress_extension_scalar.0);
        let address_spend_pubkey = EdwardsPoint::from_bytes(&self.legacy_account_spend_pubkey.0.as_bytes())
            .expect("EdwardsPoint::from_bytes") + subaddress_extension;
        let address_view_pubkey = &self.k_view_incoming.0.0 * &address_spend_pubkey;
        let is_subaddress = major_index != 0 || minor_index != 0;
        CarrotDestinationV1{
            address_spend_pubkey: AddressSpendPubkey(address_spend_pubkey.compress()),
            address_view_pubkey: AddressViewPubkey(address_view_pubkey.compress()),
            is_subaddress: is_subaddress,
            payment_id: NULL_PAYMENT_ID
        }
    }

    fn from_master_keys(s_master: Uniform32Secret,
        legacy_k_spend: ScalarSecret,
        default_derive_type: AddressDeriveType
    ) -> Self {
        let legacy_account_spend_pubkey = account::make_carrot_spend_pubkey(
            &GenerateImageKey(legacy_k_spend.clone()), &ProveSpendKey::default());

        let k_prove_spend = account::make_carrot_provespend_key(&s_master);
        let s_view_balance = account::make_carrot_viewbalance_secret(&s_master);
        let k_generate_image = account::make_carrot_generateimage_key(&s_view_balance);
        let s_generate_address = account::make_carrot_generateaddress_secret(&s_view_balance);

        let k_view_incoming = match default_derive_type {
            AddressDeriveType::Carrot => account::make_carrot_viewincoming_key(&s_view_balance),
            AddressDeriveType::Legacy => Self::make_legacy_view_key(&legacy_k_spend)
        };
        let primary_address_view_pubkey = account::make_carrot_primary_address_view_pubkey(
            &k_view_incoming);

        let carrot_account_spend_pubkey = account::make_carrot_spend_pubkey(&k_generate_image,
            &k_prove_spend);
        let carrot_account_view_pubkey = account::make_carrot_account_view_pubkey(&k_view_incoming,
            &carrot_account_spend_pubkey);

        Self {
            legacy_k_spend: legacy_k_spend,
            legacy_account_spend_pubkey:
            legacy_account_spend_pubkey,
            s_master: s_master,
            k_prove_spend: k_prove_spend,
            s_view_balance: s_view_balance,
            k_generate_image: k_generate_image,
            s_generate_address: s_generate_address,
            k_view_incoming: k_view_incoming,
            primary_address_view_pubkey: primary_address_view_pubkey,
            carrot_account_spend_pubkey: carrot_account_spend_pubkey,
            carrot_account_view_pubkey: carrot_account_view_pubkey,
            default_derive_type: default_derive_type
        }
    }
}

impl random::Random for MockKeys {
    type Params = AddressDeriveType;
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R, p: Self::Params) -> Self {
        Self::from_master_keys(Uniform32Secret::new_random_with_params(rng, ()),
        ScalarSecret::new_random_with_params(rng, ()), p)
    }
}
