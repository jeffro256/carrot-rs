use carrot_crypto::*;
use curve25519_dalek::{EdwardsPoint, Scalar};
use group::GroupEncoding;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use crate::common::math::scalar_mul_gt;

#[derive(Clone, Copy)]
pub enum AddressDeriveType {
    Carrot,
    Legacy
}

pub struct SubaddressIndex {
    pub major: u32,
    pub minor: u32
}

impl SubaddressIndex {
    pub fn is_subaddress(&self) -> bool {
        return self.major != 0 || self.minor != 0;
    }
}

pub struct SubaddressIndexExtended {
    pub index: SubaddressIndex,
    pub derive_type: Option<AddressDeriveType>
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

    pub subaddress_map: HashMap<AddressSpendPubkey, SubaddressIndexExtended>,

    pub default_derive_type: AddressDeriveType
}

impl MockKeys {
    const MAX_SUBADDRESS_MAJOR_INDEX: u32 = 5;
    const MAX_SUBADDRESS_MINOR_INDEX: u32 = 20;

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

    pub fn subaddress(&self, subaddr_index: &SubaddressIndexExtended) -> CarrotDestinationV1 {
        match self.resolve_derive_type(subaddr_index.derive_type) {
            AddressDeriveType::Carrot => {
                if subaddr_index.index.is_subaddress() {
                    CarrotDestinationV1::make_subaddress(&self.carrot_account_spend_pubkey,
                            &self.carrot_account_view_pubkey,
                            &self.s_generate_address,
                            subaddr_index.index.major,
                            subaddr_index.index.minor)
                        .expect("CarrotDestinationV1::make_subaddress")
                } else {
                    CarrotDestinationV1::make_main_address(self.carrot_account_spend_pubkey.clone(),
                        self.primary_address_view_pubkey.clone())
                }
            },
            AddressDeriveType::Legacy => {
                Self::make_legacy_subaddress(&self.k_view_incoming, &self.legacy_account_spend_pubkey,
                    subaddr_index.index.major, subaddr_index.index.minor)
            }
        }
    }

    pub fn opening_for_subaddress(&self, subaddr_index: &SubaddressIndexExtended)
        -> (Scalar, Scalar, AddressSpendPubkey)
    {
        let is_subaddress = subaddr_index.index.is_subaddress();
        let major_index = subaddr_index.index.major;
        let minor_index = subaddr_index.index.minor;

        let (address_privkey_g, address_privkey_t) = match self.resolve_derive_type(subaddr_index.derive_type)
        {
            AddressDeriveType::Carrot => {
                // s^j_gen = H_32[s_ga](j_major, j_minor)
                let address_index_generator = account::make_carrot_index_extension_generator(
                    &self.s_generate_address,
                    major_index,
                    minor_index);

                let subaddress_scalar = if is_subaddress
                {
                    // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
                    account::make_carrot_subaddress_scalar(&self.carrot_account_spend_pubkey,
                        &address_index_generator, major_index, minor_index)
                }
                else
                {
                    // k^j_subscal = 1
                    SubaddressScalarSecret(ScalarSecret(Scalar::from(1u8)))
                };

                // k^g_a = k_gi * k^j_subscal
                let address_privkey_g = self.k_generate_image.0.0 * subaddress_scalar.0.0;

                // k^t_a = k_ps * k^j_subscal
                let address_privkey_t = self.k_prove_spend.0.0 * subaddress_scalar.0.0;

                (address_privkey_g, address_privkey_t)
            },
            AddressDeriveType::Legacy => {
                // m = Hn(k_v || j_major || j_minor) if subaddress else 0
                let subaddress_extension = Self::make_legacy_subaddress_extension(
                    &self.k_view_incoming.0, major_index, minor_index);

                // k^g_a = k_s + m
                let address_privkey_g = &self.legacy_k_spend.0 + &subaddress_extension.0;

                // k^t_a = 0
                (address_privkey_g, Scalar::from(0u8))
            }
        };

        // perform sanity check
        let addr = self.subaddress(subaddr_index);
        let recomputed_address_spend_pubkey = scalar_mul_gt(&address_privkey_g, &address_privkey_t);

        assert_eq!(recomputed_address_spend_pubkey, addr.address_spend_pubkey.0);

        (address_privkey_g, address_privkey_t, AddressSpendPubkey(recomputed_address_spend_pubkey))
    }

    pub fn try_searching_for_opening_for_subaddress(&self, address_spend_pubkey: &AddressSpendPubkey)
        -> Option<(Scalar, Scalar)>
    {
        let subaddr_index = self.subaddress_map.get(address_spend_pubkey)?;
 
        let (address_privkey_g, address_privkey_t, recomputed_address_spend_pubkey)
            = self.opening_for_subaddress(subaddr_index);

        assert_eq!(&recomputed_address_spend_pubkey, address_spend_pubkey);

        Some((address_privkey_g, address_privkey_t))
    }

    pub fn try_searching_for_opening_for_onetime_address(&self,
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_g: &OnetimeExtensionG,
        sender_extension_t: &OnetimeExtensionT) -> Option<(Scalar, Scalar)>
    {
        // k^{j,g}_addr, k^{j,t}_addr
        let (address_privkey_g, address_privkey_t) = self.try_searching_for_opening_for_subaddress(
            address_spend_pubkey)?;

        // x = k^{j,g}_addr + k^g_o
        let x = address_privkey_g + sender_extension_g.0.0;

        // y = k^{j,t}_addr + k^t_o
        let y = address_privkey_t + sender_extension_t.0.0;

        Some((x, y))
    }

    pub fn can_open_fcmp_onetime_address(&self,
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_g: &OnetimeExtensionG,
        sender_extension_t: &OnetimeExtensionT,
        onetime_address: &OutputPubkey) -> bool
    {
        let Some((x, y)) = self.try_searching_for_opening_for_onetime_address(
            address_spend_pubkey,
            sender_extension_g,
            sender_extension_t)
        else {
            return false;
        };

        // O' = x G + y T
        let recomputed_onetime_address = scalar_mul_gt(&x, &y);

        // O' ?= O
        &recomputed_onetime_address == &onetime_address.0
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

    fn make_legacy_subaddress(k_view: &ViewIncomingKey,
        account_spend_pubkey: &AddressSpendPubkey,
        major_index: u32,
        minor_index: u32
    ) -> CarrotDestinationV1 {
        let subaddress_extension_scalar = Self::make_legacy_subaddress_extension(&k_view.0,
            major_index, minor_index);
        let subaddress_extension = EdwardsPoint::mul_base(&subaddress_extension_scalar.0);
        let address_spend_pubkey = EdwardsPoint::from_bytes(account_spend_pubkey.0.as_bytes().into())
            .expect("EdwardsPoint::from_bytes") + subaddress_extension;
        let address_view_pubkey = &k_view.0.0 * &address_spend_pubkey;
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
        // derive legacy pubkeys
        let legacy_account_spend_pubkey = account::make_carrot_spend_pubkey(
            &GenerateImageKey(legacy_k_spend.clone()), &ProveSpendKey::default());

        // derive carrot privkeys
        let k_prove_spend = account::make_carrot_provespend_key(&s_master);
        let s_view_balance = account::make_carrot_viewbalance_secret(&s_master);
        let k_generate_image = account::make_carrot_generateimage_key(&s_view_balance);
        let s_generate_address = account::make_carrot_generateaddress_secret(&s_view_balance);

        // derive view-incoming {pub/priv}key, dependent on address derive type
        let k_view_incoming = match default_derive_type {
            AddressDeriveType::Carrot => account::make_carrot_viewincoming_key(&s_view_balance),
            AddressDeriveType::Legacy => Self::make_legacy_view_key(&legacy_k_spend)
        };
        let primary_address_view_pubkey = account::make_carrot_primary_address_view_pubkey(
            &k_view_incoming);

        // derive carrot account pubkeys
        let carrot_account_spend_pubkey = account::make_carrot_spend_pubkey(&k_generate_image,
            &k_prove_spend);
        let carrot_account_view_pubkey = account::make_carrot_account_view_pubkey(&k_view_incoming,
            &carrot_account_spend_pubkey);

        // derive subaddress map, Carrot and Legacy
        let mut subaddress_map = HashMap::new();
        let derive_types = [AddressDeriveType::Carrot, AddressDeriveType::Legacy];
        for major_index in 0..Self::MAX_SUBADDRESS_MAJOR_INDEX {
            for minor_index in 0..Self::MAX_SUBADDRESS_MINOR_INDEX {
                for derive_type in derive_types.iter() {
                    let address_spend_pubkey = match derive_type {
                        AddressDeriveType::Carrot => if major_index != 0 || minor_index != 0 {
                                CarrotDestinationV1::make_subaddress(&carrot_account_spend_pubkey,
                                    &carrot_account_view_pubkey, &s_generate_address, major_index, minor_index)
                                    .unwrap().address_spend_pubkey
                            } else {
                                carrot_account_spend_pubkey.clone()
                            },
                        AddressDeriveType::Legacy => Self::make_legacy_subaddress(&k_view_incoming,
                            &legacy_account_spend_pubkey, major_index, minor_index).address_spend_pubkey
                    };
                    subaddress_map.insert(address_spend_pubkey, SubaddressIndexExtended{
                        index: SubaddressIndex { major: major_index, minor: minor_index },
                        derive_type: Some(derive_type.clone())
                    });
                }
            }
        }

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
            subaddress_map: subaddress_map,
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
