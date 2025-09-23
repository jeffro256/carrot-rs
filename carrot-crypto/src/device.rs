use core::fmt::{Debug, Display};

use curve25519_dalek::{EdwardsPoint, MontgomeryPoint};

use crate::core_types::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    NotConnected,
    PasswordNeeded,
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

pub type Result<T> = core::result::Result<T, Error>;

pub trait ViewIncomingKeyDevice {
    /**
     * brief: do an Ed25519 scalar mult against the incoming view key
     *   kvP = k_v * P
     * return: true on success, false on failure (e.g. unable to decompress point)
     */
    #[allow(non_snake_case)]
    fn view_key_scalar_mult_ed25519(&self, P: &EdwardsPoint) -> Result<EdwardsPoint>;

    /**
     * brief: do an X25519 scalar mult against the incoming view key
     *   kvD = k_v * D
     * return: true on success, false on failure (e.g. unable to decompress point)
     */
    #[allow(non_snake_case)]
    fn view_key_scalar_mult_x25519(&self, D: &MontgomeryPoint) -> Result<MontgomeryECDH>;

    /**
     * brief: make a janus anchor for "special" enotes
     *   anchor_sp = H_16(D_e, input_context, Ko, k_v)
     */
    fn make_janus_anchor_special(&self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
        onetime_address: &OutputPubkey) -> Result<JanusAnchor>;
}

pub trait ViewBalanceSecretDevice
{
    /**
     * brief: make an internal view tag, given non-secret data
     *   vt = H_3(s_vb || input_context || Ko)
     */
    fn make_internal_view_tag(&self, input_context: &InputContext, onetime_address: &OutputPubkey) -> Result<ViewTag>;

    /**
     * brief: make internal sender-receiver secret, given non-secret data
     *   s^ctx_sr = H_32(s_sr, D_e, input_context)
     */
    fn make_internal_sender_receiver_secret(&self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext) -> Result<SenderReceiverSecret>;
}

pub trait GenerateAddressSecretDevice
{
    /**
    * brief: make_index_extension_generator - make carrot index extension generator s^j_gen
    *   s^j_gen = H_32[s_ga](j_major, j_minor)
    */
    fn make_index_extension_generator(&self, major_index: u32, minor_index: u32) -> Result<AddressIndexGeneratorSecret>;
}

pub trait GenerateImageKeyDevice
{
    /**
     * brief: multiply associated secret key against hash-to-point of one-time address
     *   [carrot] L_partial = k_gi Hp(K_o)
     *   [legacy] L_partial = k_s Hp(K_o)
     */
    fn generate_image_scalar_mult_hash_to_point(&self, onetime_address: &OutputPubkey) -> Result<KeyImageGenerator>;
}
