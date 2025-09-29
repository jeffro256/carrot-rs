use crate::account::make_carrot_index_extension_generator;
use crate::core_types::*;
use crate::device::*;
use crate::enote_utils::*;

impl ViewIncomingKeyDevice for ViewIncomingKey {
    #[allow(non_snake_case)]
    fn view_key_scalar_mult_ed25519(
        &self,
        P: &curve25519_dalek::EdwardsPoint,
    ) -> Result<curve25519_dalek::EdwardsPoint> {
        Ok(self.0.0 * P)
    }

    #[allow(non_snake_case)]
    fn view_key_scalar_mult_x25519(
        &self,
        D: &curve25519_dalek::MontgomeryPoint,
    ) -> Result<MontgomeryECDH> {
        Ok(MontgomeryECDH(self.0.0 * D))
    }

    fn make_janus_anchor_special(
        &self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Result<JanusAnchor> {
        Ok(make_carrot_janus_anchor_special(
            enote_ephemeral_pubkey,
            input_context,
            onetime_address,
            self,
        ))
    }
}

impl ViewBalanceSecretDevice for ViewBalanceSecret {
    fn make_internal_view_tag(
        &self,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Result<ViewTag> {
        Ok(make_carrot_view_tag(
            &self.0.0,
            input_context,
            onetime_address,
        ))
    }

    fn make_internal_sender_receiver_secret(
        &self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
    ) -> Result<SenderReceiverSecret> {
        Ok(make_carrot_sender_receiver_secret(
            &self.0.0,
            enote_ephemeral_pubkey,
            input_context,
        ))
    }
}

impl GenerateAddressSecretDevice for GenerateAddressSecret {
    fn make_index_extension_generator(
        &self,
        major_index: u32,
        minor_index: u32,
    ) -> Result<AddressIndexGeneratorSecret> {
        Ok(make_carrot_index_extension_generator(
            self,
            major_index,
            minor_index,
        ))
    }
}
