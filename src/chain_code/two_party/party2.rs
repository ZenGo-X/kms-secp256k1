/*
    KMS-ECDSA
    Copyright 2018 by Kzen Networks
    This file is part of KMS library
    (https://github.com/KZen-networks/kms)
    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/kms/blob/master/LICENSE>
*/

use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use cryptography_utils::GE;

pub struct ChainCode2 {
    pub chain_code: GE,
}
impl ChainCode2 {
    pub fn chain_code_first_message() -> dh_key_exchange::Party2FirstMessage {
        dh_key_exchange::Party2FirstMessage::create()
    }

    pub fn chain_code_second_message(
        party_one_first_message: &dh_key_exchange::Party1FirstMessage,
        party_one_second_message: &dh_key_exchange::Party1SecondMessage,
    ) -> Result<dh_key_exchange::Party2SecondMessage, ProofError> {
        dh_key_exchange::Party2SecondMessage::verify_commitments_and_dlog_proof(
            &party_one_first_message.pk_commitment,
            &party_one_first_message.zk_pok_commitment,
            &party_one_second_message.zk_pok_blind_factor,
            &party_one_second_message.public_share,
            &party_one_second_message.pk_commitment_blind_factor,
            &party_one_second_message.d_log_proof,
        )
    }

    pub fn compute_chain_code(
        first_message_public_share: &GE,
        party2_first_message: &dh_key_exchange::Party2FirstMessage,
    ) -> ChainCode2 {
        ChainCode2 {
            chain_code: dh_key_exchange::compute_pubkey_party2(
                party2_first_message,
                first_message_public_share,
            ),
        }
    }
}
