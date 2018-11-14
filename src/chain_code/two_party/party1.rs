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
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;

use cryptography_utils::GE;

#[derive(Serialize, Deserialize)]
pub struct ChainCode1 {
    pub chain_code: GE,
}

impl ChainCode1 {
    pub fn chain_code_first_message() -> dh_key_exchange::Party1FirstMessage {
        dh_key_exchange::Party1FirstMessage::create_commitments()
    }
    pub fn chain_code_second_message(
        first_message: &dh_key_exchange::Party1FirstMessage,
        proof: &DLogProof,
    ) -> dh_key_exchange::Party1SecondMessage {
        dh_key_exchange::Party1SecondMessage::verify_and_decommit(&first_message, proof).expect("")
    }
    pub fn compute_chain_code(
        first_message: &dh_key_exchange::Party1FirstMessage,
        party2_first_message_public_share: &GE,
    ) -> ChainCode1 {
        ChainCode1 {
            chain_code: dh_key_exchange::compute_pubkey_party1(
                first_message,
                party2_first_message_public_share,
            ),
        }
    }
}
