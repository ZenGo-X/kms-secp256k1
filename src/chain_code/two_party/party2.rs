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

use curv::cryptographic_primitives::proofs::ProofError;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, GE};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ChainCode2 {
    pub chain_code: BigInt,
}

impl ChainCode2 {
    pub fn chain_code_first_message() -> (Party2FirstMessage, EcKeyPair) {
        Party2FirstMessage::create()
    }

    pub fn chain_code_second_message(
        party_one_first_message: &Party1FirstMessage,
        party_one_second_message: &Party1SecondMessage,
    ) -> Result<Party2SecondMessage, ProofError> {
        Party2SecondMessage::verify_commitments_and_dlog_proof(
            &party_one_first_message,
            &party_one_second_message,
        )
    }

    pub fn compute_chain_code(
        ec_key_pair: &EcKeyPair,
        party1_second_message_public_share: &GE,
    ) -> ChainCode2 {
        ChainCode2 {
            chain_code: compute_pubkey(ec_key_pair, party1_second_message_public_share)
                .bytes_compressed_to_big_int(),
        }
    }
}
