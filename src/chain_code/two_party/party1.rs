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
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, GE};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ChainCode1 {
    pub chain_code: BigInt,
}

impl ChainCode1 {
    pub fn chain_code_first_message() -> (Party1FirstMessage, CommWitness, EcKeyPair) {
        Party1FirstMessage::create_commitments()
    }
    pub fn chain_code_second_message(
        comm_witness: CommWitness,
        proof: &DLogProof,
    ) -> Party1SecondMessage {
        Party1SecondMessage::verify_and_decommit(comm_witness, proof).expect("")
    }
    pub fn compute_chain_code(
        ec_key_pair: &EcKeyPair,
        party2_first_message_public_share: &GE,
    ) -> ChainCode1 {
        ChainCode1 {
            chain_code: compute_pubkey(ec_key_pair, party2_first_message_public_share)
                .bytes_compressed_to_big_int(),
        }
    }
}
