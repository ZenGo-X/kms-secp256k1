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
use cryptography_utils::{BigInt,GE,FE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use super::traits::ManagementSystem;
//TODO: pick only relevant
use paillier::*;

pub struct Party1Public{
    pub Q: GE,
    pub P1: GE,
    paillier_pub: EncryptionKey,
    c_key : RawCiphertext,
}

struct Party1Private{
    x1: FE,
    paillier_priv: DecryptionKey,

}

pub struct MasterKey1{
    toggle: bool,
    public: Party1Public,
    private: Party1Private,
    chain_code: BigInt,

}

impl ManagementSystem for MasterKey1{

}

impl Party1Public {
    pub fn first_message() -> dh_key_exchange::Party1FirstMessage {
        dh_key_exchange::Party1FirstMessage::create_commitments()
    }
    pub fn second_message(first_message: &dh_key_exchange::Party1FirstMessage, proof: &DLogProof) -> Result<dh_key_exchange::Party1SecondMessage, ProofError>  {
        dh_key_exchange::Party1SecondMessage::verify_and_decommit(first_message, proof)

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
                first_message,
            );
    }

    pub fn third_message() -> {

        let proof_result = party_one::PaillierKeyPair::generate_proof_correct_key(
            &paillier_key_pair,
            &challenge.val,
        );
    }
}