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
use super::traits::ManagementSystem;
use cryptography_utils::arithmetic::traits::Modulo;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use cryptography_utils::elliptic::curves::secp256_k1::Secp256k1Scalar;
use cryptography_utils::elliptic::curves::traits::ECPoint;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use cryptography_utils::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one,party_two};
use paillier::*;
use std::borrow::Cow;

//TODO: add derive to structs.

pub struct Party1Public<'a> {
    pub Q: GE,
    pub P1: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: RawCiphertext<'a>,
}


pub struct MasterKey1<'a> {
    public: Party1Public<'a>,
    private: party_one::Party1Private,
    chain_code: BigInt,
}

impl<'a> ManagementSystem<Party1Public<'a>, party_one::Party1Private> for MasterKey1<'a> {
    // before rotation make sure both parties have the same key
    fn rotate(&mut self, cf: &BigInt) -> &mut Self {
        let rand_str: FE = ECScalar::from_big_int(cf);
        //TODO: use proper set functions
        self.public.P1 = self.public.P1.clone().scalar_mul(&rand_str.get_element());
        let c_key_new = BigInt::mod_pow(&self.public.c_key.0, cf, &rand_str.get_q());
        self.public.c_key = RawCiphertext(Cow::Owned(c_key_new));

        self.private = party_one::Party1Private::update_private_key(&self.private, cf);
        return self;
    }

    // fn get_child(&self, index: BigInt, height: BigInt) -> (Party1Public, Party1Private) {}
}

impl<'a> MasterKey1<'a> {
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
        party2_first_message: &dh_key_exchange::Party2FirstMessage,
    ) -> GE {
        dh_key_exchange::compute_pubkey_party1(first_message, party2_first_message)
    }

    pub fn key_gen_first_message() -> party_one::KeyGenFirstMsg {
        party_one::KeyGenFirstMsg::create_commitments()
    }
    pub fn key_gen_second_message(
        first_message: &party_one::KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> (party_one::KeyGenSecondMsg, party_one::PaillierKeyPair,EncryptedPairs, ChallengeBits, Proof) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(&first_message, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(first_message);
        let (encrypted_pairs, challenge, proof) =
            party_one::PaillierKeyPair::generate_range_proof(&paillier_key_pair, &first_message);
        (key_gen_second_message, paillier_key_pair,encrypted_pairs, challenge, proof)
    }

    pub fn key_gen_third_message(
        paillier_key_pair: &party_one::PaillierKeyPair,
        challenge: &proof::Challenge,
    ) -> CorrectKeyProof {
        party_one::PaillierKeyPair::generate_proof_correct_key(&paillier_key_pair, &challenge)
            .expect("")
    }



    pub fn set_master_key(chain_code : &GE,  party1_first_message:&party_one::KeyGenFirstMsg, party2_first_message: &party_two::KeyGenFirstMsg, paillier_key_pair: &party_one::PaillierKeyPair ) -> MasterKey1<'a>{
        let party1_public = Party1Public{
            Q: party_one::compute_pubkey(party1_first_message, party2_first_message),
            P1: party1_first_message.public_share,
            paillier_pub: paillier_key_pair.ek,
            c_key: RawCiphertext(paillier_key_pair.encrypted_share),
        };
        let part1_private = party_one::Party1Private::set_private_key(&party1_first_message,&paillier_key_pair);
        MasterKey1{
            public: party1_public,
            private: part1_private,
            chain_code: chain_code.bytes_compressed_to_big_int(),
        }
    }

    //TODO: implmenet sid / state machine
    pub fn key_rotate_first_message() -> (
        coin_flip_optimal_rounds::Party1FirstMessage,
        Secp256k1Scalar,
        Secp256k1Scalar,
    ) {
        coin_flip_optimal_rounds::Party1FirstMessage::commit()
    }

    pub fn key_rotate_second_message(
        party2_first_message: &coin_flip_optimal_rounds::Party2FirstMessage,
        m1: &Secp256k1Scalar,
        r1: &Secp256k1Scalar,
    ) -> (
        coin_flip_optimal_rounds::Party1SecondMessage,
        Secp256k1Scalar,
    ) {
        coin_flip_optimal_rounds::Party1SecondMessage::reveal(&party2_first_message.seed, m1, r1)
    }
}
