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

use cryptography_utils::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use cryptography_utils::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use paillier::proof::Challenge;
//TODO: pick only relevant
use cryptography_utils::arithmetic::traits::Modulo;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use cryptography_utils::elliptic::curves::secp256_k1::Secp256k1Scalar;
use cryptography_utils::elliptic::curves::traits::ECPoint;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use cryptography_utils::cryptographic_primitives::hashing::hmac_sha512;
use paillier::*;
use std::borrow::Cow;
use std::borrow::Borrow;

pub struct Party2Public<'a> {
    pub Q: GE,
    pub P2: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: RawCiphertext<'a>,
}

pub struct MasterKey2<'a> {
    pub public: Party2Public<'a>,
    pub private: party_two::Party2Private,
    chain_code: BigInt,
}

impl<'a> ManagementSystem<Party2Public<'a>, party_two::Party2Private> for MasterKey2<'a> {
    fn rotate(self, cf: &BigInt) -> MasterKey2<'a> {
        let rand_str: FE = ECScalar::from_big_int(cf);
        let rand_str_invert = cf.invert(&rand_str.get_q()).unwrap();
        let rand_str_invert_fe: FE = ECScalar::from_big_int(&rand_str_invert);
        let c_key_new = Paillier::mul(&self.public.paillier_pub,self.public.c_key.clone(), RawPlaintext::from(cf));
        //TODO: use proper set functions
        let public = Party2Public{
            Q: self.public.Q,
            P2: self.public.P2.clone().scalar_mul(&rand_str_invert_fe.get_element()),
            paillier_pub: self.public.paillier_pub,
            c_key: c_key_new,
        };
        MasterKey2{
            public,
            private: party_two::Party2Private::update_private_key(&self.private, &rand_str_invert),
            chain_code: self.chain_code,
        }

    }
/*
    fn get_child(&self, location_in_hir: &Vec<BigInt>) -> MasterKey2{
        let mask = BigInt::from(2).pow(256) - BigInt::one();
        let public_key = self.public.Q.clone();
        for index in location_in_hir{
            let Q_bigint = BigInt::from(&public_key.pk_to_key_slice());
            let f = hmac_sha512::HMacSha512::create_hmac(&self.chain_code,vec![&Q, &location_in_hir[index] ]);
            let f_l = &f >> 256;
            let f_r = f & mask;
            let public_key = public_key.scalar_mul(&ECScalar::from_big_int(&f_l));
        }
        let f_l_fe: FE = ECScalar::from_big_int(&f_l);
        let f_r_fe : FE = ECScalar::from_big_int(&f_r);
        let f_r_invert = f_r.invert(&f_l_fe.get_q());
        let f_r_invert_fe: FE = ECScalar::from_big_int(&f_r_invert);

        let c_key_new = Paillier::mul(&self.public.paillier_pub,self.public.c_key.clone(), RawPlaintext::from(f_r_invert_fe));
        let P2_old = self.public.P2.clone();
        let public = Party2Public{
            Q: public_key,
            P2: P2_old.scalar_mul(&f_r_fe.get_element()).scalar_mul(&f_l_fe.get_element()),
            paillier_pub: self.public.paillier_pub,
            c_key :c_key_new,
        };
        MasterKey2{
            public,
            private: party_two::Party2Private::update_private_key(&self.private, &f_r_fe.mul(&f_l_fe.get_element()).to_big_int()),
            chain_code: f_r,
        }
    }
    */
}

impl<'a> MasterKey2<'a> {
    pub fn chain_code_first_message() -> dh_key_exchange::Party2FirstMessage {
        dh_key_exchange::Party2FirstMessage::create()
    }
    pub fn chain_code_second_message(
        party_one_first_message: &dh_key_exchange::Party1FirstMessage,
        party_one_second_message: &dh_key_exchange::Party1SecondMessage,
    ) -> dh_key_exchange::Party2SecondMessage {
        dh_key_exchange::Party2SecondMessage::verify_commitments_and_dlog_proof(
            &party_one_first_message.pk_commitment,
            &party_one_first_message.zk_pok_commitment,
            &party_one_second_message.zk_pok_blind_factor,
            &party_one_second_message.public_share,
            &party_one_second_message.pk_commitment_blind_factor,
            &party_one_second_message.d_log_proof,
        ).expect("")
    }

    pub fn compute_chain_code(
        first_message: &dh_key_exchange::Party1FirstMessage,
        party2_first_message: &dh_key_exchange::Party2FirstMessage,
    ) -> GE {
        dh_key_exchange::compute_pubkey_party2(party2_first_message, first_message)
    }

    pub fn key_gen_first_message() -> party_two::KeyGenFirstMsg {
        party_two::KeyGenFirstMsg::create()
    }
    pub fn key_gen_second_message(
        party_one_first_message: &party_one::KeyGenFirstMsg,
        party_one_second_message: &party_one::KeyGenSecondMsg,
        paillier_key_pair: &party_one::PaillierKeyPair,
        challenge: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
    ) -> (party_two::KeyGenSecondMsg, party_two::PaillierPublic, Challenge, VerificationAid ){
        let party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &party_one_first_message.pk_commitment,
            &party_one_first_message.zk_pok_commitment,
            &party_one_second_message.zk_pok_blind_factor,
            &party_one_second_message.public_share,
            &party_one_second_message.pk_commitment_blind_factor,
            &party_one_second_message.d_log_proof,
        ).expect("");
        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_key_pair.ek.clone(),
            encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
        };
        party_two::PaillierPublic::verify_range_proof(
            &party_two_paillier,
            &challenge,
            &encrypted_pairs,
            &proof,
        ).expect("");
        let (challenge, verification_aid) = party_two::PaillierPublic::generate_correct_key_challenge(&party_two_paillier);
        return (party_two_second_message, party_two_paillier, challenge, verification_aid);
    }

    pub fn key_gen_third_message(proof_result: &CorrectKeyProof, verification_aid: &VerificationAid) {
        let _result = party_two::PaillierPublic::verify_correct_key(
            proof_result, verification_aid).expect("");
    }


    pub fn set_master_key(chain_code : &GE, party2_first_message: &party_two::KeyGenFirstMsg, party1_first_message:&party_one::KeyGenFirstMsg, paillier_public: &party_two::PaillierPublic ) -> MasterKey2<'a>{
        let party2_public = Party2Public{
            Q: party_two::compute_pubkey(party2_first_message, party1_first_message),
            P2: party2_first_message.public_share.clone(),
            paillier_pub: paillier_public.ek.clone(),
            c_key: RawCiphertext::from(paillier_public.encrypted_secret_share.clone()),
        };
        let party2_private = party_two::Party2Private::set_private_key(&party2_first_message);
        MasterKey2{
            public: party2_public,
            private: party2_private,
            chain_code: chain_code.bytes_compressed_to_big_int(),
        }
    }


    pub fn key_rotate_first_message(
        party1_first_message: &coin_flip_optimal_rounds::Party1FirstMessage,
    ) -> (coin_flip_optimal_rounds::Party2FirstMessage) {
        coin_flip_optimal_rounds::Party2FirstMessage::share(&party1_first_message.proof)
    }

    pub fn key_rotate_second_message(
        party1_second_message: &coin_flip_optimal_rounds::Party1SecondMessage,
        party2_first_message: &coin_flip_optimal_rounds::Party2FirstMessage,
        party1_first_message: &coin_flip_optimal_rounds::Party1FirstMessage,
    ) -> Secp256k1Scalar {
        coin_flip_optimal_rounds::finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        )
    }
}
