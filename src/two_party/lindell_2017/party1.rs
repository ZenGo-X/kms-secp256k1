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
use cryptography_utils::cryptographic_primitives::hashing::hmac_sha512;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use cryptography_utils::elliptic::curves::secp256_k1::Secp256k1Scalar;
use cryptography_utils::elliptic::curves::traits::ECPoint;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use cryptography_utils::{BigInt, FE, GE};

use cryptography_utils::cryptographic_primitives::hashing::traits::KeyedHash;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;

use super::{MasterKey1, Party1Public};
use paillier::*;

impl ManagementSystem for MasterKey1 {
    // before rotation make sure both parties have the same key
    fn rotate(self, cf: &BigInt) -> MasterKey1 {
        let rand_str: FE = ECScalar::from(cf);
        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(cf),
        );

        let c_key: &BigInt = c_key_new.0.as_ref();

        let public = Party1Public {
            q: self.public.q,
            p1: self.public.p1.clone().scalar_mul(&rand_str.get_element()),
            paillier_pub: self.public.paillier_pub,
            c_key: c_key.to_owned(),
        };
        MasterKey1 {
            public,
            private: party_one::Party1Private::update_private_key(&self.private, cf),
            chain_code: self.chain_code,
        }
    }

    fn get_child(&self, mut location_in_hir: Vec<BigInt>) -> MasterKey1 {
        let mask = BigInt::from(2).pow(256) - BigInt::one();
        let public_key = self.public.q.clone();
        let chain_code = self.chain_code.clone();

        // calc first element:
        let first = location_in_hir.remove(0);
        let master_public_key_vec = public_key.pk_to_key_slice();
        let q_bigint = BigInt::from(master_public_key_vec.as_slice());
        let f = hmac_sha512::HMacSha512::create_hmac(
            &chain_code,
            vec![&q_bigint, &first, &BigInt::zero()],
        );
        let f_l = &f >> 256;
        let f_r = &f & &mask;
        let f_l_fe: FE = ECScalar::from(&f_l);
        let f_r_invert = f_r.invert(&f_l_fe.q()).unwrap();
        let f_r_invert_fe_new: FE = ECScalar::from(&f_r_invert);

        let chain_code = hmac_sha512::HMacSha512::create_hmac(
            &chain_code,
            vec![&q_bigint, &first, &BigInt::zero()],
        );
        let public_key = self.public.q.clone();
        let public_key_new = public_key.scalar_mul(&f_l_fe.get_element());
        let (public_key_new_child, f_r_invert_fe_new_child, _f_new) =
            location_in_hir
                .iter()
                .fold((public_key_new, f_r_invert_fe_new, f), |acc, index| {
                    let master_public_key_vec = acc.0.pk_to_key_slice();
                    let q_bigint = BigInt::from(master_public_key_vec.as_slice());
                    let f = hmac_sha512::HMacSha512::create_hmac(
                        &chain_code,
                        vec![&q_bigint, index, &BigInt::zero()],
                    );
                    let f_l = &f >> 256;
                    let f_r = &f & &mask;
                    let f_l_fe: FE = ECScalar::from(&f_l);
                    let f_r_invert = f_r.invert(&f_l_fe.q()).unwrap();
                    let f_r_invert_fe: FE = ECScalar::from(&f_r_invert);
                    (
                        acc.0.scalar_mul(&f_l_fe.get_element()),
                        acc.1.mul(&f_r_invert_fe.get_element()),
                        f,
                    )
                });

        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(&f_r_invert_fe_new_child.to_big_int()),
        );
        let p1_old = self.public.p1.clone();

        let c_key: &BigInt = c_key_new.0.as_ref();

        let public = Party1Public {
            q: public_key_new_child,
            p1: p1_old.scalar_mul(&f_r_invert_fe_new_child.get_element()),
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: c_key.to_owned(),
        };
        MasterKey1 {
            public,
            private: party_one::Party1Private::update_private_key(
                &self.private,
                &f_r_invert_fe_new_child.to_big_int(),
            ),
            chain_code: chain_code,
        }
    }
}

impl MasterKey1 {
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
    ) -> GE {
        dh_key_exchange::compute_pubkey_party1(first_message, party2_first_message_public_share)
    }

    pub fn key_gen_first_message() -> party_one::KeyGenFirstMsg {
        party_one::KeyGenFirstMsg::create_commitments()
    }
    pub fn key_gen_second_message(
        first_message: &party_one::KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> (
        party_one::KeyGenSecondMsg,
        party_one::PaillierKeyPair,
        EncryptedPairs,
        ChallengeBits,
        Proof,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(&first_message, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(first_message);
        let (encrypted_pairs, challenge, proof) =
            party_one::PaillierKeyPair::generate_range_proof(&paillier_key_pair, &first_message);
        (
            key_gen_second_message,
            paillier_key_pair,
            encrypted_pairs,
            challenge,
            proof,
        )
    }

    pub fn key_gen_third_message(
        paillier_key_pair: &party_one::PaillierKeyPair,
        challenge: &proof::Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        party_one::PaillierKeyPair::generate_proof_correct_key(&paillier_key_pair, &challenge)
    }

    pub fn set_master_key(
        chain_code: &GE,
        party1_first_message: &party_one::KeyGenFirstMsg,
        party2_first_message_public_share: &GE,
        paillier_key_pair: &party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(party1_first_message, party2_first_message_public_share),
            p1: party1_first_message.public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
        };
        let part1_private =
            party_one::Party1Private::set_private_key(&party1_first_message, &paillier_key_pair);
        MasterKey1 {
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
