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
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE, GE};
use ManagementSystem;

use super::hd_key;
use super::{MasterKey1, Party1Public};
use chain_code::two_party::party1::ChainCode1;
use ecdsa::two_party::party2::SignMessage;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::EphKeyGenFirstMsg;
use paillier::*;
use rotation::two_party::Rotation;
use Errors::{self, SignError};

impl ManagementSystem for MasterKey1 {
    // before rotation make sure both parties have the same key
    fn rotate(self, cf: &Rotation) -> MasterKey1 {
        let rand_str: FE = cf.rotation.clone();
        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(cf.rotation.to_big_int()),
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
            private: party_one::Party1Private::update_private_key(
                &self.private,
                &cf.rotation.to_big_int(),
            ),
            chain_code: self.chain_code,
        }
    }

    fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey1 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code.chain_code);

        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(&f_l_new.to_big_int()),
        );
        let p1_old = self.public.p1.clone();

        let c_key: &BigInt = c_key_new.0.as_ref();

        let public = Party1Public {
            q: public_key_new_child,
            p1: p1_old * &f_l_new,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: c_key.to_owned(),
        };
        MasterKey1 {
            public,
            private: party_one::Party1Private::update_private_key(
                &self.private,
                &f_l_new.to_big_int(),
            ),
            chain_code: ChainCode1 { chain_code: cc_new },
        }
    }
}

impl MasterKey1 {
    pub fn set_master_key(
        chain_code: &GE,
        ec_key_pair_party1: &party_one::EcKeyPair,
        party2_first_message_public_share: &GE,
        paillier_key_pair: &party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(ec_key_pair_party1, party2_first_message_public_share),
            p1: ec_key_pair_party1.public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
        };
        let part1_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);
        MasterKey1 {
            public: party1_public,
            private: part1_private,
            chain_code: ChainCode1 {
                chain_code: chain_code.clone(),
            },
        }
    }

    pub fn key_gen_first_message() -> (
        party_one::KeyGenFirstMsg,
        party_one::CommWitness,
        party_one::EcKeyPair,
    ) {
        party_one::KeyGenFirstMsg::create_commitments()
    }
    pub fn key_gen_second_message(
        comm_witness: party_one::CommWitness,
        ec_key_pair_party1: &party_one::EcKeyPair,
        proof: &DLogProof,
    ) -> (
        party_one::KeyGenSecondMsg,
        party_one::PaillierKeyPair,
        EncryptedPairs,
        ChallengeBits,
        Proof,
        NICorrectKeyProof,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(comm_witness, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);
        let (encrypted_pairs, challenge, range_proof) =
            party_one::PaillierKeyPair::generate_range_proof(
                &paillier_key_pair,
                &ec_key_pair_party1,
            );
        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
        (
            key_gen_second_message,
            paillier_key_pair,
            encrypted_pairs,
            challenge,
            range_proof,
            correct_key_proof,
        )
    }

    pub fn key_gen_third_message(
        paillier_key_pair: &party_one::PaillierKeyPair,
        pdl_chal: &BigInt,
    ) -> party_one::PDL {
        paillier_key_pair.pdl_first_stage(pdl_chal)
    }

    pub fn key_gen_fourth_message(
        pdl: &party_one::PDL,
        c_tag_tag: &BigInt,
        ec_key_pair: party_one::EcKeyPair,
        a: &BigInt,
        b: &BigInt,
        blindness: &BigInt,
    ) -> Result<(party_one::PDLdecommit), ()> {
        party_one::PaillierKeyPair::pdl_second_stage(pdl, c_tag_tag, ec_key_pair, a, b, blindness)
    }

    pub fn sign_first_message() -> (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) {
        party_one::EphKeyGenFirstMsg::create()
    }

    pub fn sign_second_message(
        &self,
        party_two_sign_message: &SignMessage,
        eph_key_gen_first_message_party_two: &EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: &party_one::EphEcKeyPair,
        message: &BigInt,
    ) -> Result<party_one::Signature, Errors> {
        let verify_party_two_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
            .is_ok();

        let signature = party_one::Signature::compute(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            &eph_ec_key_pair_party1,
            &party_two_sign_message
                .second_message
                .comm_witness
                .public_share,
        );

        let verify = party_one::verify(&signature, &self.public.q, message).is_ok();
        match verify {
            true => match verify_party_two_second_message {
                true => Ok(signature),
                false => Err(SignError),
            },
            false => Err(SignError),
        }
    }
}
