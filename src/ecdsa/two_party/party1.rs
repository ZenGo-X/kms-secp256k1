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
use super::hd_key;
use super::party2::SignMessage;
use super::{MasterKey1, MasterKey2, Party1Public};
use crate::Errors::{self, SignError};
use two_party_ecdsa::curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use two_party_ecdsa::curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use two_party_ecdsa::party_two::{
    PDLFirstMessage as Party2PDLFirstMsg, PDLSecondMessage as Party2PDLSecondMsg,
};
use two_party_ecdsa::zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};
use two_party_ecdsa::{
    party_one,
    party_two::{self, EphKeyGenFirstMsg},
    EncryptionKey,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenParty1Message2 {
    pub ecdh_second_message: party_one::KeyGenSecondMsg,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

impl MasterKey1 {
    pub fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey1 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code);

        let public = Party1Public {
            q: public_key_new_child,
            p1: self.public.p1,
            p2: self.public.p2 * f_l_new,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: self.public.c_key.clone(),
        };
        MasterKey1 {
            public,
            private: self.private.clone(),
            chain_code: cc_new.bytes_compressed_to_big_int(),
        }
    }

    pub fn set_master_key(
        chain_code: &BigInt,
        party_one_private: party_one::Party1Private,
        party_one_public_ec_key: &GE,
        party2_first_message_public_share: &GE,
        paillier_key_pair: party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(&party_one_private, party2_first_message_public_share),
            p1: *party_one_public_ec_key,
            p2: *party2_first_message_public_share,
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share,
        };

        MasterKey1 {
            public: party1_public,
            private: party_one_private,
            chain_code: chain_code.clone(),
        }
    }

    //  master key of party two from counter party recovery (party one recovers party two secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_two_secret: FE) -> MasterKey2 {
        let (_, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(party_two_secret);
        let party_two_paillier = party_two::PaillierPublic {
            ek: self.public.paillier_pub.clone(),
            encrypted_secret_share: self.public.c_key.clone(),
        };
        // set master keys:
        MasterKey2::set_master_key(
            &self.chain_code,
            &ec_key_pair_party2,
            &ec_key_pair_party2.public_share,
            &party_two_paillier,
        )
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
        KeyGenParty1Message2,
        party_one::PaillierKeyPair,
        party_one::Party1Private,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(comm_witness, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(ec_key_pair_party1);

        // party one set her private key:
        let party_one_private =
            party_one::Party1Private::set_private_key(ec_key_pair_party1, &paillier_key_pair);

        let range_proof = party_one::PaillierKeyPair::generate_range_proof(
            &paillier_key_pair,
            &party_one_private,
        );
        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
        (
            KeyGenParty1Message2 {
                ecdh_second_message: key_gen_second_message,
                ek: paillier_key_pair.ek.clone(),
                c_key: paillier_key_pair.encrypted_share.clone(),
                correct_key_proof,
                range_proof,
            },
            paillier_key_pair,
            party_one_private,
        )
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
    ) -> Result<party_one::SignatureRecid, Errors> {
        let verify_party_two_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
                .is_ok();

        let signature_with_recid = party_one::Signature::compute_with_recid(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            eph_ec_key_pair_party1,
            &party_two_sign_message
                .second_message
                .comm_witness
                .public_share,
        );

        // Creating a standard signature for the verification, currently discarding recid
        // TODO: Investigate what verification could be done with recid
        let signature = party_one::Signature {
            r: signature_with_recid.r.clone(),
            s: signature_with_recid.s.clone(),
        };


        let verify = party_one::verify(&signature, &self.public.q, message).is_ok();
        if verify {
            if verify_party_two_second_message {
                Ok(signature_with_recid)
            } else {
                println!("Invalid commitments:{:?}", eph_key_gen_first_message_party_two);
                println!("party_two_sign_message.second_message:{:?}", party_two_sign_message.second_message);
                println!("sig_r: {}", signature.r);
                println!("sig_s: {}", signature.s);
                Err(SignError)
            }
        } else {
            println!("Sig does not verify");
            println!("sig_r: {}", signature.r);
            println!("sig_s: {}", signature.s);
            Err(SignError)
        }
    }

    pub fn key_gen_third_message(
        party_two_pdl_first_message: &Party2PDLFirstMsg,
        party_one_private: &party_one::Party1Private,
    ) -> (party_one::PDLFirstMessage, party_one::PDLdecommit, BigInt) {
        party_one::PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &party_two_pdl_first_message,
        )
    }

    pub fn key_gen_fourth_message(
        pdl_party_two_first_message: &Party2PDLFirstMsg,
        pdl_party_two_second_message: &Party2PDLSecondMsg,
        party_one_private: party_one::Party1Private,
        pdl_decommit: party_one::PDLdecommit,
        alpha: BigInt,
    ) -> Result<party_one::PDLSecondMessage, ()> {
        party_one::PaillierKeyPair::pdl_second_stage(
            pdl_party_two_first_message,
            pdl_party_two_second_message,
            party_one_private,
            pdl_decommit,
            alpha,
        )
    }
}
