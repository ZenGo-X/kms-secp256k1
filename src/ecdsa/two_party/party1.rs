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
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, GE};

use super::hd_key;
use super::{MasterKey1, Party1Public};
use chain_code::two_party::party1::ChainCode1;
use ecdsa::two_party::party2::SignMessage;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::EphKeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::PDLFirstMessage as Party2PDLFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::PDLSecondMessage as Party2PDLSecondMsg;

use paillier::EncryptionKey;
use rotation::two_party::Rotation;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};
use Errors::{self, SignError};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenParty1Message2 {
    pub ecdh_second_message: party_one::KeyGenSecondMsg,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationParty1Message1 {
    pub ek: EncryptionKey,
    pub c_key_new: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

impl MasterKey1 {
    // before rotation make sure both parties have the same key
    pub fn rotate(
        self,
        cf: &Rotation,
        party_one_private: party_one::Party1Private,
        ek_new: &EncryptionKey,
        c_key_new: &BigInt,
    ) -> MasterKey1 {
        let public = Party1Public {
            q: self.public.q,
            p1: &self.public.p1 * &cf.rotation,
            p2: &self.public.p2 * &cf.rotation.invert(),
            paillier_pub: ek_new.clone(),
            c_key: c_key_new.clone(),
        };
        MasterKey1 {
            public,
            private: party_one_private,
            chain_code: self.chain_code,
        }
    }

    pub fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey1 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code.chain_code);

        let public = Party1Public {
            q: public_key_new_child,
            p1: self.public.p1.clone(),
            p2: self.public.p2.clone() * &f_l_new,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: self.public.c_key.clone(),
        };
        MasterKey1 {
            public,
            private: self.private.clone(),
            chain_code: ChainCode1 { chain_code: cc_new },
        }
    }

    pub fn set_master_key(
        chain_code: &GE,
        party_one_private: party_one::Party1Private,
        party_one_public_ec_key: &GE,
        party2_first_message_public_share: &GE,
        paillier_key_pair: party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(&party_one_private, party2_first_message_public_share),
            p1: party_one_public_ec_key.clone(),
            p2: party2_first_message_public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
        };

        MasterKey1 {
            public: party1_public,
            private: party_one_private,
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
        KeyGenParty1Message2,
        party_one::PaillierKeyPair,
        party_one::Party1Private,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(comm_witness, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        // party one set her private key:
        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

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

    pub fn key_gen_third_message(
        party_two_pdl_first_message: &Party2PDLFirstMsg,
        party_one_private: &party_one::Party1Private,
    ) -> (party_one::PDLFirstMessage, party_one::PDLdecommit) {
        party_one::PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &party_two_pdl_first_message,
        )
    }

    pub fn key_gen_fourth_message(
        pdl_party_one_first_message: &party_one::PDLFirstMessage,
        pdl_party_two_first_message: &Party2PDLFirstMsg,
        pdl_party_two_second_message: &Party2PDLSecondMsg,
        party_one_private: party_one::Party1Private,
        pdl_decommit: party_one::PDLdecommit,
    ) -> Result<(party_one::PDLSecondMessage), ()> {
        party_one::PaillierKeyPair::pdl_second_stage(
            pdl_party_one_first_message,
            pdl_party_two_first_message,
            pdl_party_two_second_message,
            party_one_private,
            pdl_decommit,
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
        if verify {
            if verify_party_two_second_message {
                Ok(signature)
            } else {
                Err(SignError)
            }
        } else {
            Err(SignError)
        }
    }

    pub fn rotation_first_message(
        &self,
        cf: &Rotation,
    ) -> (RotationParty1Message1, party_one::Party1Private) {
        let (ek_new, c_key_new, new_private, correct_key_proof, range_proof) =
            party_one::Party1Private::refresh_private_key(&self.private, &cf.rotation.to_big_int());

        (
            RotationParty1Message1 {
                ek: ek_new,
                c_key_new,
                correct_key_proof,
                range_proof,
            },
            new_private,
        )
    }

    pub fn rotation_second_message(
        rotate_party_two_message_one: &Party2PDLFirstMsg,
        party_one_private: &party_one::Party1Private,
    ) -> (party_one::PDLFirstMessage, party_one::PDLdecommit) {
        party_one::PaillierKeyPair::pdl_first_stage(
            &party_one_private,
            &rotate_party_two_message_one,
        )
    }

    pub fn rotation_third_message(
        self,
        rotation_first_message: &RotationParty1Message1,
        party_one_private_new: party_one::Party1Private,
        cf: &Rotation,
        rotate_party_one_second_message: &party_one::PDLFirstMessage,
        rotate_party_two_first_message: &Party2PDLFirstMsg,
        rotate_party_two_second_message: &Party2PDLSecondMsg,
        pdl_decommit: party_one::PDLdecommit,
    ) -> Result<((party_one::PDLSecondMessage, MasterKey1)), ()> {
        let rotate_party_one_third_message = party_one::PaillierKeyPair::pdl_second_stage(
            rotate_party_one_second_message,
            rotate_party_two_first_message,
            rotate_party_two_second_message,
            party_one_private_new.clone(),
            pdl_decommit,
        );
        let master_key_new = self.rotate(
            cf,
            party_one_private_new,
            &rotation_first_message.ek,
            &rotation_first_message.c_key_new,
        );
        match rotate_party_one_third_message {
            Ok(x) => Ok((x, master_key_new)),
            Err(_) => Err(()),
        }
    }
}
