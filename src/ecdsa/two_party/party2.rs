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
use ManagementSystem;

use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenFirstMsg as Party1KeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenSecondMsg as Party1KeyGenSecondMsg;

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use super::hd_key;
use super::{MasterKey2, Party2Public};
use chain_code::two_party::party2::ChainCode2;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use paillier::{EncryptionKey, Mul, Paillier, RawCiphertext, RawPlaintext};
use rotation::two_party::Rotation;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub partial_sig: party_two::PartialSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

impl ManagementSystem for MasterKey2 {
    fn rotate(self, cf: &Rotation) -> MasterKey2 {
        let rand_str_invert_fe = cf.rotation.invert();
        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(cf.rotation.to_big_int()),
        );

        let c_key: &BigInt = c_key_new.0.as_ref();

        //TODO: use proper set functions
        let public = Party2Public {
            q: self.public.q,
            p2: self
                .public
                .p2
                .clone()
                .scalar_mul(&rand_str_invert_fe.get_element()),
            paillier_pub: self.public.paillier_pub,
            c_key: c_key.to_owned(),
        };
        MasterKey2 {
            public,
            private: party_two::Party2Private::update_private_key(
                &self.private,
                &rand_str_invert_fe.to_big_int(),
            ),
            chain_code: self.chain_code,
        }
    }

    fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey2 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code.chain_code);

        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(&f_l_new.to_big_int()),
        );
        let p2_old = self.public.p2.clone();

        let c_key: &BigInt = c_key_new.0.as_ref();

        let public = Party2Public {
            q: public_key_new_child,
            p2: p2_old,
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: c_key.to_owned(),
        };
        MasterKey2 {
            public,
            private: party_two::Party2Private::update_private_key(&self.private, &BigInt::one()),
            chain_code: ChainCode2 { chain_code: cc_new },
        }
    }
}

impl MasterKey2 {
    pub fn set_master_key(
        chain_code: &GE,
        ec_key_pair_party2: &party_two::EcKeyPair,
        party1_second_message_public_share: &GE,
        paillier_public: &party_two::PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: party_two::compute_pubkey(ec_key_pair_party2, party1_second_message_public_share),
            p2: ec_key_pair_party2.public_share.clone(),
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: ChainCode2 {
                chain_code: chain_code.clone(),
            },
        }
    }
    pub fn key_gen_first_message() -> (party_two::KeyGenFirstMsg, party_two::EcKeyPair) {
        party_two::KeyGenFirstMsg::create()
    }

    // from predefined secret key
    pub fn key_gen_first_message_predefined(
        secret_share: &FE,
    ) -> (party_two::KeyGenFirstMsg, party_two::EcKeyPair) {
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(secret_share.clone())
    }

    pub fn key_gen_second_message(
        party_one_first_message: &Party1KeyGenFirstMsg,
        party_one_second_message: &Party1KeyGenSecondMsg,
        paillier_encryption_key: &EncryptionKey,
        paillier_encrypted_share: &BigInt,
        range_proof: &RangeProofNi,
        correct_key_proof: &NICorrectKeyProof,
    ) -> Result<
        (
            Result<party_two::KeyGenSecondMsg, ProofError>,
            party_two::PaillierPublic,
            party_two::PDLchallenge,
        ),
        (),
    > {
        let party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            );

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let range_proof =
            party_two::PaillierPublic::verify_range_proof(&party_two_paillier, &range_proof);

        let pdl_chal =
            party_two_paillier.pdl_challenge(&party_one_second_message.comm_witness.public_share);

        let correct_key_verify = correct_key_proof.verify(&party_two_paillier.ek);

        match range_proof {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => Ok((party_two_second_message, party_two_paillier, pdl_chal)),
                Err(_correct_key_error) => Err(()),
            },
            Err(_range_proof_error) => Err(()),
        }
    }

    pub fn key_gen_third_message(pdl_chal: &party_two::PDLchallenge) -> party_two::PDLdecommit {
        let pdl_decom = party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal);
        pdl_decom
    }

    pub fn key_gen_fourth_message(
        pdl_chal: &party_two::PDLchallenge,
        blindness: &BigInt,
        q_hat: &GE,
        c_hat: &BigInt,
    ) -> Result<(), ()> {
        party_two::PaillierPublic::verify_pdl(pdl_chal, blindness, q_hat, c_hat)
    }

    pub fn sign_first_message() -> (
        party_two::EphKeyGenFirstMsg,
        party_two::EphCommWitness,
        party_two::EphEcKeyPair,
    ) {
        party_two::EphKeyGenFirstMsg::create_commitments()
    }
    pub fn sign_second_message(
        &self,
        ec_key_pair_party2: &party_two::EphEcKeyPair,
        eph_comm_witness: party_two::EphCommWitness,
        eph_party1_first_message: &Party1EphKeyGenFirstMsg,
        message: &BigInt,
    ) -> SignMessage {
        let eph_key_gen_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            eph_party1_first_message,
        )
        .expect("");

        let partial_sig = party_two::PartialSig::compute(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            &ec_key_pair_party2,
            &eph_party1_first_message.public_share,
            message,
        );
        SignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }
}
