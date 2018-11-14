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

use cryptography_utils::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use super::hd_key;
use super::{MasterKey2, Party2Public};
use chain_code::two_party::party2::ChainCode2;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::elliptic::curves::traits::ECPoint;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use paillier::*;
use rotation::two_party::Rotation;

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
        party2_first_message: &party_two::KeyGenFirstMsg,
        party1_first_message_public_chare: &GE,
        paillier_public: &party_two::PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: party_two::compute_pubkey(party2_first_message, party1_first_message_public_chare),
            p2: party2_first_message.public_share.clone(),
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = party_two::Party2Private::set_private_key(&party2_first_message);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: ChainCode2 {
                chain_code: chain_code.clone(),
            },
        }
    }
    pub fn key_gen_first_message() -> party_two::KeyGenFirstMsg {
        party_two::KeyGenFirstMsg::create()
    }

    // from predefined secret key
    pub fn key_gen_first_message_predefined(secret_share: &FE) -> party_two::KeyGenFirstMsg {
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(secret_share.clone())
    }

    pub fn key_gen_second_message(
        party_one_first_message_pk_commitment: &BigInt,
        party_one_first_message_zk_pok_commitment: &BigInt,
        party_one_second_message_zk_pok_blind_factor: &BigInt,
        party_one_second_message_public_share: &GE,
        party_one_second_message_pk_commitment_blind_factor: &BigInt,
        party_one_second_message_d_log_proof: &DLogProof,
        paillier_encryption_key: &EncryptionKey,
        paillier_encrypted_share: &BigInt,
        challenge: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
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
                &party_one_first_message_pk_commitment,
                &party_one_first_message_zk_pok_commitment,
                &party_one_second_message_zk_pok_blind_factor,
                &party_one_second_message_public_share,
                &party_one_second_message_pk_commitment_blind_factor,
                &party_one_second_message_d_log_proof,
            );

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let range_proof = party_two::PaillierPublic::verify_range_proof(
            &party_two_paillier,
            &challenge,
            &encrypted_pairs,
            &proof,
        );

        let pdl_chal = party_two_paillier.pdl_challenge(party_one_second_message_public_share);

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

    pub fn sign_first_message() -> party_two::EphKeyGenFirstMsg {
        party_two::EphKeyGenFirstMsg::create_commitments()
    }
    pub fn sign_second_message(
        &self,
        eph_first_message_party_two: &party_two::EphKeyGenFirstMsg,
        eph_first_message_public_share_party_one: &GE,
        proof: &DLogProof,
        message: &BigInt,
    ) -> SignMessage {
        let eph_key_gen_second_message =
            party_two::EphKeyGenSecondMsg::verify_and_decommit(eph_first_message_party_two, proof)
                .expect("");

        let partial_sig = party_two::PartialSig::compute(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            &eph_first_message_party_two,
            eph_first_message_public_share_party_one,
            message,
        );
        SignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }
}
