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
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;
use paillier::proof::Challenge;

use cryptography_utils::cryptographic_primitives::hashing::hmac_sha512;
use cryptography_utils::cryptographic_primitives::hashing::traits::KeyedHash;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;
use cryptography_utils::elliptic::curves::secp256_k1::Secp256k1Scalar;
use cryptography_utils::elliptic::curves::traits::ECPoint;
use cryptography_utils::elliptic::curves::traits::ECScalar;

use super::{MasterKey2, Party2Public};
use paillier::*;

impl ManagementSystem for MasterKey2 {
    fn rotate(self, cf: &BigInt) -> MasterKey2 {
        let rand_str: FE = ECScalar::from(cf);
        let rand_str_invert = cf.invert(&rand_str.q()).unwrap();
        let rand_str_invert_fe: FE = ECScalar::from(&rand_str_invert);
        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(cf),
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
            private: party_two::Party2Private::update_private_key(&self.private, &rand_str_invert),
            chain_code: self.chain_code,
        }
    }

    fn get_child(&self, mut location_in_hir: Vec<BigInt>) -> MasterKey2 {
        let mask = BigInt::from(2).pow(256) - BigInt::one();
        let public_key = self.public.q.clone();

        let chain_code = self.chain_code.clone();
        // calc first element:
        let first = location_in_hir.remove(0);
        let master_public_key_vec = public_key.pk_to_key_slice();
        let q_bigint = BigInt::from(master_public_key_vec.as_slice());
        let f = hmac_sha512::HMacSha512::create_hmac(
            &chain_code,
            &vec![&q_bigint, &first, &BigInt::zero()],
        );
        let f_l = &f >> 256;
        let f_r = &f & &mask;
        let f_l_fe: FE = ECScalar::from(&f_l);
        let f_r_fe: FE = ECScalar::from(&f_r);
        let f_r_invert = f_r.invert(&f_l_fe.q()).unwrap();
        let f_r_invert_fe: FE = ECScalar::from(&f_r_invert);
        let fr_mul_fl = f_l_fe.mul(&f_r_fe.get_element());
        let chain_code = hmac_sha512::HMacSha512::create_hmac(
            &chain_code,
            &vec![&q_bigint, &first, &BigInt::zero()],
        ) >> 256;
        let public_key = self.public.q.clone();
        let public_key_new = public_key.scalar_mul(&f_l_fe.get_element());
        let (public_key_new_child, fr_mul_fl_new_child, f_r_invert_fe_new_child, _f_new) =
            location_in_hir.iter().fold(
                (public_key_new, fr_mul_fl, f_r_invert_fe, f),
                |acc, index| {
                    let master_public_key_vec = acc.0.pk_to_key_slice();
                    let q_bigint = BigInt::from(master_public_key_vec.as_slice());
                    let f = hmac_sha512::HMacSha512::create_hmac(
                        &chain_code,
                        &vec![&q_bigint, index, &BigInt::zero()],
                    );
                    let f_l = &f >> 256;
                    let f_r = &f & &mask;
                    let f_l_fe: FE = ECScalar::from(&f_l);
                    let f_r_fe: FE = ECScalar::from(&f_r);
                    let f_r_invert = f_r.invert(&f_l_fe.q()).unwrap();
                    let f_r_invert_fe: FE = ECScalar::from(&f_r_invert);
                    let fr_mo_fl = f_l_fe.mul(&f_r_fe.get_element());
                    (
                        acc.0.scalar_mul(&f_l_fe.get_element()),
                        acc.1.mul(&fr_mo_fl.get_element()),
                        acc.2.mul(&f_r_invert_fe.get_element()),
                        f,
                    )
                },
            );

        let c_key_new = Paillier::mul(
            &self.public.paillier_pub,
            RawCiphertext::from(self.public.c_key.clone()),
            RawPlaintext::from(&f_r_invert_fe_new_child.to_big_int()),
        );
        let p2_old = self.public.p2.clone();

        let c_key: &BigInt = c_key_new.0.as_ref();

        let public = Party2Public {
            q: public_key_new_child,
            p2: p2_old.scalar_mul(&fr_mul_fl_new_child.get_element()),
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: c_key.to_owned(),
        };
        MasterKey2 {
            public,
            private: party_two::Party2Private::update_private_key(
                &self.private,
                &fr_mul_fl_new_child.to_big_int(),
            ),
            chain_code: chain_code,
        }
    }
}

impl MasterKey2 {
    pub fn chain_code_first_message() -> dh_key_exchange::Party2FirstMessage {
        dh_key_exchange::Party2FirstMessage::create()
    }
    pub fn chain_code_second_message(
        party_one_first_message_pk_commitment: &BigInt,
        party_one_first_message_zk_pok_commitment: &BigInt,
        party_one_second_message_zk_pok_blind_factor: &BigInt,
        party_one_second_message_public_share: &GE,
        party_one_second_message_pk_commitment_blind_factor: &BigInt,
        party_one_second_message_d_log_proof: &DLogProof,
    ) -> Result<dh_key_exchange::Party2SecondMessage, ProofError> {
        dh_key_exchange::Party2SecondMessage::verify_commitments_and_dlog_proof(
            &party_one_first_message_pk_commitment,
            &party_one_first_message_zk_pok_commitment,
            &party_one_second_message_zk_pok_blind_factor,
            &party_one_second_message_public_share,
            &party_one_second_message_pk_commitment_blind_factor,
            &party_one_second_message_d_log_proof,
        )
    }

    pub fn compute_chain_code(
        first_message_public_share: &GE,
        party2_first_message: &dh_key_exchange::Party2FirstMessage,
    ) -> GE {
        dh_key_exchange::compute_pubkey_party2(party2_first_message, first_message_public_share)
    }

    pub fn key_gen_first_message() -> party_two::KeyGenFirstMsg {
        party_two::KeyGenFirstMsg::create()
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
    ) -> Result<
        (
            Result<party_two::KeyGenSecondMsg, ProofError>,
            party_two::PaillierPublic,
            Challenge,
            VerificationAid,
        ),
        ProofError,
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

        match range_proof {
            Ok(_proof) => {
                let (challenge, verification_aid) =
                    party_two::PaillierPublic::generate_correct_key_challenge(&party_two_paillier);
                Ok((
                    party_two_second_message,
                    party_two_paillier,
                    challenge,
                    verification_aid,
                ))
            }
            Err(_range_proof_error) => Err(ProofError),
        }
    }

    pub fn key_gen_third_message(
        proof_result: &CorrectKeyProof,
        verification_aid: &VerificationAid,
    ) -> Result<(), CorrectKeyProofError> {
        party_two::PaillierPublic::verify_correct_key(proof_result, verification_aid)
    }

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
