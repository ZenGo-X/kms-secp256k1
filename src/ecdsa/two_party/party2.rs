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

use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenFirstMsg as Party1KeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::PDLFirstMessage as Party1PDLFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::PDLSecondMessage as Party1PDLSecondMsg;

use super::party1::{KeyGenParty1Message2, RotationParty1Message1};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

use super::hd_key;
use super::{MasterKey1, MasterKey2, Party2Public};
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use rotation::two_party::Rotation;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub partial_sig: party_two::PartialSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {
    pub key_gen_second_message: party_two::KeyGenSecondMsg,
    pub pdl_first_message: party_two::PDLFirstMessage,
}

impl MasterKey2 {
    pub fn rotate(self, cf: &Rotation, new_paillier: &party_two::PaillierPublic) -> MasterKey2 {
        let rand_str_invert_fe = cf.rotation.invert();
        let c_key_new = new_paillier.encrypted_secret_share.clone();

        //TODO: use proper set functions
        let public = Party2Public {
            q: self.public.q,
            p1: self.public.p1.clone() * &cf.rotation,
            p2: &self.public.p2 * &cf.rotation.invert(),
            paillier_pub: new_paillier.ek.clone(),
            c_key: c_key_new,
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

    pub fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey2 {
        let (public_key_new_child, f_l_new, cc_new) =
            hd_key(location_in_hir, &self.public.q, &self.chain_code);

        let public = Party2Public {
            q: public_key_new_child,
            p2: self.public.p2.clone() * &f_l_new,
            p1: self.public.p1.clone(),
            paillier_pub: self.public.paillier_pub.clone(),
            c_key: self.public.c_key.clone(),
        };
        MasterKey2 {
            public,
            private: party_two::Party2Private::update_private_key(
                &self.private,
                &f_l_new.to_big_int(),
            ),
            chain_code: cc_new.bytes_compressed_to_big_int(),
        }
    }

    pub fn set_master_key(
        chain_code: &BigInt,
        ec_key_pair_party2: &party_two::EcKeyPair,
        party1_second_message_public_share: &GE,
        paillier_public: &party_two::PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: party_two::compute_pubkey(ec_key_pair_party2, party1_second_message_public_share),
            p2: ec_key_pair_party2.public_share.clone(),
            p1: party1_second_message_public_share.clone(),
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: chain_code.clone(),
        }
    }

    //  master key of party one from counter party recovery (party two recovers party one secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_one_secret: FE) -> MasterKey1 {
        let (_, _, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(party_one_secret);
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        // set master keys:
        MasterKey1::set_master_key(
            &self.chain_code,
            party_one_private,
            &ec_key_pair_party1.public_share,
            &self.public.p2,
            paillier_key_pair,
        )
    }

    pub fn recover_master_key(
        recovered_secret: FE,
        party_two_public: Party2Public,
        chain_code: BigInt,
    ) -> MasterKey2 {
        //  master key of party two from party two secret recovery:
        // q1 (public key of party one), chain code, and public paillier data (c_key, ek) are needed for
        // recovery of party two master key. paillier data can be refreshed but q1 and cc must be the same
        // as before. Therefore there are two options:
        // (1) party 2 kept the public data of the master key and can retrieve it (only private key was lost)
        // (2) party 2 lost the public data as well. in this case only party 1 can help with the public data.
        //     if party 1 becomes malicious it means two failures at the same time from which the system will not be able to recover.
        //     Therefore no point of running any secure protocol with party 1 and just accept the public data as is.

        let (_, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create_with_fixed_secret_share(recovered_secret);
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        MasterKey2 {
            public: party_two_public,
            private: party2_private,
            chain_code,
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
        party_one_second_message: &KeyGenParty1Message2,
    ) -> Result<
        (
            Party2SecondMessage,
            party_two::PaillierPublic,
            party_two::PDLchallenge,
        ),
        (),
    > {
        let paillier_encryption_key = party_one_second_message.ek.clone();
        let paillier_encrypted_share = party_one_second_message.c_key.clone();

        let party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message.ecdh_second_message,
            );

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let range_proof_verify = party_two::PaillierPublic::verify_range_proof(
            &party_two_paillier,
            &party_one_second_message.range_proof,
        );

        let (pdl_first_message, pdl_chal) = party_two_paillier.pdl_challenge(
            &party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
        );

        let correct_key_verify = party_one_second_message
            .correct_key_proof
            .verify(&party_two_paillier.ek);

        match range_proof_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => match party_two_second_message {
                    Ok(t) => Ok((
                        Party2SecondMessage {
                            key_gen_second_message: t,
                            pdl_first_message,
                        },
                        party_two_paillier,
                        pdl_chal,
                    )),
                    Err(_verify_com_and_dlog_party_one) => Err(()),
                },
                Err(_correct_key_error) => Err(()),
            },
            Err(_range_proof_error) => Err(()),
        }
    }

    pub fn key_gen_third_message(
        pdl_chal: &party_two::PDLchallenge,
    ) -> party_two::PDLSecondMessage {
        party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal)
    }

    pub fn key_gen_fourth_message(
        pdl_chal: &party_two::PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMsg,
        party_one_pdl_second_message: &Party1PDLSecondMsg,
    ) -> Result<(), ()> {
        party_two::PaillierPublic::verify_pdl(
            pdl_chal,
            party_one_pdl_first_message,
            party_one_pdl_second_message,
        )
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

    // party2 receives new paillier key and new c_key = Enc(x1_new) = Enc(r*x_1).
    // party2 can compute locally the updated Q1. This is why this set of messages
    // is rotation and not new key gen.
    // party2 needs to verify range proof on c_key_new and correct key proof on the new paillier keys
    pub fn rotate_first_message(
        &self,
        cf: &Rotation,
        party_one_rotation_first_message: &RotationParty1Message1,
    ) -> Result<
        (
            party_two::PDLFirstMessage,
            party_two::PDLchallenge,
            party_two::PaillierPublic,
        ),
        (),
    > {
        let party_two_paillier = party_two::PaillierPublic {
            ek: party_one_rotation_first_message.ek.clone(),
            encrypted_secret_share: party_one_rotation_first_message.c_key_new.clone(),
        };
        let range_proof_verify = party_one_rotation_first_message.range_proof.verify(
            &party_two_paillier.ek,
            &party_two_paillier.encrypted_secret_share,
        );

        let correct_key_verify = party_one_rotation_first_message
            .correct_key_proof
            .verify(&party_two_paillier.ek);

        let (pdl_first_message, pdl_chal) =
            party_two_paillier.pdl_challenge(&(&self.public.p1 * &cf.rotation));

        match range_proof_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => Ok((pdl_first_message, pdl_chal, party_two_paillier)),
                Err(_correct_key_error) => Err(()),
            },
            Err(_range_proof_error) => Err(()),
        }
    }

    pub fn rotate_second_message(
        pdl_chal: &party_two::PDLchallenge,
    ) -> party_two::PDLSecondMessage {
        party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal)
    }

    pub fn rotate_third_message(
        self,
        cf: &Rotation,
        party_two_paillier: &party_two::PaillierPublic,
        pdl_chal: &party_two::PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMsg,
        party_one_pdl_second_message: &Party1PDLSecondMsg,
    ) -> Result<MasterKey2, ()> {
        match party_two::PaillierPublic::verify_pdl(
            pdl_chal,
            party_one_pdl_first_message,
            party_one_pdl_second_message,
        ) {
            Ok(_) => {
                let master_key = self.rotate(cf, party_two_paillier);
                Ok(master_key)
            }
            Err(_) => Err(()),
        }
    }
}
