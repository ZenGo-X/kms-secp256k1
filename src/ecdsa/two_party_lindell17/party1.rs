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
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE, GE};

use super::hd_key;
use super::{MasterKey1, MasterKey2, Party1Public};
use ecdsa::two_party_lindell17::party2::SignMessage;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::EphKeyGenFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::PDLFirstMessage as Party2PDLFirstMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::PDLSecondMessage as Party2PDLSecondMsg;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

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
            hd_key(location_in_hir, &self.public.q, &self.chain_code);

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
            p1: party_one_public_ec_key.clone(),
            p2: party2_first_message_public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
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

    pub fn recover_master_key(
        recovered_secret: FE,
        party_one_public: Party1Public,
        chain_code: BigInt,
    ) -> MasterKey1 {
        //  master key of party one from party one secret recovery:
        // q2 (public key of party two), chain code, and paillier data are needed for
        // recovery of party one master key. q2 and cc must be the same
        // as before. Therefore there are two options:
        // (1) party 1 kept the public data of the master key and can retrieve it (only private key was lost)
        // (2) party 1 lost the public data as well. in this case only party 2 can help with the public data.
        //     if party 2 becomes malicious it means two failures at the same time from which the system will not be able to recover.
        //     Therefore no point of running any secure protocol with party 2 and just accept the public data as is.
        // paillier data can be refreshed. Because it is likely that paillier private key was lost, therefore a new paillier scheme must be created
        // to make sure that party2 updates to the new paillier - a key rotation scheme must be performed. see test

        let (_, _, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(recovered_secret);
        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);
        // party one set her private key:
        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);
        MasterKey1 {
            public: party_one_public,
            private: party_one_private,
            chain_code: chain_code,
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
    ) -> Result<party_one::SignatureRecid, Errors> {
        let verify_party_two_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
            .is_ok();

        let signature_with_recid = party_one::Signature::compute_with_recid(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            &eph_ec_key_pair_party1,
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
