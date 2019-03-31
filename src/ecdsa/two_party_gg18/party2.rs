#![allow(non_snake_case)]
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

use super::*;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;
use curv::{FE, GE};
use ecdsa::two_party_gg18::{MasterKey2, MasterKeyPublic};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::{MessageA, MessageB};
use paillier::EncryptionKey;

impl MasterKey2 {
    pub fn key_gen_first_message() -> (Keys, KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let party_keys = Keys::create(2 as usize);
        let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        (party_keys, bc_i, decom_i)
    }

    pub fn key_gen_third_message(
        party2_keys: &Keys,
        party1_message1: KeyGenBroadcastMessage1,
        party2_message1: KeyGenBroadcastMessage1,
        party1_message2: KeyGenDecommitMessage1,
        party2_message2: KeyGenDecommitMessage1,
    ) -> (KeyGenMessage3, FE, Vec<GE>, Vec<EncryptionKey>) {
        let y_slice = &[party1_message2.y_i, party2_keys.y_i];
        let decom_slice = &[party1_message2, party2_message2];
        let bc1_slice = &[party1_message1.clone(), party2_message1.clone()];
        let paillier_enc_slice = &[party1_message1.e.clone(), party2_message1.e.clone()];
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        let (vss_scheme, secret_shares, _index) = party2_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames,
                &decom_slice.to_vec(),
                &bc1_slice.to_vec(),
            )
            .expect("invalid key");
        let key_gen_message3 = KeyGenMessage3 {
            vss_scheme,
            secret_share: secret_shares[0],
        };
        (
            key_gen_message3,
            secret_shares[1],
            y_slice.to_vec(),
            paillier_enc_slice.to_vec(),
        )
    }

    pub fn key_gen_fourth_message(
        party2_keys: &Keys,
        vss_scheme_party1: VerifiableSS,
        vss_scheme_party2: VerifiableSS,
        party1_ss_share_1: FE,
        party2_ss_share_1: FE,
        y_vec: &Vec<GE>,
    ) -> (SharedKeys, DLogProof, Vec<VerifiableSS>) {
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        let vss_slice = &[vss_scheme_party1, vss_scheme_party2];
        let ss_slice = &[party1_ss_share_1, party2_ss_share_1];
        let (shared_keys, dlog_proof) = party2_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                y_vec,
                &ss_slice.to_vec(),
                &vss_slice.to_vec(),
                &(2 as usize),
            )
            .expect("invalid vss");
        (shared_keys, dlog_proof, vss_slice.to_vec())
    }

    pub fn set_master_key(
        dlog_proof: Vec<DLogProof>,
        y_vec: Vec<GE>,
        party2_keys: Keys,
        party2_shared_keys: SharedKeys,
        vss_vec: Vec<VerifiableSS>,
        paillier_enc_vec: Vec<EncryptionKey>,
        chain_code: &BigInt,
    ) -> Self {
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        Keys::verify_dlog_proofs(&parames, &dlog_proof, &y_vec).expect("bad dlog proof");
        let master_key_public = MasterKeyPublic {
            q: y_vec[0] + y_vec[1],
            vss_scheme_vec: vss_vec,
            paillier_key_vec: paillier_enc_vec,
        };

        let master_key_private = PartyPrivate::set_private(party2_keys, party2_shared_keys);

        let master_key2 = MasterKey2 {
            public: master_key_public,
            private: master_key_private,
            chain_code: chain_code.clone(),
        };
        master_key2
    }

    pub fn sign_first_message(&self) -> (SignMessage1, SignDecommitPhase1, SignKeys) {
        let index: usize = 1;
        let index_list = [0 as usize, 1 as usize].to_vec();

        let sign_keys = SignKeys::create(
            &self.private,
            &self.public.vss_scheme_vec[1],
            index,
            &index_list,
        );

        let (com, decommit) = sign_keys.phase1_broadcast();
        let m_a_k = MessageA::a(&sign_keys.k_i, &self.public.paillier_key_vec[1]);

        let sign_message1 = SignMessage1 { com, m_a_k };
        (sign_message1, decommit, sign_keys)
    }

    pub fn sign_second_message(
        &self,
        party1_message1: &SignMessage1,
        party2_sign_keys: &SignKeys,
    ) -> (SignMessage2, FE, FE) {
        let (m_b_gamma, beta) = MessageB::b(
            &party2_sign_keys.gamma_i,
            &self.public.paillier_key_vec[0],
            party1_message1.m_a_k.clone(),
        );
        let (m_b_w, ni) = MessageB::b(
            &party2_sign_keys.w_i,
            &&self.public.paillier_key_vec[0],
            party1_message1.m_a_k.clone(),
        );
        let party2_message2 = SignMessage2 { m_b_gamma, m_b_w };

        (party2_message2, beta, ni)
    }

    pub fn sign_third_message(
        &self,
        party1_message2: &SignMessage2,
        party2_sign_keys: &SignKeys,
        beta: FE,
        ni: FE,
    ) -> (SignMessage3, FE) {
        let alpha = party1_message2
            .m_b_gamma
            .verify_proofs_get_alpha_gg18(&self.private, &party2_sign_keys.k_i)
            .expect("wrong dlog or m_b");;
        let miu = party1_message2
            .m_b_w
            .verify_proofs_get_alpha_gg18(&self.private, &party2_sign_keys.k_i)
            .expect("wrong dlog or m_b");;

        let index: usize = 0;
        let index_list = [0 as usize, 1 as usize].to_vec();
        let xi_com_vec = Keys::get_commitments_to_xi(&self.public.vss_scheme_vec);
        let x0_com = xi_com_vec[0];
        let g_w_i = Keys::update_commitments_to_xi(
            &x0_com,
            &self.public.vss_scheme_vec[0],
            index,
            &index_list,
        );
        assert_eq!(party1_message2.m_b_w.b_proof.pk.clone(), g_w_i);

        let delta = party2_sign_keys.phase2_delta_i(&[alpha].to_vec(), &[beta].to_vec());
        let sigma = party2_sign_keys.phase2_sigma_i(&[miu].to_vec(), &[ni].to_vec());

        let sign_message3 = SignMessage3 { delta };
        (sign_message3, sigma)
    }

    pub fn sign_fourth_message(decommit: SignDecommitPhase1) -> SignMessage4 {
        SignMessage4 { decommit }
    }

    pub fn sign_fifth_message(
        &self,
        message: BigInt,
        sigma: FE,
        party2_sign_keys: &SignKeys,
        party2_message4: SignMessage4,
        party2_message3: SignMessage3,
        party1_message3: SignMessage3,
        party1_message4: SignMessage4,
        party1_message2: SignMessage2,
        party1_message1: SignMessage1,
    ) -> (
        SignMessage5,
        Phase5ADecom1,
        HomoELGamalProof,
        LocalSignature,
        GE,
    ) {
        let delta_slice = &[party1_message3.delta, party2_message3.delta];
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_slice.to_vec());

        let b_proof = party1_message2.m_b_gamma.b_proof;
        let R = SignKeys::phase4(
            &delta_inv,
            &[&b_proof].to_vec(),
            [party1_message4.decommit.clone()].to_vec(),
            &[party1_message1.com].to_vec(),
        )
        .expect("bad gamma_i decommit");
        let R = R + party2_message4.decommit.g_gamma_i * &delta_inv;

        let local_sig = LocalSignature::phase5_local_sig(
            &party2_sign_keys.k_i,
            &message,
            &R,
            &sigma,
            &self.public.q,
        );

        let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();
        let sign_message5 = SignMessage5 { phase5_com };
        (sign_message5, phase_5a_decom, helgamal_proof, local_sig, R)
    }

    pub fn sign_sixth_message(
        phase_5a_decom: Phase5ADecom1,
        helgamal_proof: HomoELGamalProof,
    ) -> SignMessage6 {
        SignMessage6 {
            phase_5a_decom,
            helgamal_proof,
        }
    }

    pub fn sign_seventh_message(
        party2_message6: SignMessage6,
        party1_message6: SignMessage6,
        party1_message5: SignMessage5,
        local_sig: &LocalSignature,
        R: GE,
    ) -> (SignMessage7, Phase5DDecom2) {
        let (phase5_com2, phase_5d_decom2) = local_sig
            .phase5c(
                &[party1_message6.phase_5a_decom].to_vec(),
                &[party1_message5.phase5_com].to_vec(),
                &[party1_message6.helgamal_proof].to_vec(),
                &party2_message6.phase_5a_decom.V_i,
                &R,
            )
            .expect("error phase5");

        let sign_message7 = SignMessage7 { phase5_com2 };
        (sign_message7, phase_5d_decom2)
    }

    pub fn sign_eighth_message(phase_5d_decom2: Phase5DDecom2) -> SignMessage8 {
        SignMessage8 { phase_5d_decom2 }
    }

    pub fn sign_ninth_message(
        party1_message6: SignMessage6,
        party2_message6: SignMessage6,
        party1_message7: SignMessage7,
        party2_message7: SignMessage7,
        party1_message8: SignMessage8,
        party2_message8: SignMessage8,
        local_sig: &LocalSignature,
    ) -> SignMessage9 {
        let phase5a_decom_slice = [
            party1_message6.phase_5a_decom,
            party2_message6.phase_5a_decom,
        ];
        let phase5d_com_slice = [party1_message7.phase5_com2, party2_message7.phase5_com2];
        let phase5d_decom_slice = [
            party1_message8.phase_5d_decom2,
            party2_message8.phase_5d_decom2,
        ];

        let s_i = local_sig
            .phase5d(
                &phase5d_decom_slice.to_vec(),
                &phase5d_com_slice.to_vec(),
                &phase5a_decom_slice.to_vec(),
            )
            .expect("bad com 5d");

        let sign_message9 = SignMessage9 { s_i };
        sign_message9
    }

    pub fn output_signature(party2_message9: SignMessage9, local_sig: LocalSignature) -> (FE, FE) {
        let message9_vec = [party2_message9.s_i].to_vec();
        let (r, s) = local_sig
            .output_signature(&message9_vec)
            .expect("verification failed");;
        (r, s)
    }
}
