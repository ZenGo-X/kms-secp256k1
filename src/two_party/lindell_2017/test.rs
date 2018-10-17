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

#[cfg(test)]
mod tests {
    use super::super::{MasterKey1, MasterKey2};
    use cryptography_utils::elliptic::curves::traits::ECScalar;
    use cryptography_utils::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
    use two_party::lindell_2017::traits::ManagementSystem;

    #[test]
    fn test_commutativity_rotate_get_child() {
        // key gen
        let kg_party_one_first_message = MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message.pk_commitment,
            &kg_party_one_first_message.zk_pok_commitment,
            &kg_party_one_second_message.zk_pok_blind_factor,
            &kg_party_one_second_message.public_share,
            &kg_party_one_second_message.pk_commitment_blind_factor,
            &kg_party_one_second_message.d_log_proof,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, challenge, verification_aid, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let (correct_key_proof, pdl_prover) =
            MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge, &pdl_chal.c_tag)
                .expect("error correct key proof");

        let pdl_decom_party2 =
            MasterKey2::key_gen_third_message(&correct_key_proof, &verification_aid, &pdl_chal)
                .expect("error verifying proof of correct key");

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            &kg_party_one_first_message,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        ).expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        ).expect("pdl error party1");
        // chain code
        let cc_party_one_first_message = MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = MasterKey2::chain_code_second_message(
            &cc_party_one_first_message.pk_commitment,
            &cc_party_one_first_message.zk_pok_commitment,
            &cc_party_one_second_message.zk_pok_blind_factor,
            &cc_party_one_second_message.public_share,
            &cc_party_one_second_message.pk_commitment_blind_factor,
            &cc_party_one_second_message.d_log_proof,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = MasterKey2::compute_chain_code(
            &cc_party_one_first_message.public_share,
            &cc_party_two_first_message,
        );

        // rotate and then child:
        //coin flip:
        let (party1_first_message, m1, r1) = MasterKey1::key_rotate_first_message();
        let party2_first_message = MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );

        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message.public_share,
            &party_two_paillier,
        );

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1.to_big_int());
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2.to_big_int());
        let rc_party_one_master_key =
            party_one_master_key_rotated.get_child(vec![BigInt::from(10)]);
        let rc_party_two_master_key =
            party_two_master_key_rotated.get_child(vec![BigInt::from(10)]);
        assert_eq!(
            rc_party_one_master_key.chain_code,
            rc_party_two_master_key.chain_code
        );

        // child and then rotate:
        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message.public_share,
            &party_two_paillier,
        );

        let new_party_one_master_key = party_one_master_key.get_child(vec![BigInt::from(10)]);
        let new_party_two_master_key = party_two_master_key.get_child(vec![BigInt::from(10)]);
        let cr_party_one_master_key = new_party_one_master_key.rotate(&random1.to_big_int());
        let cr_party_two_master_key = new_party_two_master_key.rotate(&random2.to_big_int());

        //test signing:
        let message = BigInt::from(1234);
        let ep_party_one_first_message = MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &cr_party_two_master_key.public.c_key,
            &cr_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );

        let signature = party_one::Signature::compute(
            &cr_party_one_master_key.private,
            &partial_sig.c3,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );

        party_one::verify(&signature, &cr_party_one_master_key.public.q, &message)
            .expect("verify failed");

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &rc_party_two_master_key.public.c_key,
            &rc_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );

        let signature = party_one::Signature::compute(
            &cr_party_one_master_key.private,
            &partial_sig.c3,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );

        party_one::verify(&signature, &rc_party_one_master_key.public.q, &message)
            .expect("verify failed");
    }
    #[test]
    fn test_get_child() {
        // compute master keys:
        // key gen
        let kg_party_one_first_message = MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message.pk_commitment,
            &kg_party_one_first_message.zk_pok_commitment,
            &kg_party_one_second_message.zk_pok_blind_factor,
            &kg_party_one_second_message.public_share,
            &kg_party_one_second_message.pk_commitment_blind_factor,
            &kg_party_one_second_message.d_log_proof,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, challenge, verification_aid, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let (correct_key_proof, pdl_prover) =
            MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge, &pdl_chal.c_tag)
                .expect("error correct key proof");

        let pdl_decom_party2 =
            MasterKey2::key_gen_third_message(&correct_key_proof, &verification_aid, &pdl_chal)
                .expect("error verifying proof of correct key");

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            &kg_party_one_first_message,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        ).expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        ).expect("pdl error party1");

        // chain code
        let cc_party_one_first_message = MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );
        let cc_party_two_second_message = MasterKey2::chain_code_second_message(
            &cc_party_one_first_message.pk_commitment,
            &cc_party_one_first_message.zk_pok_commitment,
            &cc_party_one_second_message.zk_pok_blind_factor,
            &cc_party_one_second_message.public_share,
            &cc_party_one_second_message.pk_commitment_blind_factor,
            &cc_party_one_second_message.d_log_proof,
        );

        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message.public_share,
        );

        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party2_cc = MasterKey2::compute_chain_code(
            &cc_party_one_first_message.public_share,
            &cc_party_two_first_message,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message.public_share,
            &party_two_paillier,
        );

        let new_party_two_master_key =
            party_two_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let new_party_one_master_key =
            party_one_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        assert_eq!(
            new_party_one_master_key.public.q,
            new_party_two_master_key.public.q
        );

        //test signing:
        let message = BigInt::from(1234);
        let ep_party_one_first_message = MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &new_party_two_master_key.public.c_key,
            &new_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &party_one_master_key.private,
            &partial_sig.c3,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );
        party_one::verify(&signature, &new_party_two_master_key.public.q, &message)
            .expect("verify failed");
    }
    #[test]
    fn test_flip_masters() {
        // for this test to work party2 MasterKey private need to be changed to pub
        // key gen
        let kg_party_one_first_message = MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message.pk_commitment,
            &kg_party_one_first_message.zk_pok_commitment,
            &kg_party_one_second_message.zk_pok_blind_factor,
            &kg_party_one_second_message.public_share,
            &kg_party_one_second_message.pk_commitment_blind_factor,
            &kg_party_one_second_message.d_log_proof,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, challenge, verification_aid, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let (correct_key_proof, pdl_prover) =
            MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge, &pdl_chal.c_tag)
                .expect("error correct key proof");

        let pdl_decom_party2 =
            MasterKey2::key_gen_third_message(&correct_key_proof, &verification_aid, &pdl_chal)
                .expect("error verifying proof of correct key");

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            &kg_party_one_first_message,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        ).expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        ).expect("pdl error party1");

        // chain code
        let cc_party_one_first_message = MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );
        let cc_party_two_second_message = MasterKey2::chain_code_second_message(
            &cc_party_one_first_message.pk_commitment,
            &cc_party_one_first_message.zk_pok_commitment,
            &cc_party_one_second_message.zk_pok_blind_factor,
            &cc_party_one_second_message.public_share,
            &cc_party_one_second_message.pk_commitment_blind_factor,
            &cc_party_one_second_message.d_log_proof,
        );

        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message.public_share,
        );
        let party2_cc = MasterKey2::compute_chain_code(
            &cc_party_one_first_message.public_share,
            &cc_party_two_first_message,
        );
        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message.public_share,
            &party_two_paillier,
        );
        // coin flip:
        let (party1_first_message, m1, r1) = MasterKey1::key_rotate_first_message();
        let party2_first_message = MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );
        //signing & verifying before:
        let ep_party_one_first_message = MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = MasterKey2::key_gen_first_message();
        let message = BigInt::from(1234);
        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &party_two_master_key.public.c_key.clone(),
            &party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &party_one_master_key.private,
            &partial_sig.c3,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );
        party_one::verify(&signature, &party_one_master_key.public.q, &message)
            .expect("verify failed");

        //rotate:

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1.to_big_int());
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2.to_big_int());

        //signing & verifying after:
        let ep_party_one_first_message = MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &party_two_master_key_rotated.public.c_key,
            &party_two_master_key_rotated.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &party_one_master_key_rotated.private,
            &partial_sig.c3,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );
        party_one::verify(&signature, &party_one_master_key_rotated.public.q, &message)
            .expect("verify failed");
    }

    #[test]
    fn test_key_gen() {
        // key gen
        let kg_party_one_first_message = MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message.pk_commitment,
            &kg_party_one_first_message.zk_pok_commitment,
            &kg_party_one_second_message.zk_pok_blind_factor,
            &kg_party_one_second_message.public_share,
            &kg_party_one_second_message.pk_commitment_blind_factor,
            &kg_party_one_second_message.d_log_proof,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, _party_two_paillier, challenge, verification_aid, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let (correct_key_proof, pdl_prover) =
            MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge, &pdl_chal.c_tag)
                .expect("error correct key proof");

        let pdl_decom_party2 =
            MasterKey2::key_gen_third_message(&correct_key_proof, &verification_aid, &pdl_chal)
                .expect("error verifying proof of correct key");

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            &kg_party_one_first_message,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        ).expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        ).expect("pdl error party1");
    }

    #[test]
    fn test_chain_code() {
        //chain code:
        let party_one_first_message = MasterKey1::chain_code_first_message();
        let party_two_first_message = MasterKey2::chain_code_first_message();

        let party_one_second_message = MasterKey1::chain_code_second_message(
            &party_one_first_message,
            &party_two_first_message.d_log_proof,
        );

        let party_two_second_message = MasterKey2::chain_code_second_message(
            &party_one_first_message.pk_commitment,
            &party_one_first_message.zk_pok_commitment,
            &party_one_second_message.zk_pok_blind_factor,
            &party_one_second_message.public_share,
            &party_one_second_message.pk_commitment_blind_factor,
            &party_one_second_message.d_log_proof,
        );

        assert!(party_two_second_message.is_ok());

        let party1_cc = MasterKey1::compute_chain_code(
            &party_one_first_message,
            &party_two_first_message.public_share,
        );

        let party2_cc = MasterKey2::compute_chain_code(
            &party_one_first_message.public_share,
            &party_two_first_message,
        );

        assert_eq!(party1_cc, party2_cc);
    }
    #[test]
    fn test_coin_flip() {
        let (party1_first_message, m1, r1) = MasterKey1::key_rotate_first_message();
        let party2_first_message = MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );
        assert_eq!(random1, random2);
    }
}
