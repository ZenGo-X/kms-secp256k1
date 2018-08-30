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
    use cryptography_utils::elliptic::curves::traits::ECScalar;
    use cryptography_utils::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
    use two_party::lindell_2017::traits::ManagementSystem;
    use two_party::lindell_2017::*;

    #[test]
    fn test_commutativity_rotate_get_child() {
        // key gen
        let kg_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = party2::MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = party1::MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = party2::MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, challenge, verification_aid) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let kg_party_one_third_message =
            party1::MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge);
        party2::MasterKey2::key_gen_third_message(&kg_party_one_third_message, &verification_aid);

        // chain code
        let cc_party_one_first_message = party1::MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = party2::MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = party1::MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = party2::MasterKey2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );

        let party2_cc = party2::MasterKey2::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );

        // rotate and then child:
        //coin flip:
        let (party1_first_message, m1, r1) = party1::MasterKey1::key_rotate_first_message();
        let party2_first_message =
            party2::MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            party1::MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = party2::MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );

        // set master keys:
        let party_one_master_key = party1::MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message,
            &paillier_key_pair,
        );

        let party_two_master_key = party2::MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message,
            &party_two_paillier,
        );

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1.to_big_int());
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2.to_big_int());
        let rc_party_one_master_key =
            party_one_master_key_rotated.get_child(vec![BigInt::from(10)]);
        let rc_party_two_master_key =
            party_two_master_key_rotated.get_child(vec![BigInt::from(10)]);

        // child and then rotate:
        // set master keys:
        let party_one_master_key = party1::MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message,
            &paillier_key_pair,
        );

        let party_two_master_key = party2::MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message,
            &party_two_paillier,
        );

        let new_party_one_master_key = party_one_master_key.get_child(vec![BigInt::from(10)]);
        let new_party_two_master_key = party_two_master_key.get_child(vec![BigInt::from(10)]);
        let cr_party_one_master_key = new_party_one_master_key.rotate(&random1.to_big_int());
        let cr_party_two_master_key = new_party_two_master_key.rotate(&random2.to_big_int());

        //test signing:
        let message = BigInt::from(1234);
        let ep_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = party2::MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &cr_party_two_master_key.public.c_key.0,
            &cr_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );

        let signature = party_one::Signature::compute(
            &paillier_key_pair,
            &partial_sig,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );

        party_one::verify(&signature, &cr_party_one_master_key.public.q, &message)
            .expect("verify failed");

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &rc_party_two_master_key.public.c_key.0,
            &rc_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );

        let signature = party_one::Signature::compute(
            &paillier_key_pair,
            &partial_sig,
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
        let kg_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = party2::MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = party1::MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = party2::MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (kg_party_two_second_message, party_two_paillier, challenge, verification_aid) =
            key_gen_second_message.unwrap();

        assert!(kg_party_two_second_message.is_ok());

        let kg_party_one_third_message =
            party1::MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge);
        party2::MasterKey2::key_gen_third_message(&kg_party_one_third_message, &verification_aid);

        // chain code
        let cc_party_one_first_message = party1::MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = party2::MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = party1::MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );
        let cc_party_two_second_message = party2::MasterKey2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );

        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );
        let party2_cc = party2::MasterKey2::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );
        // set master keys:
        let party_one_master_key = party1::MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message,
            &paillier_key_pair,
        );

        let party_two_master_key = party2::MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message,
            &party_two_paillier,
        );

        let new_party_one_master_key =
            party_one_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let new_party_two_master_key =
            party_two_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        //test signing:
        let message = BigInt::from(1234);
        let ep_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = party2::MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &new_party_two_master_key.public.c_key.0,
            &new_party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &paillier_key_pair,
            &partial_sig,
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
        let kg_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let kg_party_two_first_message = party2::MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = party1::MasterKey1::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = party2::MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (kg_party_two_second_message, party_two_paillier, challenge, verification_aid) =
            key_gen_second_message.unwrap();

        assert!(kg_party_two_second_message.is_ok());

        let kg_party_one_third_message =
            party1::MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge);
        party2::MasterKey2::key_gen_third_message(&kg_party_one_third_message, &verification_aid);

        // chain code
        let cc_party_one_first_message = party1::MasterKey1::chain_code_first_message();
        let cc_party_two_first_message = party2::MasterKey2::chain_code_first_message();
        let cc_party_one_second_message = party1::MasterKey1::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_two_first_message.d_log_proof,
        );
        let cc_party_two_second_message = party2::MasterKey2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );

        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::MasterKey1::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );
        let party2_cc = party2::MasterKey2::compute_chain_code(
            &cc_party_one_first_message,
            &cc_party_two_first_message,
        );
        // set master keys:
        let party_one_master_key = party1::MasterKey1::set_master_key(
            &party1_cc,
            &kg_party_one_first_message,
            &kg_party_two_first_message,
            &paillier_key_pair,
        );

        let party_two_master_key = party2::MasterKey2::set_master_key(
            &party2_cc,
            &kg_party_two_first_message,
            &kg_party_one_first_message,
            &party_two_paillier,
        );
        // coin flip:
        let (party1_first_message, m1, r1) = party1::MasterKey1::key_rotate_first_message();
        let party2_first_message =
            party2::MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            party1::MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = party2::MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );
        //signing & verifying before:
        let ep_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = party2::MasterKey2::key_gen_first_message();
        let message = BigInt::from(1234);
        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &party_two_master_key.public.c_key.0.clone(),
            &party_two_master_key.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &paillier_key_pair,
            &partial_sig,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );
        party_one::verify(&signature, &party_one_master_key.public.q, &message)
            .expect("verify failed");

        //rotate:

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1.to_big_int());
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2.to_big_int());

        //signing & verifying after:
        let ep_party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let ep_party_two_first_message = party2::MasterKey2::key_gen_first_message();

        let partial_sig = party_two::PartialSig::compute(
            &party_two_paillier.ek,
            &party_two_master_key_rotated.public.c_key.0,
            &party_two_master_key_rotated.private,
            &ep_party_two_first_message,
            &ep_party_one_first_message.public_share,
            &message,
        );
        let signature = party_one::Signature::compute(
            &paillier_key_pair,
            &partial_sig,
            &ep_party_one_first_message,
            &ep_party_two_first_message.public_share,
        );
        party_one::verify(&signature, &party_one_master_key_rotated.public.q, &message)
            .expect("verify failed");
    }

    #[test]
    fn test_key_gen() {
        let party_one_first_message = party1::MasterKey1::key_gen_first_message();
        let party_two_first_message = party2::MasterKey2::key_gen_first_message();
        let (
            party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
        ) = party1::MasterKey1::key_gen_second_message(
            &party_one_first_message,
            &party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = party2::MasterKey2::key_gen_second_message(
            &party_one_first_message,
            &party_one_second_message,
            &paillier_key_pair,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, challenge, verification_aid) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let party_one_third_message =
            party1::MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge);
        party2::MasterKey2::key_gen_third_message(&party_one_third_message, &verification_aid);
    }

    #[test]
    fn test_chain_code() {
        //chain code:
        let party_one_first_message = party1::MasterKey1::chain_code_first_message();
        let party_two_first_message = party2::MasterKey2::chain_code_first_message();

        let party_one_second_message = party1::MasterKey1::chain_code_second_message(
            &party_one_first_message,
            &party_two_first_message.d_log_proof,
        );

        let party_two_second_message = party2::MasterKey2::chain_code_second_message(
            &party_one_first_message,
            &party_one_second_message,
        );

        assert!(party_two_second_message.is_ok());

        let party1_cc = party1::MasterKey1::compute_chain_code(
            &party_one_first_message,
            &party_two_first_message,
        );

        let party2_cc = party2::MasterKey2::compute_chain_code(
            &party_one_first_message,
            &party_two_first_message,
        );

        assert_eq!(party1_cc, party2_cc);
    }
    #[test]
    fn test_coin_flip() {
        let (party1_first_message, m1, r1) = party1::MasterKey1::key_rotate_first_message();
        let party2_first_message =
            party2::MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            party1::MasterKey1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = party2::MasterKey2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );
        assert_eq!(random1, random2);
    }
}
