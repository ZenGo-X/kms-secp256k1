/*
    KMS
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
    use chain_code::two_party::party1;
    use chain_code::two_party::party2;
    use cryptography_utils::BigInt;
    use rotation::two_party::party1::Rotation1;
    use rotation::two_party::party2::Rotation2;
    use ManagementSystem;

    #[test]
    fn test_commutativity_rotate_get_child() {
        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
            correct_key_proof,
        ) = MasterKey1::key_gen_second_message(
            kg_comm_witness,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
            &correct_key_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal.c_tag);

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_chal);

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            kg_ec_key_pair_party1.clone(),
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        )
        .expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        )
        .expect("pdl error party1");

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            party1::ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) =
            party2::ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = party1::ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = party2::ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = party2::ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );

        // rotate and then child:
        //coin flip:
        let (party1_first_message, m1, r1) = Rotation1::key_rotate_first_message();
        let party2_first_message = Rotation2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            Rotation1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = Rotation2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );

        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc.chain_code,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc.chain_code,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message.comm_witness.public_share,
            &party_two_paillier,
        );

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1);
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2);
        let rc_party_one_master_key =
            party_one_master_key_rotated.get_child(vec![BigInt::from(10)]);
        let rc_party_two_master_key =
            party_two_master_key_rotated.get_child(vec![BigInt::from(10)]);
        assert_eq!(
            rc_party_one_master_key.chain_code.chain_code,
            rc_party_two_master_key.chain_code.chain_code
        );

        // child and then rotate:
        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc.chain_code,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc.chain_code,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message.comm_witness.public_share,
            &party_two_paillier,
        );

        //test signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

        let new_party_one_master_key = party_one_master_key.get_child(vec![BigInt::from(10)]);
        let new_party_two_master_key = party_two_master_key.get_child(vec![BigInt::from(10)]);

        // sign with child keys
        let sign_party_two_second_message = new_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = new_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

        let cr_party_one_master_key = new_party_one_master_key.rotate(&random1);
        let cr_party_two_master_key = new_party_two_master_key.rotate(&random2);

        // sign with child and rotated keys
        let sign_party_two_second_message = cr_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = cr_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");
    }

    #[test]
    fn test_get_child() {
        // compute master keys:
        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
            correct_key_proof,
        ) = MasterKey1::key_gen_second_message(
            kg_comm_witness,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
            &correct_key_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal.c_tag);

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_chal);

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            kg_ec_key_pair_party1.clone(),
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        )
        .expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        )
        .expect("pdl error party1");

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            party1::ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) =
            party2::ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = party1::ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = party2::ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = party2::ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );

        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc.chain_code,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc.chain_code,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message.comm_witness.public_share,
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
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

        // test sign for child
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = new_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = new_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");
    }

    #[test]
    fn test_flip_masters() {
        // for this test to work party2 MasterKey private need to be changed to pub
        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
            correct_key_proof,
        ) = MasterKey1::key_gen_second_message(
            kg_comm_witness,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
            &correct_key_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal.c_tag);

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_chal);

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            kg_ec_key_pair_party1.clone(),
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        )
        .expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        )
        .expect("pdl error party1");

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            party1::ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) =
            party2::ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = party1::ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = party2::ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = party1::ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = party2::ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );
        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &party1_cc.chain_code,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.public_share,
            &paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc.chain_code,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message.comm_witness.public_share,
            &party_two_paillier,
        );
        //coin flip:
        let (party1_first_message, m1, r1) = Rotation1::key_rotate_first_message();
        let party2_first_message = Rotation2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            Rotation1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = Rotation2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );

        //signing & verifying after:
        //test signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

        //rotate:

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1);
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2);

        // sign after rotate:
        //test signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key_rotated.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message.public_share,
            &sign_party_one_first_message.d_log_proof,
            &message,
        );
        let sign_party_one_second_message = party_one_master_key_rotated.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");
    }

    #[test]
    fn test_key_gen() {
        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
        let (
            kg_party_one_second_message,
            paillier_key_pair,
            rp_encrypted_pairs,
            rp_challenge,
            rp_proof,
            correct_key_proof,
        ) = MasterKey1::key_gen_second_message(
            kg_comm_witness,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &rp_challenge,
            &rp_encrypted_pairs,
            &rp_proof,
            &correct_key_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, _party_two_paillier, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal.c_tag);

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_chal);

        let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            kg_ec_key_pair_party1,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        )
        .expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        )
        .expect("pdl error party1");
    }
}
