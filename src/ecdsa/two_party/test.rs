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
    use curv::BigInt;
    use rotation::two_party::party1::Rotation1;
    use rotation::two_party::party2::Rotation2;

    #[test]
    fn test_commutativity_rotate_get_child() {
        // key gen
        let (party_one_master_key, party_two_master_key) = test_key_gen();

        // child and rotate:
        //test signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
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
            &sign_party_one_first_message,
            &message,
        );
        let sign_party_one_second_message = new_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

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
        //rotation:
        let (rotation_party_one_first_message, party_one_private_new) =
            new_party_one_master_key.rotation_first_message(&random1);
        let result_rotate_party_one_first_message = new_party_two_master_key
            .rotate_first_message(&random2, &rotation_party_one_first_message);
        assert!(result_rotate_party_one_first_message.is_ok());

        let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
            result_rotate_party_one_first_message.unwrap();
        let (rotation_party_one_second_message, party_one_pdl_decommit) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first_message,
                &party_one_private_new,
            );
        let rotation_party_two_second_message =
            MasterKey2::rotate_second_message(&party_two_pdl_chal);
        let result_rotate_party_two_second_message = new_party_one_master_key
            .rotation_third_message(
                &rotation_party_one_first_message,
                party_one_private_new,
                &random1,
                &rotation_party_one_second_message,
                &rotation_party_two_first_message,
                &rotation_party_two_second_message,
                party_one_pdl_decommit,
            );
        assert!(result_rotate_party_two_second_message.is_ok());
        let (rotation_party_one_third_message, cr_party_one_master_key) =
            result_rotate_party_two_second_message.unwrap();
        let result_rotate_party_one_third_message = new_party_two_master_key.rotate_third_message(
            &random2,
            &party_two_paillier,
            &party_two_pdl_chal,
            &rotation_party_one_second_message,
            &rotation_party_one_third_message,
        );
        assert!(result_rotate_party_one_third_message.is_ok());
        let cr_party_two_master_key = result_rotate_party_one_third_message.unwrap();

        // sign with child and rotated keys
        let sign_party_two_second_message = cr_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message,
            &message,
        );
        let sign_party_one_second_message = cr_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

        // rotate_and_get_child:

        //rotation:
        let (rotation_party_one_first_message, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random1);
        let result_rotate_party_one_first_message =
            party_two_master_key.rotate_first_message(&random2, &rotation_party_one_first_message);
        assert!(result_rotate_party_one_first_message.is_ok());

        let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
            result_rotate_party_one_first_message.unwrap();
        let (rotation_party_one_second_message, party_one_pdl_decommit) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first_message,
                &party_one_private_new,
            );
        let rotation_party_two_second_message =
            MasterKey2::rotate_second_message(&party_two_pdl_chal);
        let result_rotate_party_two_second_message = party_one_master_key.rotation_third_message(
            &rotation_party_one_first_message,
            party_one_private_new,
            &random1,
            &rotation_party_one_second_message,
            &rotation_party_two_first_message,
            &rotation_party_two_second_message,
            party_one_pdl_decommit,
        );
        assert!(result_rotate_party_two_second_message.is_ok());
        let (rotation_party_one_third_message, rotate_party_one_master_key) =
            result_rotate_party_two_second_message.unwrap();
        let result_rotate_party_one_third_message = party_two_master_key.rotate_third_message(
            &random2,
            &party_two_paillier,
            &party_two_pdl_chal,
            &rotation_party_one_second_message,
            &rotation_party_one_third_message,
        );
        assert!(result_rotate_party_one_third_message.is_ok());
        let rotate_party_two_master_key = result_rotate_party_one_third_message.unwrap();

        //get child:
        let rc_party_one_master_key = rotate_party_one_master_key.get_child(vec![BigInt::from(10)]);
        let rc_party_two_master_key = rotate_party_two_master_key.get_child(vec![BigInt::from(10)]);

        // sign with rotated and child keys
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();

        let sign_party_two_second_message = rc_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message,
            &message,
        );
        let sign_party_one_second_message = rc_party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");
        assert_eq!(
            rc_party_one_master_key.public.q,
            cr_party_one_master_key.public.q
        );
    }

    #[test]
    fn test_get_child() {
        // compute master keys:
        let (party_one_master_key, party_two_master_key) = test_key_gen();

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
            &sign_party_one_first_message,
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
            &sign_party_one_first_message,
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
        let (party_one_master_key, party_two_master_key) = test_key_gen();

        //signing & verifying before rotation:
        //test signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message,
            &message,
        );
        let sign_party_one_second_message = party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        );
        sign_party_one_second_message.expect("bad signature");

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

        //rotation:
        let (rotation_party_one_first_message, party_one_private_new) =
            party_one_master_key.rotation_first_message(&random1);

        let result_rotate_party_one_first_message =
            party_two_master_key.rotate_first_message(&random2, &rotation_party_one_first_message);
        assert!(result_rotate_party_one_first_message.is_ok());

        let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
            result_rotate_party_one_first_message.unwrap();
        let (rotation_party_one_second_message, party_one_pdl_decommit) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first_message,
                &party_one_private_new,
            );
        let rotation_party_two_second_message =
            MasterKey2::rotate_second_message(&party_two_pdl_chal);
        let result_rotate_party_two_second_message = party_one_master_key.rotation_third_message(
            &rotation_party_one_first_message,
            party_one_private_new,
            &random1,
            &rotation_party_one_second_message,
            &rotation_party_two_first_message,
            &rotation_party_two_second_message,
            party_one_pdl_decommit,
        );
        assert!(result_rotate_party_two_second_message.is_ok());
        let (rotation_party_one_third_message, party_one_master_key_rotated) =
            result_rotate_party_two_second_message.unwrap();

        let result_rotate_party_one_third_message = party_two_master_key.rotate_third_message(
            &random2,
            &party_two_paillier,
            &party_two_pdl_chal,
            &rotation_party_one_second_message,
            &rotation_party_one_third_message,
        );
        assert!(result_rotate_party_one_third_message.is_ok());

        let party_two_master_key_rotated = result_rotate_party_one_third_message.unwrap();

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
            &sign_party_one_first_message,
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

    pub fn test_key_gen() -> (MasterKey1, MasterKey2) {
        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
        let (kg_party_one_second_message, party_one_paillier_key_pair, party_one_private) =
            MasterKey1::key_gen_second_message(
                kg_comm_witness.clone(),
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.d_log_proof,
            );

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
            key_gen_second_message.unwrap();

        let (party_one_third_message, party_one_pdl_decommit) = MasterKey1::key_gen_third_message(
            &party_two_second_message.pdl_first_message,
            &party_one_private,
        );

        let party_two_third_message = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        let party_one_fourth_message = MasterKey1::key_gen_fourth_message(
            &party_one_third_message,
            &party_two_second_message.pdl_first_message,
            &party_two_third_message,
            party_one_private.clone(),
            party_one_pdl_decommit,
        )
        .expect("pdl error party 2");

        MasterKey2::key_gen_fourth_message(
            &party_two_pdl_chal,
            &party_one_third_message,
            &party_one_fourth_message,
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
            party_one_private,
            &kg_comm_witness.public_share,
            &kg_party_two_first_message.public_share,
            party_one_paillier_key_pair,
        );

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc.chain_code,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );
        (party_one_master_key, party_two_master_key)
    }
}
