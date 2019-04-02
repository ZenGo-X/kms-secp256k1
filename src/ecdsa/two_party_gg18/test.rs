#![allow(non_snake_case)]
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
    //use centipede::juggling::segmentation::Msegmentation;
    use chain_code::two_party::party1;
    use chain_code::two_party::party2;
    use curv::BigInt;
    use ecdsa::two_party_gg18::{MasterKey1, MasterKey2};
    use rotation::two_party::party1::Rotation1;
    use rotation::two_party::party2::Rotation2;

    #[test]
    fn test_get_child() {
        let (master_key1, master_key2) = key_gen();
        let (master_key1_r, master_key2_r) = rotate(master_key1.clone(), master_key2.clone());
        let master_key1_rc = master_key1_r.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let master_key2_rc = master_key2_r.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        sign(
            master_key1_rc.clone(),
            master_key2_rc.clone(),
            BigInt::from(100),
        );
        let master_key1_c = master_key1.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let master_key2_c = master_key2.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let (master_key1_cr, master_key2_cr) = rotate(master_key1_c, master_key2_c);
        sign(
            master_key1_cr.clone(),
            master_key2_cr.clone(),
            BigInt::from(100),
        );
        assert_eq!(master_key1_cr.public.q, master_key2_rc.public.q);
    }
    #[test]
    fn test_rotate() {
        //keygen
        let (master_key1, master_key2) = key_gen();

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

        assert_eq!(random1.rotation, random2.rotation);

        let (party1_message1, party1_additive_key, party1_decom1) =
            master_key1.rotation_first_message(&random1);
        let (party2_message1, party2_additive_key, party2_decom1) =
            master_key2.rotation_first_message(&random2);

        let party1_message2 = MasterKey1::rotation_second_message(party1_decom1);
        let party2_message2 = MasterKey2::rotation_second_message(party2_decom1);

        let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) = master_key1
            .rotation_third_message(
                &party1_additive_key,
                party1_message1.clone(),
                party2_message1.clone(),
                party1_message2.clone(),
                party2_message2.clone(),
            );

        let (party2_message3, ss2_to_self, party2_y_vec, party2_ek_vec) = master_key2
            .rotation_third_message(
                &party2_additive_key,
                party1_message1,
                party2_message1,
                party1_message2,
                party2_message2,
            );

        let (party1_message4, party1_linear_key, party1_vss_vec) =
            MasterKey1::rotation_fourth_message(
                &party1_additive_key,
                party1_message3.clone(),
                party2_message3.clone(),
                ss1_to_self,
                &party1_y_vec,
            );

        let (party2_message4, party2_linear_key, party2_vss_vec) =
            MasterKey2::rotation_fourth_message(
                &party2_additive_key,
                party1_message3,
                party2_message3,
                ss2_to_self,
                &party2_y_vec,
            );

        let _master_key2 = master_key2.rotate_master_key(
            party1_message4.clone(),
            party2_message4.clone(),
            party2_y_vec.clone(),
            party2_additive_key,
            party2_linear_key,
            party2_vss_vec,
            party2_ek_vec,
        );

        let _master_key1 = master_key1.rotate_master_key(
            party1_message4,
            party2_message4,
            party1_y_vec.clone(),
            party1_additive_key,
            party1_linear_key,
            party1_vss_vec,
            party1_ek_vec,
        );

        //(master_key1, master_key2)
    }

    #[test]
    fn test_sign() {
        let (master_key1, master_key2) = key_gen();

        let message = BigInt::from(100);

        let (party1_message1, party1_decommit_phase1, party1_sign_keys) =
            master_key1.sign_first_message();
        let (party2_message1, party2_decommit_phase1, party2_sign_keys) =
            master_key2.sign_first_message();

        let (party1_message2, party1_beta, party1_ni) =
            master_key1.sign_second_message(&party2_message1, &party1_sign_keys);

        let (party2_message2, party2_beta, party2_ni) =
            master_key2.sign_second_message(&party1_message1, &party2_sign_keys);

        let (party1_message3, party1_sigma) = master_key1.sign_third_message(
            &party2_message2,
            &party1_sign_keys,
            party1_beta,
            party1_ni,
        );

        let (party2_message3, party2_sigma) = master_key2.sign_third_message(
            &party1_message2,
            &party2_sign_keys,
            party2_beta,
            party2_ni,
        );

        let party1_message4 = MasterKey1::sign_fourth_message(party1_decommit_phase1);
        let party2_message4 = MasterKey2::sign_fourth_message(party2_decommit_phase1);

        let (
            party1_message5,
            party1_phase5a_decom1,
            party1_elgamal_proof,
            party1_local_sig,
            party1_R,
        ) = master_key1.sign_fifth_message(
            message.clone(),
            party1_sigma,
            &party1_sign_keys,
            party1_message4.clone(),
            party1_message3.clone(),
            party2_message3.clone(),
            party2_message4.clone(),
            party2_message2,
            party2_message1,
        );

        let (
            party2_message5,
            party2_phase5a_decom1,
            party2_elgamal_proof,
            party2_local_sig,
            party2_R,
        ) = master_key2.sign_fifth_message(
            message,
            party2_sigma,
            &party2_sign_keys,
            party2_message4,
            party2_message3,
            party1_message3,
            party1_message4,
            party1_message2,
            party1_message1,
        );

        assert_eq!(party1_R, party2_R);
        let party1_message6 =
            MasterKey1::sign_sixth_message(party1_phase5a_decom1, party1_elgamal_proof);
        let party2_message6 =
            MasterKey2::sign_sixth_message(party2_phase5a_decom1, party2_elgamal_proof);

        let (party1_message7, party1_phase5d_decom2) = MasterKey1::sign_seventh_message(
            party1_message6.clone(),
            party2_message6.clone(),
            party2_message5,
            &party1_local_sig,
            party1_R,
        );

        let (party2_message7, party2_phase5d_decom2) = MasterKey2::sign_seventh_message(
            party2_message6.clone(),
            party1_message6.clone(),
            party1_message5,
            &party2_local_sig,
            party2_R,
        );

        let party1_message8 = MasterKey1::sign_eighth_message(party1_phase5d_decom2);
        let party2_message8 = MasterKey2::sign_eighth_message(party2_phase5d_decom2);

        let party1_message9 = MasterKey1::sign_ninth_message(
            party1_message6.clone(),
            party2_message6.clone(),
            party1_message7.clone(),
            party2_message7.clone(),
            party1_message8.clone(),
            party2_message8.clone(),
            &party1_local_sig,
        );

        let party2_message9 = MasterKey2::sign_ninth_message(
            party1_message6,
            party2_message6,
            party1_message7,
            party2_message7,
            party1_message8,
            party2_message8,
            &party2_local_sig,
        );

        let (party1_r, party1_s) = MasterKey1::output_signature(party2_message9, party1_local_sig);
        let (party2_r, party2_s) = MasterKey2::output_signature(party1_message9, party2_local_sig);
        assert_eq!(party1_r, party2_r);
        assert_eq!(party1_s, party2_s);
    }

    pub fn key_gen() -> (MasterKey1, MasterKey2) {
        let (party1_message1, party1_additive_key, party1_decom1) =
            MasterKey1::key_gen_first_message();
        let (party2_message1, party2_additive_key, party2_decom1) =
            MasterKey2::key_gen_first_message();

        let party1_message2 = MasterKey1::keygen_second_message(party1_decom1);
        let party2_message2 = MasterKey2::keygen_second_message(party2_decom1);

        let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) =
            MasterKey1::key_gen_third_message(
                &party1_additive_key,
                party1_message1.clone(),
                party2_message1.clone(),
                party1_message2.clone(),
                party2_message2.clone(),
            );

        let (party2_message3, ss2_to_self, party2_y_vec, party2_ek_vec) =
            MasterKey2::key_gen_third_message(
                &party2_additive_key,
                party1_message1,
                party2_message1,
                party1_message2,
                party2_message2,
            );

        let (party1_message4, party1_linear_key, party1_vss_vec) =
            MasterKey1::key_gen_fourth_message(
                &party1_additive_key,
                party1_message3.clone(),
                party2_message3.clone(),
                ss1_to_self,
                &party1_y_vec,
            );

        let (party2_message4, party2_linear_key, party2_vss_vec) =
            MasterKey2::key_gen_fourth_message(
                &party2_additive_key,
                party1_message3,
                party2_message3,
                ss2_to_self,
                &party2_y_vec,
            );

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

        let master_key2 = MasterKey2::set_master_key(
            party1_message4.clone(),
            party2_message4.clone(),
            party2_y_vec.clone(),
            party2_additive_key,
            party2_linear_key,
            party2_vss_vec,
            party2_ek_vec,
            &party2_cc.chain_code,
        );

        let master_key1 = MasterKey1::set_master_key(
            party1_message4,
            party2_message4,
            party1_y_vec.clone(),
            party1_additive_key,
            party1_linear_key,
            party1_vss_vec,
            party1_ek_vec,
            &party1_cc.chain_code,
        );

        (master_key1, master_key2)
    }

    pub fn rotate(master_key1: MasterKey1, master_key2: MasterKey2) -> (MasterKey1, MasterKey2) {
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

        assert_eq!(random1.rotation, random2.rotation);

        let (party1_message1, party1_additive_key, party1_decom1) =
            master_key1.rotation_first_message(&random1);
        let (party2_message1, party2_additive_key, party2_decom1) =
            master_key2.rotation_first_message(&random2);

        let party1_message2 = MasterKey1::rotation_second_message(party1_decom1);
        let party2_message2 = MasterKey2::rotation_second_message(party2_decom1);

        let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) = master_key1
            .rotation_third_message(
                &party1_additive_key,
                party1_message1.clone(),
                party2_message1.clone(),
                party1_message2.clone(),
                party2_message2.clone(),
            );

        let (party2_message3, ss2_to_self, party2_y_vec, party2_ek_vec) = master_key2
            .rotation_third_message(
                &party2_additive_key,
                party1_message1,
                party2_message1,
                party1_message2,
                party2_message2,
            );

        let (party1_message4, party1_linear_key, party1_vss_vec) =
            MasterKey1::rotation_fourth_message(
                &party1_additive_key,
                party1_message3.clone(),
                party2_message3.clone(),
                ss1_to_self,
                &party1_y_vec,
            );

        let (party2_message4, party2_linear_key, party2_vss_vec) =
            MasterKey2::rotation_fourth_message(
                &party2_additive_key,
                party1_message3,
                party2_message3,
                ss2_to_self,
                &party2_y_vec,
            );

        let _master_key2 = master_key2.rotate_master_key(
            party1_message4.clone(),
            party2_message4.clone(),
            party2_y_vec.clone(),
            party2_additive_key,
            party2_linear_key,
            party2_vss_vec,
            party2_ek_vec,
        );

        let _master_key1 = master_key1.rotate_master_key(
            party1_message4,
            party2_message4,
            party1_y_vec.clone(),
            party1_additive_key,
            party1_linear_key,
            party1_vss_vec,
            party1_ek_vec,
        );

        (master_key1, master_key2)
    }

    pub fn sign(master_key1: MasterKey1, master_key2: MasterKey2, message: BigInt) {
        let (party1_message1, party1_decommit_phase1, party1_sign_keys) =
            master_key1.sign_first_message();
        let (party2_message1, party2_decommit_phase1, party2_sign_keys) =
            master_key2.sign_first_message();

        let (party1_message2, party1_beta, party1_ni) =
            master_key1.sign_second_message(&party2_message1, &party1_sign_keys);

        let (party2_message2, party2_beta, party2_ni) =
            master_key2.sign_second_message(&party1_message1, &party2_sign_keys);

        let (party1_message3, party1_sigma) = master_key1.sign_third_message(
            &party2_message2,
            &party1_sign_keys,
            party1_beta,
            party1_ni,
        );

        let (party2_message3, party2_sigma) = master_key2.sign_third_message(
            &party1_message2,
            &party2_sign_keys,
            party2_beta,
            party2_ni,
        );

        let party1_message4 = MasterKey1::sign_fourth_message(party1_decommit_phase1);
        let party2_message4 = MasterKey2::sign_fourth_message(party2_decommit_phase1);

        let (
            party1_message5,
            party1_phase5a_decom1,
            party1_elgamal_proof,
            party1_local_sig,
            party1_R,
        ) = master_key1.sign_fifth_message(
            message.clone(),
            party1_sigma,
            &party1_sign_keys,
            party1_message4.clone(),
            party1_message3.clone(),
            party2_message3.clone(),
            party2_message4.clone(),
            party2_message2,
            party2_message1,
        );

        let (
            party2_message5,
            party2_phase5a_decom1,
            party2_elgamal_proof,
            party2_local_sig,
            party2_R,
        ) = master_key2.sign_fifth_message(
            message,
            party2_sigma,
            &party2_sign_keys,
            party2_message4,
            party2_message3,
            party1_message3,
            party1_message4,
            party1_message2,
            party1_message1,
        );

        assert_eq!(party1_R, party2_R);
        let party1_message6 =
            MasterKey1::sign_sixth_message(party1_phase5a_decom1, party1_elgamal_proof);
        let party2_message6 =
            MasterKey2::sign_sixth_message(party2_phase5a_decom1, party2_elgamal_proof);

        let (party1_message7, party1_phase5d_decom2) = MasterKey1::sign_seventh_message(
            party1_message6.clone(),
            party2_message6.clone(),
            party2_message5,
            &party1_local_sig,
            party1_R,
        );

        let (party2_message7, party2_phase5d_decom2) = MasterKey2::sign_seventh_message(
            party2_message6.clone(),
            party1_message6.clone(),
            party1_message5,
            &party2_local_sig,
            party2_R,
        );

        let party1_message8 = MasterKey1::sign_eighth_message(party1_phase5d_decom2);
        let party2_message8 = MasterKey2::sign_eighth_message(party2_phase5d_decom2);

        let party1_message9 = MasterKey1::sign_ninth_message(
            party1_message6.clone(),
            party2_message6.clone(),
            party1_message7.clone(),
            party2_message7.clone(),
            party1_message8.clone(),
            party2_message8.clone(),
            &party1_local_sig,
        );

        let party2_message9 = MasterKey2::sign_ninth_message(
            party1_message6,
            party2_message6,
            party1_message7,
            party2_message7,
            party1_message8,
            party2_message8,
            &party2_local_sig,
        );

        let (party1_r, party1_s) = MasterKey1::output_signature(party2_message9, party1_local_sig);
        let (party2_r, party2_s) = MasterKey2::output_signature(party1_message9, party2_local_sig);
        assert_eq!(party1_r, party2_r);
        assert_eq!(party1_s, party2_s);
    }
}
