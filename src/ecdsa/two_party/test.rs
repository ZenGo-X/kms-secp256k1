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
    use super::super::{MasterKey1, MasterKey2};
    use centipede::juggling::proof_system::Proof;
    use centipede::juggling::segmentation::Msegmentation;
    use chain_code::two_party::party1;
    use chain_code::two_party::party2;
    use curv::arithmetic::traits::Converter;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};
    use rotation::two_party::party1::Rotation1;
    use rotation::two_party::party2::Rotation2;
    use rotation::two_party::Rotation;

    #[test]
    fn test_recovery_from_openssl() {
        // script for keygen:
        /*
        #create EC private key
        openssl ecparam -genkey -name secp256k1 -out pri1.pem
        #derive EC public key
        openssl ec -in pri1.pem -outform PEM -pubout -out pub1.pem
        */
        // key gen
        let (party_one_master_key, party_two_master_key) = test_key_gen();
        // backup by party one of his private secret share:
        let segment_size = 8;
        let G: GE = GE::generator();
        /*
                -----BEGIN PUBLIC KEY-----
                    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELP9n+oNPDoHhEfJoYk8mFMGx4AupPEER
                dzwcJIxeqP/xMujsMEDU2mc3fzN9OGbLFnqCqgxBAe31rT84mOfrfA==
                    -----END PUBLIC KEY-----
        */
        let Y_hex = "2CFF67FA834F0E81E111F268624F2614C1B1E00BA93C4111773C1C248C5EA8FFF132E8EC3040D4DA67377F337D3866CB167A82AA0C4101ED\
        F5AD3F3898E7EB7C";
        let Y_bn = BigInt::from_str_radix(&Y_hex, 16).unwrap();
        let Y_vec = BigInt::to_vec(&Y_bn);
        let Y: GE = ECPoint::from_bytes(&Y_vec[..]).unwrap();

        /*

        -----BEGIN EC PARAMETERS-----
            BgUrgQQACg==
            -----END EC PARAMETERS-----
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIH0Ia1QLbiBwu10eY365nfI0PJhgyL+OgzDiz99KdjIZoAcGBSuBBAAK
        oUQDQgAELP9n+oNPDoHhEfJoYk8mFMGx4AupPEERdzwcJIxeqP/xMujsMEDU2mc3
        fzN9OGbLFnqCqgxBAe31rT84mOfrfA==
            -----END EC PRIVATE KEY-----
        */
        let y_hex = "7D086B540B6E2070BB5D1E637EB99DF2343C9860C8BF8E8330E2CFDF4A763219";
        let y_bn = BigInt::from_str_radix(&y_hex, 16).unwrap();
        let y: FE = ECScalar::from(&y_bn);
        assert_eq!(Y.clone(), G * &y);

        // encryption
        let (segments, encryptions_secret_party1) = party_one_master_key
            .private
            .to_encrypted_segment(segment_size, 32, &Y, &G);
        // proof and verify test:

        let proof = Proof::prove(&segments, &encryptions_secret_party1, &G, &Y, &segment_size);
        let verify = proof.verify(
            &encryptions_secret_party1,
            &G,
            &Y,
            &party_two_master_key.public.p1,
            &segment_size,
        );
        assert!(verify.is_ok());

        // encryption

        // first case: party one is dead, party two wants to recover the full key.
        // In practice party two will recover party_one_master_key and from that point will run both logic parties locally
        let secret_decrypted_party_one =
            Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);
        let _party_one_master_key_recovered = party_two_master_key
            .counter_master_key_from_recovered_secret(secret_decrypted_party_one.unwrap().clone());
    }

    #[test]
    fn test_recovery_scenarios() {
        // key gen
        let (party_one_master_key, party_two_master_key) = test_key_gen();
        // backup by party one of his private secret share: (we skip the verifiable part of proof and later verify)
        let segment_size = 8;
        let y: FE = FE::new_random();
        let G: GE = GE::generator();
        let Y = G.clone() * &y;
        // encryption
        let (_, encryptions_secret_party1) =
            party_one_master_key
                .private
                .to_encrypted_segment(segment_size, 32, &Y, &G);
        // encryption
        let (_, encryptions_secret_party2) =
            party_two_master_key
                .private
                .to_encrypted_segment(segment_size, 32, &Y, &G);

        // first case: party one is dead, party two wants to recover the full key.
        // In practice party two will recover party_one_master_key and from that point will run both logic parties locally
        let secret_decrypted_party_one =
            Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);
        let _party_one_master_key_recovered = party_two_master_key
            .counter_master_key_from_recovered_secret(secret_decrypted_party_one.unwrap().clone());

        // second case: party two wants to self-recover. public data and chain code of party two are assumed to exist locally or sent from party one
        let secret_decrypted_party_two =
            Msegmentation::decrypt(&encryptions_secret_party2, &G, &y, &segment_size);
        let _party_two_master_key_recovered = MasterKey2::recover_master_key(
            secret_decrypted_party_two.unwrap().clone(),
            party_two_master_key.public.clone(),
            party_two_master_key.chain_code.clone(),
        );

        // third case: party two is dead, party two wants to recover the full key.
        // In practice party one will recover party_two_master_key and from that point will run both logic parties locally
        let secret_decrypted_party_two =
            Msegmentation::decrypt(&encryptions_secret_party2, &G, &y, &segment_size);
        let _party_two_master_key_recovered = party_one_master_key
            .counter_master_key_from_recovered_secret(secret_decrypted_party_two.unwrap().clone());
        /*
                assert_eq!(
                    party_two_master_key_recovered.private,
                    party_two_master_key.private
                );
        */
        // fourth case: party one wants ro self-recover. to do so we first generate "half" party one master key from the recovered secret share
        // then we run rotation but with coin flip = 1. because our specific rotation includes generating new paillier key with all the zk - proofs.
        // the result is that both parties will go through rotation and have a new paillier data in the master keys. we show that signing works the same
        let secret_decrypted_party_one =
            Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);
        let party_one_master_key_half_recovered = MasterKey1::recover_master_key(
            secret_decrypted_party_one.unwrap().clone(),
            party_one_master_key.public.clone(),
            party_one_master_key.chain_code.clone(),
        );

        let one: FE = ECScalar::from(&BigInt::one());
        let random1 = Rotation {
            rotation: one.clone(),
        };
        let random2 = Rotation {
            rotation: one.clone(),
        };
        //rotation:
        let (rotation_party_one_first_message, party_one_private_new) =
            party_one_master_key_half_recovered.rotation_first_message(&random1);

        let result_rotate_party_one_first_message =
            party_two_master_key.rotate_first_message(&random2, &rotation_party_one_first_message);
        assert!(result_rotate_party_one_first_message.is_ok());

        let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
            result_rotate_party_one_first_message.unwrap();
        let (rotation_party_one_second_message, party_one_pdl_decommit, alpha) =
            MasterKey1::rotation_second_message(
                &rotation_party_two_first_message,
                &party_one_private_new,
            );
        let rotation_party_two_second_message =
            MasterKey2::rotate_second_message(&party_two_pdl_chal);
        let result_rotate_party_two_second_message = party_one_master_key_half_recovered
            .rotation_third_message(
                &rotation_party_one_first_message,
                party_one_private_new,
                &random1,
                &rotation_party_two_first_message,
                &rotation_party_two_second_message,
                party_one_pdl_decommit,
                alpha,
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

        //test by signing:
        let message = BigInt::from(1234);
        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();
        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();
        let sign_party_two_second_message = party_two_master_key_rotated.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
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

        let (cr_party_one_master_key, cr_party_two_master_key) =
            test_rotation(new_party_one_master_key, new_party_two_master_key);

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

        let (rotate_party_one_master_key, rotate_party_two_master_key) =
            test_rotation(party_one_master_key, party_two_master_key);

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

        // rotation
        let (party_one_master_key_rotated, party_two_master_key_rotated) =
            test_rotation(party_one_master_key, party_two_master_key);

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

        let (party_one_third_message, party_one_pdl_decommit, alpha) =
            MasterKey1::key_gen_third_message(
                &party_two_second_message.pdl_first_message,
                &party_one_private,
            );

        let party_two_third_message = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        let party_one_fourth_message = MasterKey1::key_gen_fourth_message(
            &party_two_second_message.pdl_first_message,
            &party_two_third_message,
            party_one_private.clone(),
            party_one_pdl_decommit,
            alpha,
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

    pub fn test_rotation(
        party_one_master_key: MasterKey1,
        party_two_master_key: MasterKey2,
    ) -> (MasterKey1, MasterKey2) {
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
        let (rotation_party_one_second_message, party_one_pdl_decommit, alpha) =
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
            &rotation_party_two_first_message,
            &rotation_party_two_second_message,
            party_one_pdl_decommit,
            alpha,
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

        (party_one_master_key_rotated, party_two_master_key_rotated)
    }
}
