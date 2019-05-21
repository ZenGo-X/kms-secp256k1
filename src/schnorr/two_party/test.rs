#![allow(non_snake_case)]
/*
    KMS-secp256k1

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
    use centipede::juggling::segmentation::Msegmentation;
    use chain_code::two_party::party1::ChainCode1;
    use chain_code::two_party::party2::ChainCode2;
    use curv::elliptic::curves::traits::ECPoint;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::{BigInt, FE, GE};
    use rotation::two_party::party1::Rotation1;
    use rotation::two_party::party2::Rotation2;
    use schnorr::two_party::{party1, party2};
    use ManagementSystem2PSchnorr;

    #[test]
    fn test_recovery_scenarios() {
        // key gen
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message();
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        assert_eq!(
            pubkey_view_party1.get_element(),
            pubkey_view_party2.get_element()
        );

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );
        // set master keys:
        let party_one_master_key =
            MasterKey1::set_master_key(&party1_cc, &keygen_party1, &keygen_party2.first_message);

        let party_two_master_key =
            MasterKey2::set_master_key(&party2_cc, &keygen_party2, &keygen_party1.first_message);

        // backup by party one of his private secret share: (we skip the verifiable part of proof and later verify)
        let segment_size = 8;
        let y: FE = FE::new_random();
        let G: GE = GE::generator();
        let Y = G.clone() * &y;
        // encryption
        let (_, encryptions_secret_party1) = party_one_master_key
            .local_key_pair
            .to_encrypted_segment(&segment_size, 32, &Y, &G);
        // encryption
        let (_, encryptions_secret_party2) = party_two_master_key
            .local_key_pair
            .to_encrypted_segment(&segment_size, 32, &Y, &G);

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
            party_two_master_key.pubkey.clone(),
            party_two_master_key.chain_code.clone(),
        );

        // third case: party two is dead, party two wants to recover the full key.
        // In practice party one will recover party_two_master_key and from that point will run both logic parties locally
        let secret_decrypted_party_two =
            Msegmentation::decrypt(&encryptions_secret_party2, &G, &y, &segment_size);
        let _party_two_master_key_recovered = party_one_master_key
            .counter_master_key_from_recovered_secret(secret_decrypted_party_two.unwrap().clone());

        // fourth case: party one wants ro self-recover. to do so we first generate "half" party one master key from the recovered secret share
        // then we run rotation but with coin flip = 1. because our specific rotation includes generating new paillier key with all the zk - proofs.
        // the result is that both parties will go through rotation and have a new paillier data in the master keys. we show that signing works the same
        let secret_decrypted_party_one =
            Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);
        let _party_one_master_key_half_recovered = MasterKey1::recover_master_key(
            secret_decrypted_party_one.unwrap().clone(),
            party_one_master_key.pubkey.clone(),
            party_one_master_key.chain_code.clone(),
        );
    }

    #[test]
    fn test_commutativity_rotate_get_child() {
        // key gen
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message();
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        assert_eq!(
            pubkey_view_party1.get_element(),
            pubkey_view_party2.get_element()
        );

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );
        // set master keys:
        let party_one_master_key =
            MasterKey1::set_master_key(&party1_cc, &keygen_party1, &keygen_party2.first_message);

        let party_two_master_key =
            MasterKey2::set_master_key(&party2_cc, &keygen_party2, &keygen_party1.first_message);

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

        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = rc_party_one_master_key
            .sign_second_message(
                &eph_keygen_party1,
                &eph_keygen_party2.first_message,
                &message,
            );
        let (sign_helper_party2, sign_party2_message2) = rc_party_two_master_key
            .sign_second_message(
                &eph_keygen_party2,
                &eph_keygen_party1.first_message,
                &message,
            );
        let _signature_view_party1 = rc_party_one_master_key
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = rc_party_two_master_key
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");

        // set master keys:
        let party_one_master_key =
            MasterKey1::set_master_key(&party1_cc, &keygen_party1, &keygen_party2.first_message);

        let party_two_master_key =
            MasterKey2::set_master_key(&party2_cc, &keygen_party2, &keygen_party1.first_message);

        let new_party_one_master_key = party_one_master_key.get_child(vec![BigInt::from(10)]);
        let new_party_two_master_key = party_two_master_key.get_child(vec![BigInt::from(10)]);

        let cr_party_one_master_key = new_party_one_master_key.rotate(&random1);
        let cr_party_two_master_key = new_party_two_master_key.rotate(&random2);

        // sign with child and rotated keys

        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = cr_party_one_master_key
            .sign_second_message(
                &eph_keygen_party1,
                &eph_keygen_party2.first_message,
                &message,
            );
        let (sign_helper_party2, sign_party2_message2) = cr_party_two_master_key
            .sign_second_message(
                &eph_keygen_party2,
                &eph_keygen_party1.first_message,
                &message,
            );
        let _signature_view_party1 = cr_party_one_master_key
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = cr_party_two_master_key
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");

        // test rotate -> child pub key == child -> rotate pub key
        assert_eq!(
            cr_party_one_master_key.pubkey.get_element(),
            rc_party_one_master_key.pubkey.get_element()
        );
    }
    #[test]
    fn test_get_child() {
        // key gen
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message();
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        assert_eq!(
            pubkey_view_party1.get_element(),
            pubkey_view_party2.get_element()
        );

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );
        // set master keys:
        let party_one_master_key =
            MasterKey1::set_master_key(&party1_cc, &keygen_party1, &keygen_party2.first_message);

        let party_two_master_key =
            MasterKey2::set_master_key(&party2_cc, &keygen_party2, &keygen_party1.first_message);

        //test signing:
        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = party_one_master_key.sign_second_message(
            &eph_keygen_party1,
            &eph_keygen_party2.first_message,
            &message,
        );
        let (sign_helper_party2, sign_party2_message2) = party_two_master_key.sign_second_message(
            &eph_keygen_party2,
            &eph_keygen_party1.first_message,
            &message,
        );
        let _signature_view_party1 = party_one_master_key
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = party_two_master_key
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");

        //get child:

        let new_party_two_master_key =
            party_two_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        let new_party_one_master_key =
            party_one_master_key.get_child(vec![BigInt::from(10), BigInt::from(5)]);
        assert_eq!(
            new_party_one_master_key.pubkey,
            new_party_two_master_key.pubkey
        );
        // sign after get child:
        //test signing:
        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = new_party_one_master_key
            .sign_second_message(
                &eph_keygen_party1,
                &eph_keygen_party2.first_message,
                &message,
            );
        let (sign_helper_party2, sign_party2_message2) = new_party_two_master_key
            .sign_second_message(
                &eph_keygen_party2,
                &eph_keygen_party1.first_message,
                &message,
            );
        let _signature_view_party1 = new_party_one_master_key
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = new_party_two_master_key
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");
    }
    #[test]
    fn test_flip_masters() {
        // key gen
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message();
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        assert_eq!(
            pubkey_view_party1.get_element(),
            pubkey_view_party2.get_element()
        );

        // chain code
        let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
            ChainCode1::chain_code_first_message();
        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();
        let cc_party_one_second_message = ChainCode1::chain_code_second_message(
            cc_comm_witness,
            &cc_party_two_first_message.d_log_proof,
        );

        let cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );
        assert!(cc_party_two_second_message.is_ok());

        let party1_cc = ChainCode1::compute_chain_code(
            &cc_ec_key_pair1,
            &cc_party_two_first_message.public_share,
        );

        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        );
        // set master keys:
        let party_one_master_key =
            MasterKey1::set_master_key(&party1_cc, &keygen_party1, &keygen_party2.first_message);

        let party_two_master_key =
            MasterKey2::set_master_key(&party2_cc, &keygen_party2, &keygen_party1.first_message);

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

        //test signing:
        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = party_one_master_key.sign_second_message(
            &eph_keygen_party1,
            &eph_keygen_party2.first_message,
            &message,
        );
        let (sign_helper_party2, sign_party2_message2) = party_two_master_key.sign_second_message(
            &eph_keygen_party2,
            &eph_keygen_party1.first_message,
            &message,
        );
        let _signature_view_party1 = party_one_master_key
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = party_two_master_key
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");

        //rotate:

        let party_one_master_key_rotated = party_one_master_key.rotate(&random1);
        let party_two_master_key_rotated = party_two_master_key.rotate(&random2);

        // sign after rotate:
        //test signing:
        let message = BigInt::from(1234);
        let eph_keygen_party1 = MasterKey1::sign_first_message();
        let eph_keygen_party2 = MasterKey2::sign_first_message();
        let (sign_helper_party1, sign_party1_message2) = party_one_master_key_rotated
            .sign_second_message(
                &eph_keygen_party1,
                &eph_keygen_party2.first_message,
                &message,
            );
        let (sign_helper_party2, sign_party2_message2) = party_two_master_key_rotated
            .sign_second_message(
                &eph_keygen_party2,
                &eph_keygen_party1.first_message,
                &message,
            );
        let _signature_view_party1 = party_one_master_key_rotated
            .signature(
                &sign_party1_message2,
                &sign_party2_message2,
                &sign_helper_party1,
            )
            .expect("bad signing");
        let _signature_view_party2 = party_two_master_key_rotated
            .signature(
                &sign_party2_message2,
                &sign_party1_message2,
                &sign_helper_party2,
            )
            .expect("bad signing");
    }

    #[test]
    fn test_key_gen() {
        // key gen
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message();
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        assert_eq!(
            pubkey_view_party1.get_element(),
            pubkey_view_party2.get_element()
        );
    }

}
