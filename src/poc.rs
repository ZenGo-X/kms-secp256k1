#![allow(non_snake_case)]

/*
    KMS

    Copyright 2018 by Kzen Networks

    This file is part of KMS library
    (https://github.com/KZen-networks/kms)

    KMS is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/kmd/blob/master/LICENSE>
*/

#[cfg(test)]
mod tests {
    use centipede::juggling::proof_system::Proof;
    use centipede::juggling::segmentation::Msegmentation;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};
    use ecdsa::two_party::MasterKey1 as EcdsaMasterKey1;
    use ecdsa::two_party::MasterKey2 as EcdsaMasterKey2;
    use schnorr::two_party::party1;
    use schnorr::two_party::party2;

    #[test]
    fn poc_schnorr_ecdsa() {
        // generate random secret share:
        let ss: FE = ECScalar::new_random();
        // party 2 is a client

        // backup: VE under public key Y (=yG):
        let segment_size = 8;
        let y: FE = ECScalar::new_random();
        let G: GE = ECPoint::generator();
        let Y = G.clone() * &y;
        let Q = &G * &ss;
        // encryption
        let (segments, encryptions) =
            Msegmentation::to_encrypted_segments(&ss, &segment_size, 32, &Y, &G);
        // provable encryption
        let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);

        //full schnorr key gen:
        let keygen_party1 = party1::KeyGen::first_message();
        let keygen_party2 = party2::KeyGen::first_message_predefined(ss.clone());
        let (hash_e1, keygen_party1_second_message) =
            keygen_party1.second_message(&keygen_party2.first_message);
        let (hash_e2, keygen_party2_second_message) =
            keygen_party2.second_message(&keygen_party1.first_message);
        let _pubkey_view_party1 = keygen_party1
            .third_message(
                &keygen_party2.first_message,
                &keygen_party2_second_message,
                &hash_e1.e,
            )
            .expect("bad key proof");
        let _pubkey_view_party2 = keygen_party2
            .third_message(
                &keygen_party1.first_message,
                &keygen_party1_second_message,
                &hash_e2.e,
            )
            .expect("bad key proof");

        // full ecdsa key gen:

        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            EcdsaMasterKey1::key_gen_first_message();
        let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
            EcdsaMasterKey2::key_gen_first_message();
        let (kg_party_one_second_message, paillier_key_pair, range_proof, correct_key_proof) =
            EcdsaMasterKey1::key_gen_second_message(
                kg_comm_witness,
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.d_log_proof,
            );

        let key_gen_second_message = EcdsaMasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            &paillier_key_pair.ek,
            &paillier_key_pair.encrypted_share,
            &range_proof,
            &correct_key_proof,
        );

        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, _party_two_paillier, pdl_chal) =
            key_gen_second_message.unwrap();

        assert!(party_two_second_message.is_ok());

        let pdl_prover =
            EcdsaMasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal.c_tag);

        let pdl_decom_party2 = EcdsaMasterKey2::key_gen_third_message(&pdl_chal);

        let pdl_decom_party1 = EcdsaMasterKey1::key_gen_fourth_message(
            &pdl_prover,
            &pdl_chal.c_tag_tag,
            kg_ec_key_pair_party1,
            &pdl_decom_party2.a,
            &pdl_decom_party2.b,
            &pdl_decom_party2.blindness,
        )
        .expect("pdl error party 2");

        EcdsaMasterKey2::key_gen_fourth_message(
            &pdl_chal,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        )
        .expect("pdl error party1");

        // recovery:
        let secret_new = Msegmentation::assemble_fe(&segments.x_vec, &segment_size);
        let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);

        assert_eq!(ss.get_element(), secret_new.get_element());
        assert_eq!(ss.get_element(), secret_decrypted.get_element());

        let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
        assert!(result.is_ok());
    }
}
