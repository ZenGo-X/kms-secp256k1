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
#![allow(non_snake_case)]
#![cfg(test)]

use crate::ecdsa::two_party::{MasterKey1 as EcdsaMasterKey1, MasterKey2 as EcdsaMasterKey2};
use two_party_ecdsa::centipede::juggling::{proof_system::Proof, segmentation::Msegmentation};
use two_party_ecdsa::curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};

#[test]
fn poc_schnorr_ecdsa() {
    // generate random secret share:
    let ss: FE = ECScalar::new_random();
    // party 2 is a client

    // backup: VE under public key Y (=yG):
    let segment_size = 8;
    let y: FE = ECScalar::new_random();
    let G: GE = ECPoint::generator();
    let Y = G * y;
    let Q = G * ss;
    // encryption
    let (segments, encryptions) =
        Msegmentation::to_encrypted_segments(&ss, &segment_size, 32, &Y, &G);
    // provable encryption
    let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);

    // party two verifier the backup zk proof
    let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
    assert!(result.is_ok());

    // full ecdsa key gen:

    // key gen
    let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
        EcdsaMasterKey1::key_gen_first_message();
    let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
        EcdsaMasterKey2::key_gen_first_message();
    let (kg_party_one_second_message, _paillier_key_pair, _party_one_private) =
        EcdsaMasterKey1::key_gen_second_message(
            kg_comm_witness,
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

    let key_gen_second_message = EcdsaMasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    assert!(key_gen_second_message.is_ok());

    let _party_two_paillier = key_gen_second_message.unwrap();

    // recovery party two:
    let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);

    // debug test
    assert_eq!(ss.get_element(), secret_decrypted.unwrap().get_element());
}
