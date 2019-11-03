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

use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;

use super::Rotation;

pub struct Rotation2 {}

impl Rotation2 {
    pub fn key_rotate_first_message(
        party1_first_message: &coin_flip_optimal_rounds::Party1FirstMessage,
    ) -> coin_flip_optimal_rounds::Party2FirstMessage {
        coin_flip_optimal_rounds::Party2FirstMessage::share(&party1_first_message.proof)
    }

    pub fn key_rotate_second_message(
        party1_second_message: &coin_flip_optimal_rounds::Party1SecondMessage,
        party2_first_message: &coin_flip_optimal_rounds::Party2FirstMessage,
        party1_first_message: &coin_flip_optimal_rounds::Party1FirstMessage,
    ) -> Rotation {
        let rotation = coin_flip_optimal_rounds::finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        Rotation { rotation }
    }
}
