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

mod tests{

    use two_party::lindell_2017::*;

    #[test]
    fn test_master_key_gen(){
        //chain code:
        let party_one_first_message = party1::MasterKey1::chain_code_first_message();
        let party_two_first_message = party2::MasterKey2::chain_code_first_message();
        let party_one_second_message = party1::MasterKey1::chain_code_second_message(&party_one_first_message,&party_two_first_message.d_log_proof);
        let party_two_second_message = party2::MasterKey2::chain_code_second_message(&party_one_first_message, &party_one_second_message);
        assert_eq!(party1::MasterKey1::compute_chain_code(&party_one_first_message, &party_two_first_message),
                   party2::MasterKey2::compute_chain_code(&party_one_first_message, &party_two_first_message));
    }
    #[test]
    fn test_coin_flip(){
        let (party1_first_message, m1, r1) = party1::MasterKey1::key_rotate_first_message();
        let party2_first_message = party2::MasterKey2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) = party1::MasterKey1::key_rotate_second_message(&party2_first_message,&m1,&r1);
        let random2 = party2::MasterKey2::key_rotate_second_message(&party1_second_message,&party2_first_message,&party1_first_message);
    }
}