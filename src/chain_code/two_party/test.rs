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
    use chain_code::two_party::party1;
    use chain_code::two_party::party2;

    #[test]
    fn test_chain_code() {
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

        assert_eq!(party1_cc.chain_code, party2_cc.chain_code);
    }
}
