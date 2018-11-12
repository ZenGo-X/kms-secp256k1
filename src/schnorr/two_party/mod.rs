/*
    Kms

    Copyright 2018 by Kzen Networks

    This file is part of KMS library
    (https://github.com/KZen-networks/kms)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/Kms/blob/master/LICENSE>
*/

use chain_code::two_party::party1::ChainCode1;
use chain_code::two_party::party2::ChainCode2;
use cryptography_utils::GE;
use multi_party_schnorr::protocols::multisig::KeyPair;

// since this special case requires two out of two signers we ignore the "accountable" property

pub struct MasterKey1 {
    local_key_pair: KeyPair,
    chain_code: ChainCode1,
    pubkey: GE,
}

pub struct MasterKey2 {
    local_key_pair: KeyPair,
    chain_code: ChainCode2,
    pubkey: GE,
}

pub mod party1;
pub mod party2;
mod test;
