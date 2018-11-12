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

use cryptography_utils::{BigInt, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use paillier::*;
use chain_code::two_party::party1::ChainCode1;
use chain_code::two_party::party2::ChainCode2;

#[derive(Serialize, Deserialize)]
pub struct Party1Public {
    pub q: GE,
    pub p1: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

pub struct MasterKey1 {
    pub public: Party1Public,
    private: party_one::Party1Private,
    chain_code: ChainCode1,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Public {
    pub q: GE,
    pub p2: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

pub struct MasterKey2 {
    pub public: Party2Public,
    pub private: party_two::Party2Private,
    chain_code: ChainCode2,
}

pub mod party1;
pub mod party2;
mod test;