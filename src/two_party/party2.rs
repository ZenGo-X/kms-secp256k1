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
use cryptography_utils::{BigInt,GE,FE};
use super::traits::ManagementSystem;
//TODO: pick only relevant
use paillier::*;

pub struct Party2Public{
    pub Q: GE,
    pub P2: GE,
    paillier_pub: EncryptionKey,
    c_key : Ciphertext,
}

struct Party2Private{
    x2: FE,

}

pub struct MasterKey2{
    toggle: bool,
    public: Party2Public,
    private: Party2Private,
    chain_code: BigInt,

}

impl ManagementSystem for MasterKey2{

}

impl Party2Public{
    //keygen party1
}