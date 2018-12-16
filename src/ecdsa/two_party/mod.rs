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

use chain_code::two_party::party1::ChainCode1;
use chain_code::two_party::party2::ChainCode2;
use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use paillier::*;

#[derive(Serialize, Deserialize)]
pub struct Party1Public {
    pub q: GE,
    pub p1: GE,
    pub p2: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey1 {
    pub public: Party1Public,
    private: party_one::Party1Private,
    chain_code: ChainCode1,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Public {
    pub q: GE,
    pub p2: GE,
    pub p1: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey2 {
    pub public: Party2Public,
    pub private: party_two::Party2Private,
    chain_code: ChainCode2,
}

pub mod party1;
pub mod party2;
mod test;

pub fn hd_key(mut location_in_hir: Vec<BigInt>, pubkey: &GE, chain_code: &GE) -> (GE, FE, GE) {
    let mask = BigInt::from(2).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();
    let chain_code_bi = chain_code.bytes_compressed_to_big_int();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = pubkey.bytes_compressed_to_big_int();
    let f = hmac_sha512::HMacSha512::create_hmac(&chain_code_bi, &vec![&pub_key_bi, &first]);
    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: FE = ECScalar::from(&f_l);
    let f_r_fe: FE = ECScalar::from(&f_r);
    let chain_code = chain_code * &f_r_fe;
    let pub_key = pubkey * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = acc.0.bytes_compressed_to_big_int();
                let f = hmac_sha512::HMacSha512::create_hmac(
                    &acc.2.bytes_compressed_to_big_int(),
                    &vec![&pub_key_bi, index],
                );
                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: FE = ECScalar::from(&f_l);
                let f_r_fe: FE = ECScalar::from(&f_r);

                (acc.0 * &f_l_fe, f_l_fe * &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}
