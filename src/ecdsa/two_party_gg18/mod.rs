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
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::{MessageA, MessageB};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::EncryptionKey;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct MasterKeyPublic {
    pub q: GE, //y_sum
    pub vss_scheme_vec: Vec<VerifiableSS>,
    pub paillier_key_vec: Vec<EncryptionKey>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct MasterKey1 {
    pub public: MasterKeyPublic,
    private: PartyPrivate,
    chain_code: BigInt,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct MasterKey2 {
    pub public: MasterKeyPublic,
    private: PartyPrivate,
    chain_code: BigInt,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenMessage1 {
    pub bc_i: KeyGenBroadcastMessage1,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenMessage2 {
    pub decom_i: KeyGenDecommitMessage1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenMessage3 {
    pub vss_scheme: VerifiableSS,
    pub secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenMessage4 {
    pub dlog_proof: DLogProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignMessage1 {
    pub com: SignBroadcastPhase1,
    pub m_a_k: MessageA,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage2 {
    pub m_b_gamma: MessageB,
    pub m_b_w: MessageB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage3 {
    pub delta: FE,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignMessage4 {
    pub decommit: SignDecommitPhase1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage5 {
    pub phase5_com: Phase5Com1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage6 {
    pub phase_5a_decom: Phase5ADecom1,
    pub helgamal_proof: HomoELGamalProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage7 {
    pub phase5_com2: Phase5Com2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage8 {
    pub phase_5d_decom2: Phase5DDecom2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage9 {
    pub s_i: FE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationParty1Message1 {}

pub mod party1;
pub mod party2;
mod test;

pub fn hd_key(
    mut location_in_hir: Vec<BigInt>,
    pubkey: &GE,
    chain_code_bi: &BigInt,
) -> (GE, FE, GE) {
    let mask = BigInt::from(2).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = pubkey.bytes_compressed_to_big_int();
    let f = hmac_sha512::HMacSha512::create_hmac(&chain_code_bi, &[&pub_key_bi, &first]);
    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: FE = ECScalar::from(&f_l);
    let f_r_fe: FE = ECScalar::from(&f_r);

    let bn_to_slice = BigInt::to_vec(chain_code_bi);
    let chain_code = GE::from_bytes(&bn_to_slice[1..33]).unwrap() * &f_r_fe;
    let g: GE = ECPoint::generator();
    let pub_key = *pubkey + g * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = acc.0.bytes_compressed_to_big_int();
                let f = hmac_sha512::HMacSha512::create_hmac(
                    &acc.2.bytes_compressed_to_big_int(),
                    &[&pub_key_bi, index],
                );
                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: FE = ECScalar::from(&f_l);
                let f_r_fe: FE = ECScalar::from(&f_r);

                (acc.0 + g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}
