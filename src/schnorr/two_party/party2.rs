#![allow(non_snake_case)]
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
use super::hd_key;
use super::MasterKey2;
use chain_code::two_party::party2::ChainCode2;
use cryptography_utils::arithmetic::traits::Converter;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use cryptography_utils::{BigInt, FE, GE};
use multi_party_schnorr::protocols::multisig::*;
use rotation::two_party::Rotation;
use schnorr::two_party::party1::{
    KeyGenParty1Message1, KeyGenParty1Message2, SignParty1Message1, SignParty1Message2,
};
use ManagementSystem;

use Errors::{self, KeyGenError, SignError};

pub struct SignEph {
    pub first_message: SignParty2Message1,
    eph_key: EphKey,
}

pub struct SignParty2Message1 {
    pub com: GE,
}

pub struct SignParty2Message2 {
    pub y2: FE,
}

pub struct SignHelper {
    pub es: FE,
    pub Xt: GE,
}

pub struct KeyGen {
    pub local_keys: Keys,
    pub first_message: KeyGenParty2Message1,
}

pub struct KeyGenParty2Message1 {
    pub ix_pub: Vec<GE>,
}

pub struct KeyGenParty2Message2 {
    pub y2: FE,
}

pub struct HashE {
    pub e: FE,
}
impl MasterKey2 {
    pub fn set_master_key(
        chain_code: &ChainCode2,
        local_key_gen: &KeyGen,
        key_gen_received_message1: &KeyGenParty1Message1,
    ) -> MasterKey2 {
        MasterKey2 {
            local_key_pair: local_key_gen.local_keys.I.clone(),
            chain_code: ChainCode2 {
                chain_code: chain_code.chain_code.clone(),
            },
            pubkey: &local_key_gen.first_message.ix_pub[0] + &key_gen_received_message1.ix_pub[0],
        }
    }

    pub fn sign_first_message() -> SignEph {
        let party2_com = EphKey::gen_commit();
        SignEph {
            first_message: SignParty2Message1 {
                com: party2_com.eph_key_pair.public_key.clone(),
            },
            eph_key: party2_com,
        }
    }

    pub fn sign_second_message(
        &self,
        eph_sign: &SignEph,
        received_message1: &SignParty1Message1,
        message: &BigInt,
    ) -> (SignHelper, SignParty2Message2) {
        let eph_pub_key_vec = vec![
            received_message1.com.clone(),
            eph_sign.first_message.com.clone(),
        ];
        let (_It, Xt, es) = EphKey::compute_joint_comm_e(
            vec![self.pubkey.clone()],
            eph_pub_key_vec,
            &BigInt::to_vec(message),
        );
        let y2 = eph_sign
            .eph_key
            .partial_sign(&self.local_key_pair, es.clone());
        (SignHelper { es, Xt }, SignParty2Message2 { y2 })
    }

    pub fn signature(
        &self,
        party_two_sign_second_message: &SignParty2Message2,
        received_message2: &SignParty1Message2,
        sign_helper: &SignHelper,
    ) -> Result<Signature, Errors> {
        let y = EphKey::add_signature_parts(vec![
            received_message2.y1.clone(),
            party_two_sign_second_message.y2.clone(),
        ]);
        let sig = Signature::set_signature(&sign_helper.Xt, &y);
        match verify(&self.pubkey, &sig, &sign_helper.es).is_ok() {
            true => Ok(sig),
            false => Err(SignError),
        }
    }
}

impl ManagementSystem for MasterKey2 {
    fn rotate(mut self, cf: &Rotation) -> MasterKey2 {
        self.local_key_pair.update_key_pair(cf.rotation.clone());
        MasterKey2 {
            local_key_pair: self.local_key_pair,
            chain_code: ChainCode2 {
                chain_code: self.chain_code.chain_code.clone(),
            },
            pubkey: self.pubkey.clone(),
        }
    }

    fn get_child(&self, location_in_hir: Vec<BigInt>) -> MasterKey2 {
        let (public_key_new_child, _f_l_new, cc_new) =
            hd_key(location_in_hir, &self.pubkey, &self.chain_code.chain_code);
        let mut local_key_pair_updated = self.local_key_pair.clone();
        local_key_pair_updated.update_key_pair(FE::zero());

        MasterKey2 {
            local_key_pair: local_key_pair_updated,
            chain_code: ChainCode2 { chain_code: cc_new },
            pubkey: public_key_new_child,
        }
    }
}

impl KeyGen {
    pub fn first_message() -> KeyGen {
        let keys_2 = Keys::create();
        let broadcast1 = Keys::broadcast(keys_2.clone());
        KeyGen {
            local_keys: keys_2,
            first_message: KeyGenParty2Message1 { ix_pub: broadcast1 },
        }
    }

    // for predefined private key:
    pub fn first_message_predefined(secret_share: FE) -> KeyGen {
        let keys_2 = Keys::create_from(secret_share);
        let broadcast1 = Keys::broadcast(keys_2.clone());
        KeyGen {
            local_keys: keys_2,
            first_message: KeyGenParty2Message1 { ix_pub: broadcast1 },
        }
    }

    // create local sig
    pub fn second_message(
        &self,
        received_message1: &KeyGenParty1Message1,
    ) -> (HashE, KeyGenParty2Message2) {
        let ix_vec = vec![
            received_message1.ix_pub.clone(),
            self.first_message.ix_pub.clone(),
        ];
        let e = Keys::collect_and_compute_challenge(&ix_vec);
        let y2 = partial_sign(&self.local_keys, e.clone());
        (HashE { e }, KeyGenParty2Message2 { y2 })
    }
    // verify remote local sig and output joint public key if valid
    pub fn third_message(
        &self,
        received_message1: &KeyGenParty1Message1,
        received_message2: &KeyGenParty1Message2,
        e: &FE,
    ) -> Result<(GE), Errors> {
        let sig1 = Signature::set_signature(&received_message1.ix_pub[1], &received_message2.y1);
        let result = verify(&received_message1.ix_pub[0], &sig1, e);
        match result.is_ok() {
            true => Ok(&received_message1.ix_pub[0] + &self.local_keys.I.public_key),
            false => Err(KeyGenError),
        }
    }
}
