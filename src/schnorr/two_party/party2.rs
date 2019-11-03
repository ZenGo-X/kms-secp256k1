#![allow(non_snake_case)]
/*
    KMS-secp256k1

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
use super::{MasterKey1, MasterKey2};
use chain_code::two_party::party1::ChainCode1;
use chain_code::two_party::party2::ChainCode2;
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE, GE};
use multi_party_schnorr::protocols::multisig::*;
use rotation::two_party::Rotation;
use schnorr::two_party::party1::{
    KeyGenParty1Message1, KeyGenParty1Message2, SignParty1Message1, SignParty1Message2,
};
use ManagementSystem2PSchnorr;

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

    //  master key of party one from counter party recovery (party two recovers party one secret share)
    pub fn counter_master_key_from_recovered_secret(&self, party_one_secret: FE) -> MasterKey1 {
        let local_keys_recovered = Keys::create_from(party_one_secret);
        // set master keys:
        MasterKey1 {
            local_key_pair: local_keys_recovered.I,
            chain_code: ChainCode1 {
                chain_code: self.chain_code.chain_code.clone(),
            },
            pubkey: self.pubkey.clone(),
        }
    }

    pub fn recover_master_key(
        recovered_secret: FE,
        party_two_public: GE,
        chain_code: ChainCode2,
    ) -> MasterKey2 {
        //  master key of party two from party two secret recovery:
        // q1 (public key of party one), chain code are needed for
        // recovery of party two master key. There are two options:
        // (1) party 2 kept the public data of the master key and can retrieve it (only private key was lost)
        // (2) party 2 lost the public data as well. in this case only party 1 can help with the public data.
        //     if party 1 becomes malicious it means two failures at the same time from which the system will not be able to recover.
        //     Therefore no point of running any secure protocol with party 1 and just accept the public data as is.
        let local_keys_recovered = Keys::create_from(recovered_secret);

        MasterKey2 {
            local_key_pair: local_keys_recovered.I,
            chain_code,
            pubkey: party_two_public,
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
        if verify(&self.pubkey, &sig, &sign_helper.es).is_ok() {
            Ok(sig)
        } else {
            Err(SignError)
        }
    }
}

impl ManagementSystem2PSchnorr for MasterKey2 {
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
            chain_code: ChainCode2 {
                chain_code: cc_new.bytes_compressed_to_big_int(),
            },
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
    ) -> Result<GE, Errors> {
        let sig1 = Signature::set_signature(&received_message1.ix_pub[1], &received_message2.y1);
        let result = verify(&received_message1.ix_pub[0], &sig1, e);
        if result.is_ok() {
            Ok(&received_message1.ix_pub[0] + &self.local_keys.I.public_key)
        } else {
            Err(KeyGenError)
        }
    }
}
