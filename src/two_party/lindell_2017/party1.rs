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
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use cryptography_utils::cryptographic_primitives::commitments::pedersen_commitment::*;
use cryptography_utils::cryptographic_primitives::proofs::{sigma_valid_pedersen,sigma_valid_pedersen_blind};
use cryptography_utils::elliptic::curves::secp256_k1::Secp256k1Scalar;
use cryptography_utils::arithmetic::traits::Modulo;
use cryptography_utils::elliptic::curves::traits::ECScalar;
use paillier::proof::Challenge;
use super::traits::ManagementSystem;
use paillier::*;
use cryptography_utils::cryptographic_primitives::twoparty::dh_key_exchange;

//TODO: add derive to structs.

pub struct Party1Public{
    pub Q: GE,
    pub P1: GE,
    paillier_pub: EncryptionKey,
    c_key : RawCiphertext,
}

struct Party1Private{
    x1: FE,
    paillier_priv: DecryptionKey,

}

pub struct MasterKey1{
    public: Party1Public,
    private: Party1Private,
    chain_code: BigInt,

}

impl ManagementSystem<Party1Public,Party1Private> for MasterKey1{
    // before rotation make sure both parties have the same key
    fn rotate(self, cf: &BigInt) -> self{
        let rand_str: FE = ECScalar::from_big_int(cf);
        //TODO: use proper set functions
        self.private.x1 = self.private.x1.mul(&rand_str.get_element());
        self.public.P1 = self.public.P1.scalar_mul(&rand_str.get_element());
        let c_key_new = BigInt::mod_pow(&self.public.c_key.0, cf, &rand_str.get_q());
        self.public.c_key = RawCiphertext(c_key_new);
        return self;
    }

    fn get_child(&self, index: BigInt, height: BigInt) -> (Party1Public,Party1Private){

    }
}

impl MasterKey1 {
    pub fn chain_code_first_message() -> dh_key_exchange::Party1FirstMessage{
        dh_key_exchange::Party1FirstMessage::create_commitments()
    }
    pub fn chain_code_second_message(first_message: &dh_key_exchange::Party1FirstMessage, proof: &DLogProof) -> dh_key_exchange::Party1SecondMessage {
        dh_key_exchange::Party1SecondMessage::verify_and_decommit(&first_message, proof).expect("")
    }
    pub fn compute_chain_code(first_message :&dh_key_exchange::Party1FirstMessage, party2_first_message: &dh_key_exchange::Party2FirstMessage ) -> GE{
        dh_key_exchange::compute_pubkey_party1(first_message,party2_first_message)
    }

    pub fn key_gen_first_message() -> party_one::KeyGenFirstMsg{
        party_one::KeyGenFirstMsg::create_commitments()
    }
    pub fn key_gen_second_message(first_message: &party_one::KeyGenFirstMsg, proof: &DLogProof) -> (party_one::KeyGenSecondMsg, party_one::PaillierKeyPair)  {
        party_one::KeyGenSecondMsg::verify_and_decommit(&first_message, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(first_message );
    }

    pub fn key_gen_third_message(paillier_key_pair: &party_one::PaillierKeyPair, challenge: &proof::Challenge ) -> CorrectKeyProof{

        let proof_result = party_one::PaillierKeyPair::generate_proof_correct_key(
            &paillier_key_pair,
            &challenge.val,
        ).expect("").val;
        return proof_result;
    }

    pub fn key_gen_forth_message(first_message: &party_one::KeyGenFirstMsg, paillier_key_pair: &party_one::PaillierKeyPair ) -> (EncryptedPairs, ChallengeBits, Proof){
        let (encrypted_pairs, challenge, proof) =
            party_one::PaillierKeyPair::generate_range_proof(
                &paillier_key_pair,
                &first_message,
            );
        return (encrypted_pairs.val, challenge.val, proof.val);
    }

    pub fn set_master_key(local_fe: &FE, other_ge: &GE) -> MasterKey1{
        //chain code using dh ke

    }

    //TODO: implmenet sid / state machine
    pub fn key_rotate_first_message() -> (coin_flip_optimal_rounds::Party1FirstMessage, Secp256k1Scalar, Secp256k1Scalar ){
        let (party1_first_message, m1, r1)  = coin_flip_optimal_rounds::Party1FirstMessage::commit();
    }

    pub fn key_rotate_second_message(party2_first_message : &coin_flip_optimal_rounds::Party2FirstMessage, m1: &Secp256k1Scalar, r1: &Secp256k1Scalar) -> ( coin_flip_optimal_rounds::Party1SecondMessage, Secp256k1Scalar){
        let (party1_second_message, random1) = coin_flip_optimal_rounds::Party1SecondMessage::reveal(&party2_first_message.seed,m1, r1);
        return (party1_second_message, random1);

    }

}