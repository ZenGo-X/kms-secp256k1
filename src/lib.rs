/*
    KMS

    Copyright 2018 by Kzen Networks

    This file is part of KMS library
    (https://github.com/KZen-networks/kms)

    KMS is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/kmd/blob/master/LICENSE>
*/
#[macro_use]
extern crate serde_derive;
extern crate serde;

extern crate centipede;
extern crate curv;
extern crate multi_party_ecdsa;
extern crate multi_party_schnorr;
extern crate paillier;
extern crate zk_paillier;

pub mod chain_code;
pub mod ecdsa;
pub mod rotation;
pub mod schnorr;
pub mod traits;
pub use traits::*;
pub mod poc;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    KeyGenError,
    SignError,
}
