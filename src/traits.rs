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

use curv::BigInt;
use rotation::two_party::Rotation;

pub trait ManagementSystem2PSchnorr {
    fn rotate(self, &Rotation) -> Self;
    fn get_child(&self, Vec<BigInt>) -> Self;
}
