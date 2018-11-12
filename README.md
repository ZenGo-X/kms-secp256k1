Key Management System (KMS) for curvr Secp256k1 
=====================================
Multi Party Key Management System (KMS) for Secp256k1 Elliptic curve based digital signatures.
 ### Currently supported features 
* Messaging wrapper for **Schnorr two party** key generation and signing (https://github.com/KZen-networks/multi-party-schnorr/tree/master/src/protocols/multisig)
* Messaging wrapper for **ECDSA two party** key generation and signing (https://github.com/KZen-networks/multi-party-ecdsa/tree/master/src/protocols/two_party_ecdsa)
* Key management trait (including implementation for Schnorr and ECDSA):
  * **two party rotation** of secret shares (no change to public key/address) 
  * **two party HD** (hirrachical deterministic) derivation for two party distributed keys
* Third party recovery of counter master secret share (root of HD tree) with support of verifiable encryption (VE) == a way for counter party to verify that third party has the power the unlock for full private key.

### Currently not supported
* The library does not provide serialize and desrialize functionalities and not handling any form of network communication
* The cryptography is not constant time or immune to side channel attacks
* The library has no unified methodology to handle errors. Usually errors are propagated from lower level code. 

### To play with the code 
Our working branch is `schnorr-support`. It is best to start with the tests code:
1. `poc.rs` for VE recovery and master keys generations
2. `ecdsa/two_party/test` and `schnorr/two_party/test` for keygen, signing, rotation, hd tests. Notice that HD and rotation are commutative such that the order of the operations does not matter. 



License
-------
KMS is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md), in addition **the [Rust utilities wiki](https://github.com/KZen-networks/rust-utils/wiki) contains information on workflow and environment set-up**.

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).
