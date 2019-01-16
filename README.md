Key Management System (KMS) for curve Secp256k1 
=====================================
Multi Party Key Management System (KMS) for Secp256k1 Elliptic curve based digital signatures.

 ### Introduction 

Digital Signature Algorithm (DSA) is the basic cryptographic primitive for blockchain interaction: private keys represent identities, transfer of ownership is done by means of signatures and the blockchain is maintained by miners verifying signatures using public keys.
Moving the classical DSA constructions to threshold signature schemes can provide enhanced security by distributed key generation and distributed signing. The miners verification process stays the same such that the change is transparent to the blockchain operators and can be done at the wallet (KMS) level. Recent years have brought major breakthroughs for threshold and multi-signatures schemes providing practical multi-party schemes for common DSAs used in blockchain today, i.e. [1–4] for ECDSA, Schnorr and BLS.

We define two roles: Owner and Provider. The Owner is the end-user who owns the funds in the account and holds one secret share of the private key. The Provider is another share holder of the private key but has no funds tied to this private key. His role is to provide the additional security in the system aiding and enabling the owner to generate keys and transact in distributed fash- ion. From network perspective one Provider is connected to many Owners which together maintain the Provider, for example paying his cost in transaction fees. The Provider can run on any machine: from a Trusted Execution Environment (TEE) to machine operated by incentivized human operator. Multiple Providers can compete for Owners. To give concrete example for use case: a company employees are all Owners and a Server owned by the company is the Provider.

 ### Currently supported features 
* Messaging wrapper for **Schnorr two party** key generation and signing (https://github.com/KZen-networks/multi-party-schnorr/tree/master/src/protocols/multisig)
* Messaging wrapper for **ECDSA two party** key generation and signing (https://github.com/KZen-networks/multi-party-ecdsa/tree/master/src/protocols/two_party_ecdsa)
* Key management trait (including implementation for Schnorr and ECDSA):
  * **two party rotation** of secret shares (no change to public key/address) 
  * **two party HD** (hirrachical deterministic) derivation for two party distributed keys
* Third party recovery of counter master secret share (root of HD tree) with support of verifiable encryption (VE) == a way for counter party to verify that third party has the ability to unlock for it to get the full private key

### Currently not supported
* The library does not provide serialize and desrialize functionalities and not handling any form of network communication
* The cryptography is not constant time or immune to side channel attacks
* The library has no unified methodology to handle errors. Usually errors are propagated from lower level code. 

### To play with the code 
It is best to start with the tests code:
1. `poc.rs` for VE recovery and master keys generation
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


References
-------
[1] R. Gennaro, S. Goldfeder. Fast Multiparty Threshold ECDSA with Fast Trustless Setup ACM Conference on Computer and Communications Security (CCS), 2018.

[2] Y. Lindell and A. Nof. Fast Secure Multiparty ECDSA with Practical Distributed Key Generation and Applications to Cryptocurrency Custody. ACM Conference on Computer and Communications Security (CCS), 2018.

[3] D. Boneh, M. Drijvers, G. Neven. Compact Multi-Signatures for Smaller Blockchains. Cryptology ePrint Archive, Report 2018/483. Last access Aug. 2018.

[4] G. Maxwell, A. Poelstra, Y. Seurin, P. Wuille. Simple Schnorr Multi-Signatures with Applications to Bitcoin. Cryptology ePrint Archive, Report 2018/068, Last accessed Aug. 2018.

