/*
 * Hybrid Post Quantum Cryptography Library
 *
 * ==========================(LICENSE BEGIN)============================
 
The MIT License

Copyright (c) 2023 Doge Protocol Community

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

 * ===========================(LICENSE END)=============================
 * 
 * WARNING! This is an experimental cryptography library. It is not ready for use yet in any production systems!!
 * 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "hybrid.h"
#include "../common/hybrid-common.h"
#include "../common/fips202.h"
#include "../common/shake_prng.h"
#include "../dilithium2/api.h"
#include "../sphincs/api.h"
#include "../tweetnacl/tweetnacl.h"
#include "../random/randombytes.h"

/*
Secret Key Length = 64 + 2560 + 1312 + 128 = 4064
==================================================
Layout of secret key:

64 bytes                             2560 bytes             1312 bytes             128 bytes         
ed25519 secret key with public key | dilithium secret key | dilithium public key | sphincs secret key with public key

The following signature length includes implementation output, in addition to actual algorithm output.

Layout of ED25519 signature
============================

64 bytes          | {1 to 64 bytes}  
ed25519 Signature | Message

Layout of Dilithium signature
==============================
2420 bytes
dilithium signature

Layout of Sphincs signature
==============================
49856 bytes
dilithium signature

Layout of Public Key
==============================
32 bytes           | 1312 bytes            | 64 bytes           
ed25519 public key | dilithium public key  | sphincs public key 


Compact Signature
==================
==================
The compact signature scheme does not sign the message using sphincs+, but only using ed25519 and dilithium. During any emergency event, such as if both ed25519 and dilithium are broken or potential attacks found, 
the SPHINCS+ key can be used to prove authenticity of signatures signed earlier or enabled for newer signatures with the same key pair.

In the compact signature mode, a new message digest is created from the original message digest and then hashed using sha3-512. This new message is signed by ed25519 and dilithium

Hybrid Signature Message (compact mode)
=========================================

40 bytes      | {0 to 64 bytes}  | 64 bytes
random nonce  | original message | sphincs public key

hybrid-message-hash = SHA3-512(compact-mode-message)

Hybrid Signature Length (compact mode) = 1 + 1 + 64 + 2420 + 40 + {1 to 64}
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | 2420 bytres         | 40 bytes     | {1 to 64 bytes}
signature id (always 1) | length of message | ed25519 signature | dilithium signature | random nonce | original message

Full Signature
==================
==================

Hybrid Signature Length (full, used during breakglass) = 1 + 1 + 64 + {1 to 64} + 2420 + 49856
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | {1 to 64 bytes}   | 2420 bytes          | 49856
signature id (always 2) | length of message | ed25519 signature | original message  | dilithium signature | sphincs signature

Message is variable length, between 1 to 64 bytes
*/

/**
 * @file hybrid.c
 * @brief Implementation of dilithium_ed25519_sphincs signature algorithm
 */

 /**
  * @brief Implementation of seed expander that expands a seed specific to dilithium_ed25519_sphincs for purpose of key generation.
  * Use this function only for specific cases like blockchain seed mnemonics where less number of seed bytes are required for human readability and mangeability.
  * All other cases should directly generate all the 160 bytes at random using a CSPRNG.
  * The input seed should be created from a CSPRNG.
  * 64 bytes of the input seed is first expanded to 128 bytes (32 bytes for ed25519 and 96 bytes for SPHINCS+)
  * The remaining 32 bytes of the input is copied as-is in the expanded seed.
  * An alternative scheme is we just take 64 bytes input seed and return 160 bytes output expanded seed, instead of this complicated scheme.
  * The rationale for doing complicated expansion instead is that;
  * Some of the expanded seed bytes are copied as is to the SPHINCS+ public key when this expanded seed is subsequently used for generating the keypair (as part of SPHINCS+ internal implementation).
  * While it shouldn’t matter if we expose some parts of the csprng output (it is computationally infeasible to recover the remaining unexposed part), 
  * as a long term hedge for using this XOF, we choose to have atleast one part of the hybrid signature scheme use the original seed material directly, than from the XOF.
  * On why ed25519 and SPHINCS+ specifically instead of a different combination from the 3 schemes;  during the normal course of signing using the compact scheme, the SPHINCS+ key isn't used at all. 
  * To maintain quantum resistance in case there is an issue with this XOF, Dilithium is used (instead of Dilithium + SPHINCS+), so that we have atleast one quantum resistance scheme that isn't relying on this expansion XOF.
  * 
  * @param[int] input seed generated randomly. should be 96 bytes in length.
  * @param[out] expanded seed of length 160 bytes.
  */
int crypto_sign_dilithium_ed25519_sphincs_keypair_seed_expander(const unsigned char* seed, unsigned char* expandedSeed) {
	uint8_t seedTemp[64] = { 0 };
	uint8_t expandedSeedTemp[128] = { 0 };

	//Copy first 64 bytes of input-seed to temp-seed
	for (int i = 0; i < 64; i++) {
		seedTemp[i] = seed[i];
		i++;
	}

	//Expand seed for ed25519 + SPHINCS+
	int ret = seedexpander_wrapper(seedTemp, 64, expandedSeedTemp, 128);
	if (ret != 0) {
		return ret;
	}

	//Copy over first 32 bytes of expandedSeed used for ed25519 in the function crypto_sign_dilithium_ed25519_sphincs_keypair_seed
	for (int i = 0; i < 32; i++) {
		expandedSeed[i] = expandedSeedTemp[i];
	}

	//Copy over last 32 bytes of original input seed to be used for Dilithium in the function crypto_sign_dilithium_ed25519_sphincs_keypair_seed
	for (int i = 0; i < 32; i++) {
		expandedSeed[32 + i] = seed[64 + i];
	}

	//Copy last 96 bytes of expanded seed for use for SPHINCS+ in the function crypto_sign_dilithium_ed25519_sphincs_keypair_seed
	for (int i = 0; i < 96; i++) {
		expandedSeed[64 + i] = expandedSeedTemp[32 + i];
	}

	return 0;
}

int crypto_sign_dilithium_ed25519_sphincs_keypair_seed(unsigned char* pk, unsigned char* sk, unsigned char* seed) {
	if (pk == NULL || sk == NULL || seed == NULL) {
		return -1;
	}

	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char pk2[1312] = { 0 }; //CRYPTO_DILITHIUM_PUBLICKEY_BYTES
	unsigned char sk2[2560] = { 0 }; //CRYPTO_DILITHIUM_SECRETKEY_BYTES
	unsigned char pk3[64] = { 0 }; //CRYPTO_SPHINCS_PUBLICKEY_BYTES
	unsigned char sk3[128] = { 0 }; //CRYPTO_SPHINCS_SECRETKEY_BYTES

	unsigned char seed1[32] = { 0 }; //SEED_LENGTH_ED25519
	unsigned char seed2[32] = { 0 }; //SEED_LENGTH_DILITHIUM
	unsigned char seed3[96] = { 0 }; //SEED_LENGTH_SPHINCS

	for (int i = 0; i < SEED_LENGTH_ED25519; i++) {
		seed1[i] = seed[i];
	}

	for (int i = 0; i < SEED_LENGTH_DILITHIUM; i++) {
		seed2[i] = seed[i + SEED_LENGTH_ED25519];
	}

	for (int i = 0; i < SEED_LENGTH_SPHINCS; i++) {
		seed3[i] = seed[i + SEED_LENGTH_ED25519 + SEED_LENGTH_DILITHIUM];
	}

	int r1 = crypto_sign_ed25519_keypair_seed(pk1, sk1, seed1);
	if (r1 != 0) {
		return -2;
	}

	for (int i = 0; i < CRYPTO_ED25519_PUBLICKEY_BYTES; i++) {
		pk[i] = pk1[i];
	}

	for (int i = 0; i < CRYPTO_ED25519_SECRETKEY_BYTES; i++) { //secret key includes public key
		sk[i] = sk1[i];
	}

	int r2 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed(pk2, sk2, seed2);

	if (r2 != 0) {
		return -3;
	}

	for (int i = 0; i < CRYPTO_DILITHIUM_SECRETKEY_BYTES; i++) {
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + i] = sk2[i];
	}

	for (int i = 0; i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES; i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + i] = pk2[i];
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_DILITHIUM_SECRETKEY_BYTES + i] = pk2[i]; //copy public key
	}

	int r3 = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_seed_keypair(pk3, sk3, seed3);

	if (r3 != 0) {
		return -4;
	}

	for (int i = 0; i < CRYPTO_SPHINCS_SECRETKEY_BYTES; i++) {
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_DILITHIUM_SECRETKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES + i] = sk3[i];
	}

	for (int i = 0; i < CRYPTO_SPHINCS_PUBLICKEY_BYTES; i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES + i] = pk3[i];
	}

	return 0;
}

int crypto_sign_dilithium_ed25519_sphincs_keypair(unsigned char* pk, unsigned char* sk) {
	if (pk == NULL || sk == NULL) {
		return -1;
	}

	unsigned char seed[160];
	if (randombytes(seed, sizeof seed) != 0) {
		return -1;
	}
	return crypto_sign_dilithium_ed25519_sphincs_keypair_seed(pk, sk, seed);
}

int crypto_sign_dilithium_ed25519_sphincs(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk) {

	if (sm == NULL || smlen == NULL || m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sk == NULL) {
		return -1;
	}

	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long sigLen3 = 0;

	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_MAX_SIGNATURE_BYTES
	unsigned char sig3[49856] = { 0 }; //CRYPTO_SPHINCS_SIGNATURE_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char sk2[2560] = { 0 }; //CRYPTO_DILITHIUM_SECRETKEY_BYTES
	unsigned char sk3[128] = { 0 }; //CRYPTO_SPHINCS_SECRETKEY_BYTES

	//Copy sk1 from input
	for (int i = 0;i < CRYPTO_ED25519_SECRETKEY_BYTES;i++) {
		sk1[i] = sk[i];
	}

	//Copy sk2 from input (skip public key part of it)
	for (int i = 0;i < CRYPTO_DILITHIUM_SECRETKEY_BYTES;i++) {
		sk2[i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + i];
	}

	//Copy sk3 from input (skip public key part of it)
	for (int i = 0; i < CRYPTO_SPHINCS_SECRETKEY_BYTES; i++) {
		sk3[i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_DILITHIUM_SECRETKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES + i];
	}

	//Always call both sign operations, instead of exiting early from first on failure, to reduce risk from timing attacks if any
	int r1 = crypto_sign_ed25519(sig1, &sigLen1, m, mlen, sk1);
	int r2 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sig2, &sigLen2, m, mlen, sk2);
	int r3 = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig3, &sigLen3, m, mlen, sk3);

	if (r1 != 0) {
		return -2;
	}

	if (r2 != 0) {
		return -3;
	}

	if (r3 != 0) {
		return -4;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + mlen) {
		return -5;
	}

	if (sigLen2 != CRYPTO_DILITHIUM_SIGNATURE_BYTES) {
		return -6;
	}

	if (sigLen3 != CRYPTO_SPHINCS_SIGNATURE_BYTES) {
		return -6;
	}

	//Set signature id and message length
	sm[0] = (unsigned char)DILITHIUM_ED25519_SPHINCS_FULL_ID;
	sm[1] = (unsigned char)mlen;

	//Copy ed25519 signature (which includes the message), to output	
	for (int i = 0;i < (int)sigLen1;i++) {
		sm[LEN_BYTES + i] = sig1[i];
	}

	//Copy the dilithium signature to the output
	for (int i = 0;i < sigLen2;i++) {
		sm[LEN_BYTES + sigLen1 + i] = sig2[i];
	}

	//Copy the sphincs signature to the output
	for (int i = 0; i < sigLen3; i++) {
		sm[LEN_BYTES + sigLen1 + sigLen2 + i] = sig3[i];
	}

	*smlen = LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + CRYPTO_SPHINCS_SIGNATURE_BYTES + mlen;

	return 0;
}

int crypto_sign_dilithium_ed25519_sphincs_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL || mlen == NULL || sm == NULL || smlen < LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + MIN_MSG_LEN + CRYPTO_DILITHIUM_SIGNATURE_BYTES + CRYPTO_SPHINCS_SIGNATURE_BYTES ||
		smlen > LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN + CRYPTO_DILITHIUM_SIGNATURE_BYTES + CRYPTO_SPHINCS_SIGNATURE_BYTES || pk == NULL) {
		return -1;
	}

	int id = (size_t)sm[0];
	if (id != DILITHIUM_ED25519_SPHINCS_FULL_ID) {
		return -2;
	}

	int msgLen = (size_t)sm[1];
	if (msgLen <= 0 || msgLen > MAX_MSG_LEN) {
		return -3;
	}

	if (smlen != LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + msgLen + CRYPTO_DILITHIUM_SIGNATURE_BYTES + CRYPTO_SPHINCS_SIGNATURE_BYTES) {
		return -4;
	}

	int sig1Len = CRYPTO_ED25519_SIGNATURE_BYTES + msgLen;

	unsigned char msgFromSignature1[64 + 64] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES
	unsigned long long msgFromSignatureLen1 = 0;
	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_SIGNATURE_BYTES
	unsigned char sig3[49856] = { 0 }; //CRYPTO_SPHINCS_SIGNATURE_BYTES
	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char pk2[1312] = { 0 }; //CRYPTO_DILITHIUM_PUBLICKEY_BYTES
	unsigned char pk3[64] = { 0 }; //CRYPTO_SPHINCS_PUBLICKEY_BYTES

	//Copy Sig1 from source, including message
	for (int i = 0;i < (int)sig1Len;i++) {
		sig1[i] = sm[LEN_BYTES + i];
	}

	//Copy pk1 from source
	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk1[i] = pk[i];
	}

	int r1 = crypto_sign_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sig1, sig1Len, pk1);
	if (r1 != 0) {
		return -5;
	}

	if ((int) msgFromSignatureLen1 != msgLen) {
		return -6;
	}
	
	//Copy actual Sig2 from source
	for (int i = 0; i < CRYPTO_DILITHIUM_SIGNATURE_BYTES; i++) {
		sig2[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + msgLen + i];
	}
	

	//Copy pk2 from source
	for (int i = 0;i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES;i++) {
		pk2[i] = pk[i + CRYPTO_ED25519_PUBLICKEY_BYTES];
	}

	int r2 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sig2, CRYPTO_DILITHIUM_SIGNATURE_BYTES, msgFromSignature1, msgLen, pk2);
	if (r2 != 0) {
		return -7;
	}	
	
	//Copy actual Sig3 from source
	for (int i = 0; i < CRYPTO_SPHINCS_SIGNATURE_BYTES; i++) {
		sig3[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + msgLen + CRYPTO_DILITHIUM_SIGNATURE_BYTES + i];
	}

	//Copy pk3 from source
	for (int i = 0; i < CRYPTO_SPHINCS_PUBLICKEY_BYTES; i++) {
		pk3[i] = pk[i + CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES];
	}

	int r3 = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig3, CRYPTO_SPHINCS_SIGNATURE_BYTES, msgFromSignature1, msgLen, pk3);
	if (r3 != 0) {
		return -8;
	}

	for (int i = 0; i < msgLen; i++) {
		m[i] = msgFromSignature1[i];
	}

	*mlen = msgLen;

	return 0;
}

int crypto_verify_dilithium_ed25519_sphincs(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL|| mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) { //smlen is checked in crypto_sign_dilithium_ed25519_open
		return -1;
	}
	
	unsigned char msgFromSignature1[64 + 64 + 32 + 64] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_SPHINCS_PUBLICKEY_BYTES
	unsigned long long msgFromSignatureLen1 = 0;

	int r = crypto_sign_dilithium_ed25519_sphincs_open(msgFromSignature1, &msgFromSignatureLen1, sm, smlen, pk);
	if (r != 0) {
		return -2;
	}

	if (msgFromSignatureLen1 != mlen) {
		return -3;
	}

	for (int i = 0;i < (int)msgFromSignatureLen1;i++) {
		if (msgFromSignature1[i] != m[i]) {
			return -4;
		}
	}

	return 0;
}

int crypto_sign_compact_dilithium_ed25519_sphincs(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk) {

	if (sm == NULL || smlen == NULL || m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sk == NULL) {
		return -1;
	}

	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;

	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + HASH_LENGTH
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_MAX_SIGNATURE_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char sk2[2560] = { 0 }; //CRYPTO_DILITHIUM_SECRETKEY_BYTES
	unsigned char hybridMsg[40 + 64 + 64] = { 0 }; //NONCE_BYTES + MAX_MSG_LEN + CRYPTO_SPHINCS_PUBLICKEY_BYTES
	unsigned char hybridMessageHash[64]; //sha3-512 HASH_LENGTH
	unsigned char nonce[40]; //NONCE_BYTES

	//Copy sk1 from input
	for (int i = 0; i < CRYPTO_ED25519_SECRETKEY_BYTES; i++) {
		sk1[i] = sk[i];
	}

	//Copy sk2 from input (skip public key part of it)
	for (int i = 0; i < CRYPTO_DILITHIUM_SECRETKEY_BYTES; i++) {
		sk2[i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + i];
	}

	//Form the hybrid msg
	if (randombytes(nonce, sizeof nonce) != 0) { //Create nonce
		return -1;
	}

	for (int i = 0; i < NONCE_BYTES; i++) { //copy nonce to hybridMsg
		hybridMsg[i] = nonce[i];
	}

	for (int i = 0; i < mlen; i++) { //copy original message to hybridMsg
		hybridMsg[NONCE_BYTES + i] = m[i];
	}	

	for (int i = 0; i < CRYPTO_SPHINCS_PUBLICKEY_BYTES; i++) { //Copy the SPHINCS+ public-key to hybridMsg
		hybridMsg[NONCE_BYTES + mlen + i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_DILITHIUM_SECRETKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES + (CRYPTO_SPHINCS_SECRETKEY_BYTES / 2) + i]; //(CRYPTO_SPHINCS_SECRETKEY_BYTES / 2) since public key is part of secret key starting from position 64
	}

	//Hash the hybrid message
	sha3_512(hybridMessageHash, hybridMsg, NONCE_BYTES + mlen + CRYPTO_SPHINCS_PUBLICKEY_BYTES);

	//Always call both sign operations, instead of exiting early from first on failure, to reduce risk from timing attacks if any
	int r1 = crypto_sign_ed25519(sig1, &sigLen1, hybridMessageHash, HASH_LENGTH, sk1);
	int r2 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sig2, &sigLen2, hybridMessageHash, HASH_LENGTH, sk2);

	if (r1 != 0) {
		return -2;
	}

	if (r2 != 0) {
		return -3;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + HASH_LENGTH) {
		return -4;
	}

	if (sigLen2 != CRYPTO_DILITHIUM_SIGNATURE_BYTES) {
		return -5;
	}

	//Set signature id and message length
	sm[0] = (unsigned char)DILITHIUM_ED25519_SPHINCS_COMPACT_ID;
	sm[1] = (unsigned char)mlen;

	//Copy ed25519 signature to output	
	for (int i = 0; i < CRYPTO_ED25519_SIGNATURE_BYTES; i++) {
		sm[LEN_BYTES + i] = sig1[i];
	}

	//Copy the dilithium signature to the output
	for (int i = 0; i < CRYPTO_DILITHIUM_SIGNATURE_BYTES; i++) {
		sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + i] = sig2[i];
	}

	//Copy the nonce to the output
	for (int i = 0; i < NONCE_BYTES; i++) {
		sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + i] = nonce[i];
	}

	//Copy the original message to the output
	for (int i = 0; i < mlen; i++) {
		sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + i] = m[i];
	}

	*smlen = LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + mlen;

	return 0;
}

int crypto_sign_compact_dilithium_ed25519_sphincs_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL || mlen == NULL || sm == NULL || smlen < LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + MIN_MSG_LEN ||
		smlen > LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + MAX_MSG_LEN || pk == NULL) {
		return -1;
	}

	int id = (size_t)sm[0];
	if (id != DILITHIUM_ED25519_SPHINCS_COMPACT_ID) {
		return -2;
	}

	int msgLen = (size_t)sm[1];
	if (msgLen <= 0 || msgLen > MAX_MSG_LEN) {
		return -3;
	}

	if (smlen != LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + msgLen) {
		return -4;
	}

	unsigned char msgFromSignature1[64 + 64] = { 0 }; //HASH_LEN + CRYPTO_ED25519_SIGNATURE_BYTES
	unsigned long long msgFromSignatureLen1 = 0;
	unsigned char hybridMsg[40 + 64 + 64] = { 0 }; //NONCE_BYTES + MAX_MSG_LEN + CRYPTO_SPHINCS_PUBLICKEY_BYTES
	unsigned char hybridMessageHash[64]; //sha3-512 HASH_LENGTH
	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + HASH_LEN
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_SIGNATURE_BYTES
	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char pk2[1312] = { 0 }; //CRYPTO_DILITHIUM_PUBLICKEY_BYTES

	//Form the hybrid msg
	for (int i = 0; i < NONCE_BYTES; i++) { //copy nonce to hybridMsg
		hybridMsg[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + i];
	}
	for (int i = 0; i < msgLen; i++) { //copy original message to hybridMsg
		hybridMsg[NONCE_BYTES + i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + i];
	}
	for (int i = 0; i < CRYPTO_SPHINCS_PUBLICKEY_BYTES; i++) { //Copy the SPHINCS+ public-key to hybridMsg
		hybridMsg[NONCE_BYTES + msgLen + i] = pk[CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_DILITHIUM_PUBLICKEY_BYTES + i];
	}

	//Hash the hybrid message
	sha3_512(hybridMessageHash, hybridMsg, NONCE_BYTES + msgLen + CRYPTO_SPHINCS_PUBLICKEY_BYTES);


	//Copy Sig1 from source
	for (int i = 0; i < CRYPTO_ED25519_SIGNATURE_BYTES; i++) {
		sig1[i] = sm[LEN_BYTES + i];
	}

	//Copy hybridMessageHash into Sig1
	for (int i = 0; i < HASH_LENGTH; i++) {
		sig1[CRYPTO_ED25519_SIGNATURE_BYTES + i] = hybridMessageHash[i];
	}

	//Copy pk1 from source
	for (int i = 0; i < CRYPTO_ED25519_PUBLICKEY_BYTES; i++) {
		pk1[i] = pk[i];
	}

	int r1 = crypto_sign_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sig1, CRYPTO_ED25519_SIGNATURE_BYTES + HASH_LENGTH, pk1);
	if (r1 != 0) {
		return -5;
	}

	if (msgFromSignatureLen1 != HASH_LENGTH) {
		return -6;
	}

	//Verify hybridMessageHash from message
	for (int i = 0; i < HASH_LENGTH; i++) {
		if (msgFromSignature1[i] != hybridMessageHash[i]) {
			return -7;
		}
	}

	//Copy actual Sig2 from source
	for (int i = 0; i < CRYPTO_DILITHIUM_SIGNATURE_BYTES; i++) {
		sig2[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + i];
	}

	//Copy pk2 from source
	for (int i = 0; i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES; i++) {
		pk2[i] = pk[i + CRYPTO_ED25519_PUBLICKEY_BYTES];
	}

	int r2 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sig2, CRYPTO_DILITHIUM_SIGNATURE_BYTES, hybridMessageHash, HASH_LENGTH, pk2);
	if (r2 != 0) {
		return -8;
	}

	//Copy the message to the output
	for (int i = 0; i < msgLen; i++) {
		m[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + NONCE_BYTES + i];
	}
	
	*mlen = msgLen;

	return 0;
}

int crypto_verify_compact_dilithium_ed25519_sphincs(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) { //smlen is checked in crypto_sign_dilithium_ed25519_open
		return -1;
	}

	unsigned char msgFromSignature1[64] = { 0 }; //MAX_MSG_LEN
	unsigned long long msgFromSignatureLen1 = 0;

	int r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msgFromSignature1, &msgFromSignatureLen1, sm, smlen, pk);
	if (r != 0) {
		return -2;
	}

	if (msgFromSignatureLen1 != mlen) {
		return -3;
	}

	for (int i = 0; i < (int)msgFromSignatureLen1; i++) {
		if (msgFromSignature1[i] != m[i]) {
			return -4;
		}
	}

	return 0;
}

int crypto_verify_dilithium(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {
	if (m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) {
		return -1;
	}

	int r = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sm, smlen, m, mlen, pk);
	if (r != 0) {
		return -2;
	}

	return 0;
}
