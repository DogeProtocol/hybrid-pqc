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
#include "../falcon512/api.h"
#include "../tweetnacl/tweetnacl.h"
#include "../random/randombytes.h"

const int SEED_LENGTH_ED25519 = 32;
const int SEED_LENGTH_FALCON = 48;

const int MIN_MSG_LEN = 1;
const int MAX_MSG_LEN = 64;
const int SIZE_LEN = 2; //2 for size

const int CRYPTO_ED25519_PUBLICKEY_BYTES = 32;
const int CRYPTO_ED25519_SECRETKEY_BYTES = 64;
const int CRYPTO_ED25519_SECRETKEY_WITHOUT_PUBLIC_KEY_BYTES = 32;
const int CRYPTO_ED25519_SIGNATURE_BYTES = 64;

const int LEN_BYTES = 2;
const int CRYPTO_FALCON_PUBLICKEY_BYTES = 897;
const int CRYPTO_FALCON_SECRETKEY_BYTES = 1281;
const int CRYPTO_FALCON_SECRETKEY_WITH_PUBLIC_KEY_BYTES = 1281 + 897;
const int CRYPTO_FALCON_NONCE_LENGTH = 40;
const int CRYPTO_FALCON_MIN_SIGNATURE_BYTES = 600 + 40 + 2; //Signature + Nonce + 2 for size
const int CRYPTO_FALCON_MAX_SIGNATURE_BYTES = 690 + 40 + 2; //Signature + Nonce + 2 for size

const int CRYPTO_HYBRID_PUBLICKEY_BYTES = 32 + 897;
const int CRYPTO_HYBRID_SECRETKEY_BYTES = 64 + 1281;
const int CRYPTO_HYBRID_SECRETKEY_WITH_FALCON_PUBLIC_KEY_BYTES = 64 + 1281 + 897; //ED25519 already contains public key
const int CRYPTO_HYBRID_MAX_FALCON_BASE_SIGNATURE_BYTES = 690;
const int CRYPTO_HYBRID_MIN_SIGNATURE_BYTES = 64 + 600 + 40 + 2;
const int CRYPTO_HYBRID_MAX_SIGNATURE_BYTES = 64 + 690 + 40 + 2;
const int CRYPTO_HYBRID_MAX_SIGNATURE_BYTES_WITH_LEN = 2 + 2 + 64 + 40 + 690;

/*
Secret Key Length = 64 + 1281 + 897 = 3587
============================================
Layout of secret key:

32 bytes             32 bytes             1281 bytes          897 bytes 
ed25519 secret key | ed25519 public key | falcon secret key | falcon public key

The following signature length includes implementation output, in addition to actual algorithm output.


Layout of ED25519 signature
============================

64 bytes          | {1 to 64 bytes}  
ed25519 Signature | Message


Layout of Falcon signature
============================
2 bytes                         | 40 bytes     |  {1 to 64 bytes} | {600 to 690 bytes}
falcon internal size big-endian | falcon nonce |  actual message  | falcon signature   


Hybrid Signature Length = 2 + 2 + 64 + {1 to 64} + {600 to 690} + 40 + 2 + {1 to 64} + {Padding} = 800 + (MSG_LEN * 2)
=======================================================================================================================
Layout of signature:


2 bytes                                         | 2 bytes                      | 64 bytes          | {1 to 64 bytes} | 40 bytes     |  {600 to 690 bytes} | {690 - falcon signature length}
length of ed25519 + falcon signature big-endian | length of message big-endian | ed25519 signature | actual message  | falcon nonce |  falcon signature   | falcon signature padding with 0's


The first 2 bytes contain signature length of ed25519, falcon including the falcon nonce and internal size, in big-endian order
The second 2 bytes contain the message length in big-endian order
Message is variable length, between 1 to 64 bytes
Falcon Signature is variable length, between 600 to 690. To give predicatable length, rest of bytes are padded with zero (690 - falcon signature).

*/

int crypto_sign_falcon_ed25519_keypair_seed(unsigned char* pk, unsigned char* sk, unsigned char* seed) {
	if (pk == NULL || sk == NULL) {
		return -1;
	}

	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char pk2[897] = { 0 }; //CRYPTO_FALCON_PUBLICKEY_BYTES
	unsigned char sk2[1281 + 897] = { 0 }; //CRYPTO_FALCON_SECRETKEY_BYTES

	unsigned char seed1[32] = { 0 }; //SEED_LENGTH_ED25519
	unsigned char seed2[48] = { 0 }; //SEED_LENGTH_FALCON

	for (int i = 0; i < SEED_LENGTH_ED25519; i++) {
		seed1[i] = seed[i];
	}

	for (int i = 0; i < SEED_LENGTH_FALCON; i++) {
		seed2[i] = seed[i + SEED_LENGTH_ED25519];
	}

	int r1 = crypto_sign_ed25519_keypair_seed(pk1, sk1, seed1);
	if (r1 != 0) {
		return -2;
	}

	for (int i = 0; i < CRYPTO_ED25519_PUBLICKEY_BYTES; i++) {
		pk[i] = pk1[i];
	}

	for (int i = 0; i < CRYPTO_ED25519_SECRETKEY_BYTES; i++) {
		sk[i] = sk1[i];
	}

	int r2 = crypto_sign_falcon_keypair_seed(pk2, sk2, seed2, sizeof seed2);

	if (r2 != 0) {
		return -3;
	}

	for (int i = 0; i < CRYPTO_FALCON_SECRETKEY_BYTES; i++) {
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + i] = sk2[i];
	}

	for (int i = 0; i < CRYPTO_FALCON_PUBLICKEY_BYTES; i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + i] = pk2[i];
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_FALCON_SECRETKEY_BYTES + i] = pk2[i]; //copy public key
	}


	return 0;
}

int crypto_sign_falcon_ed25519_keypair(unsigned char* pk, unsigned char* sk) {
	if (pk == NULL || sk == NULL) {
		return -1;
	}
	
	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char pk2[897] = { 0 }; //CRYPTO_FALCON_PUBLICKEY_BYTES
	unsigned char sk2[1281] = { 0 }; //CRYPTO_FALCON_SECRETKEY_BYTES

	int r1 = crypto_sign_ed25519_keypair(pk1, sk1);
	if (r1 != 0) {
		return -2;
	}

	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk[i] = pk1[i];
	}

	for (int i = 0;i < CRYPTO_ED25519_SECRETKEY_BYTES;i++) {
		sk[i] = sk1[i];
	}

	int r2 = crypto_sign_falcon_keypair(pk2, sk2);

	if (r2 != 0) {
		return -3;
	}

	for (int i = 0;i < CRYPTO_FALCON_SECRETKEY_BYTES;i++) {
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + i] = sk2[i];
	}

	for (int i = 0;i < CRYPTO_FALCON_PUBLICKEY_BYTES;i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + i] = pk2[i];
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_FALCON_SECRETKEY_BYTES + i] = pk2[i]; //copy public key
	}
	

	return 0;
}

int crypto_sign_falcon_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk) {

	if (sm == NULL || smlen == NULL || m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sk == NULL) {
		return -1;
	}

	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;

	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[690 + 40 + 2 + 64] = { 0 }; //CRYPTO_FALCON_MAX_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char sk2[1281] = { 0 }; //CRYPTO_FALCON_SECRETKEY_BYTES


	//Copy sk1 from input
	for (int i = 0;i < CRYPTO_ED25519_SECRETKEY_BYTES;i++) {
		sk1[i] = sk[i];
	}

	//Copy sk2 from input (skip public key part of it)
	for (int i = 0;i < CRYPTO_FALCON_SECRETKEY_BYTES;i++) {
		sk2[i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + i];
	}

	//Always call both sign operations, instead of exiting early from first on failure, to reduce risk from timing attacks if any
	int r1 = crypto_sign_ed25519(sig1, &sigLen1, m, mlen, sk1);
	int r2 = crypto_sign_falcon(sig2, &sigLen2, m, mlen, sk2);

	if (r1 != 0) {
		return -2;
	}

	if (r2 != 0) {
		return -3;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + mlen) {
		return -3;
	}

	if (sigLen2 < (CRYPTO_FALCON_MIN_SIGNATURE_BYTES + mlen) || sigLen2 > (CRYPTO_FALCON_MAX_SIGNATURE_BYTES + mlen)) {
		return -4;
	}

	//Set totalLen of sig, excluding LEN_BYTES
	unsigned long long totalLen = sigLen1 + sigLen2;
	sm[0] = (unsigned char)(totalLen >> 8);
	sm[1] = (unsigned char)totalLen;

	sm[2] = (unsigned char)(mlen >> 8);
	sm[3] = (unsigned char)mlen;

	//Copy ed25519 signature including the message, to output	
	for (int i = 0;i < (int)sigLen1;i++) {
		sm[LEN_BYTES + LEN_BYTES + i] = sig1[i];
	}

	//Copy Falcon nonce to output, exclude the 2 bytes for size
	for (int i = 0;i < CRYPTO_FALCON_NONCE_LENGTH;i++) {
		sm[LEN_BYTES + LEN_BYTES + sigLen1 + i] = sig2[LEN_BYTES + i];
	}

	//Copy the Falcon signature, excluding the message, to the output
	for (int i = 0;i < (int) sigLen2 - LEN_BYTES - CRYPTO_FALCON_NONCE_LENGTH;i++) {
		sm[LEN_BYTES + LEN_BYTES + sigLen1 + CRYPTO_FALCON_NONCE_LENGTH + i] = sig2[LEN_BYTES + CRYPTO_FALCON_NONCE_LENGTH + mlen + i];
	}

	//Set rest of bytes to zero
	int sigLenWithoutMeta = sigLen2 - LEN_BYTES - CRYPTO_FALCON_NONCE_LENGTH - mlen;
	for (int i = 0;i < CRYPTO_HYBRID_MAX_FALCON_BASE_SIGNATURE_BYTES - sigLenWithoutMeta;i++) {
		sm[LEN_BYTES + LEN_BYTES + sigLen1 + CRYPTO_FALCON_NONCE_LENGTH + sigLenWithoutMeta + i] = '0';
	}

	*smlen = CRYPTO_HYBRID_MAX_SIGNATURE_BYTES_WITH_LEN + mlen;

	return 0;

}

int crypto_sign_falcon_ed25519_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL || mlen == NULL || sm == NULL || smlen < SIZE_LEN + SIZE_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + MIN_MSG_LEN + CRYPTO_FALCON_MIN_SIGNATURE_BYTES + MIN_MSG_LEN ||
		smlen > SIZE_LEN + SIZE_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN + CRYPTO_FALCON_MAX_SIGNATURE_BYTES + MAX_MSG_LEN || pk == NULL) {
		return -1;
	}

	int totalLen = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (totalLen < CRYPTO_HYBRID_MIN_SIGNATURE_BYTES + MIN_MSG_LEN + MIN_MSG_LEN || totalLen > CRYPTO_HYBRID_MAX_SIGNATURE_BYTES + MAX_MSG_LEN + MAX_MSG_LEN) {
		return -2;
	}
	int msgLen = ((size_t)sm[2] << 8) | (size_t)sm[3];
	if (msgLen <= 0 || msgLen > MAX_MSG_LEN) {
		return -3;
	}

	int sig1Len = CRYPTO_ED25519_SIGNATURE_BYTES + msgLen;
	int sig2Len = totalLen - sig1Len;
	if (sig2Len < CRYPTO_FALCON_MIN_SIGNATURE_BYTES || sig2Len > CRYPTO_FALCON_MAX_SIGNATURE_BYTES) {
		return sig2Len;
	}

	unsigned char msgFromSignature1[64 + 64 + 32] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned long long msgFromSignatureLen1 = 0;
	unsigned char msgFromSignature2[64] = { 0 }; //MAX_MSG_LEN
	unsigned long long msgFromSignatureLen2 = 0;
	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[2 + 40 + 64 + 690] = { 0 }; //SIZE_LEN + CRYPTO_FALCON_NONCE_LENGTH + CRYPTO_FALCON_MAX_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char pk2[897] = { 0 }; //CRYPTO_FALCON_PUBLICKEY_BYTES

	//Copy Sig1 from source, including message
	for (int i = 0;i < (int)sig1Len;i++) {
		sig1[i] = sm[LEN_BYTES + LEN_BYTES + i];
	}

	//Copy pk1 from source
	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk1[i] = pk[i];
	}

	int r1 = crypto_sign_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sig1, sig1Len, pk1);
	if (r1 != 0) {
		return -4;
	}

	if ((int) msgFromSignatureLen1 != msgLen) {
		return -5;
	}

	//Copy Falon size into sig2 (big-endian)
	int actualSig2Len = sig2Len - LEN_BYTES - CRYPTO_FALCON_NONCE_LENGTH - msgLen;
	sig2[0] = (unsigned char)(actualSig2Len >> 8);
	sig2[1] = (unsigned char)actualSig2Len;

	//Copy Falcon nonce into sig2
	for (int i = 0;i < CRYPTO_FALCON_NONCE_LENGTH;i++) {
		sig2[LEN_BYTES + i] = sm[LEN_BYTES + LEN_BYTES + sig1Len + i];
	}

	//Copy Message info sig2
	for (int i = 0;i < msgLen;i++) {
		sig2[LEN_BYTES + CRYPTO_FALCON_NONCE_LENGTH + i] = sm[LEN_BYTES + LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + i];
	}

	//Copy actual Sig2 from source
	for (int i = 0;i < sig2Len - LEN_BYTES - CRYPTO_FALCON_NONCE_LENGTH - msgLen;i++) {
		sig2[LEN_BYTES + CRYPTO_FALCON_NONCE_LENGTH + msgLen + i] = sm[LEN_BYTES + LEN_BYTES + sig1Len + CRYPTO_FALCON_NONCE_LENGTH + i];
	}

	//Copy pk2 from source
	for (int i = 0;i < CRYPTO_FALCON_PUBLICKEY_BYTES;i++) {
		pk2[i] = pk[i + CRYPTO_ED25519_PUBLICKEY_BYTES];
	}

	int r2 = crypto_sign_falcon_open(msgFromSignature2, &msgFromSignatureLen2, sig2, sig2Len, pk2);
	if (r2 != 0) {
		return -6;
	}

	if ((int) msgFromSignatureLen2 != msgLen) {
		return -7;
	}

	for (int i = 0;i < msgLen;i++) {
		if (msgFromSignature1[i] != msgFromSignature2[i]) {
			return -8;
		}
		m[i] = msgFromSignature1[i];
	}

	//Verify that rest of bytes are zero
	int sigLenWithoutMeta = sig2Len - LEN_BYTES - CRYPTO_FALCON_NONCE_LENGTH - msgLen;
	for (int i = 0;i < CRYPTO_HYBRID_MAX_FALCON_BASE_SIGNATURE_BYTES - sigLenWithoutMeta;i++) {
		if (sm[LEN_BYTES + LEN_BYTES + sig1Len + CRYPTO_FALCON_NONCE_LENGTH + sigLenWithoutMeta + i] != '0') {
			return -9;
		}
	}

	*mlen = msgLen;

	return 0;
}

int crypto_verify_falcon_ed25519(unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL|| mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) {
		return -1;
	}
	
	unsigned char msgFromSignature1[64 + 64 + 32] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned long long msgFromSignatureLen1 = 0;

	int r = crypto_sign_falcon_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sm, smlen, pk);
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

int crypto_public_key_from_private_key_falcon_ed25519(unsigned char* pk, const unsigned char* sk) {
	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk[i] = sk[CRYPTO_ED25519_SECRETKEY_WITHOUT_PUBLIC_KEY_BYTES + i];
	}
	for (int i = 0;i < CRYPTO_FALCON_PUBLICKEY_BYTES;i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_FALCON_SECRETKEY_BYTES + i];
	}

	//Verify that public-key matches private-key
	unsigned char msg[64] = { 0 };
	unsigned char sig2[798 + 64] = { 0 };
	unsigned long long sigLen;
	unsigned long long msgLen;

	int r = randombytes(msg, 64);
	if (r != 0) {
		return -1;
	}

	r = crypto_sign_falcon_ed25519(sig2, &sigLen, msg, 64, sk);
	if (r != 0) {
		return r;
	}

	r = crypto_sign_falcon_ed25519_open(msg, &msgLen, sig2, sigLen, pk);
	if (r != 0) {
		return r;
	}

	return 0;
}
