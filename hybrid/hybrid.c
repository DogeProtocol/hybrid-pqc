#include <stddef.h>
#include <string.h>
#include "hybrid.h"
#include "../falcon512/api.h"
#include "../tweetnacl/tweetnacl.h"

int crypto_sign_falcon_ed25519_keypair(unsigned char* pk, unsigned char* sk) {
	if (pk == NULL || sk == NULL) {
		return -1;
	}

	int r1 = crypto_sign_ed25519_keypair(pk, sk);
	int r2 = crypto_sign_falcon_keypair(pk + CRYPTO_ED25519_PUBLICKEY_BYTES, sk + CRYPTO_ED25519_SECRETKEY_BYTES);

	if (r1 != 0 && r2 != 0) {
		return -2;
	}

	return 0;
}

int crypto_sign_falcon_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk) {

	if (sm == NULL || smlen == NULL || m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sk == NULL) {
		return -1;
	}

	unsigned long long sigLen1 = 0L;
	unsigned long long sigLen2 = 0L;

	//Always call both sign operations, instead of exiting early from first on failure, to reduce risk from timing attacks if any
	int r1 = crypto_sign_ed25519(sm + SIZE_LEN, &sigLen1, m, mlen, sk);
	int r2 = crypto_sign_falcon(sm + SIZE_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + mlen, &sigLen2, m, mlen, sk + CRYPTO_ED25519_SECRETKEY_BYTES);

	if (r1 != 0 && r2 != 0) {
		return -2;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + mlen) {
		return -3;
	}

	if (sigLen2 < (CRYPTO_FALCON_MIN_SIGNATURE_BYTES + mlen) || sigLen2 > (CRYPTO_FALCON_MAX_SIGNATURE_BYTES + mlen)) {
		return -4;
	}

	unsigned long long totalLen = sigLen1 + sigLen2;
	sm[0] = (unsigned char)(totalLen >> 8);
	sm[1] = (unsigned char)totalLen;
	for (int i = sigLen1 + sigLen2;i < CRYPTO_FALCON_MAX_SIGNATURE_BYTES + mlen;i++) {
		sm[i] = '0';
	}

	*smlen = CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_FALCON_MAX_SIGNATURE_BYTES + SIZE_LEN + mlen + mlen;

	return 0;

}

int crypto_sign_falcon_ed25519_open(unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {

	if (m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || smlen != CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_FALCON_MAX_SIGNATURE_BYTES + SIZE_LEN + mlen + mlen || pk == NULL) {
		return -1;
	}

	unsigned long long totalLen = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (totalLen < CRYPTO_HYBRID_MIN_SIGNATURE_BYTES + mlen + mlen) {
		return totalLen;
	}

	unsigned char* msgFromSignature = malloc(smlen * sizeof(unsigned char));
	unsigned long long msgLen1 = 0L;

	int r1 = crypto_sign_ed25519_open(msgFromSignature, &msgLen1, sm + SIZE_LEN, CRYPTO_ED25519_SIGNATURE_BYTES + mlen, pk);
	if (r1 != 0) {
		return -3;
	}

	if (msgLen1 != mlen) {
		return -4;
	}

	for (int i = 0;i < mlen;i++) {
		if (msgFromSignature[i] != m[i]) {
			return -5;
		}
	}
	
	memset(msgFromSignature, 0, smlen * sizeof(unsigned char));
	msgLen1 = 0L;

	unsigned long long sig2Len = totalLen - (CRYPTO_ED25519_SIGNATURE_BYTES + mlen);
	int r2 = crypto_sign_falcon_open(msgFromSignature, &msgLen1, sm + SIZE_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + mlen, sig2Len, pk + CRYPTO_ED25519_PUBLICKEY_BYTES);
	if (r2 != 0) {
		return -6;
	}
	if (msgLen1 != mlen) {
		return -7;
	}

	for (int i = 0;i < mlen;i++) {
		if (msgFromSignature[i] != m[i]) {
			return -8;
		}
	}

	return 0;
}

