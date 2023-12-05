#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include "../random/randombytes.h"
#include "../hybrid-dilithium-sphincs/hybrid.h"
#include "../sphincs/api.h"
#include "../common/fips202.h"

clock_t get_nano_sec(void);
void print_elapsed(clock_t startTime, clock_t endTime);
int test_dilithium(void);
int test_sphincs(void);
int test_hybrid_dilithium_sphincs(void);
int test_hybrid_dilithium_sphincs_deterministic();
int test_hybrid_compact_dilithium_sphincs(void);
int test_hybrid_compact_dilithium_sphincs_perf(void);
int main(int argc, char* argv[]);

const unsigned long long ED25519_PUBLICKEY_BYTES = 32UL;
const unsigned long long HYBRID_PUBLICKEY_BYTES = 897UL + 32UL;

clock_t get_nano_sec(void) {
	return clock();
}

void print_elapsed(clock_t startTime, clock_t endTime) {
	clock_t elapsed = endTime - startTime;
	double time_taken = ((double)elapsed) / CLOCKS_PER_SEC; // in seconds
	printf("\n elapsed = %f seconds", time_taken);
}

int test_dilithium() {
	printf("\n test_dilithium() start");

	unsigned char pk[1312];
	unsigned char sk[2560];
	unsigned char sig[2420 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned long long sigLen = 0;

	int r1 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk);
	if (r1 != 0) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair failed %d", (int)r1);
		return r1;
	}

	int r2 = randombytes(msg1, 32 * sizeof(unsigned char));
	if (r2 != 0) {
		printf("\n randombytes failed %d", (int)r2);
		return r2;
	}

	int r3 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(sig, &sigLen, msg1, 32, sk);
	if (r3 != 0) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign failed %d", (int)r3);
		return r3;
	}
	printf("\n dilithium sig len = %lld", sigLen);

	unsigned long long msgLen = 0;
	int r4 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(msg2, &msgLen, sig, sigLen, pk);
	if (r4 != 0) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open failed %d", (int)r4);
		return r4;
	}
	if (msgLen != 32) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open msg check failed %d", (int)msgLen);
		return -5;
	}

	for (int i = 0; i < 32; i++) {
		if (msg1[i] != msg2[i]) {
			printf("\n verify msg content failed %d", i);
			return -6;
		}
	}

	printf("\n deterministic key generation test");
	unsigned char seed1[32];
	if (randombytes(seed1, sizeof seed1) != 0) {
		return -7;
	}

	unsigned char pk2[1312];
	unsigned char sk2[2560];
	int r5 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed(pk2, sk2, seed1);
	if (r5 != 0) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed failed %d", (int)r5);
		return r5;
	}

	for (int j = 0; j < 32; j++) {
		unsigned char pk3[1312];
		unsigned char sk3[2560];
		int r6 = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed(pk3, sk3, seed1);
		if (r6 != 0) {
			printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed failed %d", (int)r6);
			return r6;
		}
		for (int i = 0; i < 1312; i++) {
			if (pk2[i] != pk3[i]) {
				printf("\n determienistic key generation failed: pk");
				return -8;
			}
		}
		for (int i = 0; i < 2560; i++) {
			if (sk2[i] != sk3[i]) {
				printf("\n determienistic key generation failed: sk %d, %d, %d", i, sk2[i], sk3[i]);
				return -9;
			}
		}

		int r = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(sig, &sigLen, msg1, 32, sk3);
		if (r != 0) {
			printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign failed %d", (int)r);
			return r;
		}

		unsigned long long msgLen = 0;
		r = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(msg2, &msgLen, sig, sigLen, pk3);
		if (r != 0) {
			printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open failed %d", (int)r);
			return r;
		}
		if (msgLen != 32) {
			printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open msg check failed %d", (int)msgLen);
			return -5;
		}

		for (int i = 0; i < 32; i++) {
			if (msg1[i] != msg2[i]) {
				printf("\n verify msg content failed %d", i);
				return -6;
			}
		}
	}

	printf("\n test_dilithium() ok");

	return 0;
}

int test_sphincs() {
	printf("\n test_sphincs() start");

	unsigned char pk[64];
	unsigned char sk[128];
	unsigned char sig[49856 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned long long sigLen = 0;
	clock_t startTime;
	clock_t endTime;

	int r1 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
	if (r1 != 0) {
		printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair failed %d", (int)r1);
		return r1;
	}

	int r2 = randombytes(msg1, 32 * sizeof(unsigned char));
	if (r2 != 0) {
		printf("\n randombytes failed %d", (int)r2);
		return r2;
	}
	for (int i = 0; i < 32; i++) {
		msg2[1] = msg1[i];
	}

	int r3 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(sig, &sigLen, msg1, 32, sk);
	if (r3 != 0) {
		printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign failed %d", (int)r3);
		return r3;
	}

	unsigned long long msgLen = 0;
	int r4 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(msg2, &msgLen, sig, sigLen, pk);
	if (r4 != 0) {
		printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open failed %d", (int)r4);
		return r4;
	}
	if (msgLen != 32) {
		printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open msg check failed %d", (int)msgLen);
		return -5;
	}

	for (int i = 0; i < 32; i++) {
		if (msg1[i] != msg2[i]) {
			printf("\n verify msg content failed %d", i);
			return -6;
		}
	}

	printf("\n deterministic key generation test");
	unsigned char seed1[96];
	if (randombytes(seed1, sizeof seed1) != 0) {
		return -7;
	}

	unsigned char pk2[64];
	unsigned char sk2[128];
	int r5 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_seed_keypair(pk2, sk2, seed1);
	if (r5 != 0) {
		printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_seed_keypair failed %d", (int)r5);
		return r5;
	}

	for (int j = 0; j < 32; j++) {
		unsigned char pk3[64];
		unsigned char sk3[128];
		int r6 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_seed_keypair(pk3, sk3, seed1);
		if (r6 != 0) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_seed_keypair failed %d", (int)r6);
			return r6;
		}
		for (int i = 0; i < 64; i++) {
			if (pk2[i] != pk3[i]) {
				printf("\n determienistic key generation failed: pk %d %d %d", i, pk2[i], pk3[i]);
				return -8;
			}
		}
		for (int i = 0; i < 128; i++) {
			if (sk2[i] != sk3[i]) {
				printf("\n determienistic key generation failed: sk %d, %d, %d", i, sk2[i], sk3[i]);
				return -9;
			}
		}

		int r =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(sig, &sigLen, msg1, 32, sk3);
		if (r != 0) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign failed %d", (int)r);
			return r;
		}

		unsigned long long msgLen = 0;
		r =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(msg2, &msgLen, sig, sigLen, pk3);
		if (r != 0) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open failed %d", (int)r);
			return r;
		}
		if (msgLen != 32) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open msg check failed %d", (int)msgLen);
			return -5;
		}

		for (int i = 0; i < 32; i++) {
			if (msg1[i] != msg2[i]) {
				printf("\n verify msg content failed %d", i);
				return -6;
			}
		}
	}

	printf("\n sphincs key gen 1000 iterations perf start");
	startTime = get_nano_sec();
	for (int i = 0; i < 1000; i++) {
		r1 = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
		if (r1 != 0) {
			printf("\n PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair failed %d", (int)r1);
			return r1;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n sphincs sign perf 1000 iterations start");
	startTime = get_nano_sec();
	for (int i = 0; i < 1000; i++) {
		r3 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(sig, &sigLen, msg1, 32, sk);
		if (r3 != 0) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign failed %d", (int)r3);
			return r3;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n sphincs verify (sign open) 10000 iterations perf start");
	startTime = get_nano_sec();
	for (int i = 0; i < 10000; i++) {
		r4 =  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(msg2, &msgLen, sig, sigLen, pk);
		if (r4 != 0) {
			printf("\n  PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open failed %d", (int)r4);
			return r4;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n test_sphincs() ok");

	return 0;
}

int test_hybrid_dilithium_sphincs() {
	printf("\n test_hybrid_dilithium_sphincs () start");

	unsigned char pk[32 + 1312 + 64];
	unsigned char pk2[32 + 1312 + 64];
	unsigned char sk[64 + 2560 + 1312 + 128];
	unsigned char sig1[2 + 64 + 32 + 2420 + 49856];
	unsigned char sig2[2 + 64 + 32 + 2420 + 49856];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned char msg1output[32];
	unsigned char msg2output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;
	const int SIG_LEN = 52374;

	int r = crypto_sign_dilithium_ed25519_sphincs_keypair(pk, sk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair failed %d", (int)r);
		return -1;
	}

	r = randombytes(msg1, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -2;
	}

	r = crypto_sign_dilithium_ed25519_sphincs(sig1, &sigLen1, msg1, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs failed %d", (int)r);
		return -3;
	}

	if (sigLen1 != SIG_LEN) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen1);
		return -4;
	}

	r = crypto_sign_dilithium_ed25519_sphincs_open(msg1output, &msgLen1, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_open failed %d", (int)r);
		return -5;
	}

	if (msgLen1 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen1);
		return -6;
	}

	for (int i = 0; i < MSG_LEN; i++) {
		if (msg1[i] != msg1output[i]) {
			printf("\n verify msg content failed %d", i);
			return -7;
		}
	}

	r = crypto_verify_dilithium_ed25519_sphincs(msg1, MSG_LEN, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_verify_dilithium_ed25519 failed %d", (int)r);
		return -8;
	}

	r = randombytes(msg2, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -9;
	}

	r = crypto_sign_dilithium_ed25519_sphincs(sig2, &sigLen2, msg2, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs failed %d", (int)r);
		return -10;
	}

	if (sigLen2 != SIG_LEN) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen2);
		return -11;
	}

	//sanity check
	r = crypto_sign_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_open failed %d", (int)r);
		return -12;
	}

	if (msgLen2 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen2);
		return -13;
	}

	for (int i = 0; i < MSG_LEN; i++) {
		if (msg2[i] != msg2output[i]) {
			printf("\n verify msg content failed %d", i);
			return -14;
		}
	}

	r = crypto_verify_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_verify_dilithium_ed25519_sphincs failed %d", (int)r);
		return -15;
	}

	//signature fuzz test (sign open)
	for (int i = 0; i < SIG_LEN; i++) {
		printf("\n test_hybrid_dilithium_sphincs sign open fuzz iteration %d of %d", i, SIG_LEN);

		unsigned char temp = sig2[i];
		sig2[i] = temp + 1;
		r = crypto_sign_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_open was ok when it should have failed %d", (int)r);
			return -16;
		}
		sig2[i] = temp;
		r = crypto_sign_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_open failed when it should have been ok %d", (int)r);
			return -17;
		}
		for (int i = 0; i < MSG_LEN; i++) {
			if (msg2[i] != msg2output[i]) {
				printf("\n verify msg content failed %d", i);
				return -14;
			}
		}
	}

	//signature fuzz test (verify)
	for (int i = 0; i < SIG_LEN; i++) {
		printf("\n test_hybrid_dilithium_sphincs verify fuzz iteration %d of %d", i, SIG_LEN);

		unsigned char temp = sig2[i];
		sig2[i] = temp + 1;
		r = crypto_verify_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_verify_dilithium_ed25519_sphincs was ok when it should have failed %d", (int)r);
			return -18;
		}
		sig2[i] = temp;
		r = crypto_verify_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_verify_dilithium_ed25519_sphincs failed when it should have been ok %d", (int)r);
			return -19;
		}
	}

	//public key fuzz test
	for (int i = 0; i < 32 + 1312 + 64; i++) {
		printf("\n test_hybrid_dilithium_sphincs pk sign open fuzz iteration %d of 32 + 1312 + 64", i);

		unsigned char temp = pk[i];
		pk[i] = temp + 1;
		r = crypto_sign_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_open was ok when it should have failed %d", (int)r);
			return -16;
		}
		pk[i] = temp;
		r = crypto_sign_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_open failed when it should have been ok %d", (int)r);
			return -17;
		}
		for (int i = 0; i < MSG_LEN; i++) {
			if (msg2[i] != msg2output[i]) {
				printf("\n verify msg content failed %d", i);
				return -14;
			}
		}
	}

	printf(" \n test_hybrid_dilithium_sphincs () ok");

	return 0;
}

int test_hybrid_compact_dilithium_sphincs() {
	printf("\n test_hybrid_compact_dilithium_sphincs () start");

	unsigned char pk[32 + 1312 + 64];
	unsigned char pk2[32 + 1312 + 64];
	unsigned char sk[64 + 2560 + 1312 + 128];
	unsigned char sig1[2 + 64 + 2420 + 40 + 32];
	unsigned char sig2[2 + 64 + 2420 + 40 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned char msg1output[32];
	unsigned char msg2output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;
	const int SIG_LEN = 2 + 64 + 2420 + 40 + MSG_LEN;

	int r = crypto_sign_dilithium_ed25519_sphincs_keypair(pk, sk);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair failed %d", (int)r);
		return -1;
	}

	r = randombytes(msg1, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -2;
	}

	r = crypto_sign_compact_dilithium_ed25519_sphincs(sig1, &sigLen1, msg1, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs failed %d", (int)r);
		return -3;
	}

	if (sigLen1 != SIG_LEN) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen1);
		return -4;
	}

	r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg1output, &msgLen1, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open A failed %d", (int)r);
		return -5;
	}

	if (msgLen1 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen1);
		return -6;
	}

	for (int i = 0; i < MSG_LEN; i++) {
		if (msg1[i] != msg1output[i]) {
			printf("\n verify msg content failed %d", i);
			return -7;
		}
	}

	r = crypto_verify_compact_dilithium_ed25519_sphincs(msg1, MSG_LEN, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_verify_compact_dilithium_ed25519 failed %d", (int)r);
		return -8;
	}

	r = randombytes(msg2, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -9;
	}

	r = crypto_sign_compact_dilithium_ed25519_sphincs(sig2, &sigLen2, msg2, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs failed %d", (int)r);
		return -10;
	}

	if (sigLen2 != SIG_LEN) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen2);
		return -11;
	}

	//sanity check
	r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open B failed %d", (int)r);
		return -12;
	}

	if (msgLen2 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen2);
		return -13;
	}

	for (int i = 0; i < MSG_LEN; i++) {
		if (msg2[i] != msg2output[i]) {
			printf("\n verify msg content failed %d", i);
			return -14;
		}
	}

	r = crypto_verify_compact_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_verify_compact_dilithium_ed25519_sphincs failed %d", (int)r);
		return -15;
	}

	//signature fuzz test (sign open)
	for (int i = 0; i < SIG_LEN; i++) {
		printf("\n test_hybrid_compact_dilithium_sphincs sign open fuzz iteration %d of %d", i, SIG_LEN);

		unsigned char temp = sig2[i];
		sig2[i] = temp + 1;
		r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open was ok when it should have failed %d", (int)r);
			return -16;
		}
		sig2[i] = temp;
		r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open failed when it should have been ok %d", (int)r);
			return -17;
		}
		for (int i = 0; i < MSG_LEN; i++) {
			if (msg2[i] != msg2output[i]) {
				printf("\n verify msg content failed %d", i);
				return -14;
			}
		}
	}

	//signature fuzz test (verify)
	for (int i = 0; i < SIG_LEN; i++) {
		printf("\n test_hybrid_compact_dilithium_sphincs verify fuzz iteration %d of %d", i, SIG_LEN);

		unsigned char temp = sig2[i];
		sig2[i] = temp + 1;
		r = crypto_verify_compact_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_verify_compact_dilithium_ed25519_sphincs was ok when it should have failed %d", (int)r);
			return -18;
		}
		sig2[i] = temp;
		r = crypto_verify_compact_dilithium_ed25519_sphincs(msg2, MSG_LEN, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_verify_compact_dilithium_ed25519_sphincs failed when it should have been ok %d", (int)r);
			return -19;
		}
	}

	//public key fuzz test
	for (int i = 0; i < 32 + 1312 + 64; i++) {
		printf("\n test_hybrid_compact_dilithium_sphincs pk sign open fuzz iteration %d of 32 + 1312 + 64", i);

		unsigned char temp = pk[i];
		pk[i] = temp + 1;
		r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open was ok when it should have failed %d", (int)r);
			return -16;
		}
		pk[i] = temp;
		r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r != 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open failed when it should have been ok %d", (int)r);
			return -17;
		}
		for (int i = 0; i < MSG_LEN; i++) {
			if (msg2[i] != msg2output[i]) {
				printf("\n verify msg content failed %d", i);
				return -14;
			}
		}
	}

	printf(" \n test_hybrid_compact_dilithium_sphincs () ok");

	return 0;
}

int test_hybrid_dilithium_sphincs_deterministic() {
	printf("\n test_hybrid_dilithium_sphincs_deterministic() start");

	unsigned char pk[32 + 1312 + 64];
	unsigned char pk2[32 + 1312 + 64];
	unsigned char pk3[32 + 1312 + 64];
	unsigned char sk[64 + 2560 + 1312 + 128];
	unsigned char sk2[64 + 2560 + 1312 + 128];
	unsigned char sk3[64 + 2560 + 1312 + 128];
	unsigned char sig1[2 + 64 + 32 + 2420 + 49856];
	unsigned char msg1[32];
	unsigned char msg1output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;
	const int SIG_LEN = 52374;

	unsigned char seed1[160] = { 129,111,254,208,138,196,60,45,101,134,78,177,227,76,82,203,26,114,241,89,26,205,174,187,167,219,156,51,195,197,228,27,119,175,131,115,192,42,246,9,171,117,239,88,235,16,133,230,150,206,59,220,176,144,178,248,188,213,239,142,236,15,177,197};

	unsigned char seed3[160];
	if (randombytes(seed3, sizeof seed3) != 0) {
		return -1;
	}

	int r = crypto_sign_dilithium_ed25519_sphincs_keypair_seed(pk, sk, seed1);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair_seed failed %d", (int)r);
		return -2;
	}
	
	/*
	printf("\n pk \n");
	for (int k = 0; k < 32 + 1312 + 64; k++) {
		printf("%d,", pk[k]);
	}
	printf("\n sk \n");
	for (int k = 0; k < 64 + 2560 + 1312 + 128; k++) {
		printf("%d,", sk[k]);
	}*/

	unsigned char pkFromSeed[32 + 1312 + 64] = { 240,78,219,55,229,129,35,19,238,250,42,184,21,246,140,49,133,117,234,93,254,183,215,211,206,92,25,21,105,115,247,115,211,10,39,252,190,40,150,237,95,4,192,163,171,100,105,240,107,33,83,68,228,125,29,161,139,146,159,81,61,31,124,158,3,166,59,195,12,211,93,68,8,73,212,169,81,201,46,231,74,162,153,110,81,197,17,33,199,26,102,208,122,104,52,207,38,215,250,125,66,231,196,39,11,76,38,106,119,57,223,51,224,176,181,25,45,166,56,84,24,246,248,143,206,211,185,64,102,123,41,1,70,43,59,167,65,94,175,70,141,218,215,213,32,22,124,94,115,102,168,74,125,180,149,149,127,142,11,64,39,145,22,16,250,47,48,174,58,155,117,170,108,243,208,177,100,217,39,116,40,76,5,203,237,210,163,118,148,156,172,112,86,185,131,37,111,115,233,190,130,69,237,16,207,146,141,103,114,100,201,9,169,72,64,150,245,18,203,123,125,241,167,147,78,41,212,29,70,169,145,50,123,12,165,57,193,211,62,248,112,126,144,229,21,9,123,111,127,158,137,236,226,142,149,190,142,222,213,89,243,231,202,161,246,152,207,74,206,182,251,22,132,205,132,191,248,63,65,27,32,76,230,148,217,236,37,198,17,193,130,245,72,174,99,132,91,1,170,167,96,152,231,136,195,250,77,4,39,128,224,138,150,179,90,102,18,23,148,59,203,99,61,157,199,112,196,11,7,98,58,32,166,2,55,120,43,108,84,157,243,234,178,247,143,110,128,94,25,179,34,30,139,178,41,133,254,76,49,221,225,135,161,56,245,90,41,215,72,10,104,158,68,93,111,181,42,126,1,37,138,63,145,142,22,60,254,124,222,125,196,227,109,34,78,71,55,3,109,147,223,40,165,81,147,13,57,210,234,108,162,69,191,71,155,91,164,112,187,212,227,72,32,204,100,94,245,205,6,230,72,87,138,92,40,148,211,32,236,1,73,99,29,106,108,116,113,254,210,62,158,103,227,126,47,194,112,55,46,82,92,204,225,138,74,170,29,179,131,183,77,234,186,174,144,53,36,159,53,85,86,203,229,174,196,234,131,99,140,226,84,236,205,197,31,143,15,188,126,214,115,111,168,156,84,14,190,140,145,209,118,177,19,98,25,179,183,191,156,95,80,89,158,173,219,222,135,65,162,210,165,177,127,95,161,162,58,248,132,251,241,102,170,186,211,97,170,200,137,78,46,219,140,66,22,208,219,19,189,29,255,254,222,204,145,14,19,238,99,201,161,103,91,8,249,122,165,255,162,107,115,211,120,41,78,130,219,142,209,254,103,82,216,49,0,205,40,105,223,59,121,55,38,254,162,241,41,51,209,143,48,190,236,0,200,146,239,137,193,223,117,205,56,186,70,137,210,1,224,142,241,2,157,31,239,12,138,141,95,216,247,225,64,45,53,248,165,19,6,178,225,95,111,218,164,218,4,49,142,71,244,78,51,29,11,140,121,230,188,22,232,13,33,140,174,115,255,162,244,112,55,29,16,91,58,28,4,158,85,171,96,151,235,235,213,247,0,90,65,227,119,2,54,104,66,185,57,182,76,234,160,170,218,119,123,162,126,79,54,35,58,36,249,117,110,76,7,114,139,135,140,63,139,133,19,128,196,12,51,35,165,76,158,54,87,133,1,58,210,75,203,183,193,34,255,21,114,182,215,122,191,149,134,135,240,198,182,60,66,1,176,144,143,132,36,184,125,62,56,124,218,85,28,245,142,60,18,0,169,99,88,215,123,181,34,16,43,239,207,40,188,127,255,91,8,224,144,125,221,248,27,4,48,212,148,75,103,62,118,7,89,35,186,154,190,95,114,217,115,213,188,217,102,217,174,90,19,7,150,26,111,68,163,109,227,219,228,109,215,110,161,69,169,114,79,226,72,109,221,84,104,224,97,94,246,85,73,156,24,153,16,115,106,16,91,129,251,74,243,51,233,109,229,76,147,48,54,63,197,74,246,209,59,47,98,205,112,178,103,149,12,106,33,168,211,92,82,32,56,184,224,158,20,30,193,27,198,209,252,37,162,248,86,7,199,142,194,110,158,155,197,254,80,36,93,102,163,82,245,75,84,215,28,99,238,82,143,123,215,75,97,226,217,245,210,178,126,46,68,243,162,54,11,32,157,156,83,51,142,52,209,160,113,116,24,79,249,60,19,23,0,186,248,75,105,200,166,160,150,157,146,148,13,26,22,142,103,115,81,196,41,131,196,91,52,126,26,43,146,102,123,63,56,150,255,21,50,12,49,84,75,76,213,86,187,150,249,166,130,105,69,173,203,137,154,120,224,57,211,249,26,188,48,63,1,21,123,245,169,12,118,247,86,112,102,238,244,162,110,249,19,160,173,79,138,225,183,192,62,28,30,150,151,47,122,75,91,178,110,70,209,50,60,80,194,45,213,214,82,139,117,186,27,11,237,207,253,227,251,108,21,161,133,182,38,114,115,139,78,119,149,17,146,125,126,208,191,38,220,130,205,56,145,3,94,38,182,232,65,151,170,104,55,255,88,93,49,181,42,44,52,213,129,189,246,253,216,250,139,139,122,20,192,129,73,36,160,209,164,71,94,252,225,18,2,200,200,64,119,51,167,59,92,122,86,83,254,10,148,164,244,12,126,25,2,231,175,46,228,164,57,10,158,197,159,85,50,1,1,186,67,40,24,67,129,231,92,115,36,217,110,4,83,150,139,162,136,54,152,183,168,184,19,167,222,190,209,105,173,6,227,129,209,109,186,227,201,123,23,47,184,65,83,16,213,21,214,227,52,36,26,177,250,27,16,227,188,63,32,191,48,155,154,30,159,86,90,155,144,196,84,190,79,242,3,152,213,10,98,16,165,146,116,123,100,186,242,53,72,60,238,218,0,21,114,236,109,242,82,185,236,91,113,49,79,184,8,249,122,113,153,177,15,127,178,79,59,17,165,8,248,32,76,33,180,169,92,71,107,125,42,42,4,95,108,166,6,244,25,207,247,84,42,13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,125,180,198,43,114,215,10,207,139,94,219,3,140,34,47,104,100,23,176,139,21,18,203,76,161,34,67,144,200,155,128,205 };
	unsigned char skFromSeed[64 + 2560 + 1312 + 128] = { 129,111,254,208,138,196,60,45,101,134,78,177,227,76,82,203,26,114,241,89,26,205,174,187,167,219,156,51,195,197,228,27,240,78,219,55,229,129,35,19,238,250,42,184,21,246,140,49,133,117,234,93,254,183,215,211,206,92,25,21,105,115,247,115,211,10,39,252,190,40,150,237,95,4,192,163,171,100,105,240,107,33,83,68,228,125,29,161,139,146,159,81,61,31,124,158,222,11,28,105,5,109,52,135,188,243,62,92,102,190,11,156,128,42,160,44,41,25,215,31,247,58,131,169,112,166,19,4,231,247,205,149,190,13,3,215,53,100,154,37,253,226,244,228,199,14,134,226,45,154,130,97,243,45,37,246,72,51,208,252,2,27,37,107,218,149,186,100,158,182,143,11,1,80,56,57,144,188,189,252,211,160,147,199,120,254,141,233,188,238,156,239,27,65,96,64,198,76,66,196,97,83,130,129,3,53,46,136,168,69,209,160,45,148,194,81,152,48,68,74,146,77,220,194,129,137,22,14,154,180,45,25,41,38,0,160,13,33,32,77,65,38,77,195,150,112,227,152,72,200,8,46,68,164,112,25,71,44,100,22,142,84,4,50,19,36,146,209,182,128,36,197,132,3,33,110,147,166,45,212,160,68,81,48,144,66,66,130,146,192,112,163,182,44,209,162,32,34,165,96,161,50,109,28,19,6,17,24,108,193,184,128,64,48,96,11,181,32,217,6,104,76,54,8,84,36,114,220,32,82,72,50,42,3,52,98,17,73,36,219,146,132,36,56,137,217,18,44,72,162,141,208,18,144,1,161,81,227,146,40,65,150,144,80,130,108,96,0,74,209,40,112,19,72,74,82,152,13,26,181,48,25,55,129,211,56,100,12,37,14,90,166,137,154,196,112,3,180,77,92,68,133,138,54,73,1,193,104,2,16,137,209,182,132,19,131,17,11,185,8,0,3,68,68,184,13,0,0,38,9,36,145,200,8,65,216,178,96,32,146,101,26,131,132,224,24,106,154,2,129,68,4,68,17,182,32,28,41,50,148,162,13,16,178,73,64,150,64,28,7,78,27,69,48,28,198,0,193,152,40,84,66,68,216,18,8,152,22,34,16,135,65,9,192,65,32,64,108,9,33,45,0,50,80,130,32,140,74,40,141,155,50,144,226,164,5,97,66,106,34,53,42,20,72,46,9,166,9,11,6,113,211,160,145,3,64,48,226,152,80,139,16,41,145,168,97,224,166,133,208,54,134,89,22,137,26,49,145,204,198,132,36,22,128,17,177,129,216,34,10,12,70,108,35,20,12,73,4,44,72,178,97,192,184,105,19,192,32,208,152,104,20,64,68,130,144,40,218,40,96,224,52,112,145,148,16,20,149,41,138,64,34,83,164,76,217,180,16,33,184,112,220,8,98,138,16,14,89,146,140,2,57,36,76,6,50,163,34,14,163,0,2,28,33,80,96,8,108,3,34,12,12,3,128,17,152,37,220,144,136,36,134,33,82,64,9,226,144,81,164,196,136,220,198,141,128,40,5,4,0,68,100,24,65,24,197,136,2,185,36,16,64,5,216,16,104,11,184,69,228,52,33,72,16,45,201,24,134,19,130,16,218,148,37,203,52,66,33,16,141,91,164,40,65,166,9,209,34,70,90,152,129,76,20,10,145,68,2,18,195,136,3,73,9,67,198,16,0,73,34,225,32,74,200,68,37,210,134,137,75,144,1,9,134,96,89,160,129,218,16,48,36,56,65,26,162,109,161,198,44,75,136,12,140,176,140,194,132,36,10,23,105,98,176,65,28,70,132,81,148,64,3,18,18,160,52,74,12,184,145,8,53,73,34,168,137,203,178,113,211,22,80,212,160,129,9,66,112,194,56,17,4,165,44,163,34,81,32,0,114,220,168,40,3,2,96,3,64,137,89,4,113,200,130,36,128,50,37,25,54,106,164,54,106,163,18,49,32,200,141,16,65,73,65,164,16,219,2,141,27,1,40,138,136,44,28,129,8,81,40,5,73,194,65,90,0,132,163,8,128,140,36,110,196,146,64,218,66,106,80,162,104,82,36,141,156,6,114,4,198,68,92,6,70,66,194,65,194,2,48,36,176,72,32,67,32,84,50,100,73,176,109,26,40,134,66,184,32,80,72,32,153,2,98,16,23,0,161,0,145,245,104,38,14,65,179,182,1,252,0,76,146,216,170,29,22,249,198,40,122,155,162,23,203,92,16,98,169,96,112,46,225,31,89,107,227,142,142,224,230,194,64,185,121,86,69,55,44,211,248,235,170,179,190,109,10,252,66,233,101,120,225,217,51,83,211,74,221,109,84,136,78,245,82,21,46,235,182,182,195,108,87,146,209,216,230,77,206,31,46,75,86,109,73,135,16,218,6,77,188,180,47,197,85,244,194,121,206,24,212,29,218,50,95,149,98,118,83,78,23,139,130,205,130,36,167,181,34,183,159,228,234,114,52,176,40,69,121,216,20,160,162,237,83,110,147,12,182,134,159,193,195,38,10,130,83,21,136,44,148,208,2,83,224,96,131,51,231,39,184,93,91,21,240,183,186,111,12,146,1,105,46,223,105,89,56,145,57,117,80,92,226,5,61,3,100,198,174,92,177,226,205,16,143,9,105,210,113,124,9,239,31,169,157,66,218,242,167,229,17,47,189,32,67,188,220,36,204,167,240,174,30,183,184,7,173,52,50,40,67,199,173,253,197,65,90,96,155,26,249,170,231,212,151,7,215,95,212,99,207,175,238,139,195,55,212,116,22,24,240,38,159,38,192,37,158,74,91,86,195,181,34,230,0,95,16,28,209,219,23,134,188,145,163,148,135,170,141,249,119,98,73,52,48,216,134,199,173,182,207,216,46,69,103,52,150,5,116,92,170,144,198,77,6,242,131,10,92,219,61,132,8,88,249,224,70,44,63,180,81,155,204,98,115,237,134,225,68,33,231,158,141,227,213,231,51,177,61,200,14,32,140,120,14,137,52,31,50,95,59,175,180,14,79,107,91,177,103,120,43,254,43,136,40,173,37,246,225,253,62,176,72,219,117,29,31,118,43,253,0,26,66,5,48,212,162,134,168,73,161,187,124,103,40,114,218,142,247,152,204,150,171,27,125,25,116,187,191,65,1,95,86,147,99,152,106,166,66,33,188,121,125,149,247,26,222,140,224,110,161,165,215,162,23,49,222,18,250,107,164,102,126,31,22,116,9,175,218,28,99,8,50,108,204,188,176,178,223,220,35,76,140,87,234,44,14,224,1,97,45,32,97,13,5,157,227,167,112,86,128,203,225,177,253,100,123,190,154,77,240,207,212,100,122,41,189,155,240,246,157,39,22,103,228,164,84,81,42,139,188,148,57,13,204,9,252,22,221,31,122,76,48,8,34,140,103,252,202,234,29,143,132,73,184,57,42,123,57,94,60,104,176,159,164,253,166,8,26,77,4,124,50,237,76,134,228,128,22,102,165,216,37,122,159,64,182,118,29,57,140,3,242,6,44,56,200,110,170,142,177,254,81,213,224,138,147,92,239,61,75,212,96,33,148,122,187,246,87,119,146,46,148,118,2,92,79,239,209,112,130,255,210,240,39,114,221,184,34,37,37,227,5,250,191,129,122,68,135,251,81,154,97,192,125,10,111,63,37,205,253,10,46,127,38,71,175,246,180,238,3,148,84,254,211,214,181,8,109,238,70,27,42,241,245,254,116,114,185,167,208,157,205,182,217,27,176,49,199,41,193,163,148,144,173,85,208,237,135,61,88,237,249,237,35,115,57,61,89,201,220,247,37,93,114,219,60,110,53,130,131,99,27,103,161,119,210,22,48,196,206,40,182,216,72,220,48,139,62,104,63,196,200,80,185,232,87,1,121,109,240,76,82,136,249,54,118,56,137,138,14,68,66,251,245,231,131,102,47,232,35,1,197,223,160,214,62,224,162,22,134,109,168,109,146,22,34,106,186,188,84,225,21,49,154,123,8,29,28,63,76,63,106,85,184,117,254,182,220,241,4,153,218,151,172,204,198,175,35,15,47,90,236,190,145,208,34,91,163,30,4,103,217,53,99,91,227,179,142,107,152,218,28,87,126,110,170,64,98,144,238,112,175,62,23,94,253,234,173,250,53,242,79,205,79,160,19,107,176,17,186,149,171,121,191,66,25,112,249,237,12,225,83,2,186,65,36,34,117,165,107,131,136,196,87,165,184,40,57,161,32,208,167,225,49,60,234,92,33,128,129,24,252,88,126,35,53,190,199,45,74,242,234,99,13,157,109,118,122,108,81,236,156,192,67,254,79,39,195,139,184,213,17,111,86,164,83,203,244,187,169,156,113,137,249,198,46,191,193,135,12,214,142,252,143,152,112,62,128,129,240,115,78,16,137,113,204,255,194,193,35,23,21,170,53,240,32,166,126,59,75,159,61,196,196,163,29,39,32,61,106,82,103,39,220,74,97,141,77,144,181,100,215,2,43,149,84,200,142,13,152,246,212,102,250,42,143,119,127,131,55,149,18,70,38,46,144,64,159,234,43,32,210,157,168,9,87,230,78,67,27,225,64,75,203,135,203,106,198,84,180,66,111,8,34,84,159,29,236,101,144,3,171,138,39,186,231,248,216,255,131,189,224,141,107,71,157,167,150,47,158,174,204,76,4,253,133,103,168,225,247,203,139,107,152,245,141,20,54,160,255,16,164,130,100,28,30,155,248,235,236,21,192,233,25,129,122,56,62,29,129,223,216,96,246,208,46,185,203,170,122,121,104,52,121,95,87,48,45,148,141,206,82,247,194,80,89,196,5,209,75,31,252,162,176,1,157,201,242,43,216,238,217,164,111,2,89,143,120,231,77,241,50,114,185,46,94,177,38,36,222,252,211,77,226,9,171,121,204,171,71,84,87,130,106,93,72,237,137,31,133,101,113,68,175,234,96,39,38,199,21,159,107,77,209,81,47,15,89,102,213,119,81,118,149,254,249,250,163,156,151,23,159,16,89,113,19,61,190,37,200,36,134,55,13,245,10,202,20,130,30,187,178,75,58,133,136,35,43,69,192,181,31,27,179,96,109,35,52,49,117,199,204,67,157,218,123,50,160,91,201,226,26,11,82,114,133,92,0,39,61,168,36,179,164,107,192,15,40,1,39,188,43,28,169,226,146,63,25,236,88,59,183,220,154,58,158,119,74,162,150,95,41,41,194,67,207,86,196,52,221,209,234,127,235,49,45,34,208,181,170,214,165,5,143,159,31,81,65,184,41,47,119,173,130,214,184,74,19,12,231,63,201,108,235,135,105,33,63,28,157,244,10,15,251,50,141,65,44,238,237,27,212,26,237,93,14,115,62,194,241,213,248,98,80,58,235,17,109,2,26,83,110,252,88,246,45,30,222,166,240,227,116,148,179,162,117,7,48,105,40,192,234,59,54,112,225,7,195,123,22,139,3,10,157,153,133,8,32,108,53,188,168,33,116,140,9,233,204,9,245,38,88,231,102,15,184,184,141,237,212,235,158,98,47,182,252,102,208,22,112,75,58,118,204,226,209,177,220,212,231,215,120,163,101,108,91,153,192,57,33,141,158,210,249,23,60,67,248,103,118,61,244,241,89,163,169,117,49,232,41,243,135,159,211,172,176,115,53,18,211,87,187,20,69,133,68,185,157,20,8,178,68,114,233,77,168,248,243,199,99,32,50,89,248,211,34,201,62,186,91,64,67,173,176,37,245,158,179,145,114,172,21,74,136,112,164,96,45,87,110,176,163,173,220,248,113,159,103,39,3,33,157,168,61,118,75,20,31,94,249,27,220,167,44,251,61,91,182,187,21,212,69,195,42,94,238,12,1,136,178,196,208,217,178,126,252,210,79,213,184,248,99,217,17,96,57,214,90,98,34,207,181,77,142,253,253,196,167,132,245,247,153,236,47,211,10,39,252,190,40,150,237,95,4,192,163,171,100,105,240,107,33,83,68,228,125,29,161,139,146,159,81,61,31,124,158,3,166,59,195,12,211,93,68,8,73,212,169,81,201,46,231,74,162,153,110,81,197,17,33,199,26,102,208,122,104,52,207,38,215,250,125,66,231,196,39,11,76,38,106,119,57,223,51,224,176,181,25,45,166,56,84,24,246,248,143,206,211,185,64,102,123,41,1,70,43,59,167,65,94,175,70,141,218,215,213,32,22,124,94,115,102,168,74,125,180,149,149,127,142,11,64,39,145,22,16,250,47,48,174,58,155,117,170,108,243,208,177,100,217,39,116,40,76,5,203,237,210,163,118,148,156,172,112,86,185,131,37,111,115,233,190,130,69,237,16,207,146,141,103,114,100,201,9,169,72,64,150,245,18,203,123,125,241,167,147,78,41,212,29,70,169,145,50,123,12,165,57,193,211,62,248,112,126,144,229,21,9,123,111,127,158,137,236,226,142,149,190,142,222,213,89,243,231,202,161,246,152,207,74,206,182,251,22,132,205,132,191,248,63,65,27,32,76,230,148,217,236,37,198,17,193,130,245,72,174,99,132,91,1,170,167,96,152,231,136,195,250,77,4,39,128,224,138,150,179,90,102,18,23,148,59,203,99,61,157,199,112,196,11,7,98,58,32,166,2,55,120,43,108,84,157,243,234,178,247,143,110,128,94,25,179,34,30,139,178,41,133,254,76,49,221,225,135,161,56,245,90,41,215,72,10,104,158,68,93,111,181,42,126,1,37,138,63,145,142,22,60,254,124,222,125,196,227,109,34,78,71,55,3,109,147,223,40,165,81,147,13,57,210,234,108,162,69,191,71,155,91,164,112,187,212,227,72,32,204,100,94,245,205,6,230,72,87,138,92,40,148,211,32,236,1,73,99,29,106,108,116,113,254,210,62,158,103,227,126,47,194,112,55,46,82,92,204,225,138,74,170,29,179,131,183,77,234,186,174,144,53,36,159,53,85,86,203,229,174,196,234,131,99,140,226,84,236,205,197,31,143,15,188,126,214,115,111,168,156,84,14,190,140,145,209,118,177,19,98,25,179,183,191,156,95,80,89,158,173,219,222,135,65,162,210,165,177,127,95,161,162,58,248,132,251,241,102,170,186,211,97,170,200,137,78,46,219,140,66,22,208,219,19,189,29,255,254,222,204,145,14,19,238,99,201,161,103,91,8,249,122,165,255,162,107,115,211,120,41,78,130,219,142,209,254,103,82,216,49,0,205,40,105,223,59,121,55,38,254,162,241,41,51,209,143,48,190,236,0,200,146,239,137,193,223,117,205,56,186,70,137,210,1,224,142,241,2,157,31,239,12,138,141,95,216,247,225,64,45,53,248,165,19,6,178,225,95,111,218,164,218,4,49,142,71,244,78,51,29,11,140,121,230,188,22,232,13,33,140,174,115,255,162,244,112,55,29,16,91,58,28,4,158,85,171,96,151,235,235,213,247,0,90,65,227,119,2,54,104,66,185,57,182,76,234,160,170,218,119,123,162,126,79,54,35,58,36,249,117,110,76,7,114,139,135,140,63,139,133,19,128,196,12,51,35,165,76,158,54,87,133,1,58,210,75,203,183,193,34,255,21,114,182,215,122,191,149,134,135,240,198,182,60,66,1,176,144,143,132,36,184,125,62,56,124,218,85,28,245,142,60,18,0,169,99,88,215,123,181,34,16,43,239,207,40,188,127,255,91,8,224,144,125,221,248,27,4,48,212,148,75,103,62,118,7,89,35,186,154,190,95,114,217,115,213,188,217,102,217,174,90,19,7,150,26,111,68,163,109,227,219,228,109,215,110,161,69,169,114,79,226,72,109,221,84,104,224,97,94,246,85,73,156,24,153,16,115,106,16,91,129,251,74,243,51,233,109,229,76,147,48,54,63,197,74,246,209,59,47,98,205,112,178,103,149,12,106,33,168,211,92,82,32,56,184,224,158,20,30,193,27,198,209,252,37,162,248,86,7,199,142,194,110,158,155,197,254,80,36,93,102,163,82,245,75,84,215,28,99,238,82,143,123,215,75,97,226,217,245,210,178,126,46,68,243,162,54,11,32,157,156,83,51,142,52,209,160,113,116,24,79,249,60,19,23,0,186,248,75,105,200,166,160,150,157,146,148,13,26,22,142,103,115,81,196,41,131,196,91,52,126,26,43,146,102,123,63,56,150,255,21,50,12,49,84,75,76,213,86,187,150,249,166,130,105,69,173,203,137,154,120,224,57,211,249,26,188,48,63,1,21,123,245,169,12,118,247,86,112,102,238,244,162,110,249,19,160,173,79,138,225,183,192,62,28,30,150,151,47,122,75,91,178,110,70,209,50,60,80,194,45,213,214,82,139,117,186,27,11,237,207,253,227,251,108,21,161,133,182,38,114,115,139,78,119,149,17,146,125,126,208,191,38,220,130,205,56,145,3,94,38,182,232,65,151,170,104,55,255,88,93,49,181,42,44,52,213,129,189,246,253,216,250,139,139,122,20,192,129,73,36,160,209,164,71,94,252,225,18,2,200,200,64,119,51,167,59,92,122,86,83,254,10,148,164,244,12,126,25,2,231,175,46,228,164,57,10,158,197,159,85,50,1,1,186,67,40,24,67,129,231,92,115,36,217,110,4,83,150,139,162,136,54,152,183,168,184,19,167,222,190,209,105,173,6,227,129,209,109,186,227,201,123,23,47,184,65,83,16,213,21,214,227,52,36,26,177,250,27,16,227,188,63,32,191,48,155,154,30,159,86,90,155,144,196,84,190,79,242,3,152,213,10,98,16,165,146,116,123,100,186,242,53,72,60,238,218,0,21,114,236,109,242,82,185,236,91,113,49,79,184,8,249,122,113,153,177,15,127,178,79,59,17,165,8,248,32,76,33,180,169,92,71,107,125,42,42,4,95,108,166,6,244,25,207,247,84,42,13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,125,180,198,43,114,215,10,207,139,94,219,3,140,34,47,104,100,23,176,139,21,18,203,76,161,34,67,144,200,155,128,205 };

	for (int j = 0; j < 32; j++) {
		printf("\n test_hybrid_dilithium_sphincs_deterministic iteration %d", j);
		r = crypto_sign_dilithium_ed25519_sphincs_keypair_seed(pk2, sk2, seed1);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair_seed failed %d", (int)r);
			return -3;
		}

		for (int k = 0; k < 32 + 1312 + 64; k++) {
			if (pk[k] != pkFromSeed[k]) {
				printf("\n deterministic generation failed pkFromSeed: pk %d,%d,%d", k, pk[k], pkFromSeed[k]);
				return -4;
			}
			if (pk[k] != pk2[k]) {
				printf("\n deterministic generation failed: pk");
				return -5;
			}
		}

		for (int k = 0; k < 64 + 2560 + 1312 + 128; k++) {
			if (sk[k] != skFromSeed[k]) {
				printf("\n deterministic generation failed skFromSeed: sk");
				return -6;
			}
			if (sk[k] != sk2[k]) {
				printf("\n deterministic generation failed: sk");
				return -7;
			}
		}

		r = crypto_sign_dilithium_ed25519_sphincs_keypair_seed(pk3, sk3, seed3);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair_seed failed %d", (int)r);
			return -8;
		}

		int matchCount = 0;
		for (int k = 0; k < 32 + 1312 + 64; k++) {
			if (pk2[k] == pk3[k]) {
				matchCount++;
			}
		}
		if (matchCount == 32 + 1312 + 64) {
			printf("\n deterministic generation failed repeat: pk");
			return -9;
		}

		matchCount = 0;
		for (int k = 0; k < 64 + 2560 + 1312 + 128; k++) {
			if (sk2[k] == sk3[k]) {
				matchCount++;
			}
		}
		if (matchCount == 64 + 2560 + 1312 + 128) {
			printf("\n deterministic generation failed repeat: pk");
			return -10;
		}

		r = randombytes(msg1, MSG_LEN * sizeof(unsigned char));
		if (r != 0) {
			printf("\n randombytes failed %d", (int)r);
			return -11;
		}

		r = crypto_sign_dilithium_ed25519_sphincs(sig1, &sigLen1, msg1, MSG_LEN, sk);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs failed %d", (int)r);
			return -12;
		}

		if (sigLen1 != SIG_LEN) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen1);
			return -13;
		}

		r = crypto_sign_dilithium_ed25519_sphincs_open(msg1output, &msgLen1, sig1, sigLen1, pk);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_open failed %d", (int)r);
			return -14;
		}

		if (msgLen1 != MSG_LEN) {
			printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen1);
			return -15;
		}

		for (int i = 0; i < MSG_LEN; i++) {
			if (msg1[i] != msg1output[i]) {
				printf("\n verify msg content failed %d", i);
				return -16;
			}
		}
	}

	printf("\n test_hybrid_dilithium_sphincs_deterministic() ok");
	return 0;
}

int test_hybrid_compact_dilithium_sphincs_perf() {
	printf("\n test_hybrid_compact_dilithium_sphincs () start");

	unsigned char pk[32 + 1312 + 64];
	unsigned char pk2[32 + 1312 + 64];
	unsigned char sk[64 + 2560 + 1312 + 128];
	unsigned char sig1[2 + 64 + 2420 + 40 + 32];
	unsigned char sig2[2 + 64 + 2420 + 40 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned char msg1output[32];
	unsigned char msg2output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;
	const int SIG_LEN = 2 + 64 + 2420 + 40 + MSG_LEN;
	clock_t startTime;
	clock_t endTime;
	int r = 0;

	printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair perf 1000 iterations");
	startTime = get_nano_sec();
	for (int i = 0; i < 1000; i++) {
		r = crypto_sign_dilithium_ed25519_sphincs_keypair(pk, sk);
		if (r != 0) {
			printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair failed %d", (int)r);
			return -1;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	r = randombytes(msg1, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -2;
	}

	printf("\n crypto_sign_compact_dilithium_ed25519_sphincs perf 1000 iterations");
	startTime = get_nano_sec();
	for (int i = 0; i < 1000; i++) {
		r = crypto_sign_compact_dilithium_ed25519_sphincs(sig1, &sigLen1, msg1, MSG_LEN, sk);
		if (r != 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs failed %d", (int)r);
			return -3;
		}

		if (sigLen1 != SIG_LEN) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs sigLen error %d", (int)sigLen1);
			return -4;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open perf 10000 iterations");
	for (int i = 0; i < 10000; i++) {
		unsigned char msgFromSignature1[64] = { 0 }; //MAX_MSG_LEN
		unsigned long long msgFromSignatureLen1 = 0;

		r = crypto_sign_compact_dilithium_ed25519_sphincs_open(msgFromSignature1, &msgFromSignatureLen1, sig1, sigLen1, pk);
		if (r != 0) {
			printf("\n crypto_sign_compact_dilithium_ed25519_sphincs_open A failed %d", (int)r);
			return -5;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n crypto_verify_compact_dilithium_ed25519_sphincs perf 10000 iterations");
	for (int i = 0; i < 10000; i++) {
		r = crypto_verify_compact_dilithium_ed25519_sphincs(msg1, MSG_LEN, sig1, sigLen1, pk);
		if (r != 0) {
			printf("\n crypto_verify_compact_dilithium_ed25519_sphincs failed %d", (int)r);
			return -8;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n crypto_verify_compact_dilithium_ed25519_sphincs perf () ok");

	return 0;
}

int main(int argc, char* argv[]) {
	int result;

	result = test_hybrid_compact_dilithium_sphincs_perf();
	if (result != 0) {
		return result;
	}

	result = test_hybrid_compact_dilithium_sphincs();
	if (result != 0) {
		return result;
	}

	result = test_hybrid_dilithium_sphincs_deterministic();
	if (result != 0) {
		return result;
	}

	result = test_hybrid_dilithium_sphincs();
	if (result != 0) {
		return result;
	}

	result = test_dilithium();
	if (result != 0) {
		return result;
	}

	result = test_sphincs();
	if (result != 0) {
		return result;
	}

	printf("\n Warning, perf tests uses approximate system clock. Is not suitable for fewer iterations of test.");

	printf(" \n test suite completed!");

	return 0;
}

