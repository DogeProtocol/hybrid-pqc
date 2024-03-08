#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../random/randombytes.h"
#include "../hybrid-dilithium-sphincs/hybrid.h"
#include "../sphincs/api.h"
#include "../common/fips202.h"
#include "../common/shake_prng.h"
#include "../dilithium2/api.h"

clock_t get_nano_sec(void);
void print_elapsed(clock_t startTime, clock_t endTime);
int test_dilithium(void);
int test_sphincs(void);
int test_hybrid_dilithium_sphincs(void);
int test_hybrid_dilithium_sphincs_deterministic();
int test_hybrid_compact_dilithium_sphincs(void);
int test_hybrid_compact_dilithium_sphincs_perf(void);
int test_hybrid_compact_dilithium_sphincs_seed_expander(void);
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

int test_hybrid_compact_dilithium_sphincs_seed_expander() {
	printf("\n starting test_hybrid_compact_dilithium_sphincs_seed_expander");
	const uint8_t zero[160] = { 0 };

	uint8_t seed[96] = { 0 };
	uint8_t expandedSeed[160] = { 0 };
	int ret = randombytes(seed, sizeof(seed));
	if (ret != 0) {
		return -1;
	}

	ret = crypto_sign_dilithium_ed25519_sphincs_keypair_seed_expander(seed, expandedSeed);
	if (ret != 0) {
		return -2;
	}
	assert(memcmp(expandedSeed, zero, sizeof(zero)) != 0);

	uint8_t byteMap[256] = { 0 };
	for (int i = 0; i < 160; i++) {
		byteMap[expandedSeed[i]] = byteMap[expandedSeed[i]] + 1;
	}
	for (int i = 0; i < 256; i++) {
		if (byteMap[i] > 0) {
			assert(byteMap[i] <= 6);
		}
	}
	
	for (int i = 0; i < 32; i++) {
		assert(seed[64 + i] == expandedSeed[32 + i]);
	}

	unsigned char pk[1312];
	unsigned char sk[2560];
	unsigned char sig[2420 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned long long sigLen = 0;

	ret = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk);
	if (ret != 0) {
		printf("\n PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair failed %d", (int)ret);
		return ret;
	}

	//Deterministic seed expander test
	uint8_t seedDet[96] = { 172,225,248,155,203,184,25,30,170,234,120,74,108,34,234,163,96,243,133,251,141,191,247,182,13,106,56,164,214,179,143,188,253,182,185,124,21,89,72,245,198,128,37,144,170,127,227,74,207,38,218,180,9,3,70,186,30,164,224,215,225,70,242,170,223,41,220,205,23,89,21,10,35,47,200,207,80,239,219,143,117,90,17,81,123,238,48,187,49,28,23,95,251,233,247,76 };
	uint8_t expandedSeedDet[160] = { 0 };
	uint8_t expectedExpandedSeed[160] = { 164,112,179,200,61,89,69,78,1,89,229,44,54,201,107,104,54,62,47,58,160,249,241,178,162,136,246,83,253,89,108,138,223,41,220,205,23,89,21,10,35,47,200,207,80,239,219,143,117,90,17,81,123,238,48,187,49,28,23,95,251,233,247,76,162,119,56,52,120,78,179,99,38,91,246,87,201,159,152,122,94,47,110,203,200,250,99,9,172,241,11,195,231,177,73,250,221,22,173,39,38,112,212,31,61,97,206,203,168,175,253,161,189,135,204,75,56,65,107,240,239,158,180,155,254,171,213,115,94,105,96,63,162,43,34,135,20,255,183,35,18,9,210,230,214,185,23,134,137,205,183,208,118,1,84,200,204,130,143,241 };

	ret = crypto_sign_dilithium_ed25519_sphincs_keypair_seed_expander(seedDet, expandedSeedDet);
	if (ret != 0) {
		return -3;
	}
	for (int i = 0; i < 160; i++) {
		assert(expandedSeedDet[i] == expectedExpandedSeed[i]);
	}

	printf("\n test_hybrid_compact_dilithium_sphincs_seed_expander complete");
	return 0;
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

	unsigned char seed1[160] = { 164, 112, 179, 200, 61, 89, 69, 78, 1, 89, 229, 44, 54, 201, 107, 104, 54, 62, 47, 58, 160, 249, 241, 178, 162, 136, 246, 83, 253, 89, 108, 138, 223, 41, 220, 205, 23, 89, 21, 10, 35, 47, 200, 207, 80, 239, 219, 143, 117, 90, 17, 81, 123, 238, 48, 187, 49, 28, 23, 95, 251, 233, 247, 76, 162, 119, 56, 52, 120, 78, 179, 99, 38, 91, 246, 87, 201, 159, 152, 122, 94, 47, 110, 203, 200, 250, 99, 9, 172, 241, 11, 195, 231, 177, 73, 250, 221, 22, 173, 39, 38, 112, 212, 31, 61, 97, 206, 203, 168, 175, 253, 161, 189, 135, 204, 75, 56, 65, 107, 240, 239, 158, 180, 155, 254, 171, 213, 115, 94, 105, 96, 63, 162, 43, 34, 135, 20, 255, 183, 35, 18, 9, 210, 230, 214, 185, 23, 134, 137, 205, 183, 208, 118, 1, 84, 200, 204, 130, 143, 241 };

	unsigned char seed3[160];
	if (randombytes(seed3, sizeof seed3) != 0) {
		return -1;
	}

	int r = crypto_sign_dilithium_ed25519_sphincs_keypair_seed(pk, sk, seed1);
	if (r != 0) {
		printf("\n crypto_sign_dilithium_ed25519_sphincs_keypair_seed failed %d", (int)r);
		return -2;
	}
	
	
	printf("\n pk \n");
	for (int k = 0; k < 32 + 1312 + 64; k++) {
		printf("%d,", pk[k]);
	}
	printf("\n sk \n");
	for (int k = 0; k < 64 + 2560 + 1312 + 128; k++) {
		printf("%d,", sk[k]);
	}

	unsigned char pkFromSeed[32 + 1312 + 64] = { 61, 175, 135, 202, 195, 30, 91, 215, 245, 243, 16, 44, 205, 11, 2, 228, 48, 220, 38, 91, 30, 33, 57, 103, 219, 92, 255, 144, 216, 184, 225, 208, 22, 247, 27, 133, 223, 50, 12, 252, 125, 88, 177, 180, 129, 109, 31, 213, 95, 93, 114, 224, 229, 58, 29, 25, 125, 56, 252, 77, 192, 254, 34, 11, 50, 218, 197, 188, 192, 244, 173, 107, 5, 150, 231, 140, 74, 64, 113, 187, 230, 191, 134, 78, 81, 184, 74, 40, 251, 14, 0, 152, 71, 41, 97, 173, 130, 23, 178, 135, 253, 44, 85, 98, 62, 206, 119, 98, 164, 56, 4, 127, 134, 11, 238, 147, 245, 244, 84, 88, 116, 196, 145, 97, 213, 182, 239, 192, 18, 138, 201, 72, 220, 101, 203, 40, 93, 39, 35, 201, 87, 5, 229, 176, 34, 54, 25, 58, 123, 182, 3, 242, 36, 40, 168, 189, 201, 95, 159, 236, 163, 215, 203, 69, 10, 110, 215, 197, 34, 105, 51, 192, 169, 227, 248, 155, 241, 221, 232, 142, 121, 136, 105, 144, 236, 28, 180, 47, 130, 194, 236, 184, 194, 82, 76, 5, 193, 123, 81, 80, 5, 60, 231, 140, 234, 95, 214, 65, 158, 4, 19, 30, 29, 62, 33, 233, 130, 161, 42, 179, 244, 154, 125, 80, 9, 233, 53, 81, 38, 238, 180, 1, 191, 157, 221, 232, 64, 148, 68, 243, 249, 188, 65, 156, 234, 81, 208, 39, 18, 98, 47, 218, 5, 100, 169, 86, 56, 214, 167, 19, 194, 149, 210, 157, 100, 51, 161, 146, 22, 220, 98, 243, 220, 39, 111, 31, 163, 243, 206, 151, 131, 75, 89, 37, 243, 1, 205, 158, 31, 185, 99, 230, 243, 92, 23, 186, 219, 69, 39, 78, 112, 183, 226, 249, 9, 49, 72, 50, 62, 232, 54, 75, 249, 160, 82, 70, 212, 52, 150, 238, 180, 174, 159, 204, 236, 52, 120, 232, 198, 247, 58, 252, 80, 154, 35, 182, 62, 91, 212, 61, 152, 127, 84, 111, 111, 239, 75, 101, 120, 223, 247, 108, 245, 12, 227, 134, 235, 230, 207, 12, 118, 249, 74, 19, 19, 32, 124, 206, 5, 244, 180, 166, 143, 226, 63, 191, 112, 245, 106, 151, 116, 73, 89, 139, 208, 203, 108, 153, 5, 252, 26, 185, 62, 170, 35, 229, 180, 228, 50, 241, 53, 160, 186, 222, 139, 183, 111, 155, 74, 176, 241, 15, 40, 99, 245, 15, 71, 48, 80, 207, 143, 42, 103, 70, 48, 213, 30, 72, 42, 58, 59, 136, 175, 109, 22, 137, 44, 92, 48, 70, 94, 17, 177, 7, 83, 210, 118, 240, 9, 6, 3, 30, 99, 32, 149, 245, 115, 246, 77, 42, 223, 178, 89, 70, 113, 75, 155, 53, 52, 89, 211, 30, 2, 220, 5, 232, 39, 210, 37, 188, 30, 220, 56, 76, 174, 139, 252, 148, 111, 4, 142, 126, 63, 205, 58, 132, 216, 146, 142, 193, 43, 107, 153, 149, 4, 34, 232, 87, 103, 92, 26, 122, 98, 141, 149, 19, 66, 106, 128, 40, 103, 239, 239, 41, 201, 34, 74, 187, 145, 254, 211, 67, 90, 135, 70, 127, 59, 233, 80, 124, 154, 153, 154, 239, 96, 100, 173, 139, 234, 50, 192, 167, 163, 30, 200, 168, 216, 21, 148, 138, 158, 147, 151, 213, 31, 137, 43, 235, 112, 117, 246, 59, 89, 194, 215, 155, 28, 14, 227, 150, 86, 213, 148, 33, 29, 81, 135, 87, 132, 166, 142, 156, 107, 69, 200, 72, 68, 152, 51, 244, 78, 114, 20, 201, 66, 138, 50, 9, 152, 212, 112, 171, 111, 95, 129, 120, 174, 232, 113, 199, 169, 87, 27, 176, 185, 180, 106, 23, 149, 33, 251, 56, 51, 210, 197, 28, 208, 112, 2, 96, 224, 121, 79, 48, 75, 42, 20, 110, 141, 133, 178, 35, 191, 125, 11, 185, 137, 3, 161, 120, 175, 0, 58, 238, 61, 12, 248, 108, 76, 111, 239, 136, 235, 234, 72, 157, 233, 205, 182, 147, 91, 37, 250, 58, 105, 38, 110, 32, 162, 147, 243, 194, 190, 49, 237, 46, 63, 53, 191, 7, 145, 52, 78, 154, 15, 148, 167, 142, 174, 19, 236, 216, 226, 87, 251, 145, 219, 85, 241, 133, 69, 150, 224, 154, 254, 237, 59, 105, 82, 207, 50, 187, 172, 179, 173, 139, 71, 107, 37, 30, 166, 171, 164, 58, 11, 102, 13, 195, 130, 135, 104, 138, 161, 149, 67, 147, 219, 190, 191, 207, 159, 157, 225, 201, 226, 178, 118, 242, 92, 57, 60, 186, 51, 61, 120, 204, 24, 103, 17, 191, 93, 98, 194, 221, 123, 157, 248, 238, 94, 184, 252, 24, 235, 161, 78, 225, 109, 188, 198, 67, 226, 152, 18, 205, 167, 160, 242, 235, 124, 98, 188, 84, 52, 93, 30, 2, 134, 31, 139, 15, 105, 26, 88, 82, 35, 186, 13, 23, 248, 249, 41, 68, 115, 117, 14, 238, 93, 138, 9, 182, 35, 19, 39, 193, 37, 111, 188, 117, 213, 93, 245, 193, 13, 133, 14, 199, 146, 209, 107, 128, 114, 5, 71, 9, 208, 221, 153, 120, 53, 213, 160, 114, 147, 208, 237, 171, 156, 166, 203, 99, 8, 146, 178, 53, 31, 66, 243, 116, 143, 131, 88, 104, 255, 149, 72, 253, 145, 140, 140, 162, 246, 205, 190, 116, 93, 56, 184, 86, 30, 165, 87, 161, 54, 70, 138, 207, 159, 122, 25, 67, 179, 227, 159, 32, 243, 217, 225, 103, 122, 84, 207, 196, 179, 103, 153, 74, 232, 177, 174, 144, 70, 193, 40, 150, 177, 157, 235, 184, 178, 12, 140, 80, 149, 82, 179, 137, 30, 59, 169, 134, 25, 67, 78, 48, 4, 2, 92, 224, 106, 111, 200, 54, 240, 120, 69, 95, 109, 197, 22, 128, 61, 246, 24, 239, 104, 55, 235, 199, 216, 68, 64, 226, 146, 184, 1, 254, 24, 193, 152, 175, 25, 131, 174, 154, 72, 93, 156, 152, 113, 34, 135, 210, 38, 128, 144, 136, 28, 179, 207, 206, 92, 174, 205, 11, 240, 127, 225, 117, 30, 90, 104, 195, 208, 188, 168, 25, 231, 58, 92, 239, 108, 224, 230, 186, 116, 88, 175, 68, 8, 215, 194, 30, 255, 187, 189, 57, 36, 181, 151, 165, 67, 131, 136, 77, 171, 108, 3, 92, 16, 65, 31, 194, 29, 6, 183, 111, 71, 126, 220, 109, 205, 196, 82, 193, 182, 69, 237, 189, 54, 187, 250, 52, 189, 10, 175, 152, 250, 92, 213, 122, 236, 71, 153, 82, 250, 159, 238, 153, 109, 56, 34, 99, 13, 108, 39, 193, 99, 227, 181, 182, 76, 3, 202, 112, 35, 122, 71, 9, 168, 43, 224, 31, 168, 252, 2, 189, 95, 150, 100, 212, 122, 172, 29, 240, 128, 181, 222, 63, 233, 123, 16, 54, 104, 8, 7, 17, 67, 177, 221, 245, 31, 228, 77, 175, 70, 253, 224, 90, 188, 95, 138, 114, 192, 88, 120, 25, 245, 85, 49, 103, 168, 111, 243, 43, 77, 234, 80, 174, 51, 162, 177, 129, 128, 66, 184, 231, 28, 76, 75, 128, 215, 132, 91, 51, 201, 202, 101, 185, 138, 233, 11, 164, 198, 67, 8, 141, 18, 78, 191, 56, 169, 156, 145, 81, 13, 118, 10, 111, 93, 235, 129, 249, 218, 102, 186, 33, 125, 155, 231, 178, 109, 213, 5, 69, 144, 22, 60, 170, 13, 167, 79, 133, 159, 193, 132, 31, 72, 21, 98, 180, 203, 42, 113, 11, 94, 88, 134, 14, 248, 241, 187, 179, 206, 66, 32, 59, 97, 28, 224, 154, 141, 63, 247, 4, 122, 72, 184, 153, 26, 35, 97, 72, 15, 38, 146, 227, 210, 213, 154, 29, 176, 213, 199, 69, 84, 87, 198, 197, 224, 209, 219, 232, 4, 78, 49, 234, 101, 151, 103, 116, 76, 248, 114, 219, 121, 113, 10, 253, 166, 189, 116, 222, 111, 136, 31, 228, 17, 163, 0, 251, 79, 101, 56, 255, 94, 105, 96, 63, 162, 43, 34, 135, 20, 255, 183, 35, 18, 9, 210, 230, 214, 185, 23, 134, 137, 205, 183, 208, 118, 1, 84, 200, 204, 130, 143, 241, 2, 38, 63, 240, 71, 173, 119, 163, 168, 81, 47, 118, 243, 253, 33, 252, 79, 214, 138, 135, 148, 201, 178, 153, 94, 182, 236, 232, 185, 206, 53, 137 };
	unsigned char skFromSeed[64 + 2560 + 1312 + 128] = { 164, 112, 179, 200, 61, 89, 69, 78, 1, 89, 229, 44, 54, 201, 107, 104, 54, 62, 47, 58, 160, 249, 241, 178, 162, 136, 246, 83, 253, 89, 108, 138, 61, 175, 135, 202, 195, 30, 91, 215, 245, 243, 16, 44, 205, 11, 2, 228, 48, 220, 38, 91, 30, 33, 57, 103, 219, 92, 255, 144, 216, 184, 225, 208, 22, 247, 27, 133, 223, 50, 12, 252, 125, 88, 177, 180, 129, 109, 31, 213, 95, 93, 114, 224, 229, 58, 29, 25, 125, 56, 252, 77, 192, 254, 34, 11, 128, 87, 59, 173, 1, 15, 8, 50, 70, 112, 226, 67, 110, 138, 214, 251, 19, 66, 161, 123, 184, 14, 42, 51, 33, 82, 37, 129, 41, 237, 88, 202, 60, 252, 96, 110, 154, 108, 187, 240, 197, 55, 107, 64, 142, 252, 197, 69, 34, 237, 110, 244, 213, 87, 243, 140, 233, 134, 30, 1, 73, 145, 210, 33, 67, 93, 113, 210, 123, 138, 211, 68, 41, 12, 106, 71, 73, 180, 71, 96, 118, 56, 111, 134, 206, 1, 22, 120, 10, 221, 100, 235, 176, 248, 174, 136, 209, 184, 136, 19, 71, 109, 201, 130, 9, 193, 56, 69, 81, 180, 140, 218, 0, 45, 25, 64, 145, 162, 192, 68, 209, 146, 108, 89, 40, 16, 18, 68, 1, 217, 150, 105, 26, 6, 17, 4, 36, 144, 1, 165, 48, 8, 19, 145, 0, 166, 109, 16, 9, 128, 216, 162, 41, 99, 52, 2, 219, 70, 34, 210, 136, 49, 2, 168, 9, 227, 24, 68, 146, 20, 32, 211, 20, 2, 8, 40, 78, 3, 130, 100, 228, 166, 41, 88, 148, 96, 137, 66, 13, 11, 32, 4, 131, 20, 96, 27, 180, 12, 204, 164, 132, 16, 7, 17, 89, 56, 130, 216, 0, 77, 100, 68, 16, 28, 8, 128, 35, 72, 34, 10, 17, 66, 138, 0, 112, 27, 57, 8, 129, 176, 145, 92, 184, 132, 163, 24, 134, 209, 0, 136, 17, 161, 80, 99, 182, 132, 27, 199, 13, 139, 48, 72, 28, 35, 102, 64, 66, 13, 202, 8, 1, 64, 16, 33, 83, 36, 80, 9, 198, 132, 74, 16, 146, 34, 48, 18, 9, 21, 114, 2, 0, 16, 75, 64, 1, 202, 192, 77, 82, 64, 12, 211, 194, 40, 32, 32, 70, 11, 5, 110, 26, 17, 133, 193, 128, 104, 11, 148, 72, 28, 167, 69, 27, 184, 140, 2, 177, 33, 4, 48, 6, 154, 178, 40, 130, 148, 144, 35, 66, 140, 211, 180, 45, 219, 70, 101, 9, 145, 77, 10, 37, 133, 2, 1, 109, 2, 64, 142, 89, 64, 69, 34, 193, 133, 89, 136, 100, 137, 180, 140, 209, 196, 80, 72, 128, 132, 26, 22, 133, 12, 194, 137, 2, 34, 132, 26, 1, 34, 152, 166, 12, 75, 64, 17, 96, 48, 113, 36, 169, 12, 220, 34, 10, 9, 193, 13, 84, 130, 77, 33, 181, 109, 203, 8, 41, 132, 148, 108, 220, 192, 109, 145, 24, 96, 227, 54, 81, 152, 36, 81, 16, 193, 37, 33, 4, 110, 164, 22, 5, 25, 21, 108, 210, 152, 77, 18, 32, 134, 24, 9, 110, 100, 16, 137, 210, 134, 40, 132, 160, 4, 66, 48, 0, 8, 184, 141, 2, 36, 14, 156, 164, 16, 203, 168, 132, 160, 56, 104, 155, 54, 9, 204, 134, 64, 17, 33, 109, 192, 64, 113, 0, 39, 144, 144, 184, 141, 155, 160, 44, 10, 52, 129, 220, 184, 77, 210, 134, 109, 3, 168, 129, 19, 129, 96, 193, 18, 98, 28, 65, 14, 218, 136, 17, 98, 6, 146, 3, 185, 45, 202, 2, 42, 64, 48, 45, 129, 70, 5, 88, 22, 45, 66, 152, 12, 8, 35, 4, 98, 68, 66, 76, 48, 138, 98, 40, 50, 1, 3, 9, 196, 194, 144, 202, 168, 9, 145, 56, 112, 35, 72, 108, 1, 200, 109, 36, 8, 50, 136, 194, 112, 3, 163, 105, 20, 144, 141, 216, 16, 13, 194, 160, 97, 24, 145, 108, 144, 194, 16, 192, 24, 144, 128, 64, 74, 147, 8, 110, 129, 146, 73, 67, 134, 101, 26, 180, 13, 208, 184, 108, 12, 57, 78, 16, 133, 104, 34, 129, 45, 8, 131, 36, 64, 136, 100, 0, 4, 73, 131, 182, 145, 82, 36, 5, 11, 197, 36, 90, 146, 0, 65, 18, 5, 32, 25, 44, 140, 178, 0, 24, 69, 38, 24, 52, 36, 28, 21, 65, 28, 0, 80, 18, 199, 64, 139, 20, 80, 204, 192, 44, 131, 144, 45, 210, 134, 80, 90, 0, 80, 2, 149, 33, 203, 132, 112, 33, 64, 114, 210, 146, 33, 136, 22, 137, 208, 8, 141, 18, 73, 37, 18, 132, 8, 20, 57, 48, 164, 166, 5, 219, 160, 137, 3, 8, 80, 193, 2, 128, 224, 178, 81, 204, 70, 144, 139, 68, 102, 196, 178, 104, 1, 9, 80, 36, 179, 81, 88, 56, 141, 147, 34, 110, 137, 48, 81, 100, 136, 104, 1, 7, 40, 33, 67, 102, 92, 198, 72, 208, 70, 2, 82, 18, 136, 74, 192, 132, 28, 41, 78, 153, 164, 0, 17, 176, 133, 2, 180, 16, 139, 136, 32, 90, 6, 68, 34, 166, 1, 12, 56, 101, 17, 151, 132, 154, 128, 128, 210, 182, 112, 211, 196, 104, 145, 18, 36, 8, 34, 138, 163, 72, 130, 18, 131, 132, 200, 50, 102, 12, 36, 44, 92, 198, 9, 11, 52, 81, 153, 56, 16, 1, 185, 45, 152, 68, 72, 18, 166, 33, 66, 200, 64, 34, 17, 34, 18, 136, 145, 17, 136, 64, 140, 32, 132, 1, 32, 16, 204, 24, 96, 140, 72, 110, 24, 66, 12, 202, 86, 214, 218, 22, 104, 138, 145, 3, 199, 208, 160, 14, 141, 114, 68, 108, 201, 235, 4, 20, 210, 61, 205, 0, 147, 113, 169, 225, 127, 13, 241, 69, 226, 236, 58, 29, 167, 199, 159, 85, 19, 48, 216, 97, 166, 249, 4, 229, 52, 36, 54, 83, 73, 170, 199, 213, 10, 202, 25, 142, 229, 246, 87, 176, 49, 245, 153, 203, 89, 229, 72, 117, 78, 198, 222, 13, 202, 42, 143, 74, 97, 29, 140, 165, 250, 198, 159, 108, 255, 255, 205, 199, 123, 204, 5, 66, 151, 190, 227, 206, 61, 233, 15, 35, 118, 126, 96, 199, 4, 37, 44, 57, 48, 73, 232, 68, 63, 59, 184, 101, 22, 137, 82, 202, 7, 160, 18, 109, 21, 120, 10, 226, 72, 209, 168, 12, 251, 156, 243, 52, 161, 146, 163, 245, 117, 9, 151, 79, 176, 75, 37, 98, 73, 240, 194, 38, 245, 235, 33, 241, 85, 197, 72, 174, 64, 160, 26, 108, 192, 98, 215, 244, 239, 170, 7, 138, 65, 58, 144, 232, 57, 72, 158, 119, 14, 164, 15, 138, 53, 45, 114, 17, 17, 221, 25, 107, 71, 87, 223, 66, 70, 57, 57, 99, 145, 145, 186, 86, 201, 112, 222, 96, 58, 64, 35, 120, 192, 116, 121, 70, 8, 52, 203, 185, 132, 91, 82, 224, 222, 56, 205, 188, 163, 18, 91, 46, 191, 226, 184, 81, 44, 90, 55, 56, 34, 134, 91, 56, 153, 50, 62, 16, 29, 237, 79, 50, 123, 163, 9, 104, 138, 140, 138, 164, 181, 213, 209, 128, 50, 98, 29, 117, 112, 175, 69, 253, 80, 125, 115, 176, 26, 160, 250, 235, 121, 234, 50, 72, 154, 42, 167, 164, 213, 169, 77, 185, 230, 80, 205, 163, 101, 32, 31, 82, 215, 89, 21, 205, 187, 31, 104, 78, 145, 242, 28, 63, 17, 100, 236, 11, 85, 67, 143, 141, 135, 131, 181, 71, 135, 202, 97, 245, 126, 28, 63, 149, 117, 93, 252, 19, 27, 242, 10, 50, 251, 123, 139, 137, 72, 28, 247, 119, 242, 78, 128, 62, 118, 235, 93, 208, 15, 8, 183, 83, 106, 195, 201, 7, 158, 96, 144, 116, 109, 216, 128, 77, 100, 174, 204, 190, 48, 59, 90, 251, 150, 184, 90, 128, 148, 132, 17, 156, 180, 115, 84, 49, 224, 212, 47, 250, 58, 157, 41, 2, 54, 127, 64, 129, 73, 0, 14, 230, 65, 118, 53, 24, 212, 85, 141, 67, 139, 110, 122, 195, 157, 160, 36, 102, 107, 83, 137, 99, 125, 69, 40, 244, 238, 54, 160, 7, 170, 194, 223, 194, 217, 107, 42, 185, 240, 46, 160, 74, 112, 62, 163, 226, 35, 80, 175, 120, 90, 224, 182, 228, 166, 248, 121, 186, 173, 206, 234, 140, 147, 7, 86, 120, 182, 174, 137, 85, 154, 196, 118, 209, 225, 150, 254, 121, 149, 52, 177, 68, 156, 103, 193, 41, 33, 5, 223, 80, 205, 52, 80, 142, 175, 38, 222, 195, 115, 49, 98, 146, 27, 130, 105, 59, 205, 217, 203, 94, 217, 139, 203, 46, 155, 64, 242, 184, 204, 34, 177, 187, 173, 186, 182, 5, 5, 0, 99, 221, 99, 110, 87, 218, 54, 24, 171, 84, 164, 210, 226, 34, 145, 238, 235, 101, 144, 213, 27, 8, 176, 120, 113, 127, 49, 116, 120, 10, 231, 39, 80, 254, 155, 172, 13, 70, 155, 40, 108, 146, 167, 167, 253, 92, 203, 102, 251, 185, 132, 24, 123, 59, 23, 97, 51, 215, 194, 231, 86, 81, 95, 69, 215, 201, 253, 207, 198, 233, 194, 202, 123, 104, 48, 225, 160, 106, 67, 234, 47, 117, 133, 200, 145, 48, 180, 70, 27, 84, 43, 20, 92, 75, 33, 27, 10, 169, 95, 186, 193, 220, 185, 179, 62, 168, 86, 245, 77, 176, 206, 31, 225, 63, 231, 121, 209, 141, 146, 169, 17, 151, 146, 184, 74, 125, 83, 61, 98, 1, 128, 189, 37, 166, 140, 23, 240, 118, 62, 162, 182, 202, 50, 245, 63, 58, 84, 254, 102, 200, 46, 201, 132, 49, 239, 125, 114, 209, 126, 181, 59, 29, 1, 113, 178, 54, 177, 57, 156, 0, 197, 180, 78, 114, 87, 203, 98, 223, 123, 136, 163, 161, 87, 212, 181, 158, 5, 248, 88, 4, 125, 99, 167, 96, 180, 201, 28, 145, 152, 21, 89, 238, 141, 27, 184, 158, 23, 196, 242, 53, 40, 253, 29, 131, 214, 36, 30, 54, 14, 111, 40, 50, 22, 226, 49, 106, 25, 149, 48, 16, 115, 88, 186, 114, 91, 93, 11, 244, 162, 5, 145, 93, 75, 129, 225, 99, 8, 251, 54, 126, 246, 160, 225, 34, 161, 166, 120, 251, 159, 96, 230, 7, 84, 190, 168, 200, 78, 57, 228, 129, 249, 199, 226, 75, 208, 6, 228, 15, 89, 49, 136, 231, 140, 94, 18, 222, 223, 26, 237, 142, 226, 237, 246, 191, 61, 167, 168, 238, 117, 56, 209, 116, 124, 106, 146, 176, 128, 171, 190, 154, 201, 248, 231, 143, 122, 152, 63, 236, 222, 190, 105, 221, 43, 81, 102, 110, 174, 163, 130, 214, 168, 126, 244, 155, 125, 119, 40, 100, 172, 247, 119, 157, 144, 142, 207, 5, 209, 237, 157, 73, 43, 217, 13, 38, 201, 160, 81, 39, 17, 50, 175, 51, 38, 55, 92, 197, 144, 113, 77, 196, 243, 66, 205, 100, 141, 47, 233, 225, 7, 177, 166, 57, 162, 137, 65, 101, 227, 158, 251, 62, 62, 161, 174, 233, 123, 80, 100, 140, 71, 122, 254, 122, 140, 219, 112, 98, 71, 227, 240, 206, 86, 1, 250, 56, 43, 232, 108, 186, 2, 125, 39, 45, 213, 92, 15, 100, 245, 246, 118, 142, 71, 77, 134, 213, 175, 212, 218, 149, 96, 58, 197, 25, 231, 41, 172, 95, 195, 132, 221, 134, 27, 228, 69, 251, 242, 165, 101, 200, 42, 107, 51, 217, 253, 75, 100, 157, 251, 70, 86, 109, 98, 107, 208, 17, 244, 73, 149, 103, 223, 3, 189, 62, 50, 201, 220, 116, 246, 23, 82, 121, 188, 245, 195, 131, 125, 246, 132, 25, 163, 131, 21, 117, 151, 153, 163, 138, 171, 79, 2, 14, 188, 38, 206, 255, 91, 213, 202, 34, 237, 230, 50, 37, 178, 120, 55, 244, 234, 139, 59, 205, 104, 17, 123, 226, 233, 67, 17, 67, 94, 64, 221, 177, 46, 167, 31, 22, 204, 190, 35, 47, 67, 157, 18, 161, 72, 102, 62, 230, 254, 114, 79, 128, 226, 47, 212, 119, 143, 163, 212, 219, 83, 5, 252, 128, 212, 110, 26, 195, 194, 67, 188, 255, 60, 205, 120, 21, 164, 47, 152, 71, 80, 69, 132, 142, 24, 187, 133, 24, 134, 118, 228, 142, 30, 49, 33, 194, 29, 23, 221, 163, 66, 127, 74, 1, 97, 209, 183, 134, 139, 218, 229, 100, 79, 226, 59, 183, 139, 179, 168, 75, 94, 136, 23, 170, 214, 52, 150, 160, 25, 44, 178, 105, 69, 225, 175, 192, 2, 58, 144, 85, 187, 134, 127, 56, 249, 227, 138, 10, 5, 5, 48, 65, 186, 111, 46, 197, 108, 132, 100, 81, 123, 55, 253, 119, 171, 119, 23, 175, 103, 104, 198, 158, 73, 0, 154, 21, 214, 209, 237, 15, 130, 192, 139, 59, 226, 154, 226, 122, 4, 136, 126, 202, 149, 163, 164, 76, 233, 220, 156, 225, 193, 173, 69, 238, 50, 123, 26, 8, 62, 162, 233, 145, 85, 246, 219, 219, 31, 214, 115, 8, 90, 90, 186, 113, 219, 121, 84, 82, 221, 241, 5, 173, 83, 115, 77, 241, 177, 45, 96, 30, 115, 27, 78, 133, 66, 176, 232, 196, 11, 41, 94, 45, 65, 238, 2, 57, 145, 37, 36, 156, 204, 141, 228, 180, 111, 187, 229, 45, 35, 184, 131, 34, 45, 138, 33, 103, 227, 171, 237, 191, 0, 231, 2, 18, 40, 218, 150, 115, 213, 127, 221, 229, 107, 183, 195, 4, 39, 3, 179, 227, 83, 60, 127, 85, 61, 89, 42, 2, 26, 140, 188, 146, 72, 49, 35, 75, 171, 148, 210, 112, 10, 148, 68, 59, 16, 157, 196, 111, 21, 11, 121, 58, 142, 53, 38, 40, 9, 187, 47, 194, 113, 177, 72, 209, 117, 37, 191, 124, 78, 109, 98, 239, 252, 74, 98, 208, 225, 148, 243, 145, 166, 55, 91, 152, 211, 183, 224, 205, 49, 211, 13, 155, 236, 110, 190, 200, 181, 40, 117, 38, 107, 178, 252, 172, 49, 68, 132, 177, 226, 99, 4, 54, 176, 59, 219, 70, 207, 255, 172, 215, 96, 181, 71, 11, 92, 210, 120, 24, 61, 193, 28, 201, 175, 149, 211, 131, 139, 13, 131, 85, 42, 251, 182, 170, 34, 48, 122, 172, 57, 0, 255, 123, 213, 151, 210, 237, 98, 126, 210, 132, 159, 213, 56, 187, 217, 0, 147, 242, 61, 241, 9, 203, 213, 41, 213, 91, 5, 223, 196, 125, 224, 236, 178, 18, 72, 180, 149, 233, 61, 107, 212, 236, 50, 139, 242, 80, 197, 222, 96, 113, 5, 81, 156, 231, 126, 161, 210, 126, 157, 92, 31, 232, 91, 147, 79, 222, 71, 213, 67, 7, 137, 197, 194, 163, 180, 21, 167, 22, 18, 223, 8, 69, 164, 45, 67, 8, 120, 223, 246, 204, 40, 45, 101, 92, 29, 171, 102, 105, 214, 115, 29, 3, 207, 15, 157, 240, 233, 150, 187, 239, 74, 253, 250, 211, 88, 177, 147, 76, 5, 138, 174, 59, 192, 58, 228, 60, 239, 185, 49, 139, 3, 50, 59, 242, 213, 148, 123, 142, 162, 136, 17, 74, 107, 157, 230, 218, 219, 191, 45, 252, 23, 37, 102, 252, 132, 78, 209, 20, 142, 12, 68, 38, 238, 229, 144, 46, 90, 27, 42, 82, 84, 105, 43, 246, 199, 233, 18, 80, 231, 28, 131, 164, 53, 104, 174, 22, 247, 27, 133, 223, 50, 12, 252, 125, 88, 177, 180, 129, 109, 31, 213, 95, 93, 114, 224, 229, 58, 29, 25, 125, 56, 252, 77, 192, 254, 34, 11, 50, 218, 197, 188, 192, 244, 173, 107, 5, 150, 231, 140, 74, 64, 113, 187, 230, 191, 134, 78, 81, 184, 74, 40, 251, 14, 0, 152, 71, 41, 97, 173, 130, 23, 178, 135, 253, 44, 85, 98, 62, 206, 119, 98, 164, 56, 4, 127, 134, 11, 238, 147, 245, 244, 84, 88, 116, 196, 145, 97, 213, 182, 239, 192, 18, 138, 201, 72, 220, 101, 203, 40, 93, 39, 35, 201, 87, 5, 229, 176, 34, 54, 25, 58, 123, 182, 3, 242, 36, 40, 168, 189, 201, 95, 159, 236, 163, 215, 203, 69, 10, 110, 215, 197, 34, 105, 51, 192, 169, 227, 248, 155, 241, 221, 232, 142, 121, 136, 105, 144, 236, 28, 180, 47, 130, 194, 236, 184, 194, 82, 76, 5, 193, 123, 81, 80, 5, 60, 231, 140, 234, 95, 214, 65, 158, 4, 19, 30, 29, 62, 33, 233, 130, 161, 42, 179, 244, 154, 125, 80, 9, 233, 53, 81, 38, 238, 180, 1, 191, 157, 221, 232, 64, 148, 68, 243, 249, 188, 65, 156, 234, 81, 208, 39, 18, 98, 47, 218, 5, 100, 169, 86, 56, 214, 167, 19, 194, 149, 210, 157, 100, 51, 161, 146, 22, 220, 98, 243, 220, 39, 111, 31, 163, 243, 206, 151, 131, 75, 89, 37, 243, 1, 205, 158, 31, 185, 99, 230, 243, 92, 23, 186, 219, 69, 39, 78, 112, 183, 226, 249, 9, 49, 72, 50, 62, 232, 54, 75, 249, 160, 82, 70, 212, 52, 150, 238, 180, 174, 159, 204, 236, 52, 120, 232, 198, 247, 58, 252, 80, 154, 35, 182, 62, 91, 212, 61, 152, 127, 84, 111, 111, 239, 75, 101, 120, 223, 247, 108, 245, 12, 227, 134, 235, 230, 207, 12, 118, 249, 74, 19, 19, 32, 124, 206, 5, 244, 180, 166, 143, 226, 63, 191, 112, 245, 106, 151, 116, 73, 89, 139, 208, 203, 108, 153, 5, 252, 26, 185, 62, 170, 35, 229, 180, 228, 50, 241, 53, 160, 186, 222, 139, 183, 111, 155, 74, 176, 241, 15, 40, 99, 245, 15, 71, 48, 80, 207, 143, 42, 103, 70, 48, 213, 30, 72, 42, 58, 59, 136, 175, 109, 22, 137, 44, 92, 48, 70, 94, 17, 177, 7, 83, 210, 118, 240, 9, 6, 3, 30, 99, 32, 149, 245, 115, 246, 77, 42, 223, 178, 89, 70, 113, 75, 155, 53, 52, 89, 211, 30, 2, 220, 5, 232, 39, 210, 37, 188, 30, 220, 56, 76, 174, 139, 252, 148, 111, 4, 142, 126, 63, 205, 58, 132, 216, 146, 142, 193, 43, 107, 153, 149, 4, 34, 232, 87, 103, 92, 26, 122, 98, 141, 149, 19, 66, 106, 128, 40, 103, 239, 239, 41, 201, 34, 74, 187, 145, 254, 211, 67, 90, 135, 70, 127, 59, 233, 80, 124, 154, 153, 154, 239, 96, 100, 173, 139, 234, 50, 192, 167, 163, 30, 200, 168, 216, 21, 148, 138, 158, 147, 151, 213, 31, 137, 43, 235, 112, 117, 246, 59, 89, 194, 215, 155, 28, 14, 227, 150, 86, 213, 148, 33, 29, 81, 135, 87, 132, 166, 142, 156, 107, 69, 200, 72, 68, 152, 51, 244, 78, 114, 20, 201, 66, 138, 50, 9, 152, 212, 112, 171, 111, 95, 129, 120, 174, 232, 113, 199, 169, 87, 27, 176, 185, 180, 106, 23, 149, 33, 251, 56, 51, 210, 197, 28, 208, 112, 2, 96, 224, 121, 79, 48, 75, 42, 20, 110, 141, 133, 178, 35, 191, 125, 11, 185, 137, 3, 161, 120, 175, 0, 58, 238, 61, 12, 248, 108, 76, 111, 239, 136, 235, 234, 72, 157, 233, 205, 182, 147, 91, 37, 250, 58, 105, 38, 110, 32, 162, 147, 243, 194, 190, 49, 237, 46, 63, 53, 191, 7, 145, 52, 78, 154, 15, 148, 167, 142, 174, 19, 236, 216, 226, 87, 251, 145, 219, 85, 241, 133, 69, 150, 224, 154, 254, 237, 59, 105, 82, 207, 50, 187, 172, 179, 173, 139, 71, 107, 37, 30, 166, 171, 164, 58, 11, 102, 13, 195, 130, 135, 104, 138, 161, 149, 67, 147, 219, 190, 191, 207, 159, 157, 225, 201, 226, 178, 118, 242, 92, 57, 60, 186, 51, 61, 120, 204, 24, 103, 17, 191, 93, 98, 194, 221, 123, 157, 248, 238, 94, 184, 252, 24, 235, 161, 78, 225, 109, 188, 198, 67, 226, 152, 18, 205, 167, 160, 242, 235, 124, 98, 188, 84, 52, 93, 30, 2, 134, 31, 139, 15, 105, 26, 88, 82, 35, 186, 13, 23, 248, 249, 41, 68, 115, 117, 14, 238, 93, 138, 9, 182, 35, 19, 39, 193, 37, 111, 188, 117, 213, 93, 245, 193, 13, 133, 14, 199, 146, 209, 107, 128, 114, 5, 71, 9, 208, 221, 153, 120, 53, 213, 160, 114, 147, 208, 237, 171, 156, 166, 203, 99, 8, 146, 178, 53, 31, 66, 243, 116, 143, 131, 88, 104, 255, 149, 72, 253, 145, 140, 140, 162, 246, 205, 190, 116, 93, 56, 184, 86, 30, 165, 87, 161, 54, 70, 138, 207, 159, 122, 25, 67, 179, 227, 159, 32, 243, 217, 225, 103, 122, 84, 207, 196, 179, 103, 153, 74, 232, 177, 174, 144, 70, 193, 40, 150, 177, 157, 235, 184, 178, 12, 140, 80, 149, 82, 179, 137, 30, 59, 169, 134, 25, 67, 78, 48, 4, 2, 92, 224, 106, 111, 200, 54, 240, 120, 69, 95, 109, 197, 22, 128, 61, 246, 24, 239, 104, 55, 235, 199, 216, 68, 64, 226, 146, 184, 1, 254, 24, 193, 152, 175, 25, 131, 174, 154, 72, 93, 156, 152, 113, 34, 135, 210, 38, 128, 144, 136, 28, 179, 207, 206, 92, 174, 205, 11, 240, 127, 225, 117, 30, 90, 104, 195, 208, 188, 168, 25, 231, 58, 92, 239, 108, 224, 230, 186, 116, 88, 175, 68, 8, 215, 194, 30, 255, 187, 189, 57, 36, 181, 151, 165, 67, 131, 136, 77, 171, 108, 3, 92, 16, 65, 31, 194, 29, 6, 183, 111, 71, 126, 220, 109, 205, 196, 82, 193, 182, 69, 237, 189, 54, 187, 250, 52, 189, 10, 175, 152, 250, 92, 213, 122, 236, 71, 153, 82, 250, 159, 238, 153, 109, 56, 34, 99, 13, 108, 39, 193, 99, 227, 181, 182, 76, 3, 202, 112, 35, 122, 71, 9, 168, 43, 224, 31, 168, 252, 2, 189, 95, 150, 100, 212, 122, 172, 29, 240, 128, 181, 222, 63, 233, 123, 16, 54, 104, 8, 7, 17, 67, 177, 221, 245, 31, 228, 77, 175, 70, 253, 224, 90, 188, 95, 138, 114, 192, 88, 120, 25, 245, 85, 49, 103, 168, 111, 243, 43, 77, 234, 80, 174, 51, 162, 177, 129, 128, 66, 184, 231, 28, 76, 75, 128, 215, 132, 91, 51, 201, 202, 101, 185, 138, 233, 11, 164, 198, 67, 8, 141, 18, 78, 191, 56, 169, 156, 145, 81, 13, 118, 10, 111, 93, 235, 129, 249, 218, 102, 186, 33, 125, 155, 231, 178, 109, 213, 5, 69, 144, 22, 60, 170, 13, 167, 79, 133, 159, 193, 132, 31, 72, 21, 98, 180, 203, 42, 113, 11, 94, 88, 134, 14, 248, 241, 187, 179, 206, 66, 32, 59, 97, 28, 224, 154, 141, 63, 247, 4, 122, 72, 184, 153, 26, 35, 97, 72, 15, 38, 146, 227, 210, 213, 154, 29, 176, 213, 199, 69, 84, 87, 198, 197, 224, 209, 219, 232, 4, 78, 49, 234, 101, 151, 103, 116, 76, 248, 114, 219, 121, 113, 10, 253, 166, 189, 116, 222, 111, 136, 31, 228, 17, 163, 0, 251, 79, 101, 56, 255, 162, 119, 56, 52, 120, 78, 179, 99, 38, 91, 246, 87, 201, 159, 152, 122, 94, 47, 110, 203, 200, 250, 99, 9, 172, 241, 11, 195, 231, 177, 73, 250, 221, 22, 173, 39, 38, 112, 212, 31, 61, 97, 206, 203, 168, 175, 253, 161, 189, 135, 204, 75, 56, 65, 107, 240, 239, 158, 180, 155, 254, 171, 213, 115, 94, 105, 96, 63, 162, 43, 34, 135, 20, 255, 183, 35, 18, 9, 210, 230, 214, 185, 23, 134, 137, 205, 183, 208, 118, 1, 84, 200, 204, 130, 143, 241, 2, 38, 63, 240, 71, 173, 119, 163, 168, 81, 47, 118, 243, 253, 33, 252, 79, 214, 138, 135, 148, 201, 178, 153, 94, 182, 236, 232, 185, 206, 53, 137 };

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

	result = test_hybrid_compact_dilithium_sphincs_seed_expander();
	if (result != 0) {
		return result;
	}

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

