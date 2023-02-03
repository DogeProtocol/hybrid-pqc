#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include "../random/randombytes.h"
#include "../hybrid/hybrid.h"
#include "../falcon512/api.h"

clock_t get_nano_sec(void);
void print_elapsed(long startTime, long endTime);
int test_falcon(void);
int test_hybrid(void);
int test_multiple(int count);
int main(int argc, char* argv[]);

const unsigned long long ED25519_PUBLICKEY_BYTES = 32UL;
const unsigned long long FALCON_PUBLICKEY_BYTES = 897UL;
const unsigned long long HYBRID_PUBLICKEY_BYTES = 897UL + 32UL;

clock_t get_nano_sec(void) {
	return clock();
}

void print_elapsed(clock_t startTime, clock_t endTime) {
	clock_t elapsed = endTime - startTime;
	double time_taken = ((double)elapsed) / CLOCKS_PER_SEC; // in seconds
	printf("\n elapsed = %f seconds", time_taken);
}

int test_falcon() {
	printf("\n test_falcon() start");

	unsigned char pk[897];
	unsigned char sk[1281 + 897];
	unsigned char sig[690 + 40 + 2 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned long long sigLen = 0;

	int r1 = crypto_sign_falcon_keypair(pk, sk);
	if (r1 != 0) {
		printf("\n crypto_sign_falcon_keypair failed %d", (int)r1);
		return r1;
	}

	int r2 = randombytes(msg1, 32 * sizeof(unsigned char));
	if (r2 != 0) {
		printf("\n randombytes failed %d", (int)r2);
		return r2;
	}
	for (int i = 0;i < 32;i++) {
		msg2[1] = msg1[i];
	}

	int r3 = crypto_sign_falcon(sig, &sigLen, msg1, 32, sk);
	if (r3 != 0) {
		printf("\n crypto_sign_falcon failed %d", (int)r3);
		return r3;
	}

	printf("\n falcon sigLen = %d", (int) sigLen);

	unsigned long long msgLen = 0;
	int r4 = crypto_sign_falcon_open(msg2, &msgLen, sig, sigLen, pk);
	if (r4 != 0) {
		printf("\n crypto_sign_falcon_open failed %d", (int)r4);
		return r4;
	}
	if (msgLen != 32) {
		printf("\n crypto_sign_falcon_open msg check failed %d", (int)msgLen);
		return -5;
	}

	for (int i = 0;i < 32;i++) {
		if (msg1[i] != msg2[i]) {
			printf("\n verify msg content failed %d", i);
			return -6;
		}
	}

	printf("\n test_falcon() ok");

	return 0;
}

int test_hybrid_perf(int count) {
	unsigned char pk[32 + 897];
	unsigned char sk[64 + 1281 + 897];
	unsigned char msg[32];
	unsigned char sig[2 + 2 + 64 + 690 + 40 + 32];
	unsigned long long sigLen = 0;
	const int MSG_LEN = 32;
	unsigned char msgOutput[32];
	unsigned long long msgOutputLen = 0;
	clock_t startTime;
	clock_t endTime;
	int r = 0;

	printf("\n Hybrid Generate KeyPair Perf Test for %d iterations", count);
	startTime = get_nano_sec();
	for (int i = 0;i < count;i++) {
		r = crypto_sign_falcon_ed25519_keypair(pk, sk);
		if (r != 0) {
			printf("\n crypto_sign_falcon_ed25519_keypair failed %d", (int)r);
			return -1;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	r = randombytes(msg, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -2;
	}

	printf("\n Hybrid Sign Perf Test for %d iterations", count);
	startTime = get_nano_sec();
	for (int i = 0;i < count;i++) {
		r = crypto_sign_falcon_ed25519(sig, &sigLen, msg, MSG_LEN, sk);
		if (r != 0) {
			printf("\n crypto_sign_falcon_ed25519 failed %d iteration %d", (int)r, i);
			return -3;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	r = crypto_sign_falcon_ed25519(sig, &sigLen, msg, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519 failed %d", (int)r);
		return -4;
	}

	printf("\n Hybrid SignOpen Perf Test for %d iterations", count);
	startTime = get_nano_sec();
	for (int i = 0;i < count;i++) {
		r = crypto_sign_falcon_ed25519_open(msgOutput, &msgOutputLen, sig, sigLen, pk);
		if (r != 0) {
			printf("\n crypto_sign_falcon_ed25519_open failed %d", (int)r);
			return -5;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	printf("\n Hybrid Verify Perf Test for %d iterations", count);
	startTime = get_nano_sec();
	for (int i = 0;i < count;i++) {
		r = crypto_verify_falcon_ed25519(msg, MSG_LEN, sig, sigLen, pk);
		if (r != 0) {
			printf("\n crypto_verify_falcon_ed25519 failed %d", (int)r);
			return -6;
		}
	}
	endTime = get_nano_sec();
	print_elapsed(startTime, endTime);

	return 0;
}

int test_hybrid() {
	printf("\n test_hybrid() start");

	unsigned char pk[32 + 897];
	unsigned char sk[64 + 1281 + 897];
	unsigned char sig1[2 + 2 + 64 + 690 + 40 + 32];
	unsigned char sig2[2 + 2 + 64 + 690 + 40 + 32];
	unsigned char msg1[32];
	unsigned char msg2[32];
	unsigned char msg1output[32];
	unsigned char msg2output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;

	int r = crypto_sign_falcon_ed25519_keypair(pk, sk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_keypair failed %d", (int)r);
		return -1;
	}

	r = randombytes(msg1, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -2;
	}

	r = crypto_sign_falcon_ed25519(sig1, &sigLen1, msg1, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519 failed %d", (int)r);
		return -3;
	}

	if (sigLen1 != 830) {
		printf("\n crypto_sign_falcon_ed25519 sigLen error %d", (int)sigLen1);
		return -4;
	}

	r = crypto_sign_falcon_ed25519_open(msg1output, &msgLen1, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_open failed %d", (int)r);
		return -5;
	}

	if (msgLen1 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen1);
		return -6;
	}

	for (int i = 0;i < MSG_LEN;i++) {
		if (msg1[i] != msg1output[i]) {
			printf("\n verify msg content failed %d", i);
			return -7;
		}
	}

	r = crypto_verify_falcon_ed25519(msg1, MSG_LEN, sig1, sigLen1, pk);
	if (r != 0) {
		printf("\n crypto_verify_falcon_ed25519 failed %d", (int)r);
		return -8;
	}

	r = randombytes(msg2, MSG_LEN * sizeof(unsigned char));
	if (r != 0) {
		printf("\n randombytes failed %d", (int)r);
		return -9;
	}

	r = crypto_sign_falcon_ed25519(sig2, &sigLen2, msg2, MSG_LEN, sk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519 failed %d", (int)r);
		return -10;
	}

	if (sigLen2 != 830) {
		printf("\n crypto_sign_falcon_ed25519 sigLen error %d", (int)sigLen2);
		return -11;
	}

	//sanity check
	r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_open failed %d", (int)r);
		return -12;
	}

	if (msgLen2 != MSG_LEN) {
		printf("\n verify msglen failed expected %d got %d", MSG_LEN, (int)msgLen2);
		return -13;
	}

	for (int i = 0;i < MSG_LEN;i++) {
		if (msg2[i] != msg2output[i]) {
			printf("\n verify msg content failed %d", i);
			return -14;
		}
	}

	r = crypto_verify_falcon_ed25519(msg2, MSG_LEN, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_verify_falcon_ed25519 failed %d", (int)r);
		return -15;
	}

	//invalid message test
	sig2[69] = sig2[69] + 1; //first byte of message in ed25519 signature
	r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r == 0) {
		printf("\n crypto_sign_falcon_ed25519_open was ok when it should have failed %d", (int)r);
		return -16;
	}

	sig2[69] = msg2[1]; //reset
	r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_open failed %d", (int)r);
		return -17;
	}

	sig2[69] = sig2[69] + 1; //first byte of message in ed25519 signature
	r = crypto_verify_falcon_ed25519(msg2output, MSG_LEN, sig2, sigLen2, pk);
	if (r == 0) {
		printf("\n crypto_verify_falcon_ed25519 was ok when it should have failed %d", (int)r);
		return -18;
	}

	sig2[69] = msg2[1]; //reset
	r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_open failed %d", (int)r);
		return -19;
	}

	int totalLen = ((size_t)sig2[0] << 8) | (size_t)sig2[1];
	if (totalLen < 828) {
		sig2[829] = 1; //padding reset check

		r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
		if (r == 0) {
			printf("\n crypto_sign_falcon_ed25519_open was ok when it should have failed %d", (int)r);
			return -20;
		}
	}

	sig2[69] = msg2[1]; //reset
	sig2[143] = sig2[143] + 1;
	r = crypto_sign_falcon_ed25519_open(msg2output, &msgLen2, sig2, sigLen2, pk);
	if (r == 0) {
		printf("\n crypto_sign_falcon_ed25519_open was ok when it should have failed %d", (int)r);
		return -21;
	}

	msg2[0] = msg2[0] + 1;
	r = crypto_verify_falcon_ed25519(msg2, MSG_LEN, sig2, sigLen2, pk);
	if (r == 0) {
		printf("\n crypto_sign_falcon_ed25519_open was ok when it should have failed %d", (int)r);
		return -22;
	}


	//todo add fuzz tests

	printf(" \n test_hybrid() ok");

	return 0;
}

int test_multiple(int count) {
	printf("\n test_multiple hybrid %d", count);
	for (int i = 0;i < count;i++) {
		int r = test_hybrid();
		if (r != 0) {
			return 2;
		}
	}
	return 0;
}

int main(int argc, char* argv[]) {
	int r0 = test_falcon();
	if (r0 != 0) {
		return r0;
	}

	int r1 = test_hybrid();
	if (r1 != 0) {
		return r1;
	}

	int count = 10;
	int r3 = test_multiple(count);
	if (r3 != 0) {
		return r3;
	}

	int perfCount = 1000;
	if (argc > 1) {
		perfCount = atoi(argv[1]);
	}
	test_hybrid_perf(perfCount);
	printf("\n Warning, perf tests uses approximate system clock. Is not suitable for fewer iterations of test.");

	printf(" \n test suite completed!");

	return 0;
}

