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
	unsigned char sk[1281];
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

	printf("\n deterministic key generation test");
	unsigned char seed1[48];
	if (randombytes(seed1, sizeof seed1) != 0) {
		return -7;
	}

	unsigned char pk2[897];
	unsigned char sk2[1281];
	int r5 = crypto_sign_falcon_keypair_seed(pk2, sk2, seed1, sizeof seed1);
	if (r5 != 0) {
		printf("\n crypto_sign_falcon_keypair_seed failed %d", (int)r5);
		return r5;
	}

	for (int j = 0; j < 32; j++) {
		unsigned char pk3[897];
		unsigned char sk3[1281];
		int r6 = crypto_sign_falcon_keypair_seed(pk3, sk3, seed1, sizeof seed1);
		if (r6 != 0) {
			printf("\n crypto_sign_falcon_keypair_seed failed %d", (int)r6);
			return r6;
		}
		for (int i = 0; i < 897; i++) {
			if (pk2[i] != pk3[i]) {
				printf("\n determienistic key generation failed: pk");
				return -8;
			}
		}
		for (int i = 0; i < 1281; i++) {
			if (sk2[i] != sk3[i]) {
				printf("\n determienistic key generation failed: sk %d, %d, %d", i, sk2[i], sk3[i]);
				return -9;
			}
		}

		int r = crypto_sign_falcon(sig, &sigLen, msg1, 32, sk3);
		if (r != 0) {
			printf("\n crypto_sign_falcon failed %d", (int)r);
			return r;
		}

		unsigned long long msgLen = 0;
		r = crypto_sign_falcon_open(msg2, &msgLen, sig, sigLen, pk3);
		if (r != 0) {
			printf("\n crypto_sign_falcon_open failed %d", (int)r);
			return r;
		}
		if (msgLen != 32) {
			printf("\n crypto_sign_falcon_open msg check failed %d", (int)msgLen);
			return -5;
		}

		for (int i = 0; i < 32; i++) {
			if (msg1[i] != msg2[i]) {
				printf("\n verify msg content failed %d", i);
				return -6;
			}
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
	for (int i = 0;i < 1000;i++) {
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
	unsigned char pk2[32 + 897];
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

	r = crypto_public_key_from_private_key_falcon_ed25519(pk2, sk);
	if (r != 0) {
		printf("\n crypto_public_key_from_private_key_falcon_ed25519 A failed %d", (int)r);
		return -23;
	}

	const int ed25519PublicKeyLastByteIndex = 64 - 1;
	unsigned char temp = sk[ed25519PublicKeyLastByteIndex]; //Last byte of ed25519 public key
	sk[ed25519PublicKeyLastByteIndex] = sk[ed25519PublicKeyLastByteIndex] + 1; //Flip it
	r = crypto_public_key_from_private_key_falcon_ed25519(pk2, sk);
	if (r == 0) {
		printf("\n crypto_public_key_from_private_key_falcon_ed25519 B was ok whe it should have failed %d", (int)r);
		return -24;
	}
	sk[ed25519PublicKeyLastByteIndex] = temp;

	r = crypto_public_key_from_private_key_falcon_ed25519(pk2, sk);
	if (r != 0) {
		printf("\n crypto_public_key_from_private_key_falcon_ed25519 C failed %d", (int)r);
		return -25;
	}

	const int falconPublicKeyLastByteIndex = 2242 - 1;
	temp = sk[falconPublicKeyLastByteIndex]; //Last byte of Falcon public key
	sk[falconPublicKeyLastByteIndex] = sk[falconPublicKeyLastByteIndex] + 1; //Flip it
	r = crypto_public_key_from_private_key_falcon_ed25519(pk2, sk);
	if (r == 0) {
		printf("\n crypto_public_key_from_private_key_falcon_ed25519 D was ok whe it should have failed %d", (int)r);
		return -26;
	}


	//todo add fuzz tests

	printf(" \n test_hybrid() ok");

	return 0;
}

int test_hybrid_deterministic() {
	printf("\n test_hybrid_deterministic() start");

	unsigned char pk[32 + 897];
	unsigned char pk2[32 + 897];
	unsigned char pk3[32 + 897];
	unsigned char sk[64 + 1281 + 897];
	unsigned char sk2[64 + 1281 + 897];
	unsigned char sk3[64 + 1281 + 897];
	unsigned char sig1[2 + 2 + 64 + 690 + 40 + 32];
	unsigned char msg1[32];
	unsigned char msg1output[32];
	unsigned long long sigLen1 = 0;
	unsigned long long sigLen2 = 0;
	unsigned long long msgLen1 = 0;
	unsigned long long msgLen2 = 0;
	const int MSG_LEN = 32;


	unsigned char seed1[80] = { 129,111,254,208,138,196,60,45,101,134,78,177,227,76,82,203,26,114,241,89,26,205,174,187,167,219,156,51,195,197,228,27,119,175,131,115,192,42,246,9,171,117,239,88,235,16,133,230,150,206,59,220,176,144,178,248,188,213,239,142,236,15,177,197,137,102,89,245,200,217,106,31,202,87,135,65,174,105,114,121 };

	unsigned char seed3[80];
	if (randombytes(seed3, sizeof seed3) != 0) {
		return -7;
	}

	int r = crypto_sign_falcon_ed25519_keypair_seed(pk, sk, seed1);
	if (r != 0) {
		printf("\n crypto_sign_falcon_ed25519_keypair_seed failed %d", (int)r);
		return -1;
	}

	/*
	printf("\n pk \n");
	for (int k = 0; k < 32 + 897; k++) {
		printf("%d,", pk[k]);
	}
	printf("\n sk \n");
	for (int k = 0; k < 64 + 1281 + 897; k++) {
		printf("%d,", sk[k]);
	}*/

	unsigned char pkFromSeed[32 + 897] = { 240,78,219,55,229,129,35,19,238,250,42,184,21,246,140,49,133,117,234,93,254,183,215,211,206,92,25,21,105,115,247,115,9,11,180,165,200,211,164,6,151,182,191,67,68,7,122,132,234,249,49,182,217,160,38,186,131,9,236,13,43,31,188,16,212,23,41,231,23,132,25,230,75,220,131,155,152,211,105,178,132,118,44,113,2,203,166,237,10,162,204,119,183,100,136,176,150,69,139,199,213,165,156,53,98,231,16,173,159,244,168,94,0,128,90,224,31,68,162,77,218,87,214,9,40,245,196,144,228,82,90,68,109,201,216,211,34,134,42,133,222,98,125,108,219,141,236,181,171,26,35,246,86,248,159,218,204,140,81,64,88,93,41,46,78,67,174,100,128,71,6,140,106,181,18,53,69,145,151,43,171,194,129,245,34,77,135,168,38,211,118,100,19,130,17,96,23,86,116,45,44,37,226,194,135,218,227,133,63,82,158,91,106,29,106,48,100,80,210,42,163,97,188,142,114,134,105,136,242,69,10,114,128,209,237,181,45,158,129,101,96,234,149,171,42,147,231,172,99,197,149,6,92,130,194,192,111,131,12,81,98,116,173,34,128,213,207,19,214,232,190,161,10,78,153,206,165,136,188,214,156,133,216,88,28,158,225,42,212,197,16,44,60,184,11,150,47,70,31,102,128,183,80,121,218,185,12,173,77,180,227,136,144,105,9,247,166,197,80,58,180,41,222,201,237,7,82,25,245,112,215,250,25,104,92,57,61,18,244,25,168,93,192,19,241,166,44,154,32,132,185,240,234,17,237,84,78,79,73,24,141,15,110,209,156,128,143,132,23,89,92,185,146,207,238,90,186,0,19,250,27,154,3,137,26,237,212,99,229,31,154,101,65,208,193,209,87,118,102,98,219,175,16,80,87,188,220,56,17,207,153,116,122,147,117,100,216,209,171,14,215,112,179,218,106,99,93,164,84,220,87,4,99,194,115,228,171,138,225,128,24,136,208,92,149,228,82,189,170,35,87,143,9,110,17,114,103,180,130,169,104,160,79,168,231,18,112,37,224,89,230,151,109,255,38,188,158,192,217,110,84,92,52,211,168,6,173,0,57,212,203,87,130,92,125,188,204,243,208,175,132,120,155,84,229,212,224,137,166,97,170,202,195,177,219,248,49,10,189,211,158,155,15,146,245,163,203,171,130,37,38,238,190,22,52,69,30,75,12,10,209,51,205,13,25,238,20,171,12,76,241,170,78,195,216,46,155,34,108,194,29,96,193,223,140,123,205,224,64,30,147,116,184,229,32,9,152,10,44,80,193,237,42,6,99,28,177,16,134,219,123,227,20,105,200,237,161,171,211,122,83,122,231,138,249,79,144,115,242,163,228,52,141,24,133,238,125,161,39,3,177,25,5,226,164,122,237,60,119,201,180,168,255,23,86,18,29,225,186,25,237,89,80,37,154,55,197,196,139,39,169,0,37,194,24,61,163,193,226,122,178,239,97,90,96,116,72,124,220,155,75,166,32,53,6,108,19,68,212,86,42,164,221,33,61,70,54,5,161,206,79,58,14,227,69,5,111,252,84,138,254,233,208,95,185,51,113,233,83,86,144,31,120,10,103,137,153,228,128,156,168,84,86,126,2,185,137,170,45,119,164,175,98,106,42,0,212,69,77,206,1,102,231,150,42,152,196,32,48,151,181,65,196,174,101,101,88,168,182,107,188,91,244,42,151,124,160,115,63,221,0,165,102,81,247,135,104,217,101,78,9,48,26,17,254,96,245,97,254,27,250,11,195,168,211,224,133,161,223,128,134,25,145,119,197,67,6,206,43,96,114,181,26,184,60,74,69,189,154,210,4,150,162,170,113,222,240,240,103,236,84,79,154,199,104,28,92,3,87,0,234,165,109,86,13,52,70,4,72,189,129,213,44,33,197,147,201,7,187,66,242,92,86,222,7,79,167,144,55,195,158,103,135,46,130,23,134,168,4,197,81,117,49,18,111,168,65,127,41,195,208,58,239,252,66,88,1,117,97,86,197,60,33,47,37,146,143,73,136,234,230,199,162,217,235,132,96,137,193,169,103,82,78,42,77,58,13,218,30 };
	unsigned char skFromSeed[64 + 1281 + 897] = { 129,111,254,208,138,196,60,45,101,134,78,177,227,76,82,203,26,114,241,89,26,205,174,187,167,219,156,51,195,197,228,27,240,78,219,55,229,129,35,19,238,250,42,184,21,246,140,49,133,117,234,93,254,183,215,211,206,92,25,21,105,115,247,115,89,0,48,124,252,0,58,248,30,132,15,207,253,27,176,184,251,239,60,244,14,190,236,79,65,244,31,253,247,224,128,16,48,61,7,241,65,3,191,195,232,48,67,244,30,197,12,65,1,247,242,253,0,16,67,240,15,133,248,128,127,8,32,252,255,242,57,255,254,67,232,64,6,4,128,125,12,0,129,255,208,137,251,254,65,255,126,69,15,208,193,15,240,63,247,239,5,255,240,253,228,81,254,0,63,64,8,64,128,240,48,134,8,14,129,4,79,193,235,223,71,27,226,60,227,239,128,255,242,66,228,46,132,0,143,197,39,192,189,11,241,67,247,240,56,4,15,7,7,142,199,32,64,68,16,0,123,4,64,189,7,241,190,12,31,66,11,223,3,11,255,130,7,96,49,252,32,246,20,31,128,11,221,136,232,46,196,23,161,130,12,64,128,36,16,72,248,49,0,12,17,63,235,240,252,251,192,120,4,32,122,251,206,71,28,31,60,8,95,65,236,0,62,244,0,129,4,49,187,244,63,139,244,78,195,3,241,65,251,223,253,251,255,71,31,144,191,12,47,255,39,239,66,3,208,126,248,30,133,24,0,125,32,15,132,15,223,186,252,30,251,252,15,127,255,161,128,231,191,2,252,15,127,15,240,66,19,224,2,228,47,60,251,208,133,11,193,63,0,32,131,7,176,130,248,0,127,12,192,130,24,0,190,255,176,68,11,224,67,248,15,248,236,78,63,244,176,7,12,113,194,15,240,64,240,15,132,20,31,127,228,1,64,244,1,61,16,46,125,7,241,204,8,78,63,3,241,4,4,47,194,19,205,186,235,191,61,244,49,7,248,15,186,3,128,189,7,190,254,247,223,253,27,191,127,4,65,65,235,225,129,7,208,131,16,16,255,248,1,57,0,32,59,0,79,192,236,0,6,0,64,63,12,46,70,0,78,60,4,49,60,248,48,126,248,80,255,12,127,65,8,30,131,23,241,191,244,160,64,252,16,123,55,207,68,15,208,198,231,239,126,240,16,2,23,194,68,239,112,255,252,1,192,244,48,62,15,224,3,247,161,194,3,176,251,15,240,68,11,193,123,24,190,250,236,16,193,244,129,64,224,15,67,255,175,255,0,80,63,224,109,198,23,223,189,247,255,59,8,31,2,7,129,189,4,31,2,8,112,63,3,192,192,239,241,1,240,46,251,4,31,252,20,46,194,35,191,193,11,223,133,23,175,193,252,46,58,235,162,60,11,144,0,252,78,130,240,79,128,236,126,124,248,17,125,251,241,69,24,80,190,12,31,67,8,128,126,251,192,139,251,143,127,28,81,192,0,32,254,236,15,255,251,241,63,39,192,126,244,15,69,227,255,192,8,65,182,248,96,70,252,32,254,255,158,126,31,253,194,248,47,129,23,192,57,251,206,195,252,17,189,255,110,131,255,127,129,247,191,251,255,205,255,32,81,4,228,15,69,8,16,188,251,224,196,8,16,193,220,63,127,4,81,64,248,1,62,0,15,185,47,208,65,232,96,193,12,64,254,243,176,65,23,255,189,240,79,192,12,80,53,11,208,253,0,96,131,255,208,58,239,176,250,232,16,63,243,207,196,20,80,70,7,177,126,0,30,189,247,240,63,255,175,121,251,206,252,12,143,64,0,33,134,7,239,187,4,48,121,248,111,65,227,208,189,248,113,127,16,15,129,239,208,65,20,143,253,3,190,192,240,17,196,251,255,69,8,31,192,2,255,246,218,14,255,223,8,30,253,206,85,2,247,227,20,6,251,30,8,229,251,16,250,202,28,38,229,38,36,233,27,253,239,16,247,214,31,51,225,210,20,57,10,242,244,222,242,7,255,226,21,25,20,11,28,81,13,241,27,11,1,6,229,227,27,21,225,16,221,2,237,8,218,241,221,213,204,4,5,2,0,29,21,9,248,2,226,247,3,37,226,244,230,24,255,252,25,251,29,253,186,22,31,224,210,241,14,204,237,240,252,7,11,31,248,7,236,8,215,233,248,35,34,215,28,21,9,244,9,6,215,240,246,10,39,64,246,27,242,31,32,8,52,10,232,211,53,28,14,36,89,50,10,232,6,1,22,191,253,14,20,244,48,10,19,21,10,246,245,237,227,202,226,234,243,227,252,252,14,21,255,2,244,29,215,215,228,251,237,4,43,230,254,28,7,232,6,7,247,40,4,14,255,33,10,230,45,21,241,224,229,223,242,11,15,220,245,15,8,253,3,238,184,22,29,234,8,4,249,16,252,254,227,24,229,18,244,29,28,251,220,247,243,45,14,31,237,38,8,3,8,0,234,235,19,252,34,255,40,1,10,4,254,42,2,15,245,224,17,243,26,4,240,246,25,25,23,203,33,3,25,235,230,29,33,19,233,35,252,236,226,1,5,4,250,197,202,227,3,0,223,25,1,225,241,0,234,229,250,24,231,8,249,209,251,191,217,34,15,231,239,190,58,253,20,252,11,7,239,13,22,50,20,4,230,210,9,1,231,241,238,234,42,11,8,13,243,233,241,21,208,21,9,12,2,37,7,11,25,235,232,228,226,243,255,223,29,32,0,23,24,6,1,253,237,8,233,254,229,240,218,235,255,16,254,240,191,239,27,16,18,223,9,1,225,25,239,45,254,237,228,35,33,239,1,223,6,5,245,242,55,21,245,250,237,14,4,236,234,24,250,19,42,239,253,252,39,22,254,245,28,1,22,245,3,247,239,2,233,230,25,3,224,190,238,30,5,255,242,7,246,246,247,251,19,243,5,242,26,228,236,245,6,222,29,4,63,87,15,4,18,199,0,25,245,4,31,251,27,252,32,241,228,34,45,229,240,3,21,12,239,27,245,19,23,25,11,1,237,221,245,253,225,238,7,247,8,246,26,0,249,9,11,180,165,200,211,164,6,151,182,191,67,68,7,122,132,234,249,49,182,217,160,38,186,131,9,236,13,43,31,188,16,212,23,41,231,23,132,25,230,75,220,131,155,152,211,105,178,132,118,44,113,2,203,166,237,10,162,204,119,183,100,136,176,150,69,139,199,213,165,156,53,98,231,16,173,159,244,168,94,0,128,90,224,31,68,162,77,218,87,214,9,40,245,196,144,228,82,90,68,109,201,216,211,34,134,42,133,222,98,125,108,219,141,236,181,171,26,35,246,86,248,159,218,204,140,81,64,88,93,41,46,78,67,174,100,128,71,6,140,106,181,18,53,69,145,151,43,171,194,129,245,34,77,135,168,38,211,118,100,19,130,17,96,23,86,116,45,44,37,226,194,135,218,227,133,63,82,158,91,106,29,106,48,100,80,210,42,163,97,188,142,114,134,105,136,242,69,10,114,128,209,237,181,45,158,129,101,96,234,149,171,42,147,231,172,99,197,149,6,92,130,194,192,111,131,12,81,98,116,173,34,128,213,207,19,214,232,190,161,10,78,153,206,165,136,188,214,156,133,216,88,28,158,225,42,212,197,16,44,60,184,11,150,47,70,31,102,128,183,80,121,218,185,12,173,77,180,227,136,144,105,9,247,166,197,80,58,180,41,222,201,237,7,82,25,245,112,215,250,25,104,92,57,61,18,244,25,168,93,192,19,241,166,44,154,32,132,185,240,234,17,237,84,78,79,73,24,141,15,110,209,156,128,143,132,23,89,92,185,146,207,238,90,186,0,19,250,27,154,3,137,26,237,212,99,229,31,154,101,65,208,193,209,87,118,102,98,219,175,16,80,87,188,220,56,17,207,153,116,122,147,117,100,216,209,171,14,215,112,179,218,106,99,93,164,84,220,87,4,99,194,115,228,171,138,225,128,24,136,208,92,149,228,82,189,170,35,87,143,9,110,17,114,103,180,130,169,104,160,79,168,231,18,112,37,224,89,230,151,109,255,38,188,158,192,217,110,84,92,52,211,168,6,173,0,57,212,203,87,130,92,125,188,204,243,208,175,132,120,155,84,229,212,224,137,166,97,170,202,195,177,219,248,49,10,189,211,158,155,15,146,245,163,203,171,130,37,38,238,190,22,52,69,30,75,12,10,209,51,205,13,25,238,20,171,12,76,241,170,78,195,216,46,155,34,108,194,29,96,193,223,140,123,205,224,64,30,147,116,184,229,32,9,152,10,44,80,193,237,42,6,99,28,177,16,134,219,123,227,20,105,200,237,161,171,211,122,83,122,231,138,249,79,144,115,242,163,228,52,141,24,133,238,125,161,39,3,177,25,5,226,164,122,237,60,119,201,180,168,255,23,86,18,29,225,186,25,237,89,80,37,154,55,197,196,139,39,169,0,37,194,24,61,163,193,226,122,178,239,97,90,96,116,72,124,220,155,75,166,32,53,6,108,19,68,212,86,42,164,221,33,61,70,54,5,161,206,79,58,14,227,69,5,111,252,84,138,254,233,208,95,185,51,113,233,83,86,144,31,120,10,103,137,153,228,128,156,168,84,86,126,2,185,137,170,45,119,164,175,98,106,42,0,212,69,77,206,1,102,231,150,42,152,196,32,48,151,181,65,196,174,101,101,88,168,182,107,188,91,244,42,151,124,160,115,63,221,0,165,102,81,247,135,104,217,101,78,9,48,26,17,254,96,245,97,254,27,250,11,195,168,211,224,133,161,223,128,134,25,145,119,197,67,6,206,43,96,114,181,26,184,60,74,69,189,154,210,4,150,162,170,113,222,240,240,103,236,84,79,154,199,104,28,92,3,87,0,234,165,109,86,13,52,70,4,72,189,129,213,44,33,197,147,201,7,187,66,242,92,86,222,7,79,167,144,55,195,158,103,135,46,130,23,134,168,4,197,81,117,49,18,111,168,65,127,41,195,208,58,239,252,66,88,1,117,97,86,197,60,33,47,37,146,143,73,136,234,230,199,162,217,235,132,96,137,193,169,103,82,78,42,77,58,13,218,30 };

	for (int j = 0; j < 32; j++) {
		r = crypto_sign_falcon_ed25519_keypair_seed(pk2, sk2, seed1);
		if (r != 0) {
			printf("\n crypto_sign_falcon_ed25519_keypair_seed failed %d", (int)r);
			return -1;
		}

		for (int k = 0; k < 32 + 897; k++) {
			if (pk[k] != pkFromSeed[k]) {
				printf("\n deterministic generation failed pkFromSeed: pk %d,%d,%d",k,pk[k],pkFromSeed[k]);
				return -10;
			}
			if (pk[k] != pk2[k]) {
				printf("\n deterministic generation failed: pk");
				return -10;
			}
		}

		for (int k = 0; k < 64 + 1281 + 897; k++) {
			if (sk[k] != skFromSeed[k]) {
				printf("\n deterministic generation failed skFromSeed: sk");
				return -10;
			}
			if (sk[k] != sk2[k]) {
				printf("\n deterministic generation failed: sk");
				return -11;
			}
		}

		r = crypto_sign_falcon_ed25519_keypair_seed(pk3, sk3, seed3);
		if (r != 0) {
			printf("\n crypto_sign_falcon_ed25519_keypair_seed failed %d", (int)r);
			return -1;
		}

		int matchCount = 0;
		for (int k = 0; k < 32 + 897; k++) {
			if (pk2[k] == pk3[k]) {
				matchCount++;
			}
		}
		if (matchCount == 32 + 897) {
			printf("\n deterministic generation failed repeat: pk");
			return -10;
		}

		matchCount = 0;
		for (int k = 0; k < 64 + 1281 + 897; k++) {
			if (sk2[k] == sk3[k]) {
				matchCount++;
			}
		}
		if (matchCount == 64 + 1281 + 897) {
			printf("\n deterministic generation failed repeat: pk");
			return -10;
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

		for (int i = 0; i < MSG_LEN; i++) {
			if (msg1[i] != msg1output[i]) {
				printf("\n verify msg content failed %d", i);
				return -7;
			}
		}
	}

	printf("\n test_hybrid_deterministic() ok");
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

	r3 = test_hybrid_deterministic();
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

