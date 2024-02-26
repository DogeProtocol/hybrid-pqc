#include "../common/shake_prng.h"
#include "../random/randombytes.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

int prngtest();

int prngtest() {
	const uint8_t zero[96] = { 0 };

	//Basic Test
	uint8_t seed[32] = { 0 };
	uint8_t expandedSeed[96] = { 0 };
	int ret = randombytes(seed, sizeof(seed));
	if (ret != 0) {
		return -1;
	}
	ret = seedexpander_wrapper(seed, 32, expandedSeed, 96);
	if (ret != 0) {
		return -2;
	}
	assert(memcmp(expandedSeed, zero, sizeof(zero)) != 0);

	uint8_t byteMap[256] = { 0 };
	for (int i = 0; i < 96; i++) {
		byteMap[expandedSeed[i]] = byteMap[expandedSeed[i]] + 1;
	}
	for (int i = 0; i < 256; i++) {
		if (byteMap[i] > 0) {
			assert(byteMap[i] <= 6);
		}
	}

	//Deterministic Test
	uint8_t deterministic_seed[32] = { 128,245,157,176,4,176,176,211,170,189,114,189,47,149,238,116,229,104,165,220,127,79,27,161,21,100,210,42,55,109,236,97 };
	uint8_t deterministic_seed_expanded[96] = { 42,69,166,190,134,52,115,60,114,28,58,189,38,1,241,41,17,231,66,106,190,30,57,229,27,81,147,251,182,120,212,239,171,249,76,129,14,151,187,219,222,162,174,50,140,40,9,138,56,225,228,57,150,208,74,95,71,233,238,1,217,220,201,152,201,65,85,103,70,106,170,229,23,202,51,100,63,240,119,222,182,98,244,31,103,193,139,232,77,198,216,160,213,49,156,101 };
	uint8_t deterministic_seed_expanded_return[96] = { 0 };
	ret = seedexpander_wrapper(deterministic_seed, 32, deterministic_seed_expanded_return, 96);
	if (ret != 0) {
		return -4;
	}
	int matchCount = 0;
	for (int i = 0; i < 96; i++) {
		if (deterministic_seed_expanded[i] != deterministic_seed_expanded_return[i]) {
			return -5;
		}
		if (deterministic_seed_expanded[i] == expandedSeed[i]) {
			matchCount = matchCount + 1;
		}
	}
	if (matchCount == 96) {
		return -6;
	}

	return 0;
}

int main(void) {
	for (int round = 1; round <= 1024; round++) {
		printf("\n Starting prng test round %d", round);
		int ret = prngtest();
		if (ret != 0) {
			printf("\n prng test failed %d", ret);
			return ret;
		}
	}
	printf("\n prng test succeeded");

	return 0;
}
