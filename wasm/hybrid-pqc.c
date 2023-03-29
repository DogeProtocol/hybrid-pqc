#include <emscripten/emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../hybrid/hybrid.h"

#ifdef __cplusplus
extern "C" {
#endif

EMSCRIPTEN_KEEPALIVE
uint8_t* mem_alloc(size_t size) {
	return (uint8_t*) malloc(size);
}

EMSCRIPTEN_KEEPALIVE
uint64_t* mem_alloc_long_long(size_t size) {
	return (uint64_t*) malloc(size);
}

EMSCRIPTEN_KEEPALIVE
void mem_free(void* ptr, size_t size) {
	memset(ptr, 0, size);
 	free(ptr);
}

EMSCRIPTEN_KEEPALIVE
int dp_sign_keypair(unsigned char* pk, unsigned char* sk) {
	return crypto_sign_falcon_ed25519_keypair(pk, sk);
}

EMSCRIPTEN_KEEPALIVE 
int dp_sign(unsigned char* sm, size_t* smlen, const unsigned char* m, size_t mlen, const unsigned char* sk){
	return crypto_sign_falcon_ed25519(sm, smlen, m, mlen, sk);
}

EMSCRIPTEN_KEEPALIVE 
int dp_sign_verify(unsigned char* m, size_t mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk){
 	return crypto_verify_falcon_ed25519(m, mlen, sm, smlen, pk);
}

#ifdef __cplusplus
}
#endif