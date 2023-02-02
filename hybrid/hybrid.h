
#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_HYBRID_ALGNAME          "Falcon-512-ed25519"

int crypto_sign_falcon_ed25519_keypair(unsigned char* pk, unsigned char* sk);

int crypto_sign_falcon_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

int crypto_sign_falcon_ed25519_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

int crypto_verify_falcon_ed25519(unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif
