
#if defined(_WIN32)
#define HYBRID_API __declspec(dllexport)
#else
#define HYBRID_API __attribute__((visibility("default")))
#endif

#if defined(HYBRID_SYS_UEFI)
#undef HYBRID_API
#define HYBRID_API
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_DILITHIUM_HYBRID_ALGNAME          "dilithium-ed25519-sphincs"


HYBRID_API int crypto_sign_dilithium_ed25519_sphincs_keypair_seed_expander(const unsigned char* seed, unsigned char* expandedSeed);

HYBRID_API int crypto_sign_dilithium_ed25519_sphincs_keypair_seed(unsigned char* pk, unsigned char* sk, unsigned char* seed); //seed needs to be 64 chars in length (32 + 32 + 96)

HYBRID_API int crypto_sign_dilithium_ed25519_sphincs_keypair(unsigned char* pk, unsigned char* sk);

HYBRID_API int crypto_sign_dilithium_ed25519_sphincs(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

HYBRID_API int crypto_sign_dilithium_ed25519_sphincs_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_dilithium_ed25519_sphincs(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_sign_compact_dilithium_ed25519_sphincs(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

HYBRID_API int crypto_sign_compact_dilithium_ed25519_sphincs_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_compact_dilithium_ed25519_sphincs(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_dilithium(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif
