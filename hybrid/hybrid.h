
#if defined(_WIN32)
#define HYBRID_API __declspec(dllexport)
#else
#define HYBRID_API __attribute__((visibility("default")))
#endif

#if defined(OQS_SYS_UEFI)
#undef HYBRID_API
#define HYBRID_API
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_HYBRID_ALGNAME          "Falcon-512-ed25519"

HYBRID_API int crypto_sign_falcon_ed25519_keypair(unsigned char* pk, unsigned char* sk);

HYBRID_API int crypto_sign_falcon_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

HYBRID_API int crypto_sign_falcon_ed25519_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_falcon_ed25519(unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_public_key_from_private_key_falcon_ed25519(unsigned char* pk, const unsigned char* sk);

#if defined(__cplusplus)
} // extern "C"
#endif
