#define CRYPTO_SECRETKEYBYTES   1281
#define CRYPTO_PUBLICKEYBYTES   897
#define CRYPTO_BYTES            690
#define CRYPTO_ALGNAME          "Falcon-512"

#if defined(_WIN32)
#define HYBRIDPQC_API __declspec(dllexport)
#else
#define HYBRIDPQC_API __attribute__((visibility("default")))
#endif

#if defined(HYBRIDPQC_SYS_UEFI)
#undef HYBRIDPQC_API
#define HYBRIDPQC_API
#endif


#if defined(__cplusplus)
extern "C" {
#endif

HYBRIDPQC_API int crypto_sign_falcon_keypair_with_seed(unsigned char* pk, unsigned char* sk, unsigned char* seed, size_t seedLen); //seed needs to be 48 chars long

HYBRIDPQC_API int crypto_sign_falcon_keypair(unsigned char* pk, unsigned char* sk);

HYBRIDPQC_API int crypto_sign_falcon(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

HYBRIDPQC_API int crypto_sign_falcon_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif
