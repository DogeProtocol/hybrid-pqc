#define CRYPTO_SECRETKEYBYTES   1281
#define CRYPTO_PUBLICKEYBYTES   897
#define CRYPTO_BYTES            690
#define CRYPTO_ALGNAME          "Falcon-512"

#if defined(_WIN32)
#define FALCON_API __declspec(dllexport)
#else
#define FALCON_API __attribute__((visibility("default")))
#endif

#if defined(OQS_SYS_UEFI)
#undef FALCON_API
#define FALCON_API
#endif


#if defined(__cplusplus)
extern "C" {
#endif

int crypto_sign_falcon_keypair(unsigned char* pk, unsigned char* sk);

int crypto_sign_falcon(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

int crypto_sign_falcon_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif