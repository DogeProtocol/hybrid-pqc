

#if defined(__cplusplus)
extern "C" {
#endif

#define MAX_MSG_LEN 64

#define CRYPTO_ED25519_SECRETKEY_BYTES   64
#define CRYPTO_ED25519_PUBLICKEY_BYTES   32
#define CRYPTO_ED25519_SIGNATURE_BYTES   64

#define CRYPTO_FALCON_SECRETKEY_BYTES   1281
#define CRYPTO_FALCON_PUBLICKEY_BYTES   897
#define SIZE_LEN 2 //2 for size
#define CRYPTO_FALCON_MIN_SIGNATURE_BYTES   600 + 40 + SIZE_LEN //Signature + Nonce + 2 for size
#define CRYPTO_FALCON_MAX_SIGNATURE_BYTES   690 + 40 + SIZE_LEN //Signature + Nonce + 2 for size

#define CRYPTO_HYBRID_SECRETKEY_BYTES   CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_FALCON_SECRETKEY_BYTES
#define CRYPTO_HYBRID_PUBLICKEY_BYTES   CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_FALCON_PUBLICKEY_BYTES
#define CRYPTO_HYBRID_MIN_SIGNATURE_BYTES   CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_FALCON_MIN_SIGNATURE_BYTES
#define CRYPTO_HYBRID_MAX_SIGNATURE_BYTES   CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_FALCON_MAX_SIGNATURE_BYTES
#define CRYPTO_HYBRID_ALGNAME          "Falcon-512-ed25519"

int crypto_sign_falcon_ed25519_keypair(unsigned char* pk, unsigned char* sk);

int crypto_sign_falcon_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

int crypto_sign_falcon_ed25519_open(unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif
