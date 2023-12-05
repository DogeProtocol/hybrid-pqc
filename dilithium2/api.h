#ifndef PQCLEAN_DILITHIUM2_CLEAN_API_H
#define PQCLEAN_DILITHIUM2_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES 1312
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES 2560
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES 2420
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_ALGNAME "Dilithium2"

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

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed); //seed needs to be 32 chars long

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

    HYBRID_API int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

#endif

#if defined(__cplusplus)
} // extern "C"
#endif
