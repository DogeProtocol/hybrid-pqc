#ifndef sss_RANDOMBYTES_H
#define sss_RANDOMBYTES_H

#if defined(_WIN32)
#define RANDOM_API __declspec(dllexport)
#else
#define RANDOM_API __attribute__((visibility("default")))
#endif

#if defined(OQS_SYS_UEFI)
#undef RANDOM_API
#define RANDOM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
/* Load size_t on windows */
#include <crtdefs.h>
#else
#include <unistd.h>
#endif /* _WIN32 */

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
RANDOM_API int randombytes(void *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* sss_RANDOMBYTES_H */
