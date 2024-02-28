#include "domains.h"
#include "fips202.h"
#include "shake_prng.h"

/**
 * @file shake_prng.c
 * @brief Implementation of SHAKE-256 based seed expander
 */

/**
 * @brief Initialise a SHAKE-256 based seed expander
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[out] state Keccak internal state and a counter
 * @param[in] seed A seed
 * @param[in] seedlen The seed bytes length
 */
void seedexpander_init(seedexpander_state *state, const uint8_t *seed, size_t seedlen) {
    uint8_t domain = SEEDEXPANDER_DOMAIN;
    shake256_inc_init(state);
    shake256_inc_absorb(state, seed, seedlen);
    shake256_inc_absorb(state, &domain, 1);
    shake256_inc_finalize(state);
}

/**
 * @brief A SHAKE-256 based seed expander
 *
 * Derived from function SHAKE_256 in fips202.c
 * Squeezes Keccak state by 64-bit blocks (hardware version compatibility)
 *
 * @param[out] state Internal state of SHAKE
 * @param[out] output The XOF data
 * @param[in] outlen Number of bytes to return
 */
void seedexpander(seedexpander_state *state, uint8_t *output, size_t outlen) {
    const size_t bsize = sizeof(uint64_t);
    const size_t remainder = outlen % bsize;
    
    uint8_t tmp[sizeof(uint64_t)];
    shake256_inc_squeeze(output, outlen - remainder, state);
    if (remainder != 0) {
        shake256_inc_squeeze(tmp, bsize, state);
        output += outlen - remainder;
        for (uint8_t i = 0; i < remainder; i++) {
            output[i] = tmp[i];
        }
    }
}

/**
 * @brief Release the seed expander context
 * @param[in] state Internal state of the seed expander
 */
void seedexpander_release(seedexpander_state *state) {
    shake256_inc_ctx_release(state);
}

/**
 * @brief Expands a seed and returns output
 * @param[in] the initial seed
 * @param[in] the initial seed length. needs to be minimum 32 bytes
 * @param[out] the output for the expanded seed
*  @param[in] the desired output length. 
 */
int seedexpander_wrapper(const uint8_t* seed, size_t seedlen, uint8_t* output, size_t outlen) {
    if (seed == NULL || output == NULL) {
        return -1;
    }
    if (seedlen < 32) {
        return -2;
    }
    if (outlen <= seedlen) {
        return -3;
    }
    seedexpander_state seedState;
    seedexpander_init(&seedState, seed, seedlen);
    seedexpander(&seedState, output, outlen);
    seedexpander_release(&seedState);

    return 0;
}