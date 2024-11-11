#include "code.h"
#include "parameters.h"
#include "reed_muller.h"
#include "reed_solomon.h"
#include "profiling.h"
#include <stdint.h>
/**
 * @file code.c
 * @brief Implementation of concatenated code
 */

/**
 *
 * @brief Encoding the message m to a code word em using the concatenated code
 *
 * First we encode the message using the Reed-Solomon code, then with the duplicated Reed-Muller code we obtain
 * a concatenated code word.
 *
 * @param[out] em Pointer to an array that is the tensor code word
 * @param[in] m Pointer to an array that is the message
 */
void PQCLEAN_HQC128_CLEAN_code_encode(uint64_t *em, const uint8_t *m, struct Trace_time *time) {
    uint8_t tmp[VEC_N1_SIZE_BYTES] = {0};
    uint32_t start_tick, end_tick;

    start_tick = HAL_GetTick();
    PQCLEAN_HQC128_CLEAN_reed_solomon_encode(tmp, m, time);
    end_tick = HAL_GetTick();
    time->rs_encode += end_tick - start_tick;

    start_tick = HAL_GetTick();
    PQCLEAN_HQC128_CLEAN_reed_muller_encode(em, tmp);
    end_tick = HAL_GetTick();
    time->rm_encode += end_tick - start_tick;

}

/**
 * @brief Decoding the code word em to a message m using the concatenated code
 *
 * @param[out] m Pointer to an array that is the message
 * @param[in] em Pointer to an array that is the code word
 */
void PQCLEAN_HQC128_CLEAN_code_decode(uint8_t *m, const uint64_t *em, struct Trace_time *time) {
    uint8_t tmp[VEC_N1_SIZE_BYTES] = {0};
    uint32_t start_tick, end_tick;

    start_tick = HAL_GetTick();
    PQCLEAN_HQC128_CLEAN_reed_muller_decode(tmp, em);
    end_tick = HAL_GetTick();
    time->rm_decode += end_tick - start_tick;

    start_tick = HAL_GetTick();
    PQCLEAN_HQC128_CLEAN_reed_solomon_decode(m, tmp, time);
    end_tick = HAL_GetTick();
    time->rs_decode += end_tick - start_tick;

}
