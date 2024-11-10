#ifndef FFT_H
#define FFT_H

/**
 * @file fft.h
 * @brief Header file of fft.c
 */
#include "profiling.h"
#include <stddef.h>
#include <stdint.h>

void PQCLEAN_HQC128_CLEAN_fft(uint16_t *w, const uint16_t *f, size_t f_coeffs, struct Trace_time *time);

void PQCLEAN_HQC128_CLEAN_fft_retrieve_error_poly(uint8_t *error, const uint16_t *w);

#endif
