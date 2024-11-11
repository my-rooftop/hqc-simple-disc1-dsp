#ifndef PROFILING_H
#define PROFILING_H

#include <stdint.h>
#include <stdio.h>

struct Trace_time {
  uint32_t stack;
  uint32_t random_fixed_weight;
  uint32_t gf_mul;
  uint32_t vect_mul_stack;
  uint32_t vect_mul;
  uint32_t vect_set_random;
  uint32_t vect_add;
  uint32_t shake256_512;
  uint32_t rm_encode;
  uint32_t rs_encode;
  uint32_t rm_decode;
  uint32_t rs_decode;
};

#endif