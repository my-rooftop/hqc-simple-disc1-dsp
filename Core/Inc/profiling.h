#ifndef PROFILING_H
#define PROFILING_H

#include <stdint.h>
#include <stdio.h>

struct Trace_time {
  uint32_t stack;
  uint32_t random_fixed_weight;
  uint32_t gf_mul;
  uint32_t vect_mul;
  uint32_t vect_set_random;
  uint32_t vect_add;
};

#endif