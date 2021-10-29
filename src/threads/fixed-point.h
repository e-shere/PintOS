#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <inttypes.h>

/* Fixed point type. */

typedef int32_t fp;

/* Fixed point parameters. */

static int const FP_Q = 14;
static int const FP_P = (31 - FP_Q);
static int const FP_F = (1 << FP_Q);

/* Fixed point arithmetic macros. */

static inline fp
fp_int_to_fp (int n)
{
  return n * FP_F;
}

static inline int
fp_fp_to_int (fp x)
{
  return x / FP_F;
}

static inline int
fp_fp_to_int_nearest (fp x)
{
  return ((x >= 0) ? (x + FP_F / 2) : (x - FP_F / 2)) / FP_F;
}

static inline fp
fp_add (fp x, fp y)
{
  return x + y;
}

static inline fp
fp_sub (fp x, fp y)
{
  return x - y;
}

static inline fp
fp_add_int (fp x, int n)
{
  return x + n * FP_F;
}

static inline fp
fp_sub_int (fp x, int n)
{
  return x - n * FP_F;
}

static inline fp
fp_mul (fp x, fp y)
{
  return ((int64_t)x) * y / FP_F;
}

static inline fp
fp_div (fp x, fp y)
{
  return ((int64_t)x) * FP_F / y;
}

static inline fp
fp_mul_int (fp x, int n)
{
  return x * n;
}

static inline fp
fp_div_int (fp x, int n)
{
  return x / n;
}


#endif  /* threads/fixed-point.h */
