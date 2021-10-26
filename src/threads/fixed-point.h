#ifndef FIXED_POINT_H
#define FIXED_POINT_H

/* Fixed point type. */

typedef int fp;

/* Fixed point parameters. */

#define FP_Q 14
#define FP_P (31 - FP_Q)
#define FP_F (1 << FP_Q)

/* Fixed point arithmetic macros. */

#define FP_INT_TO_FP(n) ((n) * FP_F)
#define FP_FP_TO_INT(x) ((x) / FP_F)
#define FP_FP_TO_INT_NEAREST(x)                                                \
  ((((x) >= 0) ? ((x) + FP_F / 2) : ((x) - FP_F / 2)) / FP_F)
#define FP_ADD(x, y) ((x) + (y))
#define FP_SUB(x, y) ((x) - (y))
#define FP_ADD_INT(x, n) ((x) + (n) * FP_F)
#define FP_SUB_INT(x, n) ((x) - (n) * FP_F)
#define FP_MUL(x, y) (((int64_t)(x)) * (y) / FP_F)
#define FP_DIV(x, y) (((int64_t)(x)) * FP_F / (y))
#define FP_MUL_INT(x, n) ((x) * (n))
#define FP_DIV_INT(x, n) ((x) / (n))

#endif  /* threads/fixed-point.h */