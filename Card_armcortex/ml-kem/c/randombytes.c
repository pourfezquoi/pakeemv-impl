#include "randombytes.h"
#include "trng_v100.h"
#include <string.h>

int randombytes(uint8_t* buf, size_t xlen)
{
	Trng_Init(PSEUDO_RANDOM_NUMER);
	Trng_Out_U8 (buf, xlen);
  return 0;
}

