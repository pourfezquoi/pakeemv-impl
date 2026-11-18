#include "../../third_party/chic/chic.h"
#include "randombytes.h"

/* The board provider selects TRUE_RANDOM_NUMER. Its vendor API returns no
 * entropy health/status result; hardware validation remains a board task. */
int chic_randombytes(uint8_t *out, size_t length)
{
    return randombytes(out, length);
}
