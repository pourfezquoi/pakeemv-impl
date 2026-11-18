#include "../../protocol/pake_emv/pake_emv.h"
#include "hash_v101.h"

/* The common profile performs all domain separation and HKDF. This adapter
 * supplies only the board's ordinary streaming SHA-256 primitive. */
void pake_emv_sha256_parts(uint8_t out[32], const pake_emv_part *parts, size_t count)
{
    HASH_CTX hash;
    size_t i;
    Hash_Init(&hash, SHA_256);
    for (i = 0; i < count; ++i) {
        Hash_Updata(&hash, (unsigned char *)parts[i].data, (unsigned int)parts[i].length);
    }
    Hash_Final(&hash, out);
    /* Hash contexts may retain partial blocks containing HKDF key material. */
    for (i = 0; i < sizeof(hash); ++i) {
        ((volatile unsigned char *)&hash)[i] = 0;
    }
}
