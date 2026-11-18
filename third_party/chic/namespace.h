#ifndef EMV_CHIC_NAMESPACE_H
#define EMV_CHIC_NAMESPACE_H
/* Build adapter only: do not modify the byte-for-byte upstream sources. */
#include <stdint.h>
#if defined(TEMPO_VECTOR_ALG) || defined(TEMPO_MATRIX_ALG)
#error "This integration requires the author's unchanged default samplers"
#endif
#ifndef KYBER_K
#define KYBER_K 2
#endif
#if KYBER_K != 2
#error "The EMV integration requires the author's CHIC-512 parameters"
#endif
#include "upstream/kyber/params.h"
#undef KYBER_NAMESPACE
#define KYBER_NAMESPACE(s) chic_kyber512_ref_##s

/* Rijndael explicitly supports an unsigned 32-bit word override. */
#define UINT32_TYPE uint32_t

#define initStart chic_ref_initStart
#define initEnd chic_ref_initEnd
#define resp chic_ref_resp
#define hic_eval chic_ref_hic_eval
#define hic_inv chic_ref_hic_inv
#define ic256_enc chic_ref_ic256_enc
#define ic256_dec chic_ref_ic256_dec
#define randombytes chic_ref_randombytes
#define xrijndaelKeySched chic_ref_xrijndaelKeySched
#define xrijndaelEncrypt chic_ref_xrijndaelEncrypt
#define xrijndaelDecrypt chic_ref_xrijndaelDecrypt
#define M0 chic_ref_M0
#define M1 chic_ref_M1
#define xrcon chic_ref_xrcon
#define xS chic_ref_xS
#define xSi chic_ref_xSi
#define pqcrystals_kyber_fips202_ref_shake128_init chic_ref_shake128_init
#define pqcrystals_kyber_fips202_ref_shake128_absorb chic_ref_shake128_absorb
#define pqcrystals_kyber_fips202_ref_shake128_finalize chic_ref_shake128_finalize
#define pqcrystals_kyber_fips202_ref_shake128_squeeze chic_ref_shake128_squeeze
#define pqcrystals_kyber_fips202_ref_shake128_absorb_once chic_ref_shake128_absorb_once
#define pqcrystals_kyber_fips202_ref_shake128_squeezeblocks chic_ref_shake128_squeezeblocks
#define pqcrystals_kyber_fips202_ref_shake256_init chic_ref_shake256_init
#define pqcrystals_kyber_fips202_ref_shake256_absorb chic_ref_shake256_absorb
#define pqcrystals_kyber_fips202_ref_shake256_finalize chic_ref_shake256_finalize
#define pqcrystals_kyber_fips202_ref_shake256_squeeze chic_ref_shake256_squeeze
#define pqcrystals_kyber_fips202_ref_shake256_absorb_once chic_ref_shake256_absorb_once
#define pqcrystals_kyber_fips202_ref_shake256_squeezeblocks chic_ref_shake256_squeezeblocks
#define pqcrystals_kyber_fips202_ref_shake128 chic_ref_shake128
#define pqcrystals_kyber_fips202_ref_shake256 chic_ref_shake256
#define pqcrystals_kyber_fips202_ref_sha3_256 chic_ref_sha3_256
#define pqcrystals_kyber_fips202_ref_sha3_512 chic_ref_sha3_512
#endif
