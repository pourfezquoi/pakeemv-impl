#ifndef CHIC_DEFAULT_SAMPLER_OPENSSL_INCLUDE_H
#define CHIC_DEFAULT_SAMPLER_OPENSSL_INCLUDE_H
/* The pinned rej_uniform.c includes this header unconditionally, but its
 * default original rejection sampler uses no OpenSSL type or function.
 * Do not fake any BIGNUM implementation: optional samplers are forbidden.
 */
#if defined(TEMPO_VECTOR_ALG) || defined(TEMPO_MATRIX_ALG)
#error "This CHIC integration builds only the author's default sampler"
#endif
#endif
