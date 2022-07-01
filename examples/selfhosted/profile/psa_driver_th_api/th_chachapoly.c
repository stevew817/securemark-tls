/*
 * Copyright (C) EEMBC(R). All Rights Reserved
 *
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.
 *
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "ee_chachapoly.h"

typedef struct {
    psa_key_attributes_t key_attr;
    uint8_t key_buffer[32];
    size_t key_len;
} th_psa_chachapoly_context_t;

/**
 * Create a context.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_create(void **pp_context // output: portable context
)
{
    *pp_context = (th_psa_chachapoly_context_t *)th_malloc(
        sizeof(th_psa_chachapoly_context_t));

    if (*pp_context == NULL)
    {
        th_printf("e-[malloc() fail in th_chachapoly_create]\r\n");
        return EE_STATUS_ERROR;
    }

    ((th_psa_chachapoly_context_t *)(*pp_context))->key_attr = psa_key_attributes_init();
    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_init(void *            p_context, // input: portable context
                   const uint8_t *   p_key,     // input: key
                   uint_fast32_t     keylen    // input: length of key in bytes
)
{
    th_psa_chachapoly_context_t* ctx = (th_psa_chachapoly_context_t*) p_context;

    if (keylen > sizeof(ctx->key_buffer))
    {
        th_printf("e-[key too large in th_chachapoly_init]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_reset_key_attributes(&ctx->key_attr);

    psa_set_key_type(&ctx->key_attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&ctx->key_attr, keylen * 8);
    psa_set_key_algorithm(&ctx->key_attr, PSA_ALG_CHACHA20_POLY1305);

    th_memcpy(ctx->key_buffer, p_key, keylen);
    ctx->key_len = keylen;
    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void
th_chachapoly_deinit(void *            p_context) // input: portable context
{
    psa_reset_key_attributes(&((th_psa_chachapoly_context_t*)p_context)->key_attr);
}

/**
 * Perform a ChaCha-Poly encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output_ ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*)p_context;
    size_t olen;

    psa_status_t status = psa_driver_wrapper_aead_encrypt(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_CHACHA20_POLY1305,
               p_iv, ivlen,
               NULL, 0,
               p_pt, ptlen,
               p_ct, ptlen + taglen, &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_encrypt: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform a ChaCha-decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output_ plaintext
    uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*)p_context;
    size_t olen;

    uint8_t* tmp_buf = (uint8_t*)th_malloc(ctlen + taglen);
    if (tmp_buf == NULL)
    {
        th_printf("e-[alloc error in th_aes_ccm_decrypt]\r\n");
        return EE_STATUS_ERROR;
    }

    th_memcpy(tmp_buf + ctlen, p_tag, taglen);
    th_memcpy(tmp_buf, p_ct, ctlen);

    psa_status_t status = psa_driver_wrapper_aead_decrypt(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_CHACHA20_POLY1305,
               p_iv, ivlen,
               NULL, 0,
               tmp_buf, ctlen + taglen,
               p_pt, ctlen, &olen);
    th_free(tmp_buf);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_decrypt: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Clean up the context created.
 */
void
th_chachapoly_destroy(void *p_context // input: portable context
)
{
    th_free(p_context);
}
