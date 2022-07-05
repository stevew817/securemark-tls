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
#include "ee_chachapoly.h"

typedef struct {
    mbedtls_svc_key_id_t our_key;
    psa_aead_operation_t aead_ctx;
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

    ((th_psa_chachapoly_context_t *)(*pp_context))->our_key = 0;
    ((th_psa_chachapoly_context_t *)(*pp_context))->aead_ctx = psa_aead_operation_init();
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
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*) p_context;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (ctx->our_key != 0)
    {
        psa_reset_key_attributes(&key_attr);
        th_printf("e-[th_chachapoly_init: trying to set new key on existing operation]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&key_attr, keylen * 8);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_usage_flags(&key_attr,
                            PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);

    status = psa_import_key(&key_attr, p_key, keylen, &ctx->our_key);
    psa_reset_key_attributes(&key_attr);
    if (status != PSA_SUCCESS)
    {
        psa_reset_key_attributes(&key_attr);
        th_printf("e-[psa_import_key: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void
th_chachapoly_deinit(void *            p_context) // input: portable context
{
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*) p_context;

    if (ctx->our_key > 0)
    {
        psa_destroy_key(ctx->our_key);
        ctx->our_key = 0;
        psa_aead_abort(&ctx->aead_ctx);
    }
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
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*) p_context;
    size_t olen;

    psa_status_t status = psa_aead_encrypt_setup(
                            &ctx->aead_ctx,
                            ctx->our_key,
                            PSA_ALG_CHACHA20_POLY1305);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_encrypt_setup: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_set_nonce(&ctx->aead_ctx, p_iv, ivlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_nonce: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->aead_ctx,
                p_pt, ptlen,
                p_ct, ptlen, &olen);
    if (status != PSA_SUCCESS || olen != ptlen)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_finish(
                &ctx->aead_ctx,
                &p_ct[olen], ptlen - olen, &olen,
                p_tag, taglen, &olen);
    if (status != PSA_SUCCESS || olen != taglen)
    {
        th_printf("e-[psa_aead_finish: %ld]\r\n", status);
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
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*) p_context;
    size_t olen;

    psa_status_t status = psa_aead_decrypt_setup(
                            &ctx->aead_ctx,
                            ctx->our_key,
                            PSA_ALG_CHACHA20_POLY1305);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_encrypt_setup: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_set_nonce(&ctx->aead_ctx, p_iv, ivlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_nonce: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->aead_ctx,
                p_ct, ctlen,
                p_pt, ctlen, &olen);
    if (status != PSA_SUCCESS || olen != ctlen)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_verify(
                &ctx->aead_ctx,
                &p_pt[olen], ctlen - olen, &olen,
                p_tag, taglen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_verify: %ld]\r\n", status);
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
    th_psa_chachapoly_context_t *ctx = (th_psa_chachapoly_context_t*) p_context;

    if (ctx->our_key > 0)
    {
        psa_destroy_key(ctx->our_key);
        ctx->our_key = 0;
        psa_aead_abort(&ctx->aead_ctx);
    }
    th_free(p_context);
}
