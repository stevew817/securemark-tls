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
#include "ee_aes.h"

typedef struct {
    ee_aes_mode_t aes_mode;
    mbedtls_svc_key_id_t our_key;
    union {
        psa_cipher_operation_t cipher_ctx;
        psa_aead_operation_t aead_ctx;
    } contexts;
} th_psa_aes_context_t;

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_create(void **           p_context, // output: portable context
              ee_aes_mode_t     mode       // input: EE_AES_ECB|CCM|GCM
)
{
    *p_context
            = (th_psa_aes_context_t *)th_malloc(sizeof(th_psa_aes_context_t));

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    ((th_psa_aes_context_t *)(*p_context))->aes_mode = mode;
    ((th_psa_aes_context_t *)(*p_context))->our_key = 0;

    switch (mode)
    {
        case EE_AES_ECB:
            // Fallthrough
        case EE_AES_CTR:
            ((th_psa_aes_context_t *)(*p_context))->contexts.cipher_ctx = psa_cipher_operation_init();
            break;
        case EE_AES_CCM:
            // Fallthrough
        case EE_AES_GCM:
            ((th_psa_aes_context_t *)(*p_context))->contexts.aead_ctx = psa_aead_operation_init();
            break;
        default:
            th_free(*p_context);
            th_printf("e-[Unknown mode in th_aes128_create]\r\n");
            return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_init(void *            p_context, // input: portable context
            const uint8_t *   p_key,     // input: key
            uint_fast32_t     keylen,    // input: length of key in bytes
            const uint8_t *   iv,        // input: IV buffer
            ee_aes_func_t     func,      // input: EE_AES_ENC or EE_AES_DEC
            ee_aes_mode_t     mode       // input: EE_AES_ECB|CCM|GCM
)
{
    (void) iv;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (mode != ctx->aes_mode)
    {
        th_printf("e-[mode in th_aes_init does not match mode from th_aes_create]\r\n");
        psa_reset_key_attributes(&key_attr);
        return EE_STATUS_ERROR;
    }

    if (ctx->our_key != 0)
    {
        psa_reset_key_attributes(&key_attr);
        th_printf("e-[th_aes_init: trying to set new key on existing operation]\r\n");
        return EE_STATUS_ERROR;
    }

    // Start by importing key
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&key_attr,
                            PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_bits(&key_attr, keylen * 8);

    switch (mode)
    {
        case EE_AES_ECB:
            psa_set_key_algorithm(&key_attr, PSA_ALG_ECB_NO_PADDING);
            break;
        case EE_AES_CTR:
            psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
            break;
        case EE_AES_CCM:
            psa_set_key_algorithm(&key_attr, PSA_ALG_CCM);
            break;
        case EE_AES_GCM:
            psa_set_key_algorithm(&key_attr, PSA_ALG_GCM);
            break;
        default:
            psa_reset_key_attributes(&key_attr);
            th_printf("e-[unknown algorithm in th_aes_init]\r\n");
            return EE_STATUS_ERROR;
    }

    status = psa_import_key(&key_attr, p_key, keylen, &ctx->our_key);
    psa_reset_key_attributes(&key_attr);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_import_key: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    // Then start the operation context
    switch (mode)
    {
        case EE_AES_ECB:
            // Fallthrough
        case EE_AES_CTR:
            if (func == EE_AES_ENC)
            {
                status = psa_cipher_encrypt_setup(
                            &ctx->contexts.cipher_ctx,
                            ctx->our_key,
                            mode == EE_AES_CTR ? PSA_ALG_CTR : PSA_ALG_ECB_NO_PADDING);
            }
            else if (func == EE_AES_DEC)
            {
                status = psa_cipher_decrypt_setup(
                            &ctx->contexts.cipher_ctx,
                            ctx->our_key,
                            mode == EE_AES_CTR ? PSA_ALG_CTR : PSA_ALG_ECB_NO_PADDING);
            }
            else
            {
                th_printf("e-[unknown mode in th_aes_init]\r\n");
                return EE_STATUS_ERROR;
            }

            if (status != PSA_SUCCESS)
            {
                th_printf("e-[psa_cipher_encrypt/decrypt_setup: %ld]\r\n", status);
                return EE_STATUS_ERROR;
            }

            if (mode == EE_AES_CTR)
            {
                status = psa_cipher_set_iv(&ctx->contexts.cipher_ctx, iv, EE_AES_CTR_IVLEN);
                if (status != PSA_SUCCESS)
                {
                    th_printf("e-[psa_cipher_set_iv: %ld]\r\n", status);
                    return EE_STATUS_ERROR;
                }
            }
            break;
        case EE_AES_CCM:
            // Fallthrough
        case EE_AES_GCM:
            if (func == EE_AES_ENC)
            {
                status = psa_aead_encrypt_setup(
                            &ctx->contexts.aead_ctx,
                            ctx->our_key,
                            mode == EE_AES_CCM ? PSA_ALG_CCM : PSA_ALG_GCM);
            }
            else if (func == EE_AES_DEC)
            {
                status = psa_aead_decrypt_setup(
                            &ctx->contexts.aead_ctx,
                            ctx->our_key,
                            mode == EE_AES_CCM ? PSA_ALG_CCM : PSA_ALG_GCM);
            }
            else
            {
                th_printf("e-[unknown mode in th_aes_init]\r\n");
                return EE_STATUS_ERROR;
            }

            if (status != PSA_SUCCESS)
            {
                th_printf("e-[psa_aead_encrypt/decrypt_setup: %ld]\r\n", status);
                return EE_STATUS_ERROR;
            }

            status = psa_aead_set_nonce(&ctx->contexts.aead_ctx, iv, EE_AES_AEAD_IVLEN);
            if (status != PSA_SUCCESS)
            {
                th_printf("e-[psa_aead_set_nonce: %ld]\r\n", status);
                return EE_STATUS_ERROR;
            }
            break;
        default:
            th_printf("e-[unknown algorithm in th_aes_init]\r\n");
            return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes_deinit(void *            p_context, // input: portable context
              ee_aes_mode_t     mode       // input: EE_AES_ECB|CCM|GCM
)
{
    (void) mode;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t *)p_context;

    if (ctx->our_key > 0)
    {
        psa_destroy_key(ctx->our_key);
        ctx->our_key = 0;

        switch (ctx->aes_mode)
        {
            case EE_AES_ECB:
                // Fallthrough
            case EE_AES_CTR:
                psa_cipher_abort(&ctx->contexts.cipher_ctx);
                break;
            case EE_AES_CCM:
                // Fallthrough
            case EE_AES_GCM:
                psa_aead_abort(&ctx->contexts.aead_ctx);
                break;
            default:
                th_printf("e-[Unknown mode in th_aes_deinit]\r\n");
                break;
        }
    }
}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ecb_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    uint8_t *      p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
)
{
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;
    psa_status_t status = psa_cipher_update(
                            &ctx->contexts.cipher_ctx,
                            p_pt,
                            EE_AES_BLOCKLEN,
                            p_ct,
                            EE_AES_BLOCKLEN,
                            &olen);

    if (status != PSA_SUCCESS || olen != EE_AES_BLOCKLEN)
    {
        th_printf("e-[psa_cipher_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ecb_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    uint8_t *      p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
)
{
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;
    psa_status_t status = psa_cipher_update(
                            &ctx->contexts.cipher_ctx,
                            p_ct,
                            EE_AES_BLOCKLEN,
                            p_pt,
                            EE_AES_BLOCKLEN,
                            &olen);

    if (status != PSA_SUCCESS || olen != EE_AES_BLOCKLEN)
    {
        th_printf("e-[psa_cipher_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Perform an AES CTR encryption.
 *
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint_fast32_t  ptlen,
                               uint8_t *      p_ct)
{
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;
    psa_status_t status = psa_cipher_update(
                            &ctx->contexts.cipher_ctx,
                            p_pt,
                            ptlen,
                            p_ct,
                            ptlen,
                            &olen);

    if (status != PSA_SUCCESS || olen != ptlen)
    {
        th_printf("e-[psa_cipher_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Perform an AES CTR decryption.
 *
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint_fast32_t  ctlen,
                               uint8_t *      p_pt)
{
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;
    psa_status_t status = psa_cipher_update(
                            &ctx->contexts.cipher_ctx,
                            p_ct,
                            ctlen,
                            p_pt,
                            ctlen,
                            &olen);

    if (status != PSA_SUCCESS || olen != ctlen)
    {
        th_printf("e-[psa_cipher_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    (void) p_iv;
    (void) ivlen;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen, tlen;

    psa_status_t status = psa_aead_set_lengths(
                            &ctx->contexts.aead_ctx,
                            0,
                            ptlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_lengths: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->contexts.aead_ctx,
                p_pt, ptlen,
                p_ct, ptlen, &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_finish(
                &ctx->contexts.aead_ctx,
                &p_ct[olen], ptlen - olen, &olen,
                p_tag, taglen, &tlen);
    if (status != PSA_SUCCESS || tlen != taglen)
    {
        th_printf("e-[psa_aead_finish (%ld): %ld]\r\n", tlen, status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    (void) p_iv;
    (void) ivlen;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

    psa_status_t status = psa_aead_set_lengths(
                            &ctx->contexts.aead_ctx,
                            0,
                            ctlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_lengths: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->contexts.aead_ctx,
                p_ct, ctlen,
                p_pt, ctlen, &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_verify(
                &ctx->contexts.aead_ctx,
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
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    (void) p_iv;
    (void) ivlen;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen, tlen;

    psa_status_t status = psa_aead_set_lengths(
                            &ctx->contexts.aead_ctx,
                            0,
                            ptlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_lengths: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->contexts.aead_ctx,
                p_pt, ptlen,
                p_ct, ptlen, &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_finish(
                &ctx->contexts.aead_ctx,
                &p_ct[olen], ptlen - olen, &olen,
                p_tag, taglen, &tlen);
    if (status != PSA_SUCCESS || tlen != taglen)
    {
        th_printf("e-[psa_aead_finish (%ld): %ld]\r\n", tlen, status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform an AES/GCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    (void) p_iv;
    (void) ivlen;
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

    psa_status_t status = psa_aead_set_lengths(
                            &ctx->contexts.aead_ctx,
                            0,
                            ctlen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_set_lengths: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_update(
                &ctx->contexts.aead_ctx,
                p_ct, ctlen,
                p_pt, ctlen, &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_aead_update: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    status = psa_aead_verify(
                &ctx->contexts.aead_ctx,
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
 *
 * Indicate the mode that was used for _create()
 */
void
th_aes_destroy(void *p_context // input: portable context
)
{
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t *)p_context;

    if (ctx->our_key > 0)
    {
        psa_destroy_key(ctx->our_key);
        ctx->our_key = 0;

        switch (ctx->aes_mode)
        {
            case EE_AES_ECB:
                // Fallthrough
            case EE_AES_CTR:
                psa_cipher_abort(&ctx->contexts.cipher_ctx);
                break;
            case EE_AES_CCM:
                // Fallthrough
            case EE_AES_GCM:
                psa_aead_abort(&ctx->contexts.aead_ctx);
                break;
            default:
                th_printf("e-[Unknown mode in th_aes_destroy]\r\n");
                break;
        }
    }
    th_free(p_context);
}
