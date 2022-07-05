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
#include "ee_aes.h"

#include "em_device.h"
#if defined(SEMAILBOX_PRESENT)
  #include "sl_se_manager.h"
  #include "sli_se_transparent_functions.h"
  #include "sli_se_driver_aead.h"

  #define TRANSPARENT_AEAD_ENCRYPT_TAG sli_se_driver_aead_encrypt_tag
  #define TRANSPARENT_AEAD_DECRYPT_TAG sli_se_driver_aead_decrypt_tag
#elif defined(CRYPTOACC_PRESENT)
  #include "sl_se_manager.h"
  #include "sli_cryptoacc_transparent_functions.h"

  #define TRANSPARENT_AEAD_ENCRYPT_TAG sli_cryptoacc_transparent_aead_encrypt_tag
  #define TRANSPARENT_AEAD_DECRYPT_TAG sli_cryptoacc_transparent_aead_decrypt_tag
#elif defined(CRYPTO_PRESENT)
  #include "sli_crypto_transparent_functions.h"

  #define TRANSPARENT_AEAD_ENCRYPT_TAG sli_crypto_transparent_aead_encrypt_tag
  #define TRANSPARENT_AEAD_DECRYPT_TAG sli_crypto_transparent_aead_decrypt_tag
#else
  #error "No known implementation for AEAD"
#endif


typedef struct {
    ee_aes_mode_t aes_mode;
    psa_key_attributes_t key_attr;
    uint8_t key_buffer[32];
    size_t key_len;
    uint8_t iv[16];
} th_psa_aes_context_t;

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_create(void **           p_context, // output: portable context
              ee_aes_mode_t mode       // input: EE_AES_ENC or EE_AES_DEC
)
{
    *p_context
            = (th_psa_aes_context_t *)th_malloc(sizeof(th_psa_aes_context_t));
    if (mode == EE_AES_ECB ||
        mode == EE_AES_CTR ||
        mode == EE_AES_CCM ||
        mode == EE_AES_GCM)
    {
        ((th_psa_aes_context_t *)(*p_context))->aes_mode = mode;
    }
    else
    {
        th_free(*p_context);
        th_printf("e-[Unknown mode in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    ((th_psa_aes_context_t *)(*p_context))->key_attr = psa_key_attributes_init();

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

    if (keylen > sizeof(ctx->key_buffer))
    {
        th_printf("e-[key size too big in th_aes_init]\r\n");
        return EE_STATUS_ERROR;
    }

    ctx->key_len = keylen;
    th_memcpy(ctx->key_buffer, p_key, keylen);
    psa_reset_key_attributes(&ctx->key_attr);

    if (mode == EE_AES_CTR)
    {
        th_memcpy(ctx->iv, iv, 16);
    }

    psa_set_key_type(&ctx->key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&ctx->key_attr,
                            PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_bits(&ctx->key_attr, keylen * 8);

    switch (mode)
    {
        case EE_AES_ECB:
            psa_set_key_algorithm(&ctx->key_attr, PSA_ALG_ECB_NO_PADDING);
            break;
        case EE_AES_CTR:
            psa_set_key_algorithm(&ctx->key_attr, PSA_ALG_CTR);
            break;
        case EE_AES_CCM:
            psa_set_key_algorithm(&ctx->key_attr, PSA_ALG_CCM);
            break;
        case EE_AES_GCM:
            psa_set_key_algorithm(&ctx->key_attr, PSA_ALG_GCM);
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
    psa_reset_key_attributes(&((th_psa_aes_context_t*)p_context)->key_attr);
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
    psa_status_t status = psa_driver_wrapper_cipher_encrypt(
                            &ctx->key_attr,
                            ctx->key_buffer,
                            ctx->key_len,
                            PSA_ALG_ECB_NO_PADDING,
                            NULL,
                            0,
                            p_pt,
                            16,
                            p_ct,
                            16,
                            &olen);

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_cipher_encrypt: %ld]\r\n", status);
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
    psa_status_t status = psa_driver_wrapper_cipher_decrypt(
                            &ctx->key_attr,
                             ctx->key_buffer,
                             ctx->key_len,
                             PSA_ALG_ECB_NO_PADDING,
                             p_ct,
                             16,
                             p_pt,
                             16,
                             &olen);

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_cipher_decrypt: %ld]\r\n", status);
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
    psa_status_t status = psa_driver_wrapper_cipher_encrypt(
                            &ctx->key_attr,
                            ctx->key_buffer,
                            ctx->key_len,
                            PSA_ALG_CTR,
                            ctx->iv,
                            16,
                            p_pt,
                            ptlen,
                            p_ct,
                            ptlen,
                            &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_cipher_encrypt: %ld]\r\n", status);
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

    th_memcpy(p_pt, ctx->iv, 16);
    th_memcpy(p_pt + 16, p_ct, ctlen);

    psa_status_t status = psa_driver_wrapper_cipher_decrypt(
                            &ctx->key_attr,
                             ctx->key_buffer,
                             ctx->key_len,
                             PSA_ALG_CTR,
                             p_pt,
                             ctlen + 16,
                             p_pt,
                             ctlen,
                             &olen);
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_cipher_decrypt: %ld]\r\n", status);
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
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

#if defined(TRANSPARENT_AEAD_ENCRYPT_TAG)
    size_t tlen;

    psa_status_t status = TRANSPARENT_AEAD_ENCRYPT_TAG(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_CCM,
               p_iv, ivlen,
               NULL, 0,
               p_pt, ptlen,
               p_ct, ptlen, &olen,
               p_tag, taglen, &tlen);
#else
    psa_status_t status = psa_driver_wrapper_aead_encrypt(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_CCM,
               p_iv, ivlen,
               NULL, 0,
               p_pt, ptlen,
               p_ct, ptlen + taglen, &olen);
#endif

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_encrypt: %ld]\r\n", status);
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
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

#if defined(TRANSPARENT_AEAD_DECRYPT_TAG)
    psa_status_t status = TRANSPARENT_AEAD_DECRYPT_TAG(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_CCM,
               p_iv, ivlen,
               NULL, 0,
               p_ct, ctlen,
               p_tag, taglen,
               p_pt, ctlen, &olen);
#else
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
               PSA_ALG_CCM,
               p_iv, ivlen,
               NULL, 0,
               tmp_buf, ctlen + taglen,
               p_pt, ctlen, &olen);
    th_free(tmp_buf);
#endif

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_decrypt: %ld]\r\n", status);
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
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

#if defined(TRANSPARENT_AEAD_ENCRYPT_TAG)
    size_t tlen;

    psa_status_t status = TRANSPARENT_AEAD_ENCRYPT_TAG(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_GCM,
               p_iv, ivlen,
               NULL, 0,
               p_pt, ptlen,
               p_ct, ptlen, &olen,
               p_tag, taglen, &tlen);
#else
    psa_status_t status = psa_driver_wrapper_aead_encrypt(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_GCM,
               p_iv, ivlen,
               NULL, 0,
               p_pt, ptlen,
               p_ct, ptlen + taglen, &olen);
#endif

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_encrypt: %ld]\r\n", status);
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
    th_psa_aes_context_t *ctx = (th_psa_aes_context_t*)p_context;
    size_t olen;

#if defined(TRANSPARENT_AEAD_DECRYPT_TAG)
    psa_status_t status = TRANSPARENT_AEAD_DECRYPT_TAG(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_GCM,
               p_iv, ivlen,
               NULL, 0,
               p_ct, ctlen,
               p_tag, taglen,
               p_pt, ctlen, &olen);
#else
    uint8_t* tmp_buf = (uint8_t*)th_malloc(ctlen + taglen);
    if (tmp_buf == NULL)
    {
        th_printf("e-[alloc error in th_aes_gcm_decrypt]\r\n");
        return EE_STATUS_ERROR;
    }

    th_memcpy(tmp_buf + ctlen, p_tag, taglen);
    th_memcpy(tmp_buf, p_ct, ctlen);

    psa_status_t status = psa_driver_wrapper_aead_decrypt(
               &ctx->key_attr, ctx->key_buffer, ctx->key_len,
               PSA_ALG_GCM,
               p_iv, ivlen,
               NULL, 0,
               tmp_buf, ctlen + taglen,
               p_pt, ctlen, &olen);
    th_free(tmp_buf);
#endif

    if (status != PSA_SUCCESS)
    {
        th_printf("e-[psa_driver_wrapper_aead_decrypt: %ld]\r\n", status);
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
    psa_reset_key_attributes(&((th_psa_aes_context_t *)p_context)->key_attr);
    th_free(p_context);
}
