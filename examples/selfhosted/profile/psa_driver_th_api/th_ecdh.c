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

#include "ee_ecdh.h"

typedef struct {
    mbedtls_svc_key_id_t our_key;
    uint8_t their_key[97];
    size_t their_key_len;
} th_psa_ecdh_t;

/**
 * @brief Creates a context and generates a key pair.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t
th_ecdh_create(void **p_context // output: portable context
, ee_ecdh_group_t group)
{
    psa_status_t status;
    *p_context = (th_psa_ecdh_t *)th_malloc(sizeof(th_psa_ecdh_t));

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }

    // Create a new key
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

    switch (group)
    {
        case EE_P256R1:
            psa_set_key_bits(&key_attr, 256);
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            break;
        case EE_P384:
            psa_set_key_bits(&key_attr, 384);
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            break;
        case EE_C25519:
            psa_set_key_bits(&key_attr, 255);
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
            break;
        default:
            th_free(*p_context);
            th_printf("e-[unknown ECC group in th_ecdh_create]\r\n");
            return EE_STATUS_ERROR;
    }
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);

    ((th_psa_ecdh_t *)(*p_context))->our_key = 0;
    status = psa_generate_key(&key_attr, &((th_psa_ecdh_t *)(*p_context))->our_key);
    if (status != PSA_SUCCESS)
    {
        th_free(*p_context);
        th_printf("e-[cannot create key in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Loads the peer public key for use in the secreat calc.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_set_peer_public_key(void *        p_context,
                                        uint8_t *     p_pub,
                                        uint_fast32_t publen)
{
    th_psa_ecdh_t *ctx = (th_psa_ecdh_t*)p_context;
    if (publen > sizeof(ctx->their_key))
    {
        th_printf("e-[pubkey too large in th_ecdh_set_peer_public_key]\r\n");
        return EE_STATUS_ERROR;
    }

    th_memcpy(ctx->their_key, p_pub, publen);
    ctx->their_key_len = publen;

    return EE_STATUS_OK;
}

/**
 * @brief Returns the DUT's public key so that the HOST can verify
 * the secret with it's private key.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param p_publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_get_public_key(void *         p_context,
                                   uint8_t *      p_pub,
                                   uint_fast32_t *p_publen)
{
    th_psa_ecdh_t *ctx =    (th_psa_ecdh_t*)p_context;
    psa_status_t            status;
    size_t                  olen;

    status = psa_export_public_key(ctx->our_key, p_pub, *p_publen, &olen);

    if (status != 0)
    {
        th_printf("e-[psa_export_public_key: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    *p_publen = olen;

    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(
    void *         p_context, // input: portable context
    uint8_t *      p_secret,  // output: shared secret
    uint_fast32_t *p_seclen   // input/output: length of shared buffer in bytes
)
{
    th_psa_ecdh_t *ctx =    (th_psa_ecdh_t*)p_context;
    psa_status_t            status;
    size_t                  olen;

    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   ctx->our_key,
                                   ctx->their_key, ctx->their_key_len,
                                   p_secret, *p_seclen, &olen);

    if (status != 0)
    {
        th_printf("e-[psa_raw_key_agreement: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    *p_seclen = olen;

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(void *p_context // input: portable context
)
{
    psa_destroy_key(((th_psa_ecdh_t *)(p_context))->our_key);
    ((th_psa_ecdh_t *)(p_context))->our_key = 0;
    th_free(p_context);
}
