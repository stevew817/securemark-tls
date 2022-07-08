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

#include "ee_ecdsa.h"
#include "th_util.h"

typedef struct {
    mbedtls_svc_key_id_t our_key;
    psa_algorithm_t our_key_alg;
    size_t our_key_bits;
    mbedtls_svc_key_id_t their_key;
} th_psa_ecdsa_t;

/**
 * @brief Creates a context and generates a key pair.
 *
 * @param pp_context - A pointer to a context pointer to be created.
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_create(void **pp_context, ee_ecdh_group_t group)
{
    psa_status_t status;
    *pp_context = (th_psa_ecdsa_t *)th_malloc(sizeof(th_psa_ecdsa_t));
    psa_algorithm_t key_alg;
    size_t key_bits;

    if (*pp_context == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }

    // Create a new key
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

    switch (group)
    {
        case EE_P256R1:
            key_bits = 256;
            key_alg = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            break;
        case EE_P384:
            key_bits = 384;
            key_alg = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            break;
        case EE_Ed25519:
            key_bits = 255;
            key_alg = PSA_ALG_PURE_EDDSA;
            psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
            break;
        default:
            th_free(*pp_context);
            th_printf("e-[unknown ECC group in th_ecdsa_create]\r\n");
            return EE_STATUS_ERROR;
    }

    psa_set_key_bits(&key_attr, key_bits);
    psa_set_key_algorithm(&key_attr, key_alg);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);

    ((th_psa_ecdsa_t *)(*pp_context))->our_key = 0;
    ((th_psa_ecdsa_t *)(*pp_context))->our_key_alg = key_alg;
    ((th_psa_ecdsa_t *)(*pp_context))->our_key_bits = key_bits;
    ((th_psa_ecdsa_t *)(*pp_context))->their_key = 0;
    status = psa_generate_key(&key_attr, &((th_psa_ecdsa_t *)(*pp_context))->our_key);
    if (status != PSA_SUCCESS)
    {
        th_free(*pp_context);
        th_printf("e-[cannot create key in th_ecdsa_create: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_ecdsa_destroy(void *p_context)
{
    psa_destroy_key(((th_psa_ecdsa_t *)(p_context))->our_key);
    psa_destroy_key(((th_psa_ecdsa_t *)(p_context))->their_key);
    ((th_psa_ecdsa_t *)(p_context))->our_key = 0;
    ((th_psa_ecdsa_t *)(p_context))->their_key = 0;
    th_free(p_context);
}

/**
 * @brief Return the public key generated during `th_ecdsa_create`.
 *
 * @param p_context - The context from the `create` function
 * @param p_out - Buffer to receive the public key
 * @param p_outlen - Number of bytes used in the buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_get_public_key(void *         p_context,
                                    uint8_t *      p_out,
                                    uint_fast32_t *p_outlen)
{
    th_psa_ecdsa_t *ctx =   (th_psa_ecdsa_t*)p_context;
    psa_status_t            status;
    size_t                  olen;

    status = psa_export_public_key(ctx->our_key, p_out, *p_outlen, &olen);

    if (status != 0)
    {
        th_printf("e-[psa_export_public_key: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    *p_outlen = olen;

    return EE_STATUS_OK;
}

/**
 * @brief Set the public key in the context in order to perform a verify.
 *
 * For EcDSA, the key shall be in SECP1 uncompressed format { 04 | X | Y }.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_set_public_key(void *        p_context,
                                    uint8_t *     p_pub,
                                    uint_fast32_t publen)
{
    th_psa_ecdsa_t *ctx =   (th_psa_ecdsa_t*)p_context;
    psa_status_t            status;

    if (ctx->their_key != 0)
    {
        psa_destroy_key(ctx->their_key);
        ctx->their_key = 0;
    }

    psa_key_attributes_t key_attr_ours = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t key_attr_theirs = PSA_KEY_ATTRIBUTES_INIT;
    status = psa_get_key_attributes(ctx->our_key, &key_attr_ours);
    if (status != 0)
    {
        th_printf("e-[psa_get_key_attributes: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    psa_set_key_algorithm(&key_attr_theirs, psa_get_key_algorithm(&key_attr_ours));
    psa_set_key_bits(&key_attr_theirs, psa_get_key_bits(&key_attr_ours));
    psa_set_key_type(&key_attr_theirs, PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(psa_get_key_type(&key_attr_ours)));
    psa_set_key_usage_flags(&key_attr_theirs, PSA_KEY_USAGE_VERIFY_HASH);

    status = psa_import_key(&key_attr_theirs, p_pub, publen, &ctx->their_key);
    if (status != 0)
    {
        th_printf("e-[psa_import_key: %ld]\r\n", status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Sign a message (hash) with the private key.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * `p_siglen` should point to the buffer size on input; on return it will
 * contain the length of the signature.
 *
 * @param p_context - The context from the `create` function
 * @param p_msg - The hashed buffer to sign
 * @param msglen - Length of the hashed buffer
 * @param p_sig - The output signature buffer (provided)
 * @param p_siglen - The number of bytes used in the output signature buffer.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_sign(void *         p_context,
                          uint8_t *      p_msg,
                          uint_fast32_t  msglen,
                          uint8_t *      p_sig,
                          uint_fast32_t *p_siglen)
{
    th_psa_ecdsa_t *ctx =   (th_psa_ecdsa_t*)p_context;
    psa_status_t            status;
    size_t                  olen;

    if (ctx->our_key_alg == PSA_ALG_PURE_EDDSA)
    {
        status = psa_sign_message(
                    ctx->our_key,
                    ctx->our_key_alg,
                    p_msg, msglen,
                    p_sig, *p_siglen, &olen);
        if (status != 0)
        {
            th_printf("e-[psa_sign_message: %ld]\r\n", status);
            return EE_STATUS_ERROR;
        }

        *p_siglen = olen;
    }
    else
    {
        psa_algorithm_t     sig_alg;
        size_t              rs_len;
        size_t              r_offset, s_offset;
        bool                is_r_large, is_s_large;

        switch (msglen)
        {
            case 32:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
                break;
            case 48:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
                break;
            case 64:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
                break;
            default:
                th_printf("e-[Unknown hash length in th_ecdsa_sign]\r\n");
                return EE_STATUS_ERROR;
        }

        status = psa_sign_hash(
                    ctx->our_key,
                    sig_alg,
                    p_msg, msglen,
                    p_sig, *p_siglen, &olen);
        if (status != 0)
        {
            th_printf("e-[psa_sign_hash: %ld]\r\n", status);
            return EE_STATUS_ERROR;
        }

        // Manually do ASN.1 encoding for Weierstrass keys
        rs_len = olen / 2;
        is_r_large = p_sig[0] >= 0x80;
        is_s_large = p_sig[rs_len] >= 0x80;

        r_offset = 4 + (is_r_large ? 1 : 0);
        s_offset = r_offset + rs_len + 2 + (is_s_large ? 1 : 0);

        th_memmove(&p_sig[s_offset], &p_sig[rs_len], rs_len);
        th_memmove(&p_sig[r_offset], p_sig, rs_len);
        p_sig[0] = 0x30;
        p_sig[1] = olen + 4 + (is_r_large ? 1 : 0) + (is_s_large ? 1 : 0);
        p_sig[2] = 0x02;
        p_sig[3] = rs_len + (is_r_large ? 1 : 0);
        if (is_r_large)
        {
            // ASN1 requires leading zero byte if MSbit of integer is 1
            p_sig[4] = 0x0;
        }

        if (is_s_large)
        {
            p_sig[s_offset - 1] = 0x0;
            p_sig[s_offset - 2] = rs_len + (is_s_large ? 1 : 0);
            p_sig[s_offset - 3] = 0x02;
        }
        else
        {
            p_sig[s_offset - 1] = rs_len + (is_s_large ? 1 : 0);
            p_sig[s_offset - 2] = 0x02;
        }

        *p_siglen = s_offset + rs_len;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Verify a message (hash) with the public key.
 *
 * It will return EE_STATUS_OK on message verify, and EE_STATUS_ERROR if the
 * message does not verify, or if there is some other error (which shall
 * be reported with `th_printf("e-[....]r\n");`.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_hash - The hashed buffer to verify
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The input signature buffer
 * @param slen - Length of the input signature buffer
 * @return ee_status_t - see above.
 */
ee_status_t th_ecdsa_verify(void *        p_context,
                            uint8_t *     p_msg,
                            uint_fast32_t msglen,
                            uint8_t *     p_sig,
                            uint_fast32_t siglen)
{
    th_psa_ecdsa_t         *ctx = (th_psa_ecdsa_t*)p_context;
    psa_status_t            status;
    mbedtls_svc_key_id_t    key_id = ctx->their_key > 0 ? ctx->their_key : ctx->our_key;

    if (ctx->our_key_alg == PSA_ALG_PURE_EDDSA)
    {
        // Do PSA signature check
        status = psa_verify_message(key_id,
                                    ctx->our_key_alg,
                                    p_msg,
                                    msglen,
                                    p_sig,
                                    siglen);

        if (status != PSA_SUCCESS)
        {
            th_printf("e-[psa_verify_message: %ld]\r\n", status);
            return EE_STATUS_ERROR;
        }
    }
    else
    {
        psa_algorithm_t sig_alg;

        // Manually extract PSA-expected format from ASN.1
        size_t          rs_len = (ctx->our_key_bits + 7) / 8;
        size_t          r_len = p_sig[3];
        uint8_t         rs_buffer[96];

        switch (msglen)
        {
            case 32:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
                break;
            case 48:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
                break;
            case 64:
                sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
                break;
            default:
                th_printf("e-[Unknown hash length in th_ecdsa_verify]\r\n");
                return EE_STATUS_ERROR;
        }

        if (r_len > rs_len)
        {
            // Copy the rightmost rs_len bytes from the ASN integer into our buffer
            th_memcpy(rs_buffer, &p_sig[4 + r_len - rs_len], rs_len);
        }
        else
        {
            // Copy all bytes from the ASN integer into our buffer, right-aligned
            th_memcpy(&rs_buffer[rs_len - r_len], &p_sig[4], r_len);
            // And zero-extend
            th_memset(rs_buffer, 0, rs_len - r_len);
        }

        size_t s_len = p_sig[4 + r_len + 1];

        if (s_len > rs_len)
        {
            th_memcpy(&rs_buffer[rs_len], &p_sig[4 + r_len + 2 + s_len - rs_len], rs_len);
        }
        else
        {
            th_memcpy(&rs_buffer[(rs_len * 2) - s_len], &p_sig[4 + r_len + 2], s_len);
            th_memset(&rs_buffer[rs_len], 0, rs_len - s_len);
        }

        // Do PSA signature check
        status = psa_verify_hash(key_id,
                                 sig_alg,
                                 p_msg,
                                 msglen,
                                 rs_buffer,
                                 rs_len * 2);

        if (status != PSA_SUCCESS)
        {
            th_printf("e-[psa_verify_hash: %ld]\r\n", status);
            return EE_STATUS_ERROR;
        }
    }



    return EE_STATUS_OK;
}
