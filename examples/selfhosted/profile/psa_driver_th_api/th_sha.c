/*
 * Copyright (C) 2015-2017 EEMBC(R). All Rights Reserved
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

#include "ee_sha.h"

typedef struct {
    psa_algorithm_t alg;
    psa_hash_operation_t ctx;
} th_psa_sha_context_t;

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_create(void **pp_context, ee_sha_size_t size)
{
    th_psa_sha_context_t *ctx;
    psa_algorithm_t alg;

    switch (size)
    {
        case EE_SHA256:
            alg = PSA_ALG_SHA_256;
            break;
        case EE_SHA384:
            alg = PSA_ALG_SHA_384;
            break;
        default:
            th_printf("e-[th_sha_create unsupported size]\r\n");
            return EE_STATUS_ERROR;
    }

    ctx = th_malloc(sizeof(th_psa_sha_context_t));
    if (!ctx)
    {
        th_printf("e-[th_sha_create malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    ctx->alg = alg;
    ctx->ctx = psa_hash_operation_init();
    *pp_context = (void *)ctx;
    return EE_STATUS_OK;
}

/**
 * Initialize the context prior to a hash operation.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_init(void *p_context)
{
    th_psa_sha_context_t *ctx = (th_psa_sha_context_t*)p_context;
    return psa_driver_wrapper_hash_setup(&ctx->ctx, ctx->alg) == PSA_SUCCESS ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Process the hash
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_process(void *p_context, const uint8_t *p_in, uint_fast32_t len)
{
    th_psa_sha_context_t *ctx = (th_psa_sha_context_t*)p_context;
    return psa_driver_wrapper_hash_update(&ctx->ctx, p_in, len) == PSA_SUCCESS ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Return the digest.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_done(void *p_context, uint8_t *p_result)
{
    th_psa_sha_context_t *ctx = (th_psa_sha_context_t*)p_context;
    size_t olen;

    return psa_driver_wrapper_hash_finish(&ctx->ctx, p_result, 48, &olen) == PSA_SUCCESS ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Destroy the context created earlier.
 *
 * return EE_STATUS_OK on success.
 */
void
th_sha_destroy(void *p_context)
{
    psa_driver_wrapper_hash_abort(&((th_psa_sha_context_t*)p_context)->ctx);
    th_free(p_context);
}
