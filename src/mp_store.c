/* mp_store.c - Trust store and verification */
#include "mp_internal.h"

MP_API int32_t mp_store_new( MP_CTX ctx, MP_STORE * store )
{
    struct MP_STORE_S * s;

    if( !ctx || !store )
        return MP_ERR_INVALID_ARG;

    s = calloc( 1, sizeof( *s ) );
    if( !s )
        return MP_ERR_UNEXPECTED;

    s->ctx = ctx;
    s->store = X509_STORE_new();
    if( !s->store )
    {
        free( s );
        return MP_ERR_OPENSSL;
    }

    *store = s;
    return MP_OK;
}

MP_API int32_t mp_store_close( MP_STORE store )
{
    if( !store )
        return MP_ERR_INVALID_ARG;

    X509_STORE_free( store->store );
    free( store );
    return MP_OK;
}

MP_API int32_t mp_store_add_root( MP_STORE store,
                                  const uint8_t * cert, size_t certlen )
{
    const uint8_t * p = cert;
    X509 * x;

    if( !store || !cert || !certlen )
        return MP_ERR_INVALID_ARG;

    x = d2i_X509( NULL, &p, (long)certlen );
    if( !x )
        return MP_ERR_PARSE;

    if( !X509_STORE_add_cert( store->store, x ) )
    {
        X509_free( x );
        return MP_ERR_OPENSSL;
    }

    X509_free( x );
    return MP_OK;
}

MP_API int32_t mp_store_add_intermediate( MP_STORE store,
                                          const uint8_t * cert, size_t certlen )
{
    /* Same as add_root — OpenSSL X509_STORE treats them uniformly;
       chain building resolves the role */
    return mp_store_add_root( store, cert, certlen );
}

MP_API int32_t mp_store_add_crl( MP_STORE store,
                                 const uint8_t * crl, size_t crllen )
{
    const uint8_t * p = crl;
    X509_CRL * c;

    if( !store || !crl || !crllen )
        return MP_ERR_INVALID_ARG;

    c = d2i_X509_CRL( NULL, &p, (long)crllen );
    if( !c )
        return MP_ERR_PARSE;

    if( !X509_STORE_add_crl( store->store, c ) )
    {
        X509_CRL_free( c );
        return MP_ERR_OPENSSL;
    }

    X509_CRL_free( c );
    return MP_OK;
}

MP_API int32_t mp_store_set_crl_check( MP_STORE store, int32_t enable )
{
    unsigned long flags = X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;
    if( !store )
        return MP_ERR_INVALID_ARG;

    if( enable )
    {
        X509_STORE_set_flags( store->store, flags );
    }
    else
    {
        X509_VERIFY_PARAM * p = X509_STORE_get0_param( store->store );
        if( p )
            X509_VERIFY_PARAM_clear_flags( p, flags );
    }
    return MP_OK;
}

/* ── Verification ────────────────────────────────────────── */

MP_API int32_t mp_verify( MP_STORE store, MP_CERT cert,
                          MP_CHAIN * chain )
{
    X509_STORE_CTX * vctx = NULL;
    STACK_OF(X509) * verified_chain = NULL;
    struct MP_CHAIN_S * ch = NULL;
    int rc;

    if( !store || !cert || !chain )
        return MP_ERR_INVALID_ARG;

    vctx = X509_STORE_CTX_new();
    if( !vctx )
        return MP_ERR_OPENSSL;

    if( !X509_STORE_CTX_init( vctx, store->store, cert->x509, NULL ) )
    {
        X509_STORE_CTX_free( vctx );
        return MP_ERR_OPENSSL;
    }

    rc = X509_verify_cert( vctx );
    if( rc != 1 )
    {
        int err = X509_STORE_CTX_get_error( vctx );
        int depth = X509_STORE_CTX_get_error_depth( vctx );
        const char * msg = X509_verify_cert_error_string( err );

        store->last_err_code = err;
        store->last_err_depth = depth;
        if( msg )
        {
            strncpy( store->last_err_msg, msg, sizeof( store->last_err_msg ) - 1 );
            store->last_err_msg[sizeof( store->last_err_msg ) - 1] = '\0';
        }
        else
        {
            store->last_err_msg[0] = '\0';
        }

        X509_STORE_CTX_free( vctx );

        switch( err )
        {
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return MP_ERR_EXPIRED;
        case X509_V_ERR_CERT_REVOKED:
            return MP_ERR_REVOKED;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return MP_ERR_NO_CHAIN;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return MP_ERR_NO_CRL;
        default:
            return MP_ERR_VERIFY;
        }
    }

    /* Build chain result */
    verified_chain = X509_STORE_CTX_get1_chain( vctx );
    X509_STORE_CTX_free( vctx );

    if( !verified_chain )
        return MP_ERR_OPENSSL;

    size_t count = (size_t)sk_X509_num( verified_chain );

    ch = calloc( 1, sizeof( *ch ) );
    if( !ch )
    {
        sk_X509_pop_free( verified_chain, X509_free );
        return MP_ERR_UNEXPECTED;
    }

    ch->chain = verified_chain;
    ch->count = count;
    ch->certs = calloc( count, sizeof( struct MP_CERT_S ) );
    if( !ch->certs )
    {
        sk_X509_pop_free( verified_chain, X509_free );
        free( ch );
        return MP_ERR_UNEXPECTED;
    }

    /* Populate cert wrappers (no separate DER cache — on demand) */
    for( size_t i = 0; i < count; i++ )
    {
        ch->certs[i].x509 = sk_X509_value( verified_chain, (int)i );
        /* x509 ownership stays with the STACK; freed in mp_chain_close */
    }

    *chain = ch;
    return MP_OK;
}

MP_API int32_t mp_verify_last_error( MP_STORE store,
                                     int32_t * code, int32_t * depth,
                                     const uint8_t ** msg, size_t * msglen )
{
    if( !store )
        return MP_ERR_INVALID_ARG;

    if( code )
        *code = store->last_err_code;
    if( depth )
        *depth = store->last_err_depth;
    if( msg )
        *msg = (const uint8_t *)store->last_err_msg;
    if( msglen )
        *msglen = strlen( store->last_err_msg );
    return MP_OK;
}

/* ── Chain ───────────────────────────────────────────────── */

MP_API int32_t mp_chain_count( MP_CHAIN chain, size_t * count )
{
    if( !chain || !count )
        return MP_ERR_INVALID_ARG;

    *count = chain->count;
    return MP_OK;
}

MP_API int32_t mp_chain_cert( MP_CHAIN chain, size_t index,
                              MP_CERT * cert )
{
    if( !chain || !cert )
        return MP_ERR_INVALID_ARG;

    if( index >= chain->count )
        return MP_ERR_INVALID_ARG;

    *cert = &chain->certs[index];
    return MP_OK;
}

MP_API int32_t mp_chain_close( MP_CHAIN chain )
{
    if( !chain )
        return MP_ERR_INVALID_ARG;

    /* Free cached strings in cert wrappers (but not x509 — owned by stack) */
    for( size_t i = 0; i < chain->count; i++ )
    {
        OPENSSL_free( chain->certs[i].der );
        OPENSSL_free( chain->certs[i].subject );
        OPENSSL_free( chain->certs[i].issuer );
        OPENSSL_free( chain->certs[i].serial );
        free( chain->certs[i].ski );
        free( chain->certs[i].aki );
        free( chain->certs[i].key_algorithm );
        free( chain->certs[i].key_curve );
        OPENSSL_free( chain->certs[i].subject_name_der );
        OPENSSL_free( chain->certs[i].issuer_name_der );
        for( size_t j = 0; j < chain->certs[i].eku_count; j++ )
            free( chain->certs[i].eku_oids[j] );
        free( chain->certs[i].eku_oids );
        for( size_t j = 0; j < chain->certs[i].san_count; j++ )
            free( chain->certs[i].san_entries[j] );
        free( chain->certs[i].san_entries );
        for( size_t j = 0; j < chain->certs[i].aia_count; j++ )
            free( chain->certs[i].aia_urls[j] );
        free( chain->certs[i].aia_urls );
        for( size_t j = 0; j < chain->certs[i].ocsp_count; j++ )
            free( chain->certs[i].ocsp_urls[j] );
        free( chain->certs[i].ocsp_urls );
        for( size_t j = 0; j < chain->certs[i].cdp_count; j++ )
            free( chain->certs[i].cdp_urls[j] );
        free( chain->certs[i].cdp_urls );
    }

    free( chain->certs );
    sk_X509_pop_free( chain->chain, X509_free );
    free( chain );
    return MP_OK;
}
