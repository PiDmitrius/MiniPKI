/* mp_crl.c - CRL parsing and accessors */
#include "mp_internal.h"

MP_API int32_t mp_crl_parse( MP_CTX ctx,
                             const uint8_t * data, size_t datalen,
                             MP_CRL * crl )
{
    struct MP_CRL_S * c;
    const uint8_t * p = data;
    X509_CRL * x;

    if( !ctx || !data || !datalen || !crl )
        return MP_ERR_INVALID_ARG;

    x = d2i_X509_CRL( NULL, &p, (long)datalen );
    if( !x )
    {
        /* Try PEM */
        BIO * bio = BIO_new_mem_buf( data, (int)datalen );
        if( !bio )
            return MP_ERR_PARSE;
        x = PEM_read_bio_X509_CRL( bio, NULL, NULL, NULL );
        BIO_free( bio );
        if( !x )
            return MP_ERR_PARSE;
    }

    c = calloc( 1, sizeof( *c ) );
    if( !c )
    {
        X509_CRL_free( x );
        return MP_ERR_UNEXPECTED;
    }

    c->crl = x;
    *crl = c;
    return MP_OK;
}

MP_API int32_t mp_crl_close( MP_CRL crl )
{
    if( !crl )
        return MP_ERR_INVALID_ARG;

    X509_CRL_free( crl->crl );
    OPENSSL_free( crl->issuer );
    free( crl );
    return MP_OK;
}

MP_API int32_t mp_crl_issuer( MP_CRL crl,
                              const uint8_t ** out, size_t * outlen )
{
    if( !crl || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !crl->issuer )
    {
        crl->issuer = X509_NAME_oneline( X509_CRL_get_issuer( crl->crl ),
                                          NULL, 0 );
        if( !crl->issuer )
            return MP_ERR_OPENSSL;
    }

    *out = (const uint8_t *)crl->issuer;
    *outlen = strlen( crl->issuer );
    return MP_OK;
}

MP_API int32_t mp_crl_this_update( MP_CRL crl, int64_t * time )
{
    struct tm tm;
    if( !crl || !time )
        return MP_ERR_INVALID_ARG;

    if( !ASN1_TIME_to_tm( X509_CRL_get0_lastUpdate( crl->crl ), &tm ) )
        return MP_ERR_OPENSSL;

    *time = (int64_t)timegm( &tm );
    return MP_OK;
}

MP_API int32_t mp_crl_next_update( MP_CRL crl, int64_t * time )
{
    struct tm tm;
    if( !crl || !time )
        return MP_ERR_INVALID_ARG;

    const ASN1_TIME * next = X509_CRL_get0_nextUpdate( crl->crl );
    if( !next )
        return MP_ERR_OPENSSL;

    if( !ASN1_TIME_to_tm( next, &tm ) )
        return MP_ERR_OPENSSL;

    *time = (int64_t)timegm( &tm );
    return MP_OK;
}

MP_API int32_t mp_crl_is_revoked( MP_CRL crl, MP_CERT cert,
                                  int32_t * result )
{
    X509_REVOKED * rev = NULL;
    if( !crl || !cert || !result )
        return MP_ERR_INVALID_ARG;

    int rc = X509_CRL_get0_by_cert( crl->crl, &rev, cert->x509 );
    *result = ( rc == 1 ) ? 1 : 0;
    return MP_OK;
}
