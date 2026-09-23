/* mp_crl.c - CRL parsing and accessors */
#include "mp_internal.h"
#include <limits.h>

X509_CRL * mp_d2i_crl( const uint8_t * data, size_t datalen )
{
    const uint8_t * p = data;
    X509_CRL * x = d2i_X509_CRL( NULL, &p, (long)datalen );
    if( x && p != data + datalen )
    {
        X509_CRL_free( x );
        return NULL;
    }
    return x;
}

MP_API int32_t mp_crl_parse( MP_CTX ctx,
                             const uint8_t * data, size_t datalen,
                             MP_CRL * crl )
{
    struct MP_CRL_S * c;
    X509_CRL * x;

    if( !ctx || !data || !datalen || datalen > INT_MAX || !crl )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    if( mp_is_binary( data, datalen ) )
        x = mp_d2i_crl( data, datalen );
    else
    {
        x = NULL;
        BIO * bio = BIO_new_mem_buf( data, (int)datalen );
        if( bio )
        {
            x = PEM_read_bio_X509_CRL( bio, NULL, NULL, NULL );
            BIO_free( bio );
        }
    }
    ERR_pop_to_mark();
    if( !x )
        return MP_ERR_PARSE;

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

MP_API int32_t mp_crl_der( MP_CRL crl,
                           const uint8_t ** der, size_t * derlen )
{
    if( !crl || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !crl->der )
    {
        uint8_t * buf = NULL;
        int len = i2d_X509_CRL( crl->crl, &buf );
        if( len <= 0 )
            return MP_ERR_OPENSSL;
        crl->der = buf;
        crl->derlen = (size_t)len;
    }

    *der = crl->der;
    *derlen = crl->derlen;
    return MP_OK;
}

MP_API int32_t mp_crl_close( MP_CRL crl )
{
    if( !crl )
        return MP_ERR_INVALID_ARG;

    X509_CRL_free( crl->crl );
    OPENSSL_free( crl->der );
    OPENSSL_free( crl->issuer );
    OPENSSL_free( crl->issuer_name_der );
    free( crl->aki );
    free( crl );
    return MP_OK;
}

MP_API int32_t mp_crl_issuer_name_der( MP_CRL crl,
                                       const uint8_t ** der, size_t * derlen )
{
    if( !crl || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !crl->issuer_name_der )
    {
        X509_NAME * name = X509_CRL_get_issuer( crl->crl );
        if( !name )
            return MP_ERR_OPENSSL;

        uint8_t * buf = NULL;
        int len = i2d_X509_NAME( name, &buf );
        if( len <= 0 )
            return MP_ERR_OPENSSL;

        crl->issuer_name_der = buf;
        crl->issuer_name_derlen = (size_t)len;
    }

    *der = crl->issuer_name_der;
    *derlen = crl->issuer_name_derlen;
    return MP_OK;
}

MP_API int32_t mp_crl_issuer( MP_CRL crl,
                              const uint8_t ** out, size_t * outlen )
{
    if( !crl || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !crl->issuer )
    {
        crl->issuer = format_name( X509_CRL_get_issuer( crl->crl ) );
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
    {
        *time = 0;
        return MP_OK;
    }

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

MP_API int32_t mp_crl_revoked_count( MP_CRL crl, size_t * count )
{
    STACK_OF(X509_REVOKED) * rev;
    if( !crl || !count )
        return MP_ERR_INVALID_ARG;

    rev = X509_CRL_get_REVOKED( crl->crl );
    *count = rev ? (size_t)sk_X509_REVOKED_num( rev ) : 0;
    return MP_OK;
}

MP_API int32_t mp_crl_aki( MP_CRL crl,
                           const uint8_t ** out, size_t * outlen )
{
    if( !crl || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !crl->aki )
    {
        AUTHORITY_KEYID * akid = X509_CRL_get_ext_d2i( crl->crl,
                                                      NID_authority_key_identifier,
                                                      NULL, NULL );
        if( akid )
        {
            if( akid->keyid )
                crl->aki = mp_octet_to_hex( akid->keyid );
            AUTHORITY_KEYID_free( akid );
        }
    }

    if( crl->aki )
    {
        *out = (const uint8_t *)crl->aki;
        *outlen = strlen( crl->aki );
    }
    else
    {
        *out = (const uint8_t *)"";
        *outlen = 0;
    }
    return MP_OK;
}

MP_API int32_t mp_crl_has_idp( MP_CRL crl, int32_t * has )
{
    if( !crl || !has )
        return MP_ERR_INVALID_ARG;

    *has = ( X509_CRL_get_ext_by_NID( crl->crl,
                                      NID_issuing_distribution_point,
                                      -1 ) >= 0 ) ? 1 : 0;
    return MP_OK;
}

MP_API int32_t mp_crl_verify( MP_CRL crl, MP_CERT issuer )
{
    EVP_PKEY * pkey;
    int rc;

    if( !crl || !issuer )
        return MP_ERR_INVALID_ARG;

    pkey = X509_get0_pubkey( issuer->x509 );
    if( !pkey )
        return MP_ERR_OPENSSL;

    rc = X509_CRL_verify( crl->crl, pkey );
    if( rc == 1 )
        return MP_OK;
    if( rc == 0 )
        return MP_ERR_VERIFY;
    return MP_ERR_OPENSSL;
}
