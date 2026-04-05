/* mp_cert.c - Certificate parsing and accessors */
#include "mp_internal.h"

/* Auto-detect DER vs PEM and parse */
static X509 * parse_x509( const uint8_t * data, size_t datalen )
{
    const uint8_t * p = data;
    X509 * x = d2i_X509( NULL, &p, (long)datalen );
    if( x )
        return x;

    /* Try PEM */
    BIO * bio = BIO_new_mem_buf( data, (int)datalen );
    if( !bio )
        return NULL;
    x = PEM_read_bio_X509( bio, NULL, NULL, NULL );
    BIO_free( bio );
    return x;
}

MP_API int32_t mp_cert_parse( MP_CTX ctx,
                              const uint8_t * data, size_t datalen,
                              MP_CERT * cert )
{
    struct MP_CERT_S * c;
    X509 * x;
    uint8_t * der = NULL;
    int derlen;

    if( !ctx || !data || !datalen || !cert )
        return MP_ERR_INVALID_ARG;

    x = parse_x509( data, datalen );
    if( !x )
        return MP_ERR_PARSE;

    c = calloc( 1, sizeof( *c ) );
    if( !c )
    {
        X509_free( x );
        return MP_ERR_UNEXPECTED;
    }

    c->x509 = x;

    /* Cache DER */
    derlen = i2d_X509( x, &der );
    if( derlen > 0 )
    {
        c->der = der;
        c->derlen = (size_t)derlen;
    }

    *cert = c;
    return MP_OK;
}

MP_API int32_t mp_cert_close( MP_CERT cert )
{
    if( !cert )
        return MP_ERR_INVALID_ARG;

    X509_free( cert->x509 );
    OPENSSL_free( cert->der );
    OPENSSL_free( cert->subject );
    OPENSSL_free( cert->issuer );
    OPENSSL_free( cert->serial );
    free( cert );
    return MP_OK;
}

MP_API int32_t mp_cert_subject( MP_CERT cert,
                                const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->subject )
    {
        cert->subject = X509_NAME_oneline( X509_get_subject_name( cert->x509 ),
                                            NULL, 0 );
        if( !cert->subject )
            return MP_ERR_OPENSSL;
    }

    *out = (const uint8_t *)cert->subject;
    *outlen = strlen( cert->subject );
    return MP_OK;
}

MP_API int32_t mp_cert_issuer( MP_CERT cert,
                               const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->issuer )
    {
        cert->issuer = X509_NAME_oneline( X509_get_issuer_name( cert->x509 ),
                                           NULL, 0 );
        if( !cert->issuer )
            return MP_ERR_OPENSSL;
    }

    *out = (const uint8_t *)cert->issuer;
    *outlen = strlen( cert->issuer );
    return MP_OK;
}

MP_API int32_t mp_cert_serial( MP_CERT cert,
                               const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->serial )
    {
        BIGNUM * bn = ASN1_INTEGER_to_BN( X509_get_serialNumber( cert->x509 ), NULL );
        if( !bn )
            return MP_ERR_OPENSSL;
        cert->serial = BN_bn2hex( bn );
        BN_free( bn );
        if( !cert->serial )
            return MP_ERR_OPENSSL;
    }

    *out = (const uint8_t *)cert->serial;
    *outlen = strlen( cert->serial );
    return MP_OK;
}

MP_API int32_t mp_cert_not_before( MP_CERT cert, int64_t * time )
{
    struct tm tm;
    if( !cert || !time )
        return MP_ERR_INVALID_ARG;

    if( !ASN1_TIME_to_tm( X509_get0_notBefore( cert->x509 ), &tm ) )
        return MP_ERR_OPENSSL;

    /* Convert to epoch — timegm is POSIX */
    *time = (int64_t)timegm( &tm );
    return MP_OK;
}

MP_API int32_t mp_cert_not_after( MP_CERT cert, int64_t * time )
{
    struct tm tm;
    if( !cert || !time )
        return MP_ERR_INVALID_ARG;

    if( !ASN1_TIME_to_tm( X509_get0_notAfter( cert->x509 ), &tm ) )
        return MP_ERR_OPENSSL;

    *time = (int64_t)timegm( &tm );
    return MP_OK;
}

MP_API int32_t mp_cert_is_ca( MP_CERT cert, int32_t * result )
{
    if( !cert || !result )
        return MP_ERR_INVALID_ARG;

    *result = X509_check_ca( cert->x509 ) > 0 ? 1 : 0;
    return MP_OK;
}

MP_API int32_t mp_cert_is_self_signed( MP_CERT cert, int32_t * result )
{
    if( !cert || !result )
        return MP_ERR_INVALID_ARG;

    *result = X509_self_signed( cert->x509, 0 ) == 1 ? 1 : 0;
    return MP_OK;
}

MP_API int32_t mp_cert_aia_count( MP_CERT cert, size_t * count )
{
    AUTHORITY_INFO_ACCESS * aia;
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    aia = X509_get_ext_d2i( cert->x509, NID_info_access, NULL, NULL );
    if( !aia )
    {
        *count = 0;
        return MP_OK;
    }

    size_t n = 0;
    for( int i = 0; i < sk_ACCESS_DESCRIPTION_num( aia ); i++ )
    {
        ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value( aia, i );
        if( OBJ_obj2nid( ad->method ) == NID_ad_ca_issuers &&
            ad->location->type == GEN_URI )
            n++;
    }

    AUTHORITY_INFO_ACCESS_free( aia );
    *count = n;
    return MP_OK;
}

MP_API int32_t mp_cert_aia_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen )
{
    AUTHORITY_INFO_ACCESS * aia;
    if( !cert || !url || !urllen )
        return MP_ERR_INVALID_ARG;

    aia = X509_get_ext_d2i( cert->x509, NID_info_access, NULL, NULL );
    if( !aia )
        return MP_ERR_INVALID_ARG;

    size_t n = 0;
    int32_t rc = MP_ERR_INVALID_ARG;
    for( int i = 0; i < sk_ACCESS_DESCRIPTION_num( aia ); i++ )
    {
        ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value( aia, i );
        if( OBJ_obj2nid( ad->method ) == NID_ad_ca_issuers &&
            ad->location->type == GEN_URI )
        {
            if( n == index )
            {
                ASN1_IA5STRING * uri = ad->location->d.uniformResourceIdentifier;
                *url = ASN1_STRING_get0_data( uri );
                *urllen = ASN1_STRING_length( uri );
                rc = MP_OK;
                break;
            }
            n++;
        }
    }

    AUTHORITY_INFO_ACCESS_free( aia );
    return rc;
}

MP_API int32_t mp_cert_cdp_count( MP_CERT cert, size_t * count )
{
    CRL_DIST_POINTS * cdp;
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    cdp = X509_get_ext_d2i( cert->x509, NID_crl_distribution_points, NULL, NULL );
    if( !cdp )
    {
        *count = 0;
        return MP_OK;
    }

    size_t n = 0;
    for( int i = 0; i < sk_DIST_POINT_num( cdp ); i++ )
    {
        DIST_POINT * dp = sk_DIST_POINT_value( cdp, i );
        if( dp->distpoint && dp->distpoint->type == 0 )
        {
            GENERAL_NAMES * names = dp->distpoint->name.fullname;
            for( int j = 0; j < sk_GENERAL_NAME_num( names ); j++ )
            {
                GENERAL_NAME * gn = sk_GENERAL_NAME_value( names, j );
                if( gn->type == GEN_URI )
                    n++;
            }
        }
    }

    CRL_DIST_POINTS_free( cdp );
    *count = n;
    return MP_OK;
}

MP_API int32_t mp_cert_cdp_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen )
{
    CRL_DIST_POINTS * cdp;
    if( !cert || !url || !urllen )
        return MP_ERR_INVALID_ARG;

    cdp = X509_get_ext_d2i( cert->x509, NID_crl_distribution_points, NULL, NULL );
    if( !cdp )
        return MP_ERR_INVALID_ARG;

    size_t n = 0;
    int32_t rc = MP_ERR_INVALID_ARG;
    for( int i = 0; i < sk_DIST_POINT_num( cdp ) && rc != MP_OK; i++ )
    {
        DIST_POINT * dp = sk_DIST_POINT_value( cdp, i );
        if( dp->distpoint && dp->distpoint->type == 0 )
        {
            GENERAL_NAMES * names = dp->distpoint->name.fullname;
            for( int j = 0; j < sk_GENERAL_NAME_num( names ); j++ )
            {
                GENERAL_NAME * gn = sk_GENERAL_NAME_value( names, j );
                if( gn->type == GEN_URI )
                {
                    if( n == index )
                    {
                        ASN1_IA5STRING * uri = gn->d.uniformResourceIdentifier;
                        *url = ASN1_STRING_get0_data( uri );
                        *urllen = ASN1_STRING_length( uri );
                        rc = MP_OK;
                        break;
                    }
                    n++;
                }
            }
        }
    }

    CRL_DIST_POINTS_free( cdp );
    return rc;
}

MP_API int32_t mp_cert_der( MP_CERT cert,
                            const uint8_t ** der, size_t * derlen )
{
    if( !cert || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->der )
        return MP_ERR_UNEXPECTED;

    *der = cert->der;
    *derlen = cert->derlen;
    return MP_OK;
}
