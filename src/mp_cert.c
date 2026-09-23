/* mp_cert.c - Certificate parsing and accessors */
#include "mp_internal.h"

static const char hex_digits[] = "0123456789ABCDEF";

char * mp_octet_to_hex( const ASN1_OCTET_STRING * oct )
{
    int len;
    const unsigned char * data;
    char * hex;

    if( !oct )
        return NULL;

    data = ASN1_STRING_get0_data( oct );
    len  = ASN1_STRING_length( oct );
    if( len <= 0 )
        return NULL;

    hex = malloc( (size_t)len * 2 + 1 );
    if( !hex )
        return NULL;

    for( int i = 0; i < len; i++ )
    {
        hex[i * 2]     = hex_digits[data[i] >> 4];
        hex[i * 2 + 1] = hex_digits[data[i] & 0x0F];
    }
    hex[len * 2] = '\0';
    return hex;
}

/* Append a single X509 (as DER) to bag */
static int bag_append( struct MP_BAG_S * bag, X509 * x )
{
    uint8_t * der = NULL;
    int len = i2d_X509( x, &der );
    if( len <= 0 )
        return 0;

    uint8_t ** new_ders = realloc( bag->ders, ( bag->count + 1 ) * sizeof( uint8_t * ) );
    if( !new_ders ) { OPENSSL_free( der ); return 0; }
    bag->ders = new_ders;

    size_t * new_lens = realloc( bag->derlens, ( bag->count + 1 ) * sizeof( size_t ) );
    if( !new_lens ) { OPENSSL_free( der ); return 0; }
    bag->derlens = new_lens;

    bag->ders[bag->count] = der;
    bag->derlens[bag->count] = (size_t)len;
    bag->count++;
    return 1;
}

static void bag_append_pkcs7_certs( struct MP_BAG_S * bag, PKCS7 * p7 )
{
    STACK_OF(X509) * certs = NULL;
    int nid = OBJ_obj2nid( p7->type );

    if( nid == NID_pkcs7_signed && p7->d.sign )
        certs = p7->d.sign->cert;
    else if( nid == NID_pkcs7_signedAndEnveloped && p7->d.signed_and_enveloped )
        certs = p7->d.signed_and_enveloped->cert;

    if( !certs )
        return;

    int n = sk_X509_num( certs );
    for( int i = 0; i < n; i++ )
        bag_append( bag, sk_X509_value( certs, i ) );
}

MP_API int32_t mp_bag_parse( MP_CTX ctx,
                             const uint8_t * data, size_t datalen,
                             MP_BAG * out )
{
    struct MP_BAG_S * bag;

    if( !ctx || !data || !datalen || !out )
        return MP_ERR_INVALID_ARG;

    bag = calloc( 1, sizeof( *bag ) );
    if( !bag )
        return MP_ERR_UNEXPECTED;

    /* Try DER X.509 (single cert) */
    const uint8_t * p;
    X509 * x = mp_d2i_x509( data, datalen );
    if( x )
    {
        bag_append( bag, x );
        X509_free( x );
        *out = bag;
        return MP_OK;
    }

    /* Try PEM X.509 (one or many concatenated) */
    BIO * bio = BIO_new_mem_buf( data, (int)datalen );
    if( bio )
    {
        while( ( x = PEM_read_bio_X509( bio, NULL, NULL, NULL ) ) != NULL )
        {
            bag_append( bag, x );
            X509_free( x );
        }
        BIO_free( bio );
    }
    if( bag->count > 0 )
    {
        *out = bag;
        return MP_OK;
    }

    /* Try PKCS#7 DER */
    p = data;
    PKCS7 * p7 = d2i_PKCS7( NULL, &p, (long)datalen );
    if( !p7 )
    {
        bio = BIO_new_mem_buf( data, (int)datalen );
        if( bio )
        {
            p7 = PEM_read_bio_PKCS7( bio, NULL, NULL, NULL );
            BIO_free( bio );
        }
    }
    if( p7 )
    {
        bag_append_pkcs7_certs( bag, p7 );
        PKCS7_free( p7 );
    }

    if( bag->count == 0 )
    {
        free( bag );
        return MP_ERR_PARSE;
    }

    *out = bag;
    return MP_OK;
}

MP_API int32_t mp_bag_count( MP_BAG bag, size_t * count )
{
    if( !bag || !count )
        return MP_ERR_INVALID_ARG;
    *count = bag->count;
    return MP_OK;
}

MP_API int32_t mp_bag_cert_der( MP_BAG bag, size_t index,
                                const uint8_t ** der, size_t * derlen )
{
    if( !bag || !der || !derlen || index >= bag->count )
        return MP_ERR_INVALID_ARG;
    *der = bag->ders[index];
    *derlen = bag->derlens[index];
    return MP_OK;
}

MP_API int32_t mp_bag_close( MP_BAG bag )
{
    if( !bag )
        return MP_ERR_INVALID_ARG;
    for( size_t i = 0; i < bag->count; i++ )
        OPENSSL_free( bag->ders[i] );
    free( bag->ders );
    free( bag->derlens );
    free( bag );
    return MP_OK;
}

/* Extract first X509 from a PKCS#7 structure */
static X509 * extract_from_pkcs7( PKCS7 * p7 )
{
    STACK_OF(X509) * certs = NULL;
    int nid = OBJ_obj2nid( p7->type );

    if( nid == NID_pkcs7_signed && p7->d.sign )
        certs = p7->d.sign->cert;
    else if( nid == NID_pkcs7_signedAndEnveloped && p7->d.signed_and_enveloped )
        certs = p7->d.signed_and_enveloped->cert;

    if( certs && sk_X509_num( certs ) > 0 )
        return X509_dup( sk_X509_value( certs, 0 ) );

    return NULL;
}

/* Try raw base64: decode and parse as DER */
static X509 * try_base64_x509( const uint8_t * data, size_t datalen )
{
    /* Skip whitespace, check if it looks like base64 */
    size_t i = 0;
    while( i < datalen && ( data[i] == ' ' || data[i] == '\t' ||
                            data[i] == '\r' || data[i] == '\n' ) )
        i++;
    if( i >= datalen )
        return NULL;

    /* Quick check: base64 starts with alphanumeric, +, / */
    uint8_t c = data[i];
    if( !( ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) ||
           ( c >= '0' && c <= '9' ) || c == '+' || c == '/' ) )
        return NULL;

    /* Reject if it looks like PEM (already tried above) */
    if( datalen > 10 && memcmp( data + i, "-----", 5 ) == 0 )
        return NULL;

    BIO * b64 = BIO_new( BIO_f_base64() );
    if( !b64 )
        return NULL;
    BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );

    BIO * bio = BIO_new_mem_buf( data + i, (int)( datalen - i ) );
    if( !bio )
    {
        BIO_free( b64 );
        return NULL;
    }
    bio = BIO_push( b64, bio );

    uint8_t * buf = malloc( datalen );
    if( !buf )
    {
        BIO_free_all( bio );
        return NULL;
    }

    int len = BIO_read( bio, buf, (int)datalen );
    BIO_free_all( bio );

    X509 * x = NULL;
    if( len > 0 )
        x = mp_d2i_x509( buf, (size_t)len );
    free( buf );
    return x;
}

/* Auto-detect DER, PEM, raw base64, or PKCS#7 and parse */
X509 * mp_d2i_x509( const uint8_t * data, size_t datalen )
{
    const uint8_t * p = data;
    X509 * x = d2i_X509( NULL, &p, (long)datalen );
    if( x && p != data + datalen )
    {
        X509_free( x );
        return NULL;
    }
    return x;
}

static X509 * parse_x509( const uint8_t * data, size_t datalen )
{
    const uint8_t * p;
    X509 * x = mp_d2i_x509( data, datalen );
    if( x )
        return x;

    /* Try PEM X.509 */
    BIO * bio = BIO_new_mem_buf( data, (int)datalen );
    if( !bio )
        return NULL;
    x = PEM_read_bio_X509( bio, NULL, NULL, NULL );
    BIO_free( bio );
    if( x )
        return x;

    /* Try raw base64 (no PEM headers) */
    x = try_base64_x509( data, datalen );
    if( x )
        return x;

    /* Try PKCS#7 DER */
    p = data;
    PKCS7 * p7 = d2i_PKCS7( NULL, &p, (long)datalen );
    if( p7 )
    {
        x = extract_from_pkcs7( p7 );
        PKCS7_free( p7 );
        if( x )
            return x;
    }

    /* Try PKCS#7 PEM */
    bio = BIO_new_mem_buf( data, (int)datalen );
    if( bio )
    {
        p7 = PEM_read_bio_PKCS7( bio, NULL, NULL, NULL );
        BIO_free( bio );
        if( p7 )
        {
            x = extract_from_pkcs7( p7 );
            PKCS7_free( p7 );
        }
    }

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
    free( cert->ski );
    free( cert->aki );
    free( cert->key_algorithm );
    free( cert->key_curve );
    OPENSSL_free( cert->subject_name_der );
    OPENSSL_free( cert->issuer_name_der );

    for( size_t i = 0; i < cert->eku_count; i++ )
        free( cert->eku_oids[i] );
    free( cert->eku_oids );

    for( size_t i = 0; i < cert->san_count; i++ )
        free( cert->san_entries[i] );
    free( cert->san_entries );

    for( size_t i = 0; i < cert->aia_count; i++ )
        free( cert->aia_urls[i] );
    free( cert->aia_urls );

    for( size_t i = 0; i < cert->ocsp_count; i++ )
        free( cert->ocsp_urls[i] );
    free( cert->ocsp_urls );

    for( size_t i = 0; i < cert->cdp_count; i++ )
        free( cert->cdp_urls[i] );
    free( cert->cdp_urls );

    free( cert );
    return MP_OK;
}

char * format_name( X509_NAME * name )
{
    BIO * bio;
    char * data;
    char * result;
    long len;

    bio = BIO_new( BIO_s_mem() );
    if( !bio )
        return NULL;

    /* XN_FLAG_ONELINE but with UTF-8 pass-through (no \xHH escaping) */
    X509_NAME_print_ex( bio, name, 0,
                        ( XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB ) );

    len = BIO_get_mem_data( bio, &data );
    result = OPENSSL_malloc( (size_t)len + 1 );
    if( result )
    {
        memcpy( result, data, (size_t)len );
        result[len] = '\0';
    }
    BIO_free( bio );
    return result;
}

MP_API int32_t mp_cert_subject( MP_CERT cert,
                                const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->subject )
    {
        cert->subject = format_name( X509_get_subject_name( cert->x509 ) );
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
        cert->issuer = format_name( X509_get_issuer_name( cert->x509 ) );
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

MP_API int32_t mp_cert_key_algorithm( MP_CERT cert,
                                       const uint8_t ** name, size_t * namelen )
{
    if( !cert || !name || !namelen )
        return MP_ERR_INVALID_ARG;

    if( !cert->key_algorithm )
    {
        X509_PUBKEY * pub = X509_get_X509_PUBKEY( cert->x509 );
        ASN1_OBJECT * oid = NULL;
        if( pub && X509_PUBKEY_get0_param( &oid, NULL, NULL, NULL, pub ) && oid )
        {
            char buf[128];
            int len = OBJ_obj2txt( buf, (int)sizeof( buf ), oid, 1 );
            if( len > 0 )
            {
                cert->key_algorithm = malloc( (size_t)len + 1 );
                if( cert->key_algorithm )
                {
                    memcpy( cert->key_algorithm, buf, (size_t)len );
                    cert->key_algorithm[len] = '\0';
                }
            }
        }
    }

    if( !cert->key_algorithm )
    {
        *name = (const uint8_t *)"";
        *namelen = 0;
        return MP_OK;
    }
    *name = (const uint8_t *)cert->key_algorithm;
    *namelen = strlen( cert->key_algorithm );
    return MP_OK;
}

MP_API int32_t mp_cert_key_bits( MP_CERT cert, int32_t * bits )
{
    EVP_PKEY * pkey;
    if( !cert || !bits )
        return MP_ERR_INVALID_ARG;

    if( !cert->key_bits_cached )
    {
        pkey = X509_get0_pubkey( cert->x509 );
        cert->key_bits = pkey ? EVP_PKEY_get_bits( pkey ) : 0;
        cert->key_bits_cached = 1;
    }

    *bits = cert->key_bits;
    return MP_OK;
}

MP_API int32_t mp_cert_key_curve( MP_CERT cert,
                                   const uint8_t ** name, size_t * namelen )
{
    EVP_PKEY * pkey;
    char buf[128];
    size_t outlen = 0;

    if( !cert || !name || !namelen )
        return MP_ERR_INVALID_ARG;

    if( !cert->key_curve_cached )
    {
        cert->key_curve_cached = 1;
        pkey = X509_get0_pubkey( cert->x509 );
        if( pkey &&
            EVP_PKEY_get_group_name( pkey, buf, sizeof( buf ), &outlen ) == 1 )
        {
            cert->key_curve = malloc( outlen + 1 );
            if( cert->key_curve )
            {
                memcpy( cert->key_curve, buf, outlen );
                cert->key_curve[outlen] = '\0';
            }
        }
    }

    if( !cert->key_curve )
    {
        *name = (const uint8_t *)"";
        *namelen = 0;
        return MP_OK;
    }
    *name = (const uint8_t *)cert->key_curve;
    *namelen = strlen( cert->key_curve );
    return MP_OK;
}

MP_API int32_t mp_cert_key_usage( MP_CERT cert, uint32_t * usage )
{
    if( !cert || !usage )
        return MP_ERR_INVALID_ARG;

    if( !cert->key_usage_cached )
    {
        cert->key_usage = X509_get_key_usage( cert->x509 );
        cert->key_usage_cached = 1;
    }

    *usage = cert->key_usage;
    return MP_OK;
}

static void mp_cert_cache_eku( MP_CERT cert )
{
    EXTENDED_KEY_USAGE * eku;
    if( cert->eku_cached )
        return;
    cert->eku_cached = 1;

    eku = X509_get_ext_d2i( cert->x509, NID_ext_key_usage, NULL, NULL );
    if( !eku )
        return;

    int n = sk_ASN1_OBJECT_num( eku );
    if( n <= 0 )
    {
        EXTENDED_KEY_USAGE_free( eku );
        return;
    }

    cert->eku_oids = calloc( (size_t)n, sizeof( char * ) );
    if( !cert->eku_oids )
    {
        EXTENDED_KEY_USAGE_free( eku );
        return;
    }

    for( int i = 0; i < n; i++ )
    {
        ASN1_OBJECT * obj = sk_ASN1_OBJECT_value( eku, i );
        char buf[128];
        /* always return raw OID, frontend resolves names */
        int len = OBJ_obj2txt( buf, (int)sizeof( buf ), obj, 1 );
        if( len > 0 )
        {
            cert->eku_oids[i] = malloc( (size_t)len + 1 );
            if( cert->eku_oids[i] )
            {
                memcpy( cert->eku_oids[i], buf, (size_t)len );
                cert->eku_oids[i][len] = '\0';
            }
        }
    }
    cert->eku_count = (size_t)n;

    EXTENDED_KEY_USAGE_free( eku );
}

MP_API int32_t mp_cert_eku_count( MP_CERT cert, size_t * count )
{
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_eku( cert );
    *count = cert->eku_count;
    return MP_OK;
}

MP_API int32_t mp_cert_eku_oid( MP_CERT cert, size_t index,
                                const uint8_t ** oid, size_t * oidlen )
{
    if( !cert || !oid || !oidlen )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_eku( cert );
    if( index >= cert->eku_count )
        return MP_ERR_INVALID_ARG;

    *oid = (const uint8_t *)cert->eku_oids[index];
    *oidlen = strlen( cert->eku_oids[index] );
    return MP_OK;
}

MP_API int32_t mp_cert_pathlen( MP_CERT cert, int32_t * pathlen )
{
    if( !cert || !pathlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->pathlen_cached )
    {
        long pl = X509_get_pathlen( cert->x509 );
        cert->pathlen = ( pl >= 0 ) ? (int32_t)pl : -1;
        cert->pathlen_cached = 1;
    }

    *pathlen = cert->pathlen;
    return MP_OK;
}

MP_API int32_t mp_cert_ski( MP_CERT cert,
                            const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->ski )
    {
        const ASN1_OCTET_STRING * ext = X509_get0_subject_key_id( cert->x509 );
        if( ext )
            cert->ski = mp_octet_to_hex( ext );
    }

    if( cert->ski )
    {
        *out = (const uint8_t *)cert->ski;
        *outlen = strlen( cert->ski );
    }
    else
    {
        *out = (const uint8_t *)"";
        *outlen = 0;
    }
    return MP_OK;
}

MP_API int32_t mp_cert_aki( MP_CERT cert,
                            const uint8_t ** out, size_t * outlen )
{
    if( !cert || !out || !outlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->aki )
    {
        const ASN1_OCTET_STRING * ext = X509_get0_authority_key_id( cert->x509 );
        if( ext )
            cert->aki = mp_octet_to_hex( ext );
    }

    if( cert->aki )
    {
        *out = (const uint8_t *)cert->aki;
        *outlen = strlen( cert->aki );
    }
    else
    {
        *out = (const uint8_t *)"";
        *outlen = 0;
    }
    return MP_OK;
}

MP_API int32_t mp_cert_subject_name_der( MP_CERT cert,
                                          const uint8_t ** der, size_t * derlen )
{
    if( !cert || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->subject_name_der )
    {
        X509_NAME * name = X509_get_subject_name( cert->x509 );
        if( !name )
            return MP_ERR_OPENSSL;

        uint8_t * buf = NULL;
        int len = i2d_X509_NAME( name, &buf );
        if( len <= 0 )
            return MP_ERR_OPENSSL;

        cert->subject_name_der    = buf;
        cert->subject_name_derlen = (size_t)len;
    }

    *der    = cert->subject_name_der;
    *derlen = cert->subject_name_derlen;
    return MP_OK;
}

MP_API int32_t mp_cert_issuer_name_der( MP_CERT cert,
                                         const uint8_t ** der, size_t * derlen )
{
    if( !cert || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->issuer_name_der )
    {
        X509_NAME * name = X509_get_issuer_name( cert->x509 );
        if( !name )
            return MP_ERR_OPENSSL;

        uint8_t * buf = NULL;
        int len = i2d_X509_NAME( name, &buf );
        if( len <= 0 )
            return MP_ERR_OPENSSL;

        cert->issuer_name_der    = buf;
        cert->issuer_name_derlen = (size_t)len;
    }

    *der    = cert->issuer_name_der;
    *derlen = cert->issuer_name_derlen;
    return MP_OK;
}

static void mp_cert_cache_san( MP_CERT cert )
{
    GENERAL_NAMES * gens;
    if( cert->san_cached )
        return;
    cert->san_cached = 1;

    gens = X509_get_ext_d2i( cert->x509, NID_subject_alt_name, NULL, NULL );
    if( !gens )
        return;

    int n = sk_GENERAL_NAME_num( gens );
    if( n <= 0 )
    {
        GENERAL_NAMES_free( gens );
        return;
    }

    cert->san_entries = calloc( (size_t)n, sizeof( char * ) );
    if( !cert->san_entries )
    {
        GENERAL_NAMES_free( gens );
        return;
    }

    size_t idx = 0;
    for( int i = 0; i < n; i++ )
    {
        GENERAL_NAME * gn = sk_GENERAL_NAME_value( gens, i );
        BIO * bio = BIO_new( BIO_s_mem() );
        if( !bio )
            continue;
        GENERAL_NAME_print( bio, gn );

        char * data;
        long len = BIO_get_mem_data( bio, &data );
        if( len > 0 )
        {
            cert->san_entries[idx] = malloc( (size_t)len + 1 );
            if( cert->san_entries[idx] )
            {
                memcpy( cert->san_entries[idx], data, (size_t)len );
                cert->san_entries[idx][len] = '\0';
                idx++;
            }
        }
        BIO_free( bio );
    }
    cert->san_count = idx;

    GENERAL_NAMES_free( gens );
}

MP_API int32_t mp_cert_san_count( MP_CERT cert, size_t * count )
{
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_san( cert );
    *count = cert->san_count;
    return MP_OK;
}

MP_API int32_t mp_cert_san_entry( MP_CERT cert, size_t index,
                                  const uint8_t ** value, size_t * valuelen )
{
    if( !cert || !value || !valuelen )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_san( cert );
    if( index >= cert->san_count )
        return MP_ERR_INVALID_ARG;

    *value = (const uint8_t *)cert->san_entries[index];
    *valuelen = strlen( cert->san_entries[index] );
    return MP_OK;
}

static void mp_cert_cache_aia_all( MP_CERT cert )
{
    AUTHORITY_INFO_ACCESS * aia;
    if( cert->aia_cached && cert->ocsp_cached )
        return;
    cert->aia_cached = 1;
    cert->ocsp_cached = 1;

    aia = X509_get_ext_d2i( cert->x509, NID_info_access, NULL, NULL );
    if( !aia )
        return;

    size_t n_aia = 0, n_ocsp = 0;
    for( int i = 0; i < sk_ACCESS_DESCRIPTION_num( aia ); i++ )
    {
        ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value( aia, i );
        if( ad->location->type != GEN_URI )
            continue;
        int nid = OBJ_obj2nid( ad->method );
        if( nid == NID_ad_ca_issuers ) n_aia++;
        else if( nid == NID_ad_OCSP ) n_ocsp++;
    }

    if( n_aia > 0 )
        cert->aia_urls = calloc( n_aia, sizeof( char * ) );
    if( n_ocsp > 0 )
        cert->ocsp_urls = calloc( n_ocsp, sizeof( char * ) );

    size_t idx_aia = 0, idx_ocsp = 0;
    for( int i = 0; i < sk_ACCESS_DESCRIPTION_num( aia ); i++ )
    {
        ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value( aia, i );
        if( ad->location->type != GEN_URI )
            continue;
        int nid = OBJ_obj2nid( ad->method );

        char ** target = NULL;
        size_t * idx = NULL;
        if( nid == NID_ad_ca_issuers && cert->aia_urls )
        {
            target = cert->aia_urls;
            idx = &idx_aia;
        }
        else if( nid == NID_ad_OCSP && cert->ocsp_urls )
        {
            target = cert->ocsp_urls;
            idx = &idx_ocsp;
        }
        if( !target )
            continue;

        ASN1_IA5STRING * uri = ad->location->d.uniformResourceIdentifier;
        int len = ASN1_STRING_length( uri );
        target[*idx] = malloc( (size_t)len + 1 );
        if( target[*idx] )
        {
            memcpy( target[*idx], ASN1_STRING_get0_data( uri ), (size_t)len );
            target[*idx][len] = '\0';
        }
        ( *idx )++;
    }
    cert->aia_count = idx_aia;
    cert->ocsp_count = idx_ocsp;

    AUTHORITY_INFO_ACCESS_free( aia );
}

MP_API int32_t mp_cert_aia_count( MP_CERT cert, size_t * count )
{
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_aia_all( cert );
    *count = cert->aia_count;
    return MP_OK;
}

MP_API int32_t mp_cert_aia_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen )
{
    if( !cert || !url || !urllen )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_aia_all( cert );
    if( index >= cert->aia_count )
        return MP_ERR_INVALID_ARG;

    *url = (const uint8_t *)cert->aia_urls[index];
    *urllen = strlen( cert->aia_urls[index] );
    return MP_OK;
}

MP_API int32_t mp_cert_ocsp_count( MP_CERT cert, size_t * count )
{
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_aia_all( cert );
    *count = cert->ocsp_count;
    return MP_OK;
}

MP_API int32_t mp_cert_ocsp_url( MP_CERT cert, size_t index,
                                 const uint8_t ** url, size_t * urllen )
{
    if( !cert || !url || !urllen )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_aia_all( cert );
    if( index >= cert->ocsp_count )
        return MP_ERR_INVALID_ARG;

    *url = (const uint8_t *)cert->ocsp_urls[index];
    *urllen = strlen( cert->ocsp_urls[index] );
    return MP_OK;
}

static void mp_cert_cache_cdp( MP_CERT cert )
{
    CRL_DIST_POINTS * cdp;
    if( cert->cdp_cached )
        return;
    cert->cdp_cached = 1;

    cdp = X509_get_ext_d2i( cert->x509, NID_crl_distribution_points, NULL, NULL );
    if( !cdp )
        return;

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

    cert->cdp_urls = calloc( n, sizeof( char * ) );
    if( !cert->cdp_urls )
    {
        CRL_DIST_POINTS_free( cdp );
        return;
    }

    size_t idx = 0;
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
                {
                    ASN1_IA5STRING * uri = gn->d.uniformResourceIdentifier;
                    int len = ASN1_STRING_length( uri );
                    cert->cdp_urls[idx] = malloc( (size_t)len + 1 );
                    if( cert->cdp_urls[idx] )
                    {
                        memcpy( cert->cdp_urls[idx], ASN1_STRING_get0_data( uri ),
                                (size_t)len );
                        cert->cdp_urls[idx][len] = '\0';
                    }
                    idx++;
                }
            }
        }
    }
    cert->cdp_count = idx;

    CRL_DIST_POINTS_free( cdp );
}

MP_API int32_t mp_cert_cdp_count( MP_CERT cert, size_t * count )
{
    if( !cert || !count )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_cdp( cert );
    *count = cert->cdp_count;
    return MP_OK;
}

MP_API int32_t mp_cert_cdp_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen )
{
    if( !cert || !url || !urllen )
        return MP_ERR_INVALID_ARG;

    mp_cert_cache_cdp( cert );
    if( index >= cert->cdp_count )
        return MP_ERR_INVALID_ARG;

    *url = (const uint8_t *)cert->cdp_urls[index];
    *urllen = strlen( cert->cdp_urls[index] );
    return MP_OK;
}

MP_API int32_t mp_cert_der( MP_CERT cert,
                            const uint8_t ** der, size_t * derlen )
{
    if( !cert || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !cert->der )
    {
        uint8_t * buf = NULL;
        int len = i2d_X509( cert->x509, &buf );
        if( len <= 0 )
            return MP_ERR_OPENSSL;
        cert->der = buf;
        cert->derlen = (size_t)len;
    }

    *der = cert->der;
    *derlen = cert->derlen;
    return MP_OK;
}
