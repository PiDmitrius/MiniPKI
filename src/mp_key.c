/* mp_key.c - signing keys: GOST R 34.10-2012 and PKCS#8 */
#include "mp_internal.h"
#include <limits.h>

/* GOST keys are GOST engine keys whose EC_KEY is reached through the
   deprecated EVP_PKEY_get0. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* A GOST engine key of the raw length rawlen, 256-bit on the CryptoPro-A
   parameter set or 512-bit on TC26 A: a fresh one, or with raw, the one
   with that private scalar and its public point. */
static int32_t key_make( const uint8_t * raw, size_t rawlen, MP_KEY * key )
{
    EVP_PKEY_CTX * pctx;
    EVP_PKEY * pkey = NULL;
    struct MP_KEY_S * k;
    int ok;

    ERR_set_mark();
    pctx = EVP_PKEY_CTX_new_id( rawlen == MP_KEY_RAW_LEN ? NID_id_GostR3410_2012_256
                                                         : NID_id_GostR3410_2012_512, NULL );
    ok = pctx != NULL;
    if( raw )
        ok = ok && EVP_PKEY_paramgen_init( pctx ) > 0 &&
             EVP_PKEY_CTX_ctrl_str( pctx, "paramset", "A" ) > 0 &&
             EVP_PKEY_paramgen( pctx, &pkey ) > 0;
    else
        ok = ok && EVP_PKEY_keygen_init( pctx ) > 0 &&
             EVP_PKEY_CTX_ctrl_str( pctx, "paramset", "A" ) > 0 &&
             EVP_PKEY_keygen( pctx, &pkey ) > 0;
    EVP_PKEY_CTX_free( pctx );

    EC_KEY * ec = ok ? EVP_PKEY_get0( pkey ) : NULL;
    const EC_GROUP * group = ec ? EC_KEY_get0_group( ec ) : NULL;
    ok = group != NULL;
    if( ok && raw )
    {
        BIGNUM * d = BN_lebin2bn( raw, (int)rawlen, BN_secure_new() );
        EC_POINT * q = EC_POINT_new( group );
        ok = d && q && !BN_is_zero( d ) &&
             BN_cmp( d, EC_GROUP_get0_order( group ) ) < 0 &&
             EC_POINT_mul( group, q, d, NULL, NULL, NULL ) &&
             EC_KEY_set_private_key( ec, d ) &&
             EC_KEY_set_public_key( ec, q );
        BN_clear_free( d );
        EC_POINT_free( q );
    }

    k = ok ? calloc( 1, sizeof( *k ) ) : NULL;
    if( !k ||
        BN_bn2lebinpad( EC_KEY_get0_private_key( ec ),
                        k->raw, (int)rawlen ) != (int)rawlen )
    {
        ERR_pop_to_mark();
        free( k );
        EVP_PKEY_free( pkey );
        return ok ? MP_ERR_UNEXPECTED : MP_ERR_OPENSSL;
    }
    ERR_pop_to_mark();

    k->pkey = pkey;
    k->gost = 1;
    k->rawlen = rawlen;
    *key = k;
    return MP_OK;
}

MP_API int32_t mp_key_generate( MP_CTX ctx, MP_KEY * key )
{
    if( !ctx || !key )
        return MP_ERR_INVALID_ARG;
    return key_make( NULL, MP_KEY_RAW_LEN, key );
}

MP_API int32_t mp_key_generate_gost( MP_CTX ctx, int32_t bits, MP_KEY * key )
{
    if( !ctx || ( bits != 256 && bits != 512 ) || !key )
        return MP_ERR_INVALID_ARG;
    return key_make( NULL, bits == 256 ? MP_KEY_RAW_LEN : MP_KEY_RAW_LEN_512, key );
}

MP_API int32_t mp_key_import( MP_CTX ctx,
                              const uint8_t * raw, size_t rawlen,
                              MP_KEY * key )
{
    if( !ctx || !raw || ( rawlen != MP_KEY_RAW_LEN && rawlen != MP_KEY_RAW_LEN_512 ) || !key )
        return MP_ERR_INVALID_ARG;
    return key_make( raw, rawlen, key );
}

MP_API int32_t mp_key_import_pkcs8( MP_CTX ctx,
                                    const uint8_t * der, size_t derlen,
                                    MP_KEY * key )
{
    const uint8_t * p = der;
    PKCS8_PRIV_KEY_INFO * p8;
    EVP_PKEY * pkey;
    struct MP_KEY_S * k;

    if( !ctx || !der || !derlen || derlen > INT_MAX || !key )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    p8 = d2i_PKCS8_PRIV_KEY_INFO( NULL, &p, (long)derlen );
    pkey = p8 && p == der + derlen ? EVP_PKCS82PKEY( p8 ) : NULL;
    if( pkey && EVP_PKEY_get_base_id( pkey ) != EVP_PKEY_RSA && EVP_PKEY_get_base_id( pkey ) != EVP_PKEY_EC )
    {
        EVP_PKEY_free( pkey );
        pkey = NULL;
    }
    PKCS8_PRIV_KEY_INFO_free( p8 );
    ERR_pop_to_mark();
    if( !pkey )
        return MP_ERR_PARSE;

    k = calloc( 1, sizeof( *k ) );
    if( !k )
    {
        EVP_PKEY_free( pkey );
        return MP_ERR_UNEXPECTED;
    }
    k->pkey = pkey;
    *key = k;
    return MP_OK;
}

MP_API int32_t mp_key_close( MP_KEY key )
{
    if( !key )
        return MP_ERR_INVALID_ARG;

    EVP_PKEY_free( key->pkey );
    OPENSSL_free( key->spki );
    OPENSSL_free( key->sig );
    OPENSSL_free( key->p12 );
    OPENSSL_free( key->tsr );
    OPENSSL_cleanse( key->raw, sizeof( key->raw ) );
    free( key );
    return MP_OK;
}

MP_API int32_t mp_key_raw( MP_KEY key,
                           const uint8_t ** raw, size_t * rawlen )
{
    if( !key || !key->gost || !raw || !rawlen )
        return MP_ERR_INVALID_ARG;

    *raw = key->raw;
    *rawlen = key->rawlen;
    return MP_OK;
}

MP_API int32_t mp_key_spki( MP_KEY key,
                            const uint8_t ** der, size_t * derlen )
{
    if( !key || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    if( !key->spki )
    {
        uint8_t * buf = NULL;
        ERR_set_mark();
        int len = i2d_PUBKEY( key->pkey, &buf );
        ERR_pop_to_mark();
        if( len <= 0 )
            return MP_ERR_OPENSSL;
        key->spki = buf;
        key->spkilen = (size_t)len;
    }

    *der = key->spki;
    *derlen = key->spkilen;
    return MP_OK;
}

static int32_t key_sign( MP_KEY key, const EVP_MD * md,
                         const uint8_t * data, size_t datalen,
                         const uint8_t ** sig, size_t * siglen )
{
    EVP_MD_CTX * mctx;
    size_t len = 0;
    uint8_t * buf = NULL;
    int ok;

    ERR_set_mark();
    mctx = EVP_MD_CTX_new();
    ok = md && mctx &&
         EVP_DigestSignInit( mctx, NULL, md, NULL, key->pkey ) > 0 &&
         EVP_DigestSign( mctx, NULL, &len, data, datalen ) > 0 &&
         ( buf = OPENSSL_malloc( len ) ) != NULL &&
         EVP_DigestSign( mctx, buf, &len, data, datalen ) > 0;
    EVP_MD_CTX_free( mctx );
    ERR_pop_to_mark();
    if( !ok )
    {
        OPENSSL_free( buf );
        return MP_ERR_OPENSSL;
    }
    OPENSSL_free( key->sig );
    key->sig = buf;
    *sig = buf;
    *siglen = len;
    return MP_OK;
}

MP_API int32_t mp_key_sign( MP_KEY key,
                            const uint8_t * data, size_t datalen,
                            const uint8_t ** sig, size_t * siglen )
{
    const EVP_MD * md;

    if( !key || ( !data && datalen ) || !sig || !siglen )
        return MP_ERR_INVALID_ARG;

    md = mp_key_md( key->pkey );
    return key_sign( key, md, data, datalen, sig, siglen );
}

const EVP_MD * mp_key_md( EVP_PKEY * pkey )
{
    switch( EVP_PKEY_get_base_id( pkey ) )
    {
    case NID_id_GostR3410_2012_256: return EVP_get_digestbynid( NID_id_GostR3411_2012_256 );
    case NID_id_GostR3410_2012_512: return EVP_get_digestbynid( NID_id_GostR3411_2012_512 );
    }
    return EVP_sha256();
}

void mp_ec_sig_alg( X509_ALGOR * alg )
{
    X509_ALGOR_set0( alg, OBJ_nid2obj( NID_X9_62_id_ecPublicKey ), V_ASN1_UNDEF, NULL );
}

int32_t mp_x509_stack( const uint8_t * const * certs, const size_t * lens, size_t n,
                       STACK_OF(X509) ** stack )
{
    size_t i;

    if( n && ( !certs || !lens ) )
        return MP_ERR_INVALID_ARG;
    if( !( *stack = sk_X509_new_null() ) )
        return MP_ERR_OPENSSL;
    for( i = 0; i < n; i++ )
    {
        X509 * x = certs[ i ] && lens[ i ] && lens[ i ] <= INT_MAX ? mp_d2i_x509( certs[ i ], lens[ i ] ) : NULL;
        if( !x || !sk_X509_push( *stack, x ) )
        {
            X509_free( x );
            sk_X509_pop_free( *stack, X509_free );
            *stack = NULL;
            return x ? MP_ERR_OPENSSL : MP_ERR_PARSE;
        }
    }
    return MP_OK;
}

MP_API int32_t mp_key_pkcs12( MP_KEY key,
                              const uint8_t * cert, size_t certlen,
                              const uint8_t * const * certs, const size_t * certlens,
                              size_t ncerts, const char * password,
                              const uint8_t ** der, size_t * derlen )
{
    X509 * x = NULL;
    STACK_OF(X509) * ca = NULL;
    PKCS12 * p12 = NULL;
    uint8_t * buf = NULL;
    int gost, pbe, len = 0;
    int32_t rc;

    if( !key || !cert || !certlen || certlen > INT_MAX || !password || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    rc = MP_ERR_PARSE;
    if( !( x = mp_d2i_x509( cert, certlen ) ) ||
        ( rc = mp_x509_stack( certs, certlens, ncerts, &ca ) ) != MP_OK )
        goto end;
    rc = MP_ERR_OPENSSL;
    gost = EVP_PKEY_get_base_id( key->pkey ) == NID_id_GostR3410_2012_256 ||
           EVP_PKEY_get_base_id( key->pkey ) == NID_id_GostR3410_2012_512;
    pbe = gost ? OBJ_txt2nid( "1.2.643.7.1.1.5.2.2" ) : NID_aes_256_cbc;
    if( !X509_check_private_key( x, key->pkey ) || pbe == NID_undef ||
        !( p12 = PKCS12_create( password, NULL, key->pkey, x, ca, pbe, pbe, 0, -1, 0 ) ) ||
        !PKCS12_set_mac( p12, password, -1, NULL, 0, PKCS12_DEFAULT_ITER,
                         gost ? EVP_get_digestbynid( NID_id_GostR3411_2012_512 ) : EVP_sha256() ) ||
        ( len = i2d_PKCS12( p12, &buf ) ) <= 0 )
        goto end;
    OPENSSL_free( key->p12 );
    key->p12 = buf;
    *der = buf;
    *derlen = (size_t)len;
    rc = MP_OK;

end:
    ERR_pop_to_mark();
    PKCS12_free( p12 );
    sk_X509_pop_free( ca, X509_free );
    X509_free( x );
    return rc;
}

MP_API int32_t mp_key_sign_digest( MP_KEY key, const char * alg,
                                   const uint8_t * data, size_t datalen,
                                   const uint8_t ** sig, size_t * siglen )
{
    const EVP_MD * md;

    if( !key || !alg || ( !data && datalen ) || !sig || !siglen || !( md = mp_md( alg ) ) )
        return MP_ERR_INVALID_ARG;
    return key_sign( key, md, data, datalen, sig, siglen );
}
