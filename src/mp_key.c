/* mp_key.c - signing keys: GOST R 34.10-2012 256-bit and PKCS#8 */
#include "mp_internal.h"
#include <limits.h>

/* GOST keys are GOST engine keys whose EC_KEY is reached through the
   deprecated EVP_PKEY_get0. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* A GOST engine key on the CryptoPro-A parameter set: a fresh one, or with
   raw, the one with that private scalar and its public point. */
static int32_t key_make( const uint8_t * raw, MP_KEY * key )
{
    EVP_PKEY_CTX * pctx;
    EVP_PKEY * pkey = NULL;
    struct MP_KEY_S * k;
    int ok;

    ERR_set_mark();
    pctx = EVP_PKEY_CTX_new_id( NID_id_GostR3410_2012_256, NULL );
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
        BIGNUM * d = BN_lebin2bn( raw, MP_KEY_RAW_LEN, BN_secure_new() );
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
                        k->raw, MP_KEY_RAW_LEN ) != MP_KEY_RAW_LEN )
    {
        ERR_pop_to_mark();
        free( k );
        EVP_PKEY_free( pkey );
        return ok ? MP_ERR_UNEXPECTED : MP_ERR_OPENSSL;
    }
    ERR_pop_to_mark();

    k->pkey = pkey;
    k->gost = 1;
    *key = k;
    return MP_OK;
}

MP_API int32_t mp_key_generate( MP_CTX ctx, MP_KEY * key )
{
    if( !ctx || !key )
        return MP_ERR_INVALID_ARG;
    return key_make( NULL, key );
}

MP_API int32_t mp_key_import( MP_CTX ctx,
                              const uint8_t * raw, size_t rawlen,
                              MP_KEY * key )
{
    if( !ctx || !raw || rawlen != MP_KEY_RAW_LEN || !key )
        return MP_ERR_INVALID_ARG;
    return key_make( raw, key );
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
    *rawlen = MP_KEY_RAW_LEN;
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

MP_API int32_t mp_key_sign( MP_KEY key,
                            const uint8_t * data, size_t datalen,
                            const uint8_t ** sig, size_t * siglen )
{
    EVP_MD_CTX * mctx;
    const EVP_MD * md;
    size_t len = 0;
    uint8_t * buf = NULL;
    int ok;

    if( !key || ( !data && datalen ) || !sig || !siglen )
        return MP_ERR_INVALID_ARG;

    md = EVP_PKEY_get_base_id( key->pkey ) == NID_id_GostR3410_2012_256
         ? EVP_get_digestbynid( NID_id_GostR3411_2012_256 ) : EVP_sha256();
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
    key->siglen = len;
    *sig = buf;
    *siglen = len;
    return MP_OK;
}
