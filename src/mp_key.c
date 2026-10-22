/* mp_key.c - GOST R 34.10-2012 256-bit keys and signing */
#include "mp_internal.h"

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
        free( k );
        EVP_PKEY_free( pkey );
        return ok ? MP_ERR_UNEXPECTED : MP_ERR_OPENSSL;
    }

    k->pkey = pkey;
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

MP_API int32_t mp_key_close( MP_KEY key )
{
    if( !key )
        return MP_ERR_INVALID_ARG;

    EVP_PKEY_free( key->pkey );
    OPENSSL_free( key->spki );
    OPENSSL_cleanse( key->raw, sizeof( key->raw ) );
    free( key );
    return MP_OK;
}

MP_API int32_t mp_key_raw( MP_KEY key,
                           const uint8_t ** raw, size_t * rawlen )
{
    if( !key || !raw || !rawlen )
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
        int len = i2d_PUBKEY( key->pkey, &buf );
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
                            uint8_t sig[ MP_SIG_LEN ] )
{
    EVP_MD_CTX * mctx;
    const EVP_MD * md;
    size_t siglen = MP_SIG_LEN;
    int ok;

    if( !key || ( !data && datalen ) || !sig )
        return MP_ERR_INVALID_ARG;

    md = EVP_get_digestbynid( NID_id_GostR3411_2012_256 );
    mctx = EVP_MD_CTX_new();
    ok = md && mctx &&
         EVP_DigestSignInit( mctx, NULL, md, NULL, key->pkey ) > 0 &&
         EVP_DigestSign( mctx, sig, &siglen, data, datalen ) > 0 &&
         siglen == MP_SIG_LEN;
    EVP_MD_CTX_free( mctx );
    return ok ? MP_OK : MP_ERR_OPENSSL;
}
