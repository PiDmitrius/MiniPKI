/* mp_ctx.c - Context management */
#include "mp_internal.h"

/* External: gost-engine provider init (from libgost.a, BUILDING_PROVIDER_AS_LIBRARY) */
extern int GOST_provider_init( const OSSL_CORE_HANDLE * handle,
                               const OSSL_DISPATCH * in,
                               const OSSL_DISPATCH ** out,
                               void ** provctx );

MP_API uint32_t mp_version( void )
{
    return MP_VERSION;
}

MP_API int32_t mp_open( int32_t type, MP_CTX * ctx )
{
    struct MP_CTX_S * c;

    if( !ctx )
        return MP_ERR_INVALID_ARG;

    if( type != MP_TYPE_OPENSSL )
        return MP_ERR_INVALID_ARG;

    c = calloc( 1, sizeof( *c ) );
    if( !c )
        return MP_ERR_UNEXPECTED;

    c->type = type;

    /* Create isolated library context */
    c->libctx = OSSL_LIB_CTX_new();
    if( !c->libctx )
    {
        free( c );
        return MP_ERR_OPENSSL;
    }

    /* Load default provider */
    c->prov_default = OSSL_PROVIDER_load( c->libctx, "default" );
    if( !c->prov_default )
    {
        OSSL_LIB_CTX_free( c->libctx );
        free( c );
        return MP_ERR_OPENSSL;
    }

    /* Register and load GOST provider */
    if( !OSSL_PROVIDER_add_builtin( c->libctx, "gost",
                                     GOST_provider_init ) )
    {
        OSSL_PROVIDER_unload( c->prov_default );
        OSSL_LIB_CTX_free( c->libctx );
        free( c );
        return MP_ERR_OPENSSL;
    }

    c->prov_gost = OSSL_PROVIDER_load( c->libctx, "gost" );
    if( !c->prov_gost )
    {
        OSSL_PROVIDER_unload( c->prov_default );
        OSSL_LIB_CTX_free( c->libctx );
        free( c );
        return MP_ERR_OPENSSL;
    }

    *ctx = c;
    return MP_OK;
}

MP_API int32_t mp_close( MP_CTX ctx )
{
    if( !ctx )
        return MP_ERR_INVALID_ARG;

    if( ctx->prov_gost )
        OSSL_PROVIDER_unload( ctx->prov_gost );
    if( ctx->prov_default )
        OSSL_PROVIDER_unload( ctx->prov_default );
    if( ctx->libctx )
        OSSL_LIB_CTX_free( ctx->libctx );

    free( ctx );
    return MP_OK;
}
