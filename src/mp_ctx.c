/* mp_ctx.c - Context management */
#include "mp_internal.h"

/* ENGINE API is deprecated in OpenSSL 3.x but still required for
   GOST signature verification (provider mode does not handle
   combined OIDs like id-tc26-signwithdigest-gost3410-2012-256). */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

MP_API uint32_t mp_version( void )
{
    return MP_VERSION;
}

/* The GOST engine named by MINIPKI_GOST_ENGINE is loaded once per process,
   becomes the default for all methods and is never unloaded. */
static CRYPTO_ONCE gost_once = CRYPTO_ONCE_STATIC_INIT;
static ENGINE * gost_engine;
static int gost_failed;

static void load_gost( void )
{
    const char * path = getenv( "MINIPKI_GOST_ENGINE" );
    if( !path || !*path )
        return;

    ENGINE_load_dynamic();
    ENGINE * dyn = ENGINE_by_id( "dynamic" );
    if( dyn &&
        ENGINE_ctrl_cmd_string( dyn, "SO_PATH", path, 0 ) &&
        ENGINE_ctrl_cmd_string( dyn, "ID", "gost", 0 ) &&
        ENGINE_ctrl_cmd_string( dyn, "LOAD", NULL, 0 ) &&
        ENGINE_init( dyn ) )
    {
        ENGINE_set_default( dyn, ENGINE_METHOD_ALL );
        gost_engine = dyn;
        return;
    }
    ENGINE_free( dyn );
    gost_failed = 1;
}

MP_API int32_t mp_open( int32_t type, MP_CTX * ctx )
{
    struct MP_CTX_S * c;

    if( !ctx )
        return MP_ERR_INVALID_ARG;

    if( type != MP_TYPE_OPENSSL )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    if( !CRYPTO_THREAD_run_once( &gost_once, load_gost ) || gost_failed )
    {
        ERR_pop_to_mark();
        return MP_ERR_OPENSSL;
    }
    ERR_pop_to_mark();

    c = calloc( 1, sizeof( *c ) );
    if( !c )
        return MP_ERR_UNEXPECTED;

    c->type = type;
    c->eng_gost = gost_engine;

    /* Load default provider into global context */
    c->prov_default = OSSL_PROVIDER_load( NULL, "default" );
    if( !c->prov_default )
    {
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

    if( ctx->prov_default )
        OSSL_PROVIDER_unload( ctx->prov_default );

    free( ctx );
    return MP_OK;
}
