/* mp_ctx.c - Context management */
#include "mp_internal.h"
#include <stdio.h>

/* ENGINE API is deprecated in OpenSSL 3.x but still required for
   GOST signature verification (provider mode does not handle
   combined OIDs like id-tc26-signwithdigest-gost3410-2012-256). */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

    /* Load default provider into global context */
    c->prov_default = OSSL_PROVIDER_load( NULL, "default" );
    if( !c->prov_default )
    {
        free( c );
        return MP_ERR_OPENSSL;
    }

    /* Load gost-engine as dynamic ENGINE — provides all GOST algorithms
       (signatures, hashes, key management) and X509 verify support. */
    const char * eng_path = getenv( "MINIPKI_GOST_ENGINE" );
    if( eng_path && *eng_path )
    {
        ENGINE_load_dynamic();
        ENGINE * dyn = ENGINE_by_id( "dynamic" );
        if( !dyn )
        {
            fprintf( stderr, "[minipki] ENGINE_by_id(dynamic) failed\n" );
        }
        else
        {
            if( !ENGINE_ctrl_cmd_string( dyn, "SO_PATH", eng_path, 0 ) )
                fprintf( stderr, "[minipki] SO_PATH %s failed: %s\n",
                         eng_path, ERR_error_string( ERR_get_error(), NULL ) );
            if( !ENGINE_ctrl_cmd_string( dyn, "ID", "gost", 0 ) )
                fprintf( stderr, "[minipki] ID gost failed\n" );
            if( !ENGINE_ctrl_cmd_string( dyn, "LOAD", NULL, 0 ) )
                fprintf( stderr, "[minipki] LOAD failed: %s\n",
                         ERR_error_string( ERR_get_error(), NULL ) );
            if( !ENGINE_init( dyn ) )
            {
                fprintf( stderr, "[minipki] ENGINE_init failed: %s\n",
                         ERR_error_string( ERR_get_error(), NULL ) );
                ENGINE_free( dyn );
            }
            else
            {
                ENGINE_set_default( dyn, ENGINE_METHOD_ALL );
                c->eng_gost = dyn;
                fprintf( stderr, "[minipki] gost engine loaded from %s\n", eng_path );
            }
        }
    }

    *ctx = c;
    return MP_OK;
}

MP_API int32_t mp_close( MP_CTX ctx )
{
    if( !ctx )
        return MP_ERR_INVALID_ARG;

    if( ctx->eng_gost )
    {
        ENGINE_finish( ctx->eng_gost );
        ENGINE_free( ctx->eng_gost );
    }
    if( ctx->prov_default )
        OSSL_PROVIDER_unload( ctx->prov_default );

    free( ctx );
    return MP_OK;
}
