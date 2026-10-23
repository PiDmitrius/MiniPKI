/* mp_ctx.c - Context management and digests */
#include "mp_internal.h"

/* ENGINE API is deprecated in OpenSSL 3.x but still required for
   GOST signature verification (provider mode does not handle
   combined OIDs like id-tc26-signwithdigest-gost3410-2012-256). */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

MP_API uint32_t mp_version( void )
{
    return MP_VERSION;
}

/* The GOST engine is loaded once per process, becomes the default for all
   methods and is never unloaded: the one built into the library with
   MINIPKI_GOST_BUILTIN, else the one named by MINIPKI_GOST_ENGINE. */
static CRYPTO_ONCE gost_once = CRYPTO_ONCE_STATIC_INIT;
static int gost_failed;

#ifdef MINIPKI_GOST_BUILTIN
void ENGINE_load_gost( void );  /* gost-engine built as a static library */

static void load_gost( void )
{
    ENGINE_load_gost();
    ENGINE * e = ENGINE_by_id( "gost" );
    if( e && ENGINE_init( e ) )
    {
        ENGINE_set_default( e, ENGINE_METHOD_ALL );
        return;
    }
    ENGINE_free( e );
    gost_failed = 1;
}
#else
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
        return;
    }
    ENGINE_free( dyn );
    gost_failed = 1;
}
#endif

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

MP_API int32_t mp_digest( MP_CTX ctx, const char * alg, const uint8_t * data, size_t datalen,
                          uint8_t md[ MP_DIGEST_MAX ], size_t * mdlen )
{
    ASN1_OBJECT * obj;
    const EVP_MD * m = NULL;
    EVP_MD_CTX * c = NULL;
    unsigned int n = 0;
    int nid, rc = MP_ERR_INVALID_ARG;

    if( !ctx || !alg || ( !data && datalen ) || !md || !mdlen )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    obj = OBJ_txt2obj( alg, 1 );
    nid = OBJ_obj2nid( obj );
    ASN1_OBJECT_free( obj );
    /* A signature OID finds its digest too; a digest without an
       implementation fails to init */
    if( nid != NID_undef )
        m = EVP_get_digestbynid( nid );
    if( m && EVP_MD_get_type( m ) == nid && !( EVP_MD_get_flags( m ) & EVP_MD_FLAG_XOF ) &&
        EVP_MD_get_size( m ) > 0 && EVP_MD_get_size( m ) <= MP_DIGEST_MAX &&
        ( c = EVP_MD_CTX_new() ) && EVP_DigestInit_ex( c, m, NULL ) )
        rc = EVP_DigestUpdate( c, data, datalen ) && EVP_DigestFinal_ex( c, md, &n ) ? MP_OK : MP_ERR_OPENSSL;
    EVP_MD_CTX_free( c );
    ERR_pop_to_mark();

    if( rc == MP_OK )
        *mdlen = n;
    return rc;
}
