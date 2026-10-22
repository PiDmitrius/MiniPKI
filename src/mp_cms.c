/* mp_cms.c - CMS SignedData verification */
#include "mp_internal.h"
#include <limits.h>

MP_API int32_t mp_cms_verify( MP_CTX ctx,
                              const uint8_t * data, size_t datalen,
                              MP_CMS * cms )
{
    const uint8_t * p = data;
    CMS_ContentInfo * ci;
    STACK_OF(X509) * signers = NULL;
    BIO * out = NULL;
    struct MP_CMS_S * c = NULL;
    BUF_MEM * mem = NULL;
    int32_t rc = MP_ERR_PARSE;
    int len;

    if( !ctx || !data || !datalen || datalen > INT_MAX || !cms )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    ci = d2i_CMS_ContentInfo( NULL, &p, (long)datalen );
    if( !ci || p != data + datalen ||
        OBJ_obj2nid( CMS_get0_type( ci ) ) != NID_pkcs7_signed ||
        sk_CMS_SignerInfo_num( CMS_get0_SignerInfos( ci ) ) != 1 ||
        CMS_is_detached( ci ) )
        goto end;

    rc = MP_ERR_OPENSSL;
    out = BIO_new( BIO_s_mem() );
    if( !out )
        goto end;
    if( CMS_verify( ci, NULL, NULL, NULL, out,
                    CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY ) != 1 )
    {
        rc = MP_ERR_VERIFY;
        goto end;
    }
    signers = CMS_get0_signers( ci );
    if( !signers || sk_X509_num( signers ) != 1 )
        goto end;

    c = calloc( 1, sizeof( *c ) );
    if( !c )
    {
        rc = MP_ERR_UNEXPECTED;
        goto end;
    }
    len = i2d_X509( sk_X509_value( signers, 0 ), &c->signer );
    BIO_get_mem_ptr( out, &mem );
    if( len <= 0 || !mem )
        goto end;
    c->signerlen = (size_t)len;
    c->contentlen = mem->length;
    c->content = malloc( mem->length ? mem->length : 1 );
    if( !c->content )
    {
        rc = MP_ERR_UNEXPECTED;
        goto end;
    }
    memcpy( c->content, mem->data, mem->length );

    *cms = c;
    c = NULL;
    rc = MP_OK;

end:
    if( c )
        mp_cms_close( c );
    sk_X509_free( signers );
    BIO_free( out );
    CMS_ContentInfo_free( ci );
    ERR_pop_to_mark();
    return rc;
}

MP_API int32_t mp_cms_close( MP_CMS cms )
{
    if( !cms )
        return MP_ERR_INVALID_ARG;

    OPENSSL_free( cms->signer );
    OPENSSL_free( cms->der );
    free( cms->content );
    free( cms );
    return MP_OK;
}

MP_API int32_t mp_cms_content( MP_CMS cms,
                               const uint8_t ** content, size_t * contentlen )
{
    if( !cms || !content || !contentlen )
        return MP_ERR_INVALID_ARG;

    *content = cms->content;
    *contentlen = cms->contentlen;
    return MP_OK;
}

MP_API int32_t mp_cms_signer( MP_CMS cms,
                              const uint8_t ** der, size_t * derlen )
{
    if( !cms || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    *der = cms->signer;
    *derlen = cms->signerlen;
    return MP_OK;
}

MP_API int32_t mp_cms_sign( MP_KEY key,
                            const uint8_t * signer, size_t signerlen,
                            const char * content_type,
                            const uint8_t * content, size_t contentlen,
                            const uint8_t * const * certs, const size_t * certlens,
                            size_t ncerts,
                            MP_CMS * cms )
{
    X509 * sx = NULL;
    STACK_OF(X509) * stack = NULL;
    BIO * in = NULL;
    CMS_ContentInfo * ci = NULL;
    ASN1_OBJECT * type = NULL;
    struct MP_CMS_S * c = NULL;
    int32_t rc = MP_ERR_INVALID_ARG;
    int len;
    size_t i;

    if( !key || !signer || !signerlen || signerlen > INT_MAX ||
        ( !content && contentlen ) || contentlen > INT_MAX ||
        ( ncerts && ( !certs || !certlens ) ) || !cms )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    rc = MP_ERR_PARSE;
    if( !( sx = mp_d2i_x509( signer, signerlen ) ) ||
        ( content_type && !( type = OBJ_txt2obj( content_type, 1 ) ) ) )
        goto end;
    if( !( stack = sk_X509_new_null() ) )
    {
        rc = MP_ERR_OPENSSL;
        goto end;
    }
    for( i = 0; i < ncerts; i++ )
    {
        X509 * x;
        if( !certs[ i ] || !certlens[ i ] || certlens[ i ] > INT_MAX ||
            !( x = mp_d2i_x509( certs[ i ], certlens[ i ] ) ) )
            goto end;
        if( !sk_X509_push( stack, x ) )
        {
            X509_free( x );
            rc = MP_ERR_OPENSSL;
            goto end;
        }
    }

    rc = MP_ERR_OPENSSL;
    in = BIO_new_mem_buf( content ? (const void *)content : "", (int)contentlen );
    if( !in )
        goto end;
    ci = CMS_sign( sx, key->pkey, stack, NULL,
                   CMS_PARTIAL | CMS_BINARY | CMS_NOCERTS );
    if( !ci )
        goto end;
    for( i = 0; i < ncerts; i++ )
        if( !CMS_add1_cert( ci, sk_X509_value( stack, (int)i ) ) )
            goto end;
    if( ( type && !CMS_set1_eContentType( ci, type ) ) ||
        !CMS_final( ci, in, NULL, CMS_BINARY ) )
        goto end;

    c = calloc( 1, sizeof( *c ) );
    if( !c )
    {
        rc = MP_ERR_UNEXPECTED;
        goto end;
    }
    len = i2d_CMS_ContentInfo( ci, &c->der );
    if( len <= 0 )
        goto end;
    c->derlen = (size_t)len;
    len = i2d_X509( sx, &c->signer );
    if( len <= 0 )
        goto end;
    c->signerlen = (size_t)len;
    c->content = malloc( contentlen ? contentlen : 1 );
    if( !c->content )
    {
        rc = MP_ERR_UNEXPECTED;
        goto end;
    }
    if( contentlen )
        memcpy( c->content, content, contentlen );
    c->contentlen = contentlen;

    *cms = c;
    c = NULL;
    rc = MP_OK;

end:
    if( c )
        mp_cms_close( c );
    CMS_ContentInfo_free( ci );
    BIO_free( in );
    sk_X509_pop_free( stack, X509_free );
    ASN1_OBJECT_free( type );
    X509_free( sx );
    ERR_pop_to_mark();
    return rc;
}

MP_API int32_t mp_cms_der( MP_CMS cms,
                           const uint8_t ** der, size_t * derlen )
{
    if( !cms || !der || !derlen || !cms->der )
        return MP_ERR_INVALID_ARG;

    *der = cms->der;
    *derlen = cms->derlen;
    return MP_OK;
}
