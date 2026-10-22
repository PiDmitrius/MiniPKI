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
