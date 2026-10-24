/* mp_tsp.c - time-stamp responses (RFC 3161) */
#include "mp_internal.h"
#include <limits.h>

static ASN1_INTEGER * serial_cb( TS_RESP_CTX * ctx, void * data )
{
    (void)ctx;
    return ASN1_INTEGER_dup( data );
}

MP_API int32_t mp_key_tsp_reply( MP_KEY key,
                                 const uint8_t * signer, size_t signerlen,
                                 const uint8_t * const * certs, const size_t * certlens,
                                 size_t ncerts, const char * policy, const char * digest,
                                 const uint8_t * serial, size_t seriallen,
                                 const uint8_t * req, size_t reqlen,
                                 const uint8_t ** der, size_t * derlen )
{
    X509 * x = NULL;
    TS_REQ * tsq = NULL;
    const uint8_t * p = req;
    char alg[ 128 ];
    const EVP_MD * m = NULL;
    TS_STATUS_INFO * si;
    STACK_OF(X509) * chain = NULL;
    ASN1_OBJECT * pol = NULL;
    ASN1_INTEGER * sn = NULL;
    BIGNUM * bn = NULL;
    TS_RESP_CTX * ctx = NULL;
    TS_RESP * resp = NULL;
    BIO * in = NULL;
    uint8_t * buf = NULL;
    const EVP_MD * md;
    int len;
    int32_t rc;

    if( !key || !signer || !signerlen || signerlen > INT_MAX || !policy || !serial || !seriallen ||
        seriallen > INT_MAX || !req || !reqlen || reqlen > INT_MAX || !der || !derlen )
        return MP_ERR_INVALID_ARG;

    ERR_set_mark();
    rc = MP_ERR_PARSE;
    if( !( x = mp_d2i_x509( signer, signerlen ) ) ||
        ( rc = mp_x509_stack( certs, certlens, ncerts, &chain ) ) != MP_OK )
        goto end;
    rc = MP_ERR_INVALID_ARG;
    if( !( pol = OBJ_txt2obj( policy, 1 ) ) || !( md = digest ? mp_md( digest ) : mp_key_md( key->pkey ) ) )
        goto end;
    rc = MP_ERR_OPENSSL;
    if( !X509_check_private_key( x, key->pkey ) )
        goto end;
    /* Only a whole request, whose hash is any mp_digest takes, is answered;
       anything else is answered by a rejection of bad data */
    tsq = d2i_TS_REQ( NULL, &p, (long)reqlen );
    if( tsq && p != req + reqlen )
    {
        TS_REQ_free( tsq );
        tsq = NULL;
    }
    if( tsq )
    {
        const ASN1_OBJECT * obj;
        X509_ALGOR_get0( &obj, NULL, NULL, TS_MSG_IMPRINT_get_algo( TS_REQ_get_msg_imprint( tsq ) ) );
        if( OBJ_obj2txt( alg, sizeof( alg ), obj, 1 ) > 0 )
            m = mp_md( alg );
    }
    if( !( bn = BN_bin2bn( serial, (int)seriallen, NULL ) ) || !( sn = BN_to_ASN1_INTEGER( bn, NULL ) ) ||
        !( ctx = TS_RESP_CTX_new() ) ||
        !TS_RESP_CTX_set_signer_cert( ctx, x ) || !TS_RESP_CTX_set_signer_key( ctx, key->pkey ) ||
        !TS_RESP_CTX_set_signer_digest( ctx, md ) || !TS_RESP_CTX_set_ess_cert_id_digest( ctx, md ) ||
        !TS_RESP_CTX_set_certs( ctx, chain ) || !TS_RESP_CTX_set_def_policy( ctx, pol ) ||
        !TS_RESP_CTX_set_accuracy( ctx, 1, 0, 0 ) )
        goto end;
    if( m && !TS_RESP_CTX_add_md( ctx, m ) )
        goto end;
    TS_RESP_CTX_set_serial_cb( ctx, serial_cb, sn );
    if( !( in = tsq ? BIO_new_mem_buf( req, (int)reqlen ) : BIO_new_mem_buf( "", 0 ) ) ||
        !( resp = TS_RESP_create_response( ctx, in ) ) )
        goto end;
    /* OpenSSL rejects a request with a failure info, and fails itself
       without one */
    si = TS_RESP_get_status_info( resp );
    if( ASN1_INTEGER_get( TS_STATUS_INFO_get0_status( si ) ) != TS_STATUS_GRANTED &&
        !TS_STATUS_INFO_get0_failure_info( si ) )
        goto end;
    if( TS_RESP_get_token( resp ) && EVP_PKEY_get_base_id( key->pkey ) == EVP_PKEY_EC )
    {
        X509_ALGOR * alg;
        PKCS7_SIGNER_INFO_get0_algs( sk_PKCS7_SIGNER_INFO_value( PKCS7_get_signer_info( TS_RESP_get_token( resp ) ), 0 ),
                                     NULL, NULL, &alg );
        mp_ec_sig_alg( alg );
    }
    if( ( len = i2d_TS_RESP( resp, &buf ) ) <= 0 )
        goto end;
    OPENSSL_free( key->tsr );
    key->tsr = buf;
    *der = buf;
    *derlen = (size_t)len;
    rc = MP_OK;

end:
    ERR_pop_to_mark();
    TS_RESP_free( resp );
    TS_REQ_free( tsq );
    BIO_free( in );
    TS_RESP_CTX_free( ctx );
    ASN1_INTEGER_free( sn );
    BN_free( bn );
    ASN1_OBJECT_free( pol );
    sk_X509_pop_free( chain, X509_free );
    X509_free( x );
    return rc;
}
