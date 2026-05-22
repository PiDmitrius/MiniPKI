/* mp_ocsp.c - OCSP request/response */
#include "mp_internal.h"
#include <stdio.h>

/* ── Request ─────────────────────────────────────────────── */

MP_API int32_t mp_ocsp_request_new( MP_CTX ctx,
                                     MP_CERT cert, MP_CERT issuer,
                                     MP_OCSP_REQ * out )
{
    OCSP_REQUEST * req = NULL;
    OCSP_CERTID  * cid = NULL;
    struct MP_OCSP_REQ_S * r;
    uint8_t * buf = NULL;
    int len;

    if( !ctx || !cert || !issuer || !out )
        return MP_ERR_INVALID_ARG;

    req = OCSP_REQUEST_new();
    if( !req )
        return MP_ERR_OPENSSL;

    cid = OCSP_cert_to_id( EVP_sha1(), cert->x509, issuer->x509 );
    if( !cid )
    {
        OCSP_REQUEST_free( req );
        return MP_ERR_OPENSSL;
    }

    if( !OCSP_request_add0_id( req, cid ) )
    {
        OCSP_CERTID_free( cid );
        OCSP_REQUEST_free( req );
        return MP_ERR_OPENSSL;
    }

    len = i2d_OCSP_REQUEST( req, &buf );
    OCSP_REQUEST_free( req );
    if( len <= 0 )
        return MP_ERR_OPENSSL;

    r = calloc( 1, sizeof( *r ) );
    if( !r )
    {
        OPENSSL_free( buf );
        return MP_ERR_UNEXPECTED;
    }
    r->der = buf;
    r->derlen = (size_t)len;

    *out = r;
    return MP_OK;
}

MP_API int32_t mp_ocsp_request_close( MP_OCSP_REQ req )
{
    if( !req )
        return MP_ERR_INVALID_ARG;
    OPENSSL_free( req->der );
    free( req );
    return MP_OK;
}

MP_API int32_t mp_ocsp_request_der( MP_OCSP_REQ req,
                                     const uint8_t ** der, size_t * derlen )
{
    if( !req || !der || !derlen )
        return MP_ERR_INVALID_ARG;
    *der = req->der;
    *derlen = req->derlen;
    return MP_OK;
}

/* ── Response ────────────────────────────────────────────── */

MP_API int32_t mp_ocsp_response_parse( MP_CTX ctx,
                                        MP_CERT cert, MP_CERT issuer,
                                        const uint8_t * data, size_t datalen,
                                        MP_OCSP_RESP * out )
{
    OCSP_RESPONSE  * resp = NULL;
    OCSP_BASICRESP * basic = NULL;
    OCSP_CERTID    * cid = NULL;
    X509_STORE     * store = NULL;
    struct MP_OCSP_RESP_S * r = NULL;
    const uint8_t  * p;
    int rc;

    if( !ctx || !cert || !issuer || !data || !datalen || !out )
        return MP_ERR_INVALID_ARG;

    p = data;
    resp = d2i_OCSP_RESPONSE( NULL, &p, (long)datalen );
    if( !resp )
        return MP_ERR_PARSE;

    /* Overall response status */
    rc = OCSP_response_status( resp );
    if( rc != OCSP_RESPONSE_STATUS_SUCCESSFUL )
    {
        OCSP_RESPONSE_free( resp );
        return MP_ERR_PARSE;
    }

    basic = OCSP_response_get1_basic( resp );
    if( !basic )
    {
        OCSP_RESPONSE_free( resp );
        return MP_ERR_PARSE;
    }

    r = calloc( 1, sizeof( *r ) );
    if( !r )
    {
        OCSP_BASICRESP_free( basic );
        OCSP_RESPONSE_free( resp );
        return MP_ERR_UNEXPECTED;
    }
    r->resp = resp;
    r->basic = basic;
    r->revoke_reason = -1;

    /* Verify signature: build temporary trust store with issuer.
       OCSP responder is either the issuer itself or a delegated cert
       embedded in the response with id-kp-OCSPSigning EKU. */
    store = X509_STORE_new();
    if( store )
    {
        X509_STORE_add_cert( store, issuer->x509 );
        /* Allow intermediate cert as trust anchor — issuer is usually
           intermediate, and we trust it as the OCSP signer chain anchor. */
        X509_STORE_set_flags( store, X509_V_FLAG_PARTIAL_CHAIN );

        STACK_OF(X509) * untrusted = sk_X509_new_null();
        if( untrusted )
            sk_X509_push( untrusted, issuer->x509 );

        ERR_clear_error();
        rc = OCSP_basic_verify( basic, untrusted, store, 0 );
        if( rc > 0 )
        {
            r->verified = 1;
        }
        else
        {
            unsigned long err = ERR_get_error();
            if( err )
            {
                char buf[256];
                ERR_error_string_n( err, buf, sizeof( buf ) );
                fprintf( stderr, "[mp_ocsp] verify failed: %s\n", buf );
            }
            else
            {
                fprintf( stderr, "[mp_ocsp] verify returned %d (no error)\n", rc );
            }
            r->verified = 0;
        }
        if( untrusted )
            sk_X509_free( untrusted );
        X509_STORE_free( store );
    }

    /* Find status for our specific cert */
    cid = OCSP_cert_to_id( EVP_sha1(), cert->x509, issuer->x509 );
    if( cid )
    {
        int status, reason;
        ASN1_GENERALIZEDTIME * revtime = NULL;
        ASN1_GENERALIZEDTIME * thisupd = NULL;
        ASN1_GENERALIZEDTIME * nextupd = NULL;

        if( OCSP_resp_find_status( basic, cid, &status, &reason,
                                    &revtime, &thisupd, &nextupd ) )
        {
            switch( status )
            {
            case V_OCSP_CERTSTATUS_GOOD:    r->status = MP_OCSP_GOOD; break;
            case V_OCSP_CERTSTATUS_REVOKED: r->status = MP_OCSP_REVOKED; break;
            default:                        r->status = MP_OCSP_UNKNOWN; break;
            }

            struct tm tm;
            if( thisupd && ASN1_TIME_to_tm( thisupd, &tm ) )
                r->this_update = (int64_t)timegm( &tm );
            if( nextupd && ASN1_TIME_to_tm( nextupd, &tm ) )
                r->next_update = (int64_t)timegm( &tm );
            if( revtime && ASN1_TIME_to_tm( revtime, &tm ) )
                r->revoked_at = (int64_t)timegm( &tm );

            if( status == V_OCSP_CERTSTATUS_REVOKED )
                r->revoke_reason = reason;
        }
        else
        {
            r->status = MP_OCSP_UNKNOWN;
        }
        OCSP_CERTID_free( cid );
    }
    else
    {
        r->status = MP_OCSP_UNKNOWN;
    }

    /* producedAt from the basic response */
    {
        const ASN1_GENERALIZEDTIME * gt = OCSP_resp_get0_produced_at( basic );
        if( gt )
        {
            struct tm tm;
            if( ASN1_TIME_to_tm( gt, &tm ) )
                r->produced_at = (int64_t)timegm( &tm );
        }
    }

    /* Cache DER for later access */
    {
        uint8_t * buf = NULL;
        int len = i2d_OCSP_RESPONSE( resp, &buf );
        if( len > 0 )
        {
            r->der = buf;
            r->derlen = (size_t)len;
        }
    }

    *out = r;
    return MP_OK;
}

MP_API int32_t mp_ocsp_response_close( MP_OCSP_RESP resp )
{
    if( !resp )
        return MP_ERR_INVALID_ARG;
    if( resp->basic )
        OCSP_BASICRESP_free( resp->basic );
    if( resp->resp )
        OCSP_RESPONSE_free( resp->resp );
    OPENSSL_free( resp->der );
    free( resp );
    return MP_OK;
}

MP_API int32_t mp_ocsp_status( MP_OCSP_RESP resp, int32_t * status )
{
    if( !resp || !status ) return MP_ERR_INVALID_ARG;
    *status = resp->status;
    return MP_OK;
}

MP_API int32_t mp_ocsp_verified( MP_OCSP_RESP resp, int32_t * verified )
{
    if( !resp || !verified ) return MP_ERR_INVALID_ARG;
    *verified = resp->verified;
    return MP_OK;
}

MP_API int32_t mp_ocsp_this_update( MP_OCSP_RESP resp, int64_t * t )
{
    if( !resp || !t ) return MP_ERR_INVALID_ARG;
    *t = resp->this_update;
    return MP_OK;
}

MP_API int32_t mp_ocsp_next_update( MP_OCSP_RESP resp, int64_t * t )
{
    if( !resp || !t ) return MP_ERR_INVALID_ARG;
    *t = resp->next_update;
    return MP_OK;
}

MP_API int32_t mp_ocsp_produced_at( MP_OCSP_RESP resp, int64_t * t )
{
    if( !resp || !t ) return MP_ERR_INVALID_ARG;
    *t = resp->produced_at;
    return MP_OK;
}

MP_API int32_t mp_ocsp_revoked_at( MP_OCSP_RESP resp, int64_t * t )
{
    if( !resp || !t ) return MP_ERR_INVALID_ARG;
    *t = resp->revoked_at;
    return MP_OK;
}

MP_API int32_t mp_ocsp_revoke_reason( MP_OCSP_RESP resp, int32_t * reason )
{
    if( !resp || !reason ) return MP_ERR_INVALID_ARG;
    *reason = resp->revoke_reason;
    return MP_OK;
}

MP_API int32_t mp_ocsp_der( MP_OCSP_RESP resp,
                             const uint8_t ** der, size_t * derlen )
{
    if( !resp || !der || !derlen ) return MP_ERR_INVALID_ARG;
    *der = resp->der;
    *derlen = resp->derlen;
    return MP_OK;
}
