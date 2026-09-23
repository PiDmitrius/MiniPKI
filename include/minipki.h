/* minipki.h - MiniPKI SDK */
#ifndef MINIPKI_H
#define MINIPKI_H

#include <stdint.h>
#include <stddef.h>

/* Version */
#define MP_VERSION_MAJOR 1
#define MP_VERSION_MINOR 0
#define MP_VERSION_PATCH 3

#define MP_VERSION \
    ( ( MP_VERSION_MAJOR << 16 ) | ( MP_VERSION_MINOR << 8 ) | MP_VERSION_PATCH )

#define MP_MAKE_VERSION( major, minor, patch ) \
    ( ( ( major ) << 16 ) | ( ( minor ) << 8 ) | ( patch ) )

#ifdef _WIN32
#define MP_API __declspec( dllexport )
#else
#define MP_API __attribute__( ( visibility( "default" ) ) )
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct MP_CTX_S   * MP_CTX;
typedef struct MP_CERT_S  * MP_CERT;
typedef struct MP_CRL_S   * MP_CRL;
typedef struct MP_STORE_S * MP_STORE;
typedef struct MP_CHAIN_S * MP_CHAIN;
typedef struct MP_BAG_S   * MP_BAG;
typedef struct MP_OCSP_REQ_S  * MP_OCSP_REQ;
typedef struct MP_OCSP_RESP_S * MP_OCSP_RESP;

/* Context types */
#define MP_TYPE_OPENSSL  1

/* Error codes */
#define MP_OK                    0
#define MP_ERR_INVALID_ARG      -1
#define MP_ERR_PARSE            -2
#define MP_ERR_VERIFY           -3
#define MP_ERR_EXPIRED          -4
#define MP_ERR_REVOKED          -5
#define MP_ERR_NO_CHAIN         -6
#define MP_ERR_NO_CRL           -7
#define MP_ERR_OPENSSL          -8
#define MP_ERR_UNEXPECTED       -9

/* -- Version ------------------------------------------------------- */

MP_API uint32_t mp_version( void );

/* -- Context ------------------------------------------------------- */

MP_API int32_t mp_open( int32_t type, MP_CTX * ctx );
MP_API int32_t mp_close( MP_CTX ctx );

/* -- Certificate --------------------------------------------------- */

MP_API int32_t mp_cert_parse( MP_CTX ctx,
                              const uint8_t * data, size_t datalen,
                              MP_CERT * cert );
MP_API int32_t mp_cert_close( MP_CERT cert );

MP_API int32_t mp_cert_subject( MP_CERT cert,
                                const uint8_t ** out, size_t * outlen );
MP_API int32_t mp_cert_issuer( MP_CERT cert,
                               const uint8_t ** out, size_t * outlen );
MP_API int32_t mp_cert_serial( MP_CERT cert,
                               const uint8_t ** out, size_t * outlen );

MP_API int32_t mp_cert_not_before( MP_CERT cert, int64_t * time );
MP_API int32_t mp_cert_not_after( MP_CERT cert, int64_t * time );

MP_API int32_t mp_cert_is_ca( MP_CERT cert, int32_t * result );
MP_API int32_t mp_cert_is_self_signed( MP_CERT cert, int32_t * result );

MP_API int32_t mp_cert_key_algorithm( MP_CERT cert,
                                       const uint8_t ** name, size_t * namelen );
MP_API int32_t mp_cert_key_bits( MP_CERT cert, int32_t * bits );
MP_API int32_t mp_cert_key_curve( MP_CERT cert,
                                   const uint8_t ** name, size_t * namelen );

MP_API int32_t mp_cert_key_usage( MP_CERT cert, uint32_t * usage );
MP_API int32_t mp_cert_eku_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_eku_oid( MP_CERT cert, size_t index,
                                const uint8_t ** oid, size_t * oidlen );
MP_API int32_t mp_cert_pathlen( MP_CERT cert, int32_t * pathlen );

MP_API int32_t mp_cert_ski( MP_CERT cert,
                            const uint8_t ** out, size_t * outlen );
MP_API int32_t mp_cert_aki( MP_CERT cert,
                            const uint8_t ** out, size_t * outlen );

MP_API int32_t mp_cert_subject_name_der( MP_CERT cert,
                                          const uint8_t ** der, size_t * derlen );
MP_API int32_t mp_cert_issuer_name_der( MP_CERT cert,
                                         const uint8_t ** der, size_t * derlen );

MP_API int32_t mp_cert_san_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_san_entry( MP_CERT cert, size_t index,
                                  const uint8_t ** value, size_t * valuelen );

MP_API int32_t mp_cert_aia_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_aia_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen );

MP_API int32_t mp_cert_ocsp_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_ocsp_url( MP_CERT cert, size_t index,
                                 const uint8_t ** url, size_t * urllen );

MP_API int32_t mp_cert_cdp_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_cdp_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen );

MP_API int32_t mp_cert_der( MP_CERT cert,
                            const uint8_t ** der, size_t * derlen );

/* -- Bag (extract all certs from DER/PEM/PKCS#7) ------------------- */

MP_API int32_t mp_bag_parse( MP_CTX ctx,
                             const uint8_t * data, size_t datalen,
                             MP_BAG * bag );
MP_API int32_t mp_bag_count( MP_BAG bag, size_t * count );
MP_API int32_t mp_bag_cert_der( MP_BAG bag, size_t index,
                                const uint8_t ** der, size_t * derlen );
MP_API int32_t mp_bag_close( MP_BAG bag );

/* -- CRL ----------------------------------------------------------- */

MP_API int32_t mp_crl_parse( MP_CTX ctx,
                             const uint8_t * data, size_t datalen,
                             MP_CRL * crl );
MP_API int32_t mp_crl_close( MP_CRL crl );

MP_API int32_t mp_crl_issuer( MP_CRL crl,
                              const uint8_t ** out, size_t * outlen );
MP_API int32_t mp_crl_this_update( MP_CRL crl, int64_t * time );
MP_API int32_t mp_crl_next_update( MP_CRL crl, int64_t * time );

MP_API int32_t mp_crl_is_revoked( MP_CRL crl, MP_CERT cert,
                                  int32_t * result );
MP_API int32_t mp_crl_revoked_count( MP_CRL crl, size_t * count );
MP_API int32_t mp_crl_issuer_name_der( MP_CRL crl,
                                       const uint8_t ** der, size_t * derlen );
MP_API int32_t mp_crl_aki( MP_CRL crl,
                           const uint8_t ** out, size_t * outlen );

/* Reports whether CRL has issuingDistributionPoint extension (RFC 5280 §5.2.5).
 * Presence implies scoped/partitioned/delta CRL — callers that don't parse IDP
 * should warn that revocation scope is not fully understood. */
MP_API int32_t mp_crl_has_idp( MP_CRL crl, int32_t * has );

/* Verifies CRL signature against issuer's public key.
 * Returns MP_OK on valid signature, MP_ERR_VERIFY on bad signature,
 * MP_ERR_OPENSSL on internal failure. Does NOT check name/AKI match,
 * freshness, or scope — caller is responsible. */
MP_API int32_t mp_crl_verify( MP_CRL crl, MP_CERT issuer );

/* -- Trust Store --------------------------------------------------- */

MP_API int32_t mp_store_new( MP_CTX ctx, MP_STORE * store );
MP_API int32_t mp_store_close( MP_STORE store );

MP_API int32_t mp_store_add_root( MP_STORE store,
                                  const uint8_t * cert, size_t certlen );
MP_API int32_t mp_store_add_intermediate( MP_STORE store,
                                          const uint8_t * cert, size_t certlen );
MP_API int32_t mp_store_add_crl( MP_STORE store,
                                 const uint8_t * crl, size_t crllen );
MP_API int32_t mp_store_set_crl_check( MP_STORE store, int32_t enable );

/* -- Verification -------------------------------------------------- */

MP_API int32_t mp_verify( MP_STORE store, MP_CERT cert,
                          MP_CHAIN * chain );

MP_API int32_t mp_verify_last_error( MP_STORE store,
                                     int32_t * code, int32_t * depth,
                                     const uint8_t ** msg, size_t * msglen );

/* -- OCSP ---------------------------------------------------------- */

#define MP_OCSP_GOOD     0
#define MP_OCSP_REVOKED  1
#define MP_OCSP_UNKNOWN  2

MP_API int32_t mp_ocsp_request_new( MP_CTX ctx,
                                     MP_CERT cert, MP_CERT issuer,
                                     MP_OCSP_REQ * req );
MP_API int32_t mp_ocsp_request_close( MP_OCSP_REQ req );
MP_API int32_t mp_ocsp_request_der( MP_OCSP_REQ req,
                                     const uint8_t ** der, size_t * derlen );

MP_API int32_t mp_ocsp_response_parse( MP_CTX ctx,
                                        MP_CERT cert, MP_CERT issuer,
                                        const uint8_t * data, size_t datalen,
                                        MP_OCSP_RESP * resp );
MP_API int32_t mp_ocsp_response_close( MP_OCSP_RESP resp );

MP_API int32_t mp_ocsp_status( MP_OCSP_RESP resp, int32_t * status );
MP_API int32_t mp_ocsp_verified( MP_OCSP_RESP resp, int32_t * verified );
MP_API int32_t mp_ocsp_this_update( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_next_update( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_produced_at( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_revoked_at( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_revoke_reason( MP_OCSP_RESP resp, int32_t * reason );
MP_API int32_t mp_ocsp_der( MP_OCSP_RESP resp,
                             const uint8_t ** der, size_t * derlen );

/* -- Chain --------------------------------------------------------- */

MP_API int32_t mp_chain_count( MP_CHAIN chain, size_t * count );
MP_API int32_t mp_chain_cert( MP_CHAIN chain, size_t index,
                              MP_CERT * cert );
MP_API int32_t mp_chain_close( MP_CHAIN chain );

#ifdef __cplusplus
}
#endif

#endif /* MINIPKI_H */
