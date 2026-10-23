/* minipki.h - MiniPKI SDK */
#ifndef MINIPKI_H
#define MINIPKI_H

#include <stdint.h>
#include <stddef.h>

/* Version */
#define MP_VERSION_MAJOR 3
#define MP_VERSION_MINOR 0
#define MP_VERSION_PATCH 0

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

/* Handles are not thread-safe: a handle, and handles obtained from it,
 * must not be used by several threads at once. Distinct handles may be used
 * concurrently. Binary input (starting with a DER SEQUENCE) is parsed only
 * as DER and must be consumed exactly; other input is parsed as text (PEM,
 * or raw base64 for certificates). */

/* Opaque handles */
typedef struct MP_CTX_S   * MP_CTX;
typedef struct MP_CERT_S  * MP_CERT;
typedef struct MP_CRL_S   * MP_CRL;
typedef struct MP_STORE_S * MP_STORE;
typedef struct MP_CHAIN_S * MP_CHAIN;
typedef struct MP_BAG_S   * MP_BAG;
typedef struct MP_OCSP_REQ_S  * MP_OCSP_REQ;
typedef struct MP_OCSP_RESP_S * MP_OCSP_RESP;
typedef struct MP_KEY_S   * MP_KEY;
typedef struct MP_CMS_S   * MP_CMS;

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

/* If MINIPKI_GOST_ENGINE names the GOST engine, it is loaded on the first
 * call; MP_ERR_OPENSSL if it cannot be loaded. */
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

/* DER encoding of the parsed CRL, whatever form it was parsed from. */
MP_API int32_t mp_crl_der( MP_CRL crl,
                           const uint8_t ** der, size_t * derlen );

MP_API int32_t mp_crl_issuer( MP_CRL crl,
                              const uint8_t ** out, size_t * outlen );
MP_API int32_t mp_crl_this_update( MP_CRL crl, int64_t * time );
/* 0 if the CRL has no nextUpdate. */
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
/* Roots are trust anchors; intermediates only help build the chain. */
MP_API int32_t mp_store_add_intermediate( MP_STORE store,
                                          const uint8_t * cert, size_t certlen );
MP_API int32_t mp_store_add_crl( MP_STORE store,
                                 const uint8_t * crl, size_t crllen );

/* Verification flags; none are set on a new store. */
#define MP_VERIFY_CRL_CHECK     0x1  /* every certificate needs its CRL */
#define MP_VERIFY_CHECK_SS_SIG  0x2  /* check the signature of a self-signed
                                        trust anchor */
#define MP_VERIFY_PARTIAL_CHAIN 0x4  /* a root need not be self-signed */

/* Replaces the verification flags of the store. */
MP_API int32_t mp_store_set_flags( MP_STORE store, uint32_t flags );

/* -- Verification -------------------------------------------------- */

MP_API int32_t mp_verify( MP_STORE store, MP_CERT cert,
                          MP_CHAIN * chain );

/* Error of the last mp_verify on the store; code 0 after a success. */
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

/* Status and times come from the response's own fields whether or not its
 * signature verified: trust them only when mp_ocsp_verified reports 1. */
MP_API int32_t mp_ocsp_status( MP_OCSP_RESP resp, int32_t * status );
MP_API int32_t mp_ocsp_verified( MP_OCSP_RESP resp, int32_t * verified );
MP_API int32_t mp_ocsp_this_update( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_next_update( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_produced_at( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_revoked_at( MP_OCSP_RESP resp, int64_t * time );
MP_API int32_t mp_ocsp_revoke_reason( MP_OCSP_RESP resp, int32_t * reason );
MP_API int32_t mp_ocsp_der( MP_OCSP_RESP resp,
                             const uint8_t ** der, size_t * derlen );

/* -- Key ----------------------------------------------------------- */

/* A signing key: a GOST R 34.10-2012 256-bit key on the CryptoPro-A
 * parameter set, generated or imported from its raw form, the 32-byte
 * little-endian private scalar as in its PKCS#8 (these need the GOST engine
 * named by MINIPKI_GOST_ENGINE); or any key OpenSSL reads from PKCS#8, such
 * as RSA or ECDSA. */
#define MP_KEY_RAW_LEN  32

MP_API int32_t mp_key_generate( MP_CTX ctx, MP_KEY * key );
MP_API int32_t mp_key_import( MP_CTX ctx,
                              const uint8_t * raw, size_t rawlen,
                              MP_KEY * key );
MP_API int32_t mp_key_import_pkcs8( MP_CTX ctx,
                                    const uint8_t * der, size_t derlen,
                                    MP_KEY * key );
MP_API int32_t mp_key_close( MP_KEY key );

/* The raw form of a GOST key; MP_ERR_INVALID_ARG for other keys. */
MP_API int32_t mp_key_raw( MP_KEY key,
                           const uint8_t ** raw, size_t * rawlen );
/* SubjectPublicKeyInfo DER */
MP_API int32_t mp_key_spki( MP_KEY key,
                            const uint8_t ** der, size_t * derlen );

/* Signs data over the GOST R 34.11-2012 256-bit hash for a GOST key and
 * SHA-256 for others. The signature is the signatureValue of X.509
 * certificates and CRLs signed with id-tc26-signwithdigest-gost3410-12-256,
 * sha256WithRSAEncryption or ecdsa-with-SHA256, valid until the next
 * mp_key_sign on the key. */
MP_API int32_t mp_key_sign( MP_KEY key,
                            const uint8_t * data, size_t datalen,
                            const uint8_t ** sig, size_t * siglen );

/* -- CMS ----------------------------------------------------------- */

/* Parses a DER CMS SignedData with its content and exactly one signer, and
 * verifies the signature with the signer certificate: the one given, or
 * else the one the SignedData carries; the certificate itself is not
 * verified. MP_ERR_VERIFY on a bad signature. */
MP_API int32_t mp_cms_verify( MP_CTX ctx,
                              const uint8_t * data, size_t datalen,
                              const uint8_t * signer, size_t signerlen,
                              MP_CMS * cms );
/* Signs content of the given content type (a dotted OID, NULL for id-data)
 * with key, whose certificate is signer, into a DER CMS SignedData holding
 * the content and exactly the certificates certs, which need not include
 * signer. */
MP_API int32_t mp_cms_sign( MP_KEY key,
                            const uint8_t * signer, size_t signerlen,
                            const char * content_type,
                            const uint8_t * content, size_t contentlen,
                            const uint8_t * const * certs, const size_t * certlens,
                            size_t ncerts,
                            MP_CMS * cms );
MP_API int32_t mp_cms_close( MP_CMS cms );
MP_API int32_t mp_cms_der( MP_CMS cms,
                           const uint8_t ** der, size_t * derlen );

MP_API int32_t mp_cms_content( MP_CMS cms,
                               const uint8_t ** content, size_t * contentlen );
MP_API int32_t mp_cms_signer( MP_CMS cms,
                              const uint8_t ** der, size_t * derlen );

/* -- Chain --------------------------------------------------------- */

MP_API int32_t mp_chain_count( MP_CHAIN chain, size_t * count );
/* The certificate is owned by the chain: valid until mp_chain_close and
 * never passed to mp_cert_close. */
MP_API int32_t mp_chain_cert( MP_CHAIN chain, size_t index,
                              MP_CERT * cert );
MP_API int32_t mp_chain_close( MP_CHAIN chain );

#ifdef __cplusplus
}
#endif

#endif /* MINIPKI_H */
