/* minipki.h - MiniPKI SDK */
#ifndef MINIPKI_H
#define MINIPKI_H

#include <stdint.h>
#include <stddef.h>

/* Version */
#define MP_VERSION_MAJOR 1
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

/* Opaque handles */
typedef struct MP_CTX_S   * MP_CTX;
typedef struct MP_CERT_S  * MP_CERT;
typedef struct MP_CRL_S   * MP_CRL;
typedef struct MP_STORE_S * MP_STORE;
typedef struct MP_CHAIN_S * MP_CHAIN;

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

MP_API int32_t mp_cert_aia_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_aia_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen );

MP_API int32_t mp_cert_cdp_count( MP_CERT cert, size_t * count );
MP_API int32_t mp_cert_cdp_url( MP_CERT cert, size_t index,
                                const uint8_t ** url, size_t * urllen );

MP_API int32_t mp_cert_der( MP_CERT cert,
                            const uint8_t ** der, size_t * derlen );

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

/* -- Trust Store --------------------------------------------------- */

MP_API int32_t mp_store_new( MP_CTX ctx, MP_STORE * store );
MP_API int32_t mp_store_close( MP_STORE store );

MP_API int32_t mp_store_add_root( MP_STORE store,
                                  const uint8_t * cert, size_t certlen );
MP_API int32_t mp_store_add_intermediate( MP_STORE store,
                                          const uint8_t * cert, size_t certlen );
MP_API int32_t mp_store_add_crl( MP_STORE store,
                                 const uint8_t * crl, size_t crllen );

/* -- Verification -------------------------------------------------- */

MP_API int32_t mp_verify( MP_STORE store, MP_CERT cert,
                          MP_CHAIN * chain );

/* -- Chain --------------------------------------------------------- */

MP_API int32_t mp_chain_count( MP_CHAIN chain, size_t * count );
MP_API int32_t mp_chain_cert( MP_CHAIN chain, size_t index,
                              MP_CERT * cert );
MP_API int32_t mp_chain_close( MP_CHAIN chain );

#ifdef __cplusplus
}
#endif

#endif /* MINIPKI_H */
