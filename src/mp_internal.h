/* mp_internal.h - MiniPKI internal definitions */
#ifndef MP_INTERNAL_H
#define MP_INTERNAL_H

#define _GNU_SOURCE

#include "minipki.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define timegm _mkgmtime
#endif

/* ── Context ──────────────────────────────────────────────── */

struct MP_CTX_S
{
    int32_t         type;
    OSSL_PROVIDER * prov_default;
    ENGINE        * eng_gost;
};

/* ── Certificate ──────────────────────────────────────────── */

struct MP_CERT_S
{
    X509          * x509;
    /* cached DER encoding */
    uint8_t       * der;
    size_t          derlen;
    /* cached strings (one-line format) */
    char          * subject;
    char          * issuer;
    /* cached serial (hex) */
    char          * serial;
    /* cached key identifiers (hex) */
    char          * ski;
    char          * aki;
    /* cached DER-encoded X509_NAME */
    uint8_t       * subject_name_der;
    size_t          subject_name_derlen;
    uint8_t       * issuer_name_der;
    size_t          issuer_name_derlen;
    /* cached key info */
    char          * key_algorithm;
    int32_t         key_bits;
    int             key_bits_cached;
    char          * key_curve;
    int             key_curve_cached;
    /* cached key usage / EKU / pathlen */
    uint32_t        key_usage;
    int             key_usage_cached;
    char         ** eku_oids;
    size_t          eku_count;
    int             eku_cached;
    int32_t         pathlen;
    int             pathlen_cached;
    /* cached SAN entries (formatted "DNS:...", "IP:...", etc) */
    char         ** san_entries;
    size_t          san_count;
    int             san_cached;
    /* cached AIA caIssuers URLs */
    char         ** aia_urls;
    size_t          aia_count;
    int             aia_cached;
    /* cached AIA OCSP URLs */
    char         ** ocsp_urls;
    size_t          ocsp_count;
    int             ocsp_cached;
    /* cached CDP URLs */
    char         ** cdp_urls;
    size_t          cdp_count;
    int             cdp_cached;
};

/* ── CRL ──────────────────────────────────────────────────── */

struct MP_CRL_S
{
    X509_CRL      * crl;
    char          * issuer;
    uint8_t       * issuer_name_der;
    size_t          issuer_name_derlen;
    char          * aki;
};

/* ── Store ────────────────────────────────────────────────── */

struct MP_STORE_S
{
    MP_CTX          ctx;
    X509_STORE    * store;
    int             last_err_code;
    int             last_err_depth;
    char            last_err_msg[256];
};

/* ── Chain ────────────────────────────────────────────────── */

struct MP_CHAIN_S
{
    STACK_OF(X509)    * chain;    /* owned copy */
    struct MP_CERT_S  * certs;    /* array of MP_CERT_S wrappers */
    size_t              count;
};

/* ── OCSP request ────────────────────────────────────────── */

struct MP_OCSP_REQ_S
{
    uint8_t       * der;
    size_t          derlen;
};

/* ── OCSP response ───────────────────────────────────────── */

struct MP_OCSP_RESP_S
{
    OCSP_RESPONSE  * resp;
    OCSP_BASICRESP * basic;
    int32_t          status;          /* MP_OCSP_GOOD/REVOKED/UNKNOWN */
    int32_t          verified;
    int64_t          this_update;
    int64_t          next_update;
    int64_t          produced_at;
    int64_t          revoked_at;
    int32_t          revoke_reason;
    uint8_t        * der;
    size_t           derlen;
};

/* ── Bag (multi-cert container) ──────────────────────────── */

struct MP_BAG_S
{
    uint8_t      ** ders;
    size_t        * derlens;
    size_t          count;
};

/* Shared helpers (mp_cert.c) */
/* DER decoders that accept the input only if it is consumed exactly. */
X509 * mp_d2i_x509( const uint8_t * data, size_t datalen );
X509_CRL * mp_d2i_crl( const uint8_t * data, size_t datalen );

char * format_name( X509_NAME * name );
char * mp_octet_to_hex( const ASN1_OCTET_STRING * oct );

#endif /* MP_INTERNAL_H */
