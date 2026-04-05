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
#include <openssl/err.h>
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
    OSSL_PROVIDER * prov_gost;
    OSSL_LIB_CTX  * libctx;
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
};

/* ── CRL ──────────────────────────────────────────────────── */

struct MP_CRL_S
{
    X509_CRL      * crl;
    char          * issuer;
};

/* ── Store ────────────────────────────────────────────────── */

struct MP_STORE_S
{
    MP_CTX          ctx;
    X509_STORE    * store;
};

/* ── Chain ────────────────────────────────────────────────── */

struct MP_CHAIN_S
{
    STACK_OF(X509)    * chain;    /* owned copy */
    struct MP_CERT_S  * certs;    /* array of MP_CERT_S wrappers */
    size_t              count;
};

#endif /* MP_INTERNAL_H */
