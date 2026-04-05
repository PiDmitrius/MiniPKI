# MiniPKI

C FFI-библиотека для работы с PKI: парсинг сертификатов, построение цепочек, верификация подписей (включая ГОСТ 34.10), работа с CRL.

## Назначение

Низкоуровневый слой для сервиса администрирования сертификатов. Сервис (Go/Kotlin) вызывает MiniPKI через FFI. MiniPKI отвечает за криптографию и PKI-логику, сервис — за REST API, планировщик, HTTP-клиент, хранилище.

## Стек

- **C** (C ABI, вызывается из любого языка)
- **OpenSSL 3.x** — статическая линковка libcrypto
- **gost-engine/provider** — статически встроен через `OSSL_PROVIDER_add_builtin`
- Единственная внешняя зависимость: **libc**

## Сущности

| Тип | Описание |
|-----|----------|
| Root CA | Корневые сертификаты (самоподписанные) |
| Intermediate CA | Промежуточные, скачиваются по AIA |
| CRL | Списки отзыва, скачиваются по CDP |

## API (проектируемый)

### Инициализация
```c
mp_ctx *mp_init(void);        // создать контекст, загрузить ГОСТ-провайдер
void    mp_free(mp_ctx *ctx);  // освободить
```

### Парсинг сертификатов
```c
mp_cert *mp_cert_parse(const uint8_t *der, size_t len);
void     mp_cert_free(mp_cert *cert);

// Извлечение полей
const char *mp_cert_subject(mp_cert *cert);
const char *mp_cert_issuer(mp_cert *cert);
int         mp_cert_is_ca(mp_cert *cert);
int         mp_cert_is_self_signed(mp_cert *cert);

// AIA — URL промежуточных CA
int         mp_cert_aia_count(mp_cert *cert);
const char *mp_cert_aia_url(mp_cert *cert, int index);

// CDP — URL CRL
int         mp_cert_cdp_count(mp_cert *cert);
const char *mp_cert_cdp_url(mp_cert *cert, int index);
```

### CRL
```c
mp_crl *mp_crl_parse(const uint8_t *der, size_t len);
void    mp_crl_free(mp_crl *crl);

const char *mp_crl_issuer(mp_crl *crl);
time_t      mp_crl_this_update(mp_crl *crl);
time_t      mp_crl_next_update(mp_crl *crl);
int         mp_crl_is_revoked(mp_crl *crl, mp_cert *cert);
```

### Хранилище (in-memory trust store)
```c
mp_store *mp_store_new(void);
void      mp_store_free(mp_store *store);

int mp_store_add_root(mp_store *store, mp_cert *cert);
int mp_store_add_intermediate(mp_store *store, mp_cert *cert);
int mp_store_add_crl(mp_store *store, mp_crl *crl);
```

### Верификация цепочки
```c
// Верифицирует leaf через store (roots + intermediates + CRL)
// Возвращает 0 = OK, иначе код ошибки
int mp_verify(mp_ctx *ctx, mp_store *store, mp_cert *leaf);
```

## Сборка (план)

```bash
# 1. OpenSSL 3.x static
./config no-shared no-tests -static
make -j$(nproc)

# 2. gost-provider static
cmake -DBUILD_SHARED_LIBS=OFF ...
make

# 3. MiniPKI
make  # → libminipki.a + libminipki.so
```

## Контекст

Часть архитектуры сервиса администрирования сертификатов для air-gapped СКЗИ:

```
Интернет ← HTTP → [Сервис: Go/Kotlin + MiniPKI] → snapshot-бандл → [СКЗИ]
                    ├── REST API (сервис)
                    ├── Планировщик обновления CRL (сервис)
                    ├── Парсинг/верификация (MiniPKI)
                    └── Хранилище (сервис + MiniPKI store)
```

## Связанные проекты

- **MiniCrypto** — C ABI криптобиблиотека того же автора (OpenSSL backend, статическая линковка)
