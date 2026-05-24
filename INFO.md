# MiniPKI

MiniPKI is a small C FFI library for PKI operations:

- X.509 certificate parsing
- certificate chain building and verification
- GOST 34.10 signature verification through OpenSSL/GOST
- CRL parsing and revocation checks
- OCSP request/response helpers
- a stable C ABI declared in `include/minipki.h`

The repository is now the core library only. The web/product layer (`certview`
and `certget`) lives in `github.com/PiDmitrius/certview`.

## Version

The MiniPKI core version is defined in `include/minipki.h`:

```c
#define MP_VERSION_MAJOR 1
#define MP_VERSION_MINOR 0
#define MP_VERSION_PATCH 1
```

Release tags for this repository should follow that value, for example
`v1.0.1`.

## Layout

- `include/minipki.h` — public C ABI.
- `src/` — MiniPKI implementation.
- `test/test_minipki.c` — core test binary.
- `build/Makefile` — cross-platform library/test build.
- `build/Dockerfile` — Docker image for deterministic cross-builds with Zig,
  OpenSSL, and gost-engine.
- `build/build-zig-openssl.sh` — helper used by `build/Dockerfile` to build
  OpenSSL + gost-engine for all supported targets.

## Docker Build

Build the deterministic build image:

```sh
docker build -f build/Dockerfile -t pidmitrius/minipki-zig-build:latest build
```

Build all shared libraries:

```sh
docker run --rm -v "$PWD:/src" -w /src/build pidmitrius/minipki-zig-build:latest make lib
```

Build all static libraries:

```sh
docker run --rm -v "$PWD:/src" -w /src/build pidmitrius/minipki-zig-build:latest make static
```

Build all test binaries:

```sh
docker run --rm -v "$PWD:/src" -w /src/build pidmitrius/minipki-zig-build:latest make test
```

Run the Linux amd64 test binary after `make test`:

```sh
docker run --rm -v "$PWD:/src" -w /src/build \
  -e LD_LIBRARY_PATH=/src/build/out/linux-amd64:/opt/openssl/linux-amd64/lib \
  pidmitrius/minipki-zig-build:latest \
  ./out/linux-amd64/test_minipki
```

## Targets

`build/Makefile` builds:

- `linux-amd64`
- `linux-arm64`
- `macos-amd64`
- `macos-arm64`
- `windows-amd64`
- `windows-arm64`

Artifacts are written under `build/out/<target>/`:

- shared library: `libminipki.so`, `libminipki.dylib`, or `minipki.dll`
- static library: `libminipki.a`
- test binary: `test_minipki`
