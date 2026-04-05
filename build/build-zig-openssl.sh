#!/bin/bash
set -e

# Build static OpenSSL + gost-engine for all 6 targets using zig cc
# Environment:
#   OPENSSL_VERSION  - required
#   GOST_ENGINE_SRC  - path to gost-engine source (default: /tmp/gost-engine-src)
#   OPENSSL_BASE     - output prefix (default: /opt/openssl)

if [ -z "${OPENSSL_VERSION:-}" ]; then
    echo "Error: OPENSSL_VERSION not set" >&2
    exit 1
fi
OPENSSL_BASE=${OPENSSL_BASE:-/opt/openssl}
GOST_ENGINE_SRC=${GOST_ENGINE_SRC:-/tmp/gost-engine-src}

OPENSSL_SRC="/tmp/openssl-src-${OPENSSL_VERSION}"

# Download OpenSSL if not cached
if [ ! -d "$OPENSSL_SRC" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
        | tar -xz -C /tmp
    mv "/tmp/openssl-${OPENSSL_VERSION}" "$OPENSSL_SRC"
fi

# ssl_target          zig_target                    short_name
TARGETS=(
    "linux-x86_64       x86_64-linux-gnu              linux-amd64"
    "linux-aarch64      aarch64-linux-gnu             linux-arm64"
    "darwin64-x86_64    x86_64-macos-none             macos-amd64"
    "darwin64-arm64     aarch64-macos-none            macos-arm64"
    "mingw64            x86_64-windows-gnu            windows-amd64"
    "mingw64            aarch64-windows-gnu           windows-arm64"
)

# Common OpenSSL Configure flags
COMMON_FLAGS=(
    --libdir=lib
    no-shared
    no-asm
    no-tests
    no-docs
    no-apps
    no-ui-console
    no-async
    no-comp
    no-legacy
    no-dso
    no-quic
    -fPIC
)

# Per-target gost-engine defines
# All our targets are little-endian
# arm64: strict alignment; x86_64: relaxed alignment
gost_defines_for_target() {
    local short_name="$1"
    local defs="-DL_ENDIAN"
    case "$short_name" in
        *-arm64) defs="$defs -DSTRICT_ALIGNMENT" ;;
        *-amd64) defs="$defs -DHAVE_ADDCARRY_U64" ;;
    esac
    echo "$defs"
}

# Create zig wrapper scripts for a target
make_wrappers() {
    local zig_target="$1"
    local dir="$2"
    mkdir -p "$dir"
    cat > "$dir/cc" <<EOF
#!/bin/bash
exec zig cc -target $zig_target "\$@"
EOF
    cat > "$dir/c++" <<EOF
#!/bin/bash
exec zig c++ -target $zig_target "\$@"
EOF
    cat > "$dir/ar" <<EOF
#!/bin/bash
exec zig ar "\$@"
EOF
    cat > "$dir/ranlib" <<EOF
#!/bin/bash
exec zig ranlib "\$@"
EOF
    chmod +x "$dir"/*
}

# gost-engine source files (provider mode)
GOST_CORE_SRCS="
    gost89.c
    gosthash.c
    gosthash2012.c
    gost_ameth.c
    gost_pmeth.c
    gost_ctl.c
    gost_asn1.c
    gost_crypt.c
    gost_keywrap.c
    gost_md.c
    gost_md2012.c
    gost_omac.c
    gost_omac_acpkm.c
    gost_gost2015.c
    gost_params.c
    gost_keyexpimp.c
    gost_digest.c
    gost_digest_ctx.c
    gost_grasshopper_core.c
    gost_grasshopper_defines.c
    gost_grasshopper_galois_precompiled.c
    gost_grasshopper_precompiled.c
    gost_grasshopper_cipher.c
    gost_ec_keyx.c
    gost_ec_sign.c
    ecp_id_GostR3410_2001_CryptoPro_A_ParamSet.c
    ecp_id_GostR3410_2001_CryptoPro_B_ParamSet.c
    ecp_id_GostR3410_2001_CryptoPro_C_ParamSet.c
    ecp_id_GostR3410_2001_TestParamSet.c
    ecp_id_tc26_gost_3410_2012_256_paramSetA.c
    ecp_id_tc26_gost_3410_2012_512_paramSetA.c
    ecp_id_tc26_gost_3410_2012_512_paramSetB.c
    ecp_id_tc26_gost_3410_2012_512_paramSetC.c
    gost_tls12_additional_kdftree.c
    gost_tls12_additional_kexpimp.c
    gost_tls12_additional_tlstree.c
    gost_eng.c
    gost_eng_digest.c
    gost_eng_digest_define.c
"

GOST_PROV_SRCS="
    gost_prov.c
    gost_prov_cipher.c
    gost_prov_digest.c
    gost_prov_mac.c
    gost_prov_keymgmt.c
    gost_prov_encoder.c
    gost_prov_signature.c
    gost_prov_decoder.c
    gost_prov_keyexch.c
    gost_prov_tls.c
"

build_gost_static() {
    local short_name="$1"
    local zig_target="$2"
    local prefix="$3"

    local gost_defines
    gost_defines=$(gost_defines_for_target "$short_name")

    local build_dir="/tmp/gost-build-${short_name}"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "--- Building gost-engine for $short_name ---"

    local cflags="-Wall -O2 -fPIC -std=gnu99 -DBUILDING_PROVIDER_AS_LIBRARY -DBUILDING_GOST_PROVIDER $gost_defines"
    cflags="$cflags -Wno-unused-parameter -Wno-unused-function -Wno-missing-braces"
    cflags="$cflags -Wno-deprecated-declarations"
    cflags="$cflags -I${GOST_ENGINE_SRC} -I${GOST_ENGINE_SRC}/libprov/include -I${prefix}/include"

    # Compile core + provider sources
    for src in $GOST_CORE_SRCS $GOST_PROV_SRCS; do
        local obj="${build_dir}/$(basename "$src" .c).o"
        zig cc -target "$zig_target" $cflags \
            -c "${GOST_ENGINE_SRC}/${src}" -o "$obj"
    done

    # Compile libprov sources
    for src in libprov/err.c libprov/num.c; do
        local obj="${build_dir}/libprov_$(basename "$src" .c).o"
        zig cc -target "$zig_target" $cflags \
            -c "${GOST_ENGINE_SRC}/${src}" -o "$obj"
    done

    # Create static library
    zig ar rcs "${prefix}/lib/libgost.a" "$build_dir"/*.o

    rm -rf "$build_dir"
    echo "--- Done: ${prefix}/lib/libgost.a ---"
}

for entry in "${TARGETS[@]}"; do
    read -r ssl_target zig_target short_name <<< "$entry"

    PREFIX="${OPENSSL_BASE}/${short_name}"
    if [ -f "$PREFIX/lib/libcrypto.a" ] && [ -f "$PREFIX/lib/libgost.a" ]; then
        echo "=== $short_name already built, skipping ==="
        continue
    fi

    echo "=== Building OpenSSL ${OPENSSL_VERSION} + gost-engine for $short_name ==="

    # --- OpenSSL ---
    if [ ! -f "$PREFIX/lib/libcrypto.a" ]; then
        BUILD_DIR="/tmp/openssl-build-${short_name}"
        rm -rf "$BUILD_DIR"
        cp -r "$OPENSSL_SRC" "$BUILD_DIR"
        cd "$BUILD_DIR"

        WRAPPERS="/tmp/zig-wrappers-${short_name}"
        make_wrappers "$zig_target" "$WRAPPERS"

        export CC="$WRAPPERS/cc"
        export CXX="$WRAPPERS/c++"
        export AR="$WRAPPERS/ar"
        export RANLIB="$WRAPPERS/ranlib"

        EXTRA_FLAGS=()
        if [[ "$short_name" == macos-* ]]; then
            EXTRA_FLAGS+=("-DOPENSSL_NO_APPLE_CRYPTO_RANDOM")
        fi

        ./Configure "$ssl_target" \
            --prefix="$PREFIX" \
            "${COMMON_FLAGS[@]}" \
            "${EXTRA_FLAGS[@]}"

        make -j$(nproc) build_libs
        make install_dev

        cd /
        rm -rf "$BUILD_DIR" "$WRAPPERS"
        unset CC CXX AR RANLIB
    fi

    # --- gost-engine ---
    build_gost_static "$short_name" "$zig_target" "$PREFIX"

    echo "=== Done: $short_name ==="
done

echo "=== All builds complete ==="
ls -la ${OPENSSL_BASE}/*/lib/libcrypto.a
ls -la ${OPENSSL_BASE}/*/lib/libgost.a
