FROM debian:bookworm-slim

ARG ZIG_VERSION=0.15.2
ARG OPENSSL_VERSION=3.5.5
ARG GOST_ENGINE_REF=master

# Base tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    make perl cmake \
    && rm -rf /var/lib/apt/lists/*

# Install zig from PyPI wheel
RUN ZIG_URL=$(curl -sL "https://pypi.org/pypi/ziglang/${ZIG_VERSION}/json" | \
      grep -o '"url": *"[^"]*manylinux[^"]*x86_64[^"]*\.whl"' | \
      head -1 | sed 's/"url": *"//;s/"$//') && \
    echo "Downloading: $ZIG_URL" && \
    curl -fSL -o /tmp/zig.whl "$ZIG_URL" && \
    cd /opt && jar xf /tmp/zig.whl ziglang/ 2>/dev/null || \
    (apt-get update && apt-get install -y --no-install-recommends unzip && \
     cd /opt && unzip -q /tmp/zig.whl 'ziglang/*' && \
     apt-get purge -y unzip && apt-get autoremove -y) && \
    chmod +x /opt/ziglang/zig && \
    ln -s /opt/ziglang/zig /usr/local/bin/zig && \
    rm /tmp/zig.whl && \
    zig version

# Clone gost-engine
RUN git clone --depth 1 --branch ${GOST_ENGINE_REF} \
    https://github.com/gost-engine/engine.git /tmp/gost-engine-src && \
    cd /tmp/gost-engine-src && git submodule update --init

# Download OpenSSL source
RUN curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    | tar -xz -C /tmp && \
    mv /tmp/openssl-${OPENSSL_VERSION} /tmp/openssl-src-${OPENSSL_VERSION}

# Build OpenSSL + gost-engine for all 6 targets
COPY build-zig-openssl.sh /tmp/build-zig-openssl.sh
RUN chmod +x /tmp/build-zig-openssl.sh && \
    OPENSSL_VERSION=${OPENSSL_VERSION} \
    OPENSSL_BASE=/opt/openssl \
    GOST_ENGINE_SRC=/tmp/gost-engine-src \
    /tmp/build-zig-openssl.sh && \
    rm -rf /tmp/openssl-src-* /tmp/openssl-build-* /tmp/gost-build-* \
           /tmp/zig-wrappers-* /tmp/build-zig-openssl.sh /tmp/gost-engine-src

RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
ENTRYPOINT ["tini", "--"]
