.PHONY: all clean lib static test

ROOT := ..

CFLAGS := -Wall -O2 -fPIC -Werror -Wno-unused-function -fvisibility=hidden -std=c11

, := ,

OPENSSL_BASE := /opt/openssl
GOST_ENGINE_SRC := /tmp/gost-engine-src

# 6 targets
TARGETS := linux-amd64 linux-arm64 macos-amd64 macos-arm64 windows-amd64 windows-arm64

# Zig targets
ZIG_linux-amd64    := x86_64-linux-gnu
ZIG_linux-arm64    := aarch64-linux-gnu
ZIG_macos-amd64    := x86_64-macos-none
ZIG_macos-arm64    := aarch64-macos-none
ZIG_windows-amd64  := x86_64-windows-gnu
ZIG_windows-arm64  := aarch64-windows-gnu

# Library extensions
EXT_linux-amd64    := .so
EXT_linux-arm64    := .so
EXT_macos-amd64    := .dylib
EXT_macos-arm64    := .dylib
EXT_windows-amd64  := .dll
EXT_windows-arm64  := .dll

# Library prefixes
PFX_linux-amd64    := lib
PFX_linux-arm64    := lib
PFX_macos-amd64    := lib
PFX_macos-arm64    := lib
PFX_windows-amd64  :=
PFX_windows-arm64  :=

# Executable extensions
EXEEXT_linux-amd64    :=
EXEEXT_linux-arm64    :=
EXEEXT_macos-amd64    :=
EXEEXT_macos-arm64    :=
EXEEXT_windows-amd64  := .exe
EXEEXT_windows-arm64  := .exe

# MiniPKI source files
MP_SRCS := mp_ctx.c mp_cert.c mp_crl.c mp_store.c mp_ocsp.c

# Object files for a target
MP_OBJS = $(patsubst %.c,out/$(1)/%.o,$(MP_SRCS))

# Platform link flags
PLAT_LDFLAGS = -L$(OPENSSL_BASE)/$(1)/lib -lgost -lcrypto \
	$(if $(findstring windows,$(1)),-lws2_32 -lcrypt32 -lbcrypt,) \
	$(if $(findstring linux,$(1)),-lpthread -ldl,) \
	$(if $(findstring macos,$(1)),-Wl$(,)-headerpad$(,)0x1000,)

# --- Output paths ---
outlib  = out/$(1)/$(PFX_$(1))minipki$(EXT_$(1))
outstatic = out/$(1)/libminipki.a
outtest   = out/$(1)/test_minipki$(EXEEXT_$(1))

ALL_LIBS    := $(foreach t,$(TARGETS),$(call outlib,$(t)))
ALL_STATICS := $(foreach t,$(TARGETS),$(call outstatic,$(t)))
ALL_TESTS   := $(foreach t,$(TARGETS),$(call outtest,$(t)))

all: lib

lib: $(ALL_LIBS)

static: $(ALL_STATICS)

test: $(ALL_TESTS)

# Per-target build
define BUILD_TARGET
out/$(1):
	mkdir -p out/$(1)

out/$(1)/%.o: $(ROOT)/src/%.c | out/$(1)
	zig cc $$(CFLAGS) -target $$(ZIG_$(1)) \
		-I$(ROOT)/include \
		-I$(OPENSSL_BASE)/$(1)/include \
		-I$(ROOT)/src \
		-c $$< -o $$@

out/$(1)/test_minipki.o: $(ROOT)/test/test_minipki.c | out/$(1)
	zig cc $$(CFLAGS) -Wno-error -target $$(ZIG_$(1)) \
		-I$(ROOT)/include \
		-c $$< -o $$@

# Static library
$(call outstatic,$(1)): $(call MP_OBJS,$(1))
	zig ar rcs $$@ $$^

# Shared library
$(call outlib,$(1)): $(call MP_OBJS,$(1))
	zig cc -target $$(ZIG_$(1)) -shared -s -o $$@ $$^ \
		$(call PLAT_LDFLAGS,$(1)) \
		$(if $(findstring windows,$(1)),-Wl$(,)--out-implib$(,)out/$(1)/minipki.lib,) \
		$(if $(findstring linux,$(1)),-Wl$(,)-soname$(,)$(PFX_$(1))minipki$(EXT_$(1)) -Wl$(,)--version-script$(,)$(ROOT)/build/minipki.map,) \
		$(if $(findstring macos,$(1)),-Wl$(,)-install_name$(,)@rpath/$(PFX_$(1))minipki$(EXT_$(1)),)

# Test binary (dynamic)
$(call outtest,$(1)): out/$(1)/test_minipki.o $(call outlib,$(1))
	zig cc -target $$(ZIG_$(1)) -s -o $$@ out/$(1)/test_minipki.o \
		-Lout/$(1) -lminipki \
		$(if $(findstring linux,$(1)),-Wl$(,)-rpath$(,)'$$$$ORIGIN',) \
		$(if $(findstring macos,$(1)),-Wl$(,)-rpath$(,)'@executable_path' -Wl$(,)-headerpad$(,)0x1000,)
endef

$(foreach t,$(TARGETS),$(eval $(call BUILD_TARGET,$(t))))

clean:
	rm -rf out
