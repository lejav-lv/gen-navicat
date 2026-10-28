#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo '请在 Apple Silicon Mac 的原生 ARM64 终端运行。' >&2
    exit 1
fi
LEJAV_GEN_NAVICAT_ZIG=${LEJAV_GEN_NAVICAT_ZIG:-zig}
if ! command -v "$LEJAV_GEN_NAVICAT_ZIG" >/dev/null 2>&1; then
    echo '找不到 Zig 0.17.0。请安装，或设置 LEJAV_GEN_NAVICAT_ZIG=/完整路径/zig。' >&2
    exit 1
fi
if [ "$("$LEJAV_GEN_NAVICAT_ZIG" version)" != '0.17.0' ]; then
    echo '本移植版已验证的编译器版本为 Zig 0.17.0。' >&2
    exit 1
fi
LEJAV_GEN_NAVICAT_OPENSSL_PREFIX=${LEJAV_GEN_NAVICAT_OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}
if [ ! -f "$LEJAV_GEN_NAVICAT_OPENSSL_PREFIX/lib/libcrypto.a" ]; then
    echo '缺少 ARM64 OpenSSL 3 静态库。可先运行 brew install openssl@3。' >&2
    exit 1
fi
"$LEJAV_GEN_NAVICAT_ZIG" build test --release=safe "-Dopenssl-prefix=$LEJAV_GEN_NAVICAT_OPENSSL_PREFIX"
"$LEJAV_GEN_NAVICAT_ZIG" build --release=safe "-Dopenssl-prefix=$LEJAV_GEN_NAVICAT_OPENSSL_PREFIX"
mkdir -p bin
cp zig-out/bin/lejav-gen-navicat bin/lejav-gen-navicat
/usr/bin/codesign --force --sign - --identifier lejav-gen-navicat bin/lejav-gen-navicat
/usr/bin/codesign --verify --strict bin/lejav-gen-navicat
/usr/bin/file bin/lejav-gen-navicat
printf '\n完成：%s/bin/lejav-gen-navicat\n' "$PWD"
