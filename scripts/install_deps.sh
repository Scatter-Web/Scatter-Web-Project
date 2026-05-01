#!/usr/bin/env bash
# Build and install all ScatterWeb dependencies into /opt/sw-deps.
# Matches the AnonRouter Test Lab setup (Ubuntu 24.04 LTS).
set -euo pipefail

PREFIX=/opt/sw-deps
JOBS=$(nproc)

sudo mkdir -p "$PREFIX"
sudo chown "$USER" "$PREFIX"

cd /tmp

# ── liboqs 0.10.1 ──────────────────────────────────────────────────────────
if [ ! -f "$PREFIX/include/oqs/oqs.h" ]; then
    echo "==> Building liboqs..."
    rm -rf liboqs
    git clone --depth 1 --branch 0.10.1 https://github.com/open-quantum-safe/liboqs.git
    cmake -S liboqs -B liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DOQS_BUILD_ONLY_LIB=ON
    cmake --build liboqs/build --parallel "$JOBS"
    cmake --install liboqs/build
fi

# ── libsodium 1.0.20 ───────────────────────────────────────────────────────
if [ ! -f "$PREFIX/include/sodium.h" ]; then
    echo "==> Building libsodium..."
    rm -rf libsodium-stable
    curl -fsSL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz | tar xz
    cd libsodium-1.0.20
    ./configure --prefix="$PREFIX" --disable-shared
    make -j"$JOBS"
    make install
    cd /tmp
fi

# ── libcbor 0.11.0 ─────────────────────────────────────────────────────────
if [ ! -f "$PREFIX/include/cbor.h" ]; then
    echo "==> Building libcbor..."
    rm -rf libcbor
    git clone --depth 1 --branch v0.11.0 https://github.com/PJK/libcbor.git
    cmake -S libcbor -B libcbor/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DBUILD_SHARED_LIBS=OFF \
        -DWITH_EXAMPLES=OFF
    cmake --build libcbor/build --parallel "$JOBS"
    cmake --install libcbor/build
fi

# ── SQLite3 (system) ───────────────────────────────────────────────────────
sudo apt-get install -y libsqlite3-dev

echo ""
echo "All dependencies installed to $PREFIX"
echo "Configure with: cmake -B build -DCMAKE_PREFIX_PATH=$PREFIX"
