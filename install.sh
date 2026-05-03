#/bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build git pkg-config \
  libssl-dev libsqlite3-dev \
  libboost-all-dev libprotobuf-dev protobuf-compiler


export REPO_PATH=$(pwd)
export SW_DEPS=/opt/sw-deps
sudo mkdir -p $SW_DEPS && sudo chown $USER:$USER $SW_DEPS
export PKG_CONFIG_PATH=$SW_DEPS/lib/pkgconfig:$SW_DEPS/lib64/pkgconfig
export CMAKE_PREFIX_PATH=$SW_DEPS

# Install liboqs
cd /tmp
git clone --branch 0.10.1 --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja \
  -DCMAKE_INSTALL_PREFIX=$SW_DEPS -DCMAKE_BUILD_TYPE=Release \
  -DOQS_ENABLE_KEM_KYBER=ON -DOQS_ENABLE_SIG_DILITHIUM=ON \
  -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build
cmake --install liboqs/build

# Install libsodium
cd /tmp
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
tar xf libsodium-1.0.20.tar.gz
cd libsodium-1.0.20 && ./configure --prefix=$SW_DEPS
make -j$(nproc) && make install
cd /tmp

# Install libcbor
cd /tmp
git clone --branch v0.11.0 --depth 1 https://github.com/PJK/libcbor.git
cmake -S libcbor -B libcbor/build -GNinja \
  -DCMAKE_INSTALL_PREFIX=$SW_DEPS -DCMAKE_BUILD_TYPE=Release \
  -DWITH_EXAMPLES=OFF
cmake --build libcbor/build
cmake --install libcbor/build


cd $REPO_PATH   # back to the repository
rm -rf build   # required if the directory exists from a previous run
cmake -S . -B build -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/opt/sw-deps

cmake --build build -j$(nproc)