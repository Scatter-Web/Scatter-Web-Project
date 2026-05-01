add_library(sw_common STATIC
    src/crypto/mlkem.cpp
    src/crypto/mldsa.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/kdf.cpp
    src/ratchet/ratchet.cpp
    src/ipc/codec.cpp
    src/ipc/server.cpp
    src/ipc/client.cpp
    src/store/db.cpp
    src/dht/record.cpp
)

target_include_directories(sw_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(sw_common PUBLIC
    LibOQS::LibOQS
    LibSodium::LibSodium
    LibCBOR::LibCBOR
    OpenSSL::Crypto
    SQLite3::SQLite3
    Threads::Threads
)

target_compile_options(sw_common PRIVATE -Wall -Wextra -Wpedantic)
