add_executable(sw-client
    src/main.cpp
    src/config.cpp
    src/keystore.cpp
    src/store.cpp
    src/cert.cpp
    src/dht_pub.cpp
    src/ratchet_manager.cpp
    src/ipc_handler.cpp
    src/client.cpp
)

target_include_directories(sw-client PRIVATE src)

target_link_libraries(sw-client PRIVATE
    sw_common
    LibOQS::LibOQS
    LibSodium::LibSodium
    LibCBOR::LibCBOR
    OpenSSL::Crypto
    SQLite3::SQLite3
    Threads::Threads
)

install(TARGETS sw-client RUNTIME DESTINATION bin)
