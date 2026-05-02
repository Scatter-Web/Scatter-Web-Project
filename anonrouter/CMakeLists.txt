add_executable(sw-anonrouter
    src/main.cpp
    src/cell.cpp
    src/guard.cpp
    src/tft.cpp
    src/garlic.cpp
    src/udp_transport.cpp
    src/tunnel.cpp
    src/channel.cpp
    src/dht.cpp
    src/ipc_handler.cpp
    src/router.cpp
)

target_include_directories(sw-anonrouter PRIVATE src)

target_link_libraries(sw-anonrouter PRIVATE
    sw_common
    LibOQS::LibOQS
    LibSodium::LibSodium
    LibCBOR::LibCBOR
    OpenSSL::Crypto
    Threads::Threads
)

install(TARGETS sw-anonrouter RUNTIME DESTINATION bin)
