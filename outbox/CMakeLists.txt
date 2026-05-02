add_executable(sw-outbox
    src/main.cpp
    src/store.cpp
    src/frame_parser.cpp
    src/ipc_handler.cpp
    src/outbox.cpp
)

target_include_directories(sw-outbox PRIVATE src)

target_link_libraries(sw-outbox PRIVATE
    sw_common
    LibOQS::LibOQS
    LibSodium::LibSodium
    LibCBOR::LibCBOR
    OpenSSL::Crypto
    SQLite3::SQLite3
    Threads::Threads
)

install(TARGETS sw-outbox RUNTIME DESTINATION bin)
