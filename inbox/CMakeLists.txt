add_executable(sw-inbox
    src/main.cpp
    src/store.cpp
    src/frame_parser.cpp
    src/ipc_handler.cpp
    src/inbox.cpp
)

target_include_directories(sw-inbox PRIVATE src)

target_link_libraries(sw-inbox PRIVATE
    sw_common
    LibOQS::LibOQS
    LibSodium::LibSodium
    LibCBOR::LibCBOR
    OpenSSL::Crypto
    SQLite3::SQLite3
    Threads::Threads
)

install(TARGETS sw-inbox RUNTIME DESTINATION bin)
