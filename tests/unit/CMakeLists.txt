add_executable(sw_unit_tests
    crypto/test_mlkem.cpp
    crypto/test_mldsa.cpp
    crypto/test_aes_gcm.cpp
    crypto/test_kdf.cpp
    ratchet/test_ratchet.cpp
    ipc/test_codec.cpp
    dht/test_record.cpp
)

target_link_libraries(sw_unit_tests PRIVATE
    sw_common
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(sw_unit_tests)
