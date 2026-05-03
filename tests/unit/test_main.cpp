#include <gtest/gtest.h>
#include <sodium.h>
#include <stdexcept>

int main(int argc, char** argv) {
    if (sodium_init() < 0)
        throw std::runtime_error("sodium_init() failed");
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
