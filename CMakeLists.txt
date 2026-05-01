cmake_minimum_required(VERSION 3.26)
project(ScatterWeb VERSION 0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default dep search path matching test lab setup
list(PREPEND CMAKE_PREFIX_PATH "/opt/sw-deps")
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(LibOQS REQUIRED)
find_package(LibSodium REQUIRED)
find_package(LibCBOR REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(googletest)

add_subdirectory(common)
add_subdirectory(tests)
