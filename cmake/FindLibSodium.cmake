find_path(LIBSODIUM_INCLUDE_DIR NAMES sodium.h
    PATHS /opt/sw-deps/include /usr/local/include /usr/include)

find_library(LIBSODIUM_LIBRARY NAMES sodium
    PATHS /opt/sw-deps/lib /opt/sw-deps/lib64 /usr/local/lib /usr/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibSodium DEFAULT_MSG LIBSODIUM_LIBRARY LIBSODIUM_INCLUDE_DIR)

if(LIBSODIUM_FOUND AND NOT TARGET LibSodium::LibSodium)
    add_library(LibSodium::LibSodium UNKNOWN IMPORTED)
    set_target_properties(LibSodium::LibSodium PROPERTIES
        IMPORTED_LOCATION "${LIBSODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSODIUM_INCLUDE_DIR}")
endif()
