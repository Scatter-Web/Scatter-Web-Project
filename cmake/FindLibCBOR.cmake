find_path(LIBCBOR_INCLUDE_DIR NAMES cbor.h
    PATHS /opt/sw-deps/include /usr/local/include /usr/include)

find_library(LIBCBOR_LIBRARY NAMES cbor
    PATHS /opt/sw-deps/lib /opt/sw-deps/lib64 /usr/local/lib /usr/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibCBOR DEFAULT_MSG LIBCBOR_LIBRARY LIBCBOR_INCLUDE_DIR)

if(LIBCBOR_FOUND AND NOT TARGET LibCBOR::LibCBOR)
    add_library(LibCBOR::LibCBOR UNKNOWN IMPORTED)
    set_target_properties(LibCBOR::LibCBOR PROPERTIES
        IMPORTED_LOCATION "${LIBCBOR_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBCBOR_INCLUDE_DIR}")
endif()
