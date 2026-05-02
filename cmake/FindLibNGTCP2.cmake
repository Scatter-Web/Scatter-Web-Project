find_path(LIBNGTCP2_INCLUDE_DIR NAMES ngtcp2/ngtcp2.h
    PATHS /opt/sw-deps/include /usr/local/include /usr/include)

find_library(LIBNGTCP2_LIBRARY NAMES ngtcp2
    PATHS /opt/sw-deps/lib /opt/sw-deps/lib64 /usr/local/lib /usr/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibNGTCP2 DEFAULT_MSG LIBNGTCP2_LIBRARY LIBNGTCP2_INCLUDE_DIR)

if(LIBNGTCP2_FOUND AND NOT TARGET LibNGTCP2::LibNGTCP2)
    add_library(LibNGTCP2::LibNGTCP2 UNKNOWN IMPORTED)
    set_target_properties(LibNGTCP2::LibNGTCP2 PROPERTIES
        IMPORTED_LOCATION "${LIBNGTCP2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBNGTCP2_INCLUDE_DIR}")
endif()
