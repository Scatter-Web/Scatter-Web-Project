find_path(LIBOQS_INCLUDE_DIR NAMES oqs/oqs.h
    PATHS /opt/sw-deps/include /usr/local/include /usr/include)

find_library(LIBOQS_LIBRARY NAMES oqs
    PATHS /opt/sw-deps/lib /opt/sw-deps/lib64 /usr/local/lib /usr/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibOQS DEFAULT_MSG LIBOQS_LIBRARY LIBOQS_INCLUDE_DIR)

if(LIBOQS_FOUND AND NOT TARGET LibOQS::LibOQS)
    add_library(LibOQS::LibOQS UNKNOWN IMPORTED)
    set_target_properties(LibOQS::LibOQS PROPERTIES
        IMPORTED_LOCATION "${LIBOQS_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INCLUDE_DIR}")
endif()
