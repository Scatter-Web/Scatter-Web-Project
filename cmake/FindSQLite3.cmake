find_path(SQLite3_INCLUDE_DIR NAMES sqlite3.h
    PATHS /usr/local/include /usr/include)

find_library(SQLite3_LIBRARY NAMES sqlite3
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu)

if(SQLite3_INCLUDE_DIR AND EXISTS "${SQLite3_INCLUDE_DIR}/sqlite3.h")
    file(STRINGS "${SQLite3_INCLUDE_DIR}/sqlite3.h" _ver_line
         REGEX "^#define SQLITE_VERSION[ \t]+\"[0-9.]+\"")
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" SQLite3_VERSION "${_ver_line}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SQLite3
    REQUIRED_VARS SQLite3_LIBRARY SQLite3_INCLUDE_DIR
    VERSION_VAR SQLite3_VERSION)

if(SQLite3_FOUND AND NOT TARGET SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 UNKNOWN IMPORTED)
    set_target_properties(SQLite3::SQLite3 PROPERTIES
        IMPORTED_LOCATION "${SQLite3_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SQLite3_INCLUDE_DIR}")
endif()

mark_as_advanced(SQLite3_INCLUDE_DIR SQLite3_LIBRARY)
