add_executable(sw
    src/main.cpp
)

target_compile_features(sw PRIVATE cxx_std_23)

target_link_libraries(sw PRIVATE
    sw_common
    Threads::Threads
)

target_compile_options(sw PRIVATE -Wall -Wextra)

install(TARGETS sw DESTINATION bin)
