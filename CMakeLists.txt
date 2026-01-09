cmake_minimum_required(VERSION 3.10)
project(gravastar CXX)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

add_library(gravastar_core
    src/blocklist.cpp
    src/cache.cpp
    src/config.cpp
    src/dns_packet.cpp
    src/dns_server.cpp
    src/local_records.cpp
    src/upstream_resolver.cpp
    src/util.cpp
)

target_include_directories(gravastar_core PUBLIC src)
target_link_libraries(gravastar_core PUBLIC Threads::Threads)

add_executable(gravastar src/main.cpp)
target_link_libraries(gravastar gravastar_core)

add_executable(gravastar_tests
    tests/main.cpp
    tests/test_cache.cpp
    tests/test_config.cpp
    tests/test_dns_packet.cpp
)
target_link_libraries(gravastar_tests gravastar_core)

enable_testing()
add_test(NAME gravastar_tests COMMAND gravastar_tests)
add_test(NAME gravastar_integration COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_dig.sh $<TARGET_FILE:gravastar>)
set_tests_properties(gravastar_integration PROPERTIES TIMEOUT 10)

install(TARGETS gravastar RUNTIME DESTINATION /usr/local/bin)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/gravastar.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/blocklist.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/local_records.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/upstreams.toml
    DESTINATION /etc/gravastar
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(CODE [[
        if(EXISTS "/run/systemd/system")
            file(INSTALL
                DESTINATION "/etc/systemd/system"
                TYPE FILE
                FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/systemd/gravastar.service"
            )
        elseif(EXISTS "/sbin/openrc-run" OR EXISTS "/sbin/rc-service" OR EXISTS "/etc/init.d")
            file(INSTALL
                DESTINATION "/etc/init.d"
                TYPE PROGRAM
                FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/openrc/gravastar"
            )
        else()
            message(STATUS "No supported Linux init system detected; skipping service install.")
        endif()
    ]])
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    install(PROGRAMS
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/openbsd/gravastar
        DESTINATION /etc/rc.d
    )
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    IMMEDIATE @ONLY
)
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)
