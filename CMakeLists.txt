cmake_minimum_required(VERSION 3.10)
project(gravastar CXX)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(PkgConfig)
if(APPLE AND PKG_CONFIG_FOUND)
    set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/opt/homebrew/opt/libressl/lib/pkgconfig:/opt/homebrew/opt/curl/lib/pkgconfig")
    pkg_check_modules(LIBRESSL libtls)
    pkg_check_modules(LIBCURL libcurl)
endif()
if(LIBRESSL_FOUND)
    set(GRAVASTAR_TLS_LIBS ${LIBRESSL_LIBRARIES} ${LIBRESSL_LDFLAGS_OTHER})
    set(GRAVASTAR_TLS_INCLUDES ${LIBRESSL_INCLUDE_DIRS})
    link_directories(${LIBRESSL_LIBRARY_DIRS})
else()
    find_path(LIBTLS_INCLUDE_DIR tls.h PATH_SUFFIXES libressl)
    find_library(LIBTLS tls PATH_SUFFIXES libressl)
    find_library(LIBSSL ssl PATH_SUFFIXES libressl)
    find_library(LIBCRYPTO crypto PATH_SUFFIXES libressl)
    if(NOT LIBTLS OR NOT LIBSSL OR NOT LIBCRYPTO)
        message(FATAL_ERROR "LibreSSL libraries not found (tls, ssl, crypto required).")
    endif()
    set(GRAVASTAR_TLS_LIBS ${LIBTLS} ${LIBSSL} ${LIBCRYPTO})
    if(LIBTLS_INCLUDE_DIR)
        set(GRAVASTAR_TLS_INCLUDES ${LIBTLS_INCLUDE_DIR})
    endif()
endif()

if(LIBCURL_FOUND)
    set(GRAVASTAR_CURL_LIBS ${LIBCURL_LIBRARIES} ${LIBCURL_LDFLAGS_OTHER})
    set(GRAVASTAR_CURL_INCLUDES ${LIBCURL_INCLUDE_DIRS})
    link_directories(${LIBCURL_LIBRARY_DIRS})
else()
    find_package(CURL REQUIRED)
    set(GRAVASTAR_CURL_LIBS CURL::libcurl)
    set(GRAVASTAR_CURL_INCLUDES ${CURL_INCLUDE_DIRS})
endif()

add_library(gravastar_core
    src/blocklist.cpp
    src/cache.cpp
    src/config.cpp
    src/controller_logger.cpp
    src/dns_packet.cpp
    src/dns_server.cpp
    src/local_records.cpp
    src/query_logger.cpp
    src/upstream_blocklist.cpp
    src/upstream_resolver.cpp
    src/util.cpp
)

target_include_directories(gravastar_core PUBLIC src ${GRAVASTAR_TLS_INCLUDES} ${GRAVASTAR_CURL_INCLUDES})
target_link_libraries(gravastar_core PUBLIC Threads::Threads ${GRAVASTAR_TLS_LIBS} ${GRAVASTAR_CURL_LIBS})

add_executable(gravastar src/main.cpp)
target_link_libraries(gravastar gravastar_core)

add_executable(gravastar_tests
    tests/main.cpp
    tests/test_cache.cpp
    tests/test_config.cpp
    tests/test_dns_packet.cpp
    tests/test_logging.cpp
    tests/test_upstream.cpp
    tests/test_upstream_blocklist.cpp
)
target_link_libraries(gravastar_tests gravastar_core)

enable_testing()
add_test(NAME gravastar_tests COMMAND gravastar_tests)
add_test(NAME gravastar_integration COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_dig.sh $<TARGET_FILE:gravastar>)
add_test(NAME gravastar_integration_dot COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_dot.sh $<TARGET_FILE:gravastar>)
add_test(NAME gravastar_integration_upstream_blocklist COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_upstream_blocklist.sh $<TARGET_FILE:gravastar>)
add_test(NAME gravastar_integration_rebind COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_rebind.sh $<TARGET_FILE:gravastar>)
set_tests_properties(gravastar_integration PROPERTIES TIMEOUT 10)
set_tests_properties(gravastar_integration_dot PROPERTIES TIMEOUT 30)
set_tests_properties(gravastar_integration_upstream_blocklist PROPERTIES TIMEOUT 15)
set_tests_properties(gravastar_integration_rebind PROPERTIES TIMEOUT 20)

install(TARGETS gravastar RUNTIME DESTINATION /usr/local/bin)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/gravastar.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/blocklist.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/local_records.toml
    ${CMAKE_CURRENT_SOURCE_DIR}/config/upstreams.toml
    DESTINATION /etc/gravastar
)
install(CODE [[
    file(MAKE_DIRECTORY "/var/gravastar")
]])

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
