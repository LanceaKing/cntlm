cmake_minimum_required(VERSION 3.22.1)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(cntlm C)
endif()

include(CheckSymbolExists)
include(CMakePushCheckState)
include(TestBigEndian)
find_package(Threads REQUIRED)
# Keep libc probes and the embedded target in the same feature namespace.
# Annex K must be requested before embedded.h first includes string.h.
set(cntlm_feature_definitions _GNU_SOURCE _DEFAULT_SOURCE _XOPEN_SOURCE=600
    __STDC_WANT_LIB_EXT1__=1)
if(APPLE)
    list(APPEND cntlm_feature_definitions _DARWIN_C_SOURCE)
endif()
cmake_push_check_state()
foreach(definition IN LISTS cntlm_feature_definitions)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D${definition}")
endforeach()
check_symbol_exists(gethostname "unistd.h" config_gethostname)
check_symbol_exists(strdup "string.h" config_strdup)
check_symbol_exists(arc4random_buf "stdlib.h" config_arc4random_buf)
check_symbol_exists(strlcpy "string.h" config_strlcpy)
check_symbol_exists(strlcat "string.h" config_strlcat)
check_symbol_exists(memset_s "string.h" config_memset_s)
cmake_pop_check_state()
set(config_socklen_t 1)
test_big_endian(CNTLM_BIG_ENDIAN)
if(CNTLM_BIG_ENDIAN)
    set(config_endian 0)
else()
    set(config_endian 1)
endif()
# GSS/SSPI require platform services; this portable target provides NTLM.
set(config_gss 0)
configure_file(cmake/config.h.in generated/config/config.h)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" CNTLM_VERSION LIMIT_COUNT 1)

add_library(cntlm-embedded OBJECT main.c utils.c ntlm.c xcrypt.c config.c
    socket.c acl.c auth.c http.c forward.c direct.c scanner.c pages.c proxy.c
    pac.c duktape/duktape.c)
set_target_properties(cntlm-embedded PROPERTIES C_STANDARD 99
    POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_compile_definitions(cntlm-embedded PRIVATE CNTLM_EMBEDDED
    VERSION="${CNTLM_VERSION}" ${cntlm_feature_definitions})
target_compile_options(cntlm-embedded PRIVATE -include "${CMAKE_CURRENT_SOURCE_DIR}/embedded.h")
target_include_directories(cntlm-embedded BEFORE PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/generated" "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(cntlm-embedded PUBLIC Threads::Threads m)

option(CNTLM_BUILD_TESTS "Build embedded core regression tests" OFF)
if(CNTLM_BUILD_TESTS)
    enable_testing()
    add_executable(cntlm-core-test tests/test_core.c)
    set_target_properties(cntlm-core-test PROPERTIES C_STANDARD 99)
    target_compile_definitions(cntlm-core-test PRIVATE ${cntlm_feature_definitions})
    target_link_libraries(cntlm-core-test PRIVATE cntlm-embedded)
    add_test(NAME cntlm-core COMMAND cntlm-core-test)
endif()
