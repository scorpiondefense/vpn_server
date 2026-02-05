cmake_minimum_required(VERSION 3.20)
project(wireguard_vpn VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler warnings for our code only (not dependencies)
set(VPN_COMPILE_OPTIONS
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    -Wshadow -Wnon-virtual-dtor
)

# Debug/Release settings
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
else()
    add_compile_options(-O3 -DNDEBUG)
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)

# Fetch Catch2 for testing
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
)
FetchContent_MakeAvailable(Catch2)

# Main library
add_library(vpn_lib STATIC
    # Crypto
    src/crypto/curve25519.cpp
    src/crypto/chacha20poly1305.cpp
    src/crypto/blake2s.cpp
    src/crypto/noise.cpp

    # Network
    src/net/udp_socket.cpp
    src/net/tun_device.cpp
    src/net/address.cpp

    # Protocol
    src/protocol/message.cpp
    src/protocol/peer.cpp
    src/protocol/session.cpp
    src/protocol/timer.cpp

    # Core
    src/core/server.cpp
    src/core/thread_pool.cpp
    src/core/config.cpp

    # Util
    src/util/base64.cpp
    src/util/logger.cpp
)

target_include_directories(vpn_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(vpn_lib PRIVATE ${VPN_COMPILE_OPTIONS})

target_link_libraries(vpn_lib PUBLIC
    ${SODIUM_LIBRARIES}
)

# Platform-specific libraries
if(APPLE)
    target_link_libraries(vpn_lib PUBLIC
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
elseif(UNIX)
    target_link_libraries(vpn_lib PUBLIC pthread)
endif()

# Main executable
add_executable(vpn_server src/main.cpp)
target_link_libraries(vpn_server PRIVATE vpn_lib)
target_compile_options(vpn_server PRIVATE ${VPN_COMPILE_OPTIONS})

# Key generation tool
add_executable(wg-keygen tools/wg-keygen.cpp)
target_link_libraries(wg-keygen PRIVATE vpn_lib)
target_compile_options(wg-keygen PRIVATE ${VPN_COMPILE_OPTIONS})

# Tests
enable_testing()

add_executable(vpn_tests
    tests/test_main.cpp
    tests/crypto/test_curve25519.cpp
    tests/crypto/test_chacha20poly1305.cpp
    tests/crypto/test_blake2s.cpp
    tests/crypto/test_noise.cpp
    tests/protocol/test_message.cpp
    tests/protocol/test_handshake.cpp
    tests/net/test_udp_socket.cpp
)

target_link_libraries(vpn_tests PRIVATE
    vpn_lib
    Catch2::Catch2WithMain
)
target_compile_options(vpn_tests PRIVATE ${VPN_COMPILE_OPTIONS})

include(CTest)
include(Catch)
catch_discover_tests(vpn_tests)

# Installation
install(TARGETS vpn_server wg-keygen
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/vpn
    DESTINATION include
)
