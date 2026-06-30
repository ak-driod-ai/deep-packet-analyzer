cmake_minimum_required(VERSION 3.16)
project(packetanalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(packetanalyzer
    src/main.cpp
    src/pcap.cpp
    src/ethernet.cpp
    src/ipv4.cpp
    src/ipv6.cpp
    src/tcp.cpp
    src/udp.cpp
    src/dns.cpp
    src/http.cpp
    src/tls.cpp
    src/flow.cpp
    src/policy.cpp
    src/policy_loader.cpp
    src/stats.cpp
    src/dpi.cpp
)

target_include_directories(packetanalyzer PRIVATE include)

if(MSVC)
    target_compile_options(packetanalyzer PRIVATE /W4 /permissive-)
else()
    target_compile_options(packetanalyzer PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()

add_executable(packetanalyzer_tests
    tests/parser_tests.cpp
    src/dns.cpp
)

target_include_directories(packetanalyzer_tests PRIVATE include)

if(MSVC)
    target_compile_options(packetanalyzer_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(packetanalyzer_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME parser_tests COMMAND packetanalyzer_tests)
