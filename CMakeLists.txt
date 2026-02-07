cmake_minimum_required(VERSION 3.20)
project(sql_proxy VERSION 1.0.0 LANGUAGES CXX)

# C++23 standard required
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Thread support
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ============================================================================
# Database Backend Options
# ============================================================================

option(ENABLE_POSTGRESQL "Enable PostgreSQL backend" ON)
option(ENABLE_MYSQL "Enable MySQL/MariaDB backend" OFF)

# ============================================================================
# Find Required System Libraries
# ============================================================================

# PostgreSQL client library
if(ENABLE_POSTGRESQL)
    find_package(PostgreSQL REQUIRED)
endif()

# MySQL client library (MariaDB Connector/C or libmysqlclient)
if(ENABLE_MYSQL)
    find_package(PkgConfig)
    pkg_check_modules(MYSQL REQUIRED mysqlclient)
endif()

# OpenSSL (required by Drogon)
find_package(OpenSSL REQUIRED)

# UUID library
find_library(UUID_LIBRARY uuid REQUIRED)

# Drogon framework
find_package(Drogon REQUIRED)

# ============================================================================
# Third-party Header-only Libraries
# ============================================================================

# xxHash - hashing
set(XXHASH_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/xxHash)

# glaze (high-performance JSON library with compile-time reflection)
include(FetchContent)
FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG v4.2.2
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(glaze)

# ============================================================================
# Download dependencies via FetchContent
# ============================================================================

# REMOVED: glaze, tomlplusplus, ctre - not used in codebase
# These were causing "Failed to connect to github.com" errors
# If needed in future, vendor them to third_party/ instead of FetchContent

# ============================================================================
# libpg_query - PostgreSQL parser
# ============================================================================

set(LIBPGQUERY_DIR ${CMAKE_SOURCE_DIR}/third_party/libpg_query)
set(LIBPGQUERY_INCLUDE_DIR ${LIBPGQUERY_DIR})
set(LIBPGQUERY_LIBRARY ${LIBPGQUERY_DIR}/libpg_query.a)

# ============================================================================
# Source Files (auto-discovered via GLOB_RECURSE)
# ============================================================================

file(GLOB_RECURSE CORE_SOURCES       src/core/*.cpp)
file(GLOB_RECURSE SERVER_SOURCES     src/server/*.cpp)
file(GLOB_RECURSE PARSER_SOURCES     src/parser/*.cpp)
file(GLOB_RECURSE ANALYZER_SOURCES   src/analyzer/*.cpp)
file(GLOB_RECURSE POLICY_SOURCES     src/policy/*.cpp)
file(GLOB_RECURSE EXECUTOR_SOURCES   src/executor/*.cpp)
file(GLOB_RECURSE DB_SOURCES         src/db/*.cpp)
file(GLOB_RECURSE CLASSIFIER_SOURCES src/classifier/*.cpp)
file(GLOB_RECURSE AUDIT_SOURCES      src/audit/*.cpp)
file(GLOB_RECURSE CONFIG_SOURCES     src/config/*.cpp)

# Exclude disabled database backends
if(NOT ENABLE_POSTGRESQL)
    list(FILTER DB_SOURCES EXCLUDE REGEX "src/db/postgresql/")
endif()
if(NOT ENABLE_MYSQL)
    list(FILTER DB_SOURCES EXCLUDE REGEX "src/db/mysql/")
endif()

set(LIB_SOURCES
    ${CORE_SOURCES}
    ${SERVER_SOURCES}
    ${PARSER_SOURCES}
    ${ANALYZER_SOURCES}
    ${POLICY_SOURCES}
    ${EXECUTOR_SOURCES}
    ${DB_SOURCES}
    ${CLASSIFIER_SOURCES}
    ${AUDIT_SOURCES}
    ${CONFIG_SOURCES}
)

set(ALL_SOURCES
    ${LIB_SOURCES}
    src/main.cpp
)

# ============================================================================
# Include Directories
# ============================================================================

set(INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/include
    ${XXHASH_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${Drogon_INCLUDE_DIRS}
)

if(ENABLE_POSTGRESQL)
    list(APPEND INCLUDE_DIRS
        ${LIBPGQUERY_INCLUDE_DIR}
        ${PostgreSQL_INCLUDE_DIRS}
    )
endif()

if(ENABLE_MYSQL)
    list(APPEND INCLUDE_DIRS ${MYSQL_INCLUDE_DIRS})
endif()

# ============================================================================
# Static Library (shared between main executable and tests)
# ============================================================================

add_library(${PROJECT_NAME}_lib STATIC ${LIB_SOURCES})

target_include_directories(${PROJECT_NAME}_lib PUBLIC ${INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME}_lib PUBLIC
    # System libraries
    Threads::Threads
    ${UUID_LIBRARY}

    # OpenSSL
    OpenSSL::SSL
    OpenSSL::Crypto

    # Drogon
    Drogon::Drogon

    # JSON
    glaze::glaze
)

# PostgreSQL libraries (conditional)
if(ENABLE_POSTGRESQL)
    target_link_libraries(${PROJECT_NAME}_lib PUBLIC
        ${PostgreSQL_LIBRARIES}
        ${LIBPGQUERY_LIBRARY}
    )
    target_compile_definitions(${PROJECT_NAME}_lib PUBLIC ENABLE_POSTGRESQL=1)
endif()

# MySQL libraries (conditional)
if(ENABLE_MYSQL)
    target_link_libraries(${PROJECT_NAME}_lib PUBLIC ${MYSQL_LIBRARIES})
    target_compile_definitions(${PROJECT_NAME}_lib PUBLIC ENABLE_MYSQL=1)
endif()

target_compile_definitions(${PROJECT_NAME}_lib PUBLIC
    PROJECT_NAME="${PROJECT_NAME}"
    PROJECT_VERSION="${PROJECT_VERSION}"
    $<$<CONFIG:Debug>:DEBUG_BUILD>
    $<$<CONFIG:Release>:RELEASE_BUILD>
)

# ============================================================================
# Create Executable
# ============================================================================

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)

# ============================================================================
# Installation Rules
# ============================================================================

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

install(DIRECTORY config/
    DESTINATION etc/${PROJECT_NAME}
    FILES_MATCHING PATTERN "*.toml"
)

# ============================================================================
# Testing (Optional - using Catch2)
# ============================================================================

option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    include(FetchContent)
    enable_testing()

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.0
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(Catch2)

    file(GLOB TEST_SOURCES tests/test_*.cpp)
    list(FILTER TEST_SOURCES EXCLUDE REGEX "test_benchmark")

    add_executable(${PROJECT_NAME}_tests ${TEST_SOURCES})

    target_include_directories(${PROJECT_NAME}_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests)

    target_link_libraries(${PROJECT_NAME}_tests PRIVATE
        Catch2::Catch2WithMain
        ${PROJECT_NAME}_lib
    )

    include(CTest)
    include(Catch)
    catch_discover_tests(${PROJECT_NAME}_tests)
endif()

# ============================================================================
# Benchmarks (Optional - using Google Benchmark)
# ============================================================================

option(BUILD_BENCHMARKS "Build performance benchmarks" OFF)

if(BUILD_BENCHMARKS)
    include(FetchContent)

    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.8.0
        GIT_SHALLOW TRUE
    )

    # Disable Google Benchmark's internal tests to avoid pulling in Google Test
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(benchmark)

    file(GLOB BENCHMARK_SOURCES tests/test_benchmark*.cpp)
    add_executable(${PROJECT_NAME}_benchmarks ${BENCHMARK_SOURCES})

    target_link_libraries(${PROJECT_NAME}_benchmarks PRIVATE
        benchmark::benchmark
        benchmark::benchmark_main
        ${PROJECT_NAME}_lib
    )

    # Benchmarks must run with optimizations for meaningful results
    target_compile_options(${PROJECT_NAME}_benchmarks PRIVATE -O2)
endif()

# ============================================================================
# Custom Targets
# ============================================================================

# Format code with clang-format
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include -iname "*.hpp" -o -iname "*.cpp" | xargs clang-format -i
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Formatting source code with clang-format"
)

# Run static analysis with clang-tidy
add_custom_target(lint
    COMMAND clang-tidy ${ALL_SOURCES} -- -std=c++23 ${INCLUDE_DIRS}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running static analysis with clang-tidy"
)

# ============================================================================
# Build Summary
# ============================================================================

message(STATUS "")
message(STATUS "==================== SQL Proxy Build Configuration ====================")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard:     C++${CMAKE_CXX_STANDARD}")
message(STATUS "C++ Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler flags:   ${CMAKE_CXX_FLAGS}")
message(STATUS "")
message(STATUS "Database Backends:")
message(STATUS "  PostgreSQL:     ${ENABLE_POSTGRESQL}")
if(ENABLE_POSTGRESQL)
    message(STATUS "    Version:      ${PostgreSQL_VERSION_STRING}")
    message(STATUS "    libpg_query:  ${LIBPGQUERY_LIBRARY}")
endif()
message(STATUS "  MySQL:          ${ENABLE_MYSQL}")
if(ENABLE_MYSQL)
    message(STATUS "    Libraries:    ${MYSQL_LIBRARIES}")
endif()
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  Drogon:         Found")
message(STATUS "  xxHash:         ${XXHASH_INCLUDE_DIR}")
message(STATUS "")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Build tests:      ${BUILD_TESTS}")
message(STATUS "========================================================================")
message(STATUS "")
