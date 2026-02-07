cmake_minimum_required(VERSION 3.20)
project(sql_proxy VERSION 1.0.0 LANGUAGES CXX)

# C++20 standard required
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")

# Thread support
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ============================================================================
# Find Required System Libraries
# ============================================================================

# PostgreSQL client library
find_package(PostgreSQL REQUIRED)

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

# nlohmann-json (header-only JSON parser)
set(NLOHMANN_JSON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/nlohmann-json/include)

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
# Source Files Organization
# ============================================================================

set(CORE_SOURCES
    src/core/arena.cpp
    src/core/pipeline.cpp
)

set(SERVER_SOURCES
    src/server/http_server.cpp
    src/server/rate_limiter.cpp
)

set(PARSER_SOURCES
    src/parser/sql_parser.cpp
    src/parser/fingerprinter.cpp
    src/parser/parse_cache.cpp
)

set(ANALYZER_SOURCES
    src/analyzer/sql_analyzer.cpp
    src/analyzer/schema_cache.cpp
)

set(POLICY_SOURCES
    src/policy/policy_engine.cpp
    src/policy/policy_trie.cpp
    src/policy/policy_loader.cpp
)

set(EXECUTOR_SOURCES
    src/executor/connection_pool.cpp
    src/executor/circuit_breaker.cpp
    src/executor/query_executor.cpp
)

set(CLASSIFIER_SOURCES
    src/classifier/classifier_registry.cpp
)

set(AUDIT_SOURCES
    src/audit/audit_emitter.cpp
)

set(CONFIG_SOURCES
    src/config/config_loader.cpp
)

set(ALL_SOURCES
    ${CORE_SOURCES}
    ${SERVER_SOURCES}
    ${PARSER_SOURCES}
    ${ANALYZER_SOURCES}
    ${POLICY_SOURCES}
    ${EXECUTOR_SOURCES}
    ${CLASSIFIER_SOURCES}
    ${AUDIT_SOURCES}
    ${CONFIG_SOURCES}
    src/main.cpp
)

# ============================================================================
# Include Directories
# ============================================================================

set(INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/include
    ${XXHASH_INCLUDE_DIR}
    ${LIBPGQUERY_INCLUDE_DIR}
    ${PostgreSQL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${Drogon_INCLUDE_DIRS}
    ${NLOHMANN_JSON_INCLUDE_DIR}
)

# ============================================================================
# Create Executable
# ============================================================================

add_executable(${PROJECT_NAME} ${ALL_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} PRIVATE
    # System libraries
    Threads::Threads
    ${UUID_LIBRARY}

    # PostgreSQL
    ${PostgreSQL_LIBRARIES}

    # OpenSSL
    OpenSSL::SSL
    OpenSSL::Crypto

    # Drogon
    Drogon::Drogon

    # libpg_query (static)
    ${LIBPGQUERY_LIBRARY}
)

# ============================================================================
# Compiler Definitions
# ============================================================================

target_compile_definitions(${PROJECT_NAME} PRIVATE
    PROJECT_NAME="${PROJECT_NAME}"
    PROJECT_VERSION="${PROJECT_VERSION}"
    $<$<CONFIG:Debug>:DEBUG_BUILD>
    $<$<CONFIG:Release>:RELEASE_BUILD>
)

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
    enable_testing()

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.0
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(Catch2)

    set(TEST_SOURCES
        tests/test_fingerprinter.cpp
        tests/test_parser.cpp
        tests/test_analyzer.cpp
        tests/test_policy_engine.cpp
        tests/test_classifier.cpp
        tests/test_rate_limiter.cpp
    )

    add_executable(${PROJECT_NAME}_tests ${TEST_SOURCES})

    target_link_libraries(${PROJECT_NAME}_tests PRIVATE
        Catch2::Catch2WithMain
        # ... same as main executable
    )

    include(CTest)
    include(Catch)
    catch_discover_tests(${PROJECT_NAME}_tests)
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
    COMMAND clang-tidy ${ALL_SOURCES} -- -std=c++20 ${INCLUDE_DIRS}
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
message(STATUS "Dependencies:")
message(STATUS "  PostgreSQL:     ${PostgreSQL_VERSION_STRING}")
message(STATUS "  Drogon:         Found")
message(STATUS "  xxHash:         ${XXHASH_INCLUDE_DIR}")
message(STATUS "  libpg_query:    ${LIBPGQUERY_LIBRARY}")
message(STATUS "")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Build tests:      ${BUILD_TESTS}")
message(STATUS "========================================================================")
message(STATUS "")
