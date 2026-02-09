# Multi-stage build for SQL Proxy Service with optimized caching
# Stage 1: Base with system dependencies (cached unless apt packages change)
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    wget \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    libbrotli-dev \
    uuid-dev \
    postgresql-server-dev-16 \
    libpq-dev \
    libjsoncpp-dev \
    curl \
    gcc-14 \
    g++-14 \
    && rm -rf /var/lib/apt/lists/*

# Use GCC 14 for C++23 support
ENV CC=gcc-14
ENV CXX=g++-14

# Stage 2: Build libpg_query (cached unless libpg_query source changes)
FROM base AS libpgquery-builder

WORKDIR /build

# Copy ONLY libpg_query sources to maximize cache hits
COPY third_party/libpg_query /build/libpg_query

RUN cd /build/libpg_query && \
    make -j$(nproc)

# Stage 3: Build SQL Proxy (only this rebuilds on code changes)
FROM base AS proxy-builder

WORKDIR /build/sql_proxy

# Copy CMakeLists.txt and build config first (cached unless CMake config changes)
COPY CMakeLists.txt /build/sql_proxy/

# Copy include headers (cached unless headers change)
COPY include /build/sql_proxy/include

# Copy libpg_query from libpgquery-builder (already built)
COPY --from=libpgquery-builder /build/libpg_query /build/sql_proxy/third_party/libpg_query

# Copy header-only libraries
COPY third_party/cpp-httplib /build/sql_proxy/third_party/cpp-httplib
COPY third_party/xxHash /build/sql_proxy/third_party/xxHash
# Copy source files (this layer rebuilds on code changes, but deps are cached)
COPY src /build/sql_proxy/src

# Build the proxy service
RUN mkdir -p build && \
    cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-Wno-deprecated-declarations" .. && \
    ninja

# Stage 4: Build Catch2 (cached until CMakeLists.txt changes, survives src/ edits)
FROM proxy-builder AS test-deps

# Create a stub test file so cmake configure succeeds without real test sources
RUN mkdir -p tests && echo "// stub" > tests/test_stub.cpp

# Configure with tests enabled and build only Catch2
RUN cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON .. && \
    ninja Catch2 Catch2WithMain

FROM test-deps AS test-builder

# Copy real test sources (overwrites stubs, only this layer invalidates on test changes)
COPY tests /build/sql_proxy/tests

# Reconfigure to re-glob real test files, then build (Catch2 is already cached)
RUN cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON .. && \
    ninja sql_proxy_tests

# Run tests
RUN cd build && ./sql_proxy_tests --reporter compact

# Stage 4b: Build benchmarks (optional, used by: docker build --target benchmark-builder)
FROM proxy-builder AS benchmark-builder

# Copy test/benchmark sources
COPY tests /build/sql_proxy/tests

# Build with benchmarks enabled (library is already built, only benchmarks compile)
RUN cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARKS=ON .. && \
    ninja sql_proxy_benchmarks

# Stage 5: Runtime (minimal production image)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    libbrotli1 \
    libjsoncpp25 \
    uuid-runtime \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy the built binary
COPY --from=proxy-builder /build/sql_proxy/build/sql_proxy /app/

# Copy configuration files (these can change without rebuilding C++ code)
COPY config /app/config

# Copy SQL scripts (for reference)
COPY sql /app/sql

# Create directories for logs and plugins
RUN mkdir -p /app/logs /app/plugins

# Expose HTTP, Wire Protocol, and Binary RPC ports
EXPOSE 8080 5433 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the proxy service
CMD ["/app/sql_proxy"]
