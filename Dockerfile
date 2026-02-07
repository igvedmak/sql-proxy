# Multi-stage build for SQL Proxy Service with optimized caching
# Stage 1: Base with system dependencies (cached unless apt packages change)
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    libbrotli-dev \
    uuid-dev \
    postgresql-server-dev-14 \
    libpq-dev \
    libjsoncpp-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Build Drogon (cached unless Drogon version changes)
FROM base AS drogon-builder

WORKDIR /build

RUN git clone --depth 1 --branch v1.9.3 https://github.com/drogonframework/drogon.git && \
    cd drogon && \
    git submodule update --init && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Stage 3: Build libpg_query (cached unless libpg_query source changes)
FROM base AS libpgquery-builder

WORKDIR /build

# Copy ONLY libpg_query sources to maximize cache hits
COPY third_party/libpg_query /build/libpg_query

RUN cd /build/libpg_query && \
    make -j$(nproc)

# Stage 4: Build SQL Proxy (only this rebuilds on code changes)
FROM base AS proxy-builder

# Copy Drogon installation from drogon-builder stage
COPY --from=drogon-builder /usr/local/lib/libdrogon* /usr/local/lib/
COPY --from=drogon-builder /usr/local/lib/libtrantor* /usr/local/lib/
COPY --from=drogon-builder /usr/local/lib/cmake /usr/local/lib/cmake
COPY --from=drogon-builder /usr/local/include/drogon /usr/local/include/drogon
COPY --from=drogon-builder /usr/local/include/trantor /usr/local/include/trantor
RUN ldconfig

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
COPY third_party/nlohmann-json/include /build/sql_proxy/third_party/nlohmann-json/include

# Copy source files (this layer rebuilds on code changes, but deps are cached)
COPY src /build/sql_proxy/src

# Build the proxy service
RUN mkdir -p build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Stage 5: Runtime (minimal production image)
FROM ubuntu:22.04

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

# Copy Drogon shared libraries
COPY --from=proxy-builder /usr/local/lib/libdrogon* /usr/local/lib/
COPY --from=proxy-builder /usr/local/lib/libtrantor* /usr/local/lib/

# Update library cache
RUN ldconfig

# Create application directory
WORKDIR /app

# Copy the built binary
COPY --from=proxy-builder /build/sql_proxy/build/sql_proxy /app/

# Copy configuration files (these can change without rebuilding C++ code)
COPY config /app/config

# Copy SQL scripts (for reference)
COPY sql /app/sql

# Create directory for audit logs
RUN mkdir -p /app/logs

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the proxy service
CMD ["/app/sql_proxy"]
