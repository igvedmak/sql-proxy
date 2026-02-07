#!/bin/bash
set -e

echo "📋 PHASE 1: BUILD & UNIT TESTS"
cd /home/gerav/sql_proxy
rm -rf build && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON ..
make -j$(nproc)
echo "✓ Build complete"

echo ""
echo "🧪 Running unit tests..."
./sql_proxy_tests --reporter compact
echo "✓ Tests passed"

echo ""
echo "📦 PHASE 2: DOCKER BUILD"
cd /home/gerav/sql_proxy
docker build -t sql-proxy:latest .
docker images | grep sql-proxy
echo "✓ Docker image ready"

echo ""
echo "🚀 PHASE 3: START DOCKER CONTAINER"
docker run -d --name sql-proxy-test -p 8080:8080 sql-proxy:latest
sleep 3
echo "✓ Container running"

echo ""
echo "📋 Container logs:"
docker logs sql-proxy-test | head -30

echo ""
echo "🔍 PHASE 4: HEALTH CHECK"
curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8080/health || echo "FAILED"
echo "✓ Health check done"

echo ""
echo "🧪 PHASE 5: TEST SUITE"
cd /home/gerav/sql_proxy
./test_suite.sh 2>&1 | tail -50
echo "✓ Integration tests complete"

echo ""
echo "🛑 PHASE 6: CLEANUP"
docker stop sql-proxy-test
docker rm sql-proxy-test
echo "✓ Container stopped"

echo ""
echo "✅ PHASE 7: GIT STATUS"
git log --oneline -5
echo ""
git status
echo ""
git diff origin/main --stat

echo ""
echo "=========================================="
echo "✅ ALL VERIFICATION COMPLETE"
echo "=========================================="
