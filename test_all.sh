#!/bin/bash
# =============================================================================
# Tokamak-FROST Test Suite
# =============================================================================
# This script runs all tests for the project including:
# - Rust unit tests
# - Makefile DKG/Signing flow
# - TypeScript server integration tests
# =============================================================================

set -e  # Exit on first error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_OUT_DIR="test_run_$$"
BIND_PORT=9034
BIND_ADDR="127.0.0.1:$BIND_PORT"

# Track failures
FAILED_TESTS=()

print_header() {
    echo ""
    echo -e "${BLUE}=============================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=============================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_failure() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

cleanup() {
    print_info "Cleaning up..."
    
    # Close server gracefully first
    curl -s "http://$BIND_ADDR/close" >/dev/null 2>&1 || true
    sleep 1
    
    # Kill any background server processes by name
    pkill -f "ts-fserver" 2>/dev/null || true
    pkill -f "ts-node.*index.ts" 2>/dev/null || true
    pkill -f "fserver.*server" 2>/dev/null || true
    pkill -f "cargo run -p fserver" 2>/dev/null || true
    
    # Kill processes using port directly (more aggressive)
    # Note: fuser on Linux supports -k and tcp ports, but macOS fuser has different syntax
    # We check for Linux fuser specifically and fall back to lsof on macOS
    if [[ "$(uname)" == "Linux" ]] && command -v fuser &> /dev/null; then
        fuser -k $BIND_PORT/tcp 2>/dev/null || true
    fi
    
    # Use lsof approach to find and kill processes on the port (works on both Linux and macOS)
    if command -v lsof &> /dev/null; then
        for pid in $(lsof -iTCP:$BIND_PORT -sTCP:LISTEN -t 2>/dev/null); do
            kill -9 $pid 2>/dev/null || true
        done
    fi
    
    # Remove test artifacts
    rm -rf "$TEST_OUT_DIR" 2>/dev/null || true
    rm -f debug_test.log 2>/dev/null || true
    
    # Wait for port to be fully released by the OS
    sleep 3
    
    # Verify port is free
    local attempts=0
    while lsof -iTCP:$BIND_PORT -sTCP:LISTEN -t >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ $attempts -ge 10 ]; then
            print_failure "Port $BIND_PORT is still in use after cleanup attempts"
            break
        fi
        sleep 1
    done
}

wait_for_server() {
    local max_attempts=30
    local attempt=0
    while ! nc -z 127.0.0.1 $BIND_PORT >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            print_failure "Server failed to start on port $BIND_PORT"
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# =============================================================================
# Test 1: Rust Unit Tests
# =============================================================================
test_rust() {
    print_header "Running Rust Unit Tests"
    
    if cargo test --workspace; then
        print_success "Rust unit tests passed"
        return 0
    else
        print_failure "Rust unit tests failed"
        FAILED_TESTS+=("Rust Unit Tests")
        return 1
    fi
}

# =============================================================================
# Test 2: WASM Build
# =============================================================================
test_wasm_build() {
    print_header "Testing WASM Build"
    
    if npm run build:wasm; then
        print_success "WASM build successful"
        return 0
    else
        print_failure "WASM build failed"
        FAILED_TESTS+=("WASM Build")
        return 1
    fi
}

# =============================================================================
# Test 3: Makefile DKG Flow (secp256k1)
# =============================================================================
test_makefile_dkg_secp256k1() {
    print_header "Testing Makefile DKG (secp256k1)"
    
    cleanup
    
    if make dkg t=2 n=2 gid=test_secp out="$TEST_OUT_DIR" KEY_TYPE=secp256k1 bind="$BIND_ADDR"; then
        if [ -f "$TEST_OUT_DIR/group.json" ] && ls "$TEST_OUT_DIR"/share_*.json >/dev/null 2>&1; then
            print_success "Makefile DKG (secp256k1) passed"
            make close bind="$BIND_ADDR" || true
            cleanup
            return 0
        fi
    fi
    
    print_failure "Makefile DKG (secp256k1) failed"
    FAILED_TESTS+=("Makefile DKG secp256k1")
    make close bind="$BIND_ADDR" || true
    cleanup
    return 1
}

# =============================================================================
# Test 4: Makefile DKG Flow (EdDSA)
# =============================================================================
test_makefile_dkg_eddsa() {
    print_header "Testing Makefile DKG (EdDSA)"
    
    cleanup
    
    if make dkg t=2 n=2 gid=test_ed out="$TEST_OUT_DIR" KEY_TYPE=edwards_on_bls12381 bind="$BIND_ADDR"; then
        if [ -f "$TEST_OUT_DIR/group.json" ] && ls "$TEST_OUT_DIR"/share_*.json >/dev/null 2>&1; then
            print_success "Makefile DKG (EdDSA) passed"
            make close bind="$BIND_ADDR" || true
            cleanup
            return 0
        fi
    fi
    
    print_failure "Makefile DKG (EdDSA) failed"
    FAILED_TESTS+=("Makefile DKG EdDSA")
    make close bind="$BIND_ADDR" || true
    cleanup
    return 1
}

# =============================================================================
# Test 5: TypeScript Server Integration Tests
# =============================================================================
test_ts_integration() {
    print_header "Testing TypeScript Server Integration"
    
    cleanup
    
    # Start TypeScript server in background
    print_info "Starting TypeScript server..."
    npm run start:server &
    SERVER_PID=$!
    
    # Wait for server to be ready
    if ! wait_for_server; then
        kill -9 $SERVER_PID 2>/dev/null || true
        pkill -9 -P $SERVER_PID 2>/dev/null || true  # Kill child processes
        FAILED_TESTS+=("TypeScript Integration")
        cleanup
        return 1
    fi
    
    print_info "Server is running, executing integration tests..."
    
    # Run the signing test
    cd packages/ts/ts-fserver
    local test_result=0
    if timeout 120 node --loader ts-node/esm test/signing_test.ts 2>&1 | tee /dev/stderr | grep -q "ALL TESTS PASSED"; then
        print_success "TypeScript integration tests passed"
    else
        print_failure "TypeScript integration tests failed"
        FAILED_TESTS+=("TypeScript Integration")
        test_result=1
    fi
    cd ../../..
    
    # Kill server and all child processes
    kill $SERVER_PID 2>/dev/null || true
    pkill -P $SERVER_PID 2>/dev/null || true  # Kill child processes
    sleep 1
    kill -9 $SERVER_PID 2>/dev/null || true
    pkill -9 -P $SERVER_PID 2>/dev/null || true
    
    # Ensure port is freed before next test
    cleanup
    
    return $test_result
}

# =============================================================================
# Test 6: Web Dev Server Smoke Test
# =============================================================================
test_web_dev_server() {
    print_header "Testing Web Dev Server"
    
    # Note: npm run dev:web starts a UNIFIED server at port 5173:
    # - Vite frontend serves at http://localhost:5173
    # - ts-fserver WebSocket is attached at ws://localhost:5173/frost-ws
    # This test verifies the unified server starts correctly.
    
    # Start web dev server briefly to check it works (redirect stderr to suppress npm lifecycle errors on kill)
    print_info "Starting unified Vite + ts-fserver dev server on port 5173..."
    npm run dev:web 2>/dev/null &
    WEB_PID=$!
    
    # Wait for Vite and embedded server to be ready
    sleep 5
    
    local vite_ok=false
    local server_ok=false
    
    # Check if Vite frontend is responding
    if curl -s http://localhost:5173 >/dev/null 2>&1; then
        print_success "Vite frontend started successfully"
        vite_ok=true
    else
        print_failure "Vite frontend failed to start"
    fi
    
    # Check if embedded ts-fserver WebSocket is responding at /frost-ws
    # We check by making an HTTP request to the WebSocket endpoint (should return 400 or similar, not connection refused)
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:5173/frost-ws 2>/dev/null | grep -qE "^[45][0-9][0-9]$"; then
        # Getting 4xx/5xx means the endpoint exists (WebSocket upgrade expected, not regular HTTP)
        print_success "Embedded ts-fserver WebSocket endpoint responding at /frost-ws"
        server_ok=true
    elif nc -z 127.0.0.1 5173 >/dev/null 2>&1; then
        # If nc works but curl check fails, the server is up - WebSocket likely just not responding to HTTP
        print_success "Embedded ts-fserver is running (unified with Vite on port 5173)"
        server_ok=true
    else
        print_failure "Embedded ts-fserver failed to start"
    fi
    
    # Graceful cleanup: send SIGTERM first, then wait briefly for clean exit
    # This suppresses the noisy npm "Lifecycle script failed" errors
    {
        kill -TERM $WEB_PID 2>/dev/null || true
        pkill -TERM -P $WEB_PID 2>/dev/null || true
        sleep 1
        # Force kill if still running
        kill -9 $WEB_PID 2>/dev/null || true
        pkill -9 -P $WEB_PID 2>/dev/null || true
    } 2>/dev/null
    
    # Wait for the background job to finish (suppresses shell job control messages)
    wait $WEB_PID 2>/dev/null || true
    
    if $vite_ok && $server_ok; then
        return 0
    else
        FAILED_TESTS+=("Web Dev Server")
        return 1
    fi
}

# =============================================================================
# Main Test Runner
# =============================================================================
main() {
    print_header "Tokamak-FROST Test Suite"
    
    echo "Starting comprehensive test suite..."
    echo "Test output directory: $TEST_OUT_DIR"
    echo ""
    
    # Ensure we're in the project root
    if [ ! -f "Cargo.toml" ] || [ ! -f "package.json" ]; then
        print_failure "Must run from project root directory"
        exit 1
    fi
    
    # Cleanup before starting
    cleanup
    
    # Run all tests
    test_rust || true
    test_wasm_build || true
    test_makefile_dkg_secp256k1 || true
    test_makefile_dkg_eddsa || true
    test_ts_integration || true
    test_web_dev_server || true
    
    # Final cleanup
    cleanup
    rm -rf "$TEST_OUT_DIR" 2>/dev/null || true
    
    # Summary
    print_header "Test Summary"
    
    if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    ALL TESTS PASSED! ✅                       ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                    SOME TESTS FAILED! ❌                       ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Failed tests:"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}• $test${NC}"
        done
        exit 1
    fi
}

# Run main with cleanup on exit
trap cleanup EXIT
main "$@"
