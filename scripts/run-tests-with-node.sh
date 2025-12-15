#!/bin/bash
#
# Run MASP verification tests against a local Ethereum node with full BLS12-381 precompile support
#
# This script:
# 1. Starts a local Anvil node with Prague hardfork enabled
# 2. Runs Forge tests against the local node
# 3. Cleans up the node on exit
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ANVIL_PORT=${ANVIL_PORT:-8545}
ANVIL_HOST=${ANVIL_HOST:-127.0.0.1}
RPC_URL="http://${ANVIL_HOST}:${ANVIL_PORT}"
ANVIL_PID=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Ensure we're using the correct PATH for Foundry tools
export PATH="$HOME/.foundry/bin:$PATH"

# Cleanup function
cleanup() {
    if [ -n "$ANVIL_PID" ] && kill -0 "$ANVIL_PID" 2>/dev/null; then
        echo -e "\n${YELLOW}Stopping Anvil node (PID: $ANVIL_PID)...${NC}"
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
        echo -e "${GREEN}Anvil node stopped.${NC}"
    fi
}

# Set up trap to cleanup on exit
trap cleanup EXIT INT TERM

# Print header
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MASP Verifier Test Runner${NC}"
echo -e "${BLUE}  Local Ethereum Node with Prague HF${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if Anvil is available
if ! command -v anvil &> /dev/null; then
    echo -e "${RED}Error: Anvil not found. Please install Foundry first.${NC}"
    echo "Run: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

# Check if Forge is available
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Forge not found. Please install Foundry first.${NC}"
    echo "Run: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

# Check if port is already in use
if nc -z "$ANVIL_HOST" "$ANVIL_PORT" 2>/dev/null; then
    echo -e "${YELLOW}Warning: Port $ANVIL_PORT is already in use.${NC}"
    echo -e "${YELLOW}Attempting to use existing node at $RPC_URL${NC}"
else
    # Start Anvil with Prague hardfork
    echo -e "${BLUE}Starting Anvil node with Prague hardfork...${NC}"
    echo -e "  Host: $ANVIL_HOST"
    echo -e "  Port: $ANVIL_PORT"
    echo -e "  Hardfork: prague"
    echo ""

    anvil \
        --host "$ANVIL_HOST" \
        --port "$ANVIL_PORT" \
        --hardfork prague \
        --accounts 10 \
        --balance 10000 \
        --gas-limit 30000000 \
        --code-size-limit 100000 \
        --block-time 1 \
        --silent &

    ANVIL_PID=$!

    # Wait for Anvil to start
    echo -e "${YELLOW}Waiting for Anvil to start...${NC}"
    MAX_RETRIES=30
    RETRY_COUNT=0

    while ! nc -z "$ANVIL_HOST" "$ANVIL_PORT" 2>/dev/null; do
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
            echo -e "${RED}Error: Anvil failed to start within timeout.${NC}"
            exit 1
        fi
        sleep 0.5
    done

    echo -e "${GREEN}Anvil node started successfully (PID: $ANVIL_PID)${NC}"
    echo ""
fi

# Change to project directory
cd "$PROJECT_DIR"

# Run tests
echo -e "${BLUE}Running Forge tests against local node...${NC}"
echo -e "  RPC URL: $RPC_URL"
echo ""

# Parse command line arguments
TEST_PATTERN=""
VERBOSE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --match-contract)
            TEST_PATTERN="--match-contract $2"
            shift 2
            ;;
        --match-test)
            TEST_PATTERN="--match-test $2"
            shift 2
            ;;
        -v|-vv|-vvv|-vvvv)
            VERBOSE="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Run forge test with the local node
# Note: We use --fork-url to run tests against the local node
# This ensures the precompiles are executed on the actual node
FORGE_CMD="forge test --fork-url $RPC_URL $TEST_PATTERN $VERBOSE"

echo -e "${YELLOW}Executing: $FORGE_CMD${NC}"
echo ""

if $FORGE_CMD; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  All tests passed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    EXIT_CODE=0
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Some tests failed!${NC}"
    echo -e "${RED}========================================${NC}"
    EXIT_CODE=1
fi

exit $EXIT_CODE
