#!/bin/bash
#
# Run MASP verification tests against Ethereum with full BLS12-381 precompile support
#
# This script supports two modes:
# 1. Fork from Ethereum mainnet (default) - Uses actual mainnet precompiles via public RPC
# 2. Local Anvil node - Uses Anvil with Prague hardfork (limited precompile support)
#
# Usage:
#   ./run-tests-with-node.sh                     # Fork from mainnet (recommended)
#   ./run-tests-with-node.sh --local             # Use local Anvil node
#   ./run-tests-with-node.sh --rpc-url <url>     # Fork from custom RPC endpoint
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
LOCAL_RPC_URL="http://${ANVIL_HOST}:${ANVIL_PORT}"
ANVIL_PID=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default to mainnet fork mode
USE_LOCAL=false
MAINNET_RPC_URL="${ETH_RPC_URL:-https://ethereum-rpc.publicnode.com}"

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

# Parse command line arguments
TEST_PATTERN=""
VERBOSE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --local)
            USE_LOCAL=true
            shift
            ;;
        --rpc-url)
            MAINNET_RPC_URL="$2"
            shift 2
            ;;
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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --local              Use local Anvil node instead of mainnet fork"
            echo "  --rpc-url <url>      Fork from custom RPC endpoint"
            echo "  --match-contract <p> Run tests matching contract pattern"
            echo "  --match-test <p>     Run tests matching test pattern"
            echo "  -v/-vv/-vvv/-vvvv    Verbosity level"
            echo "  --help               Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  ETH_RPC_URL          Ethereum RPC URL for mainnet fork"
            echo "  ANVIL_PORT           Local Anvil port (default: 8545)"
            echo "  ANVIL_HOST           Local Anvil host (default: 127.0.0.1)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Print header
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MASP Verifier Test Runner${NC}"
if [ "$USE_LOCAL" = true ]; then
    echo -e "${BLUE}  Mode: Local Anvil Node (Prague HF)${NC}"
else
    echo -e "${BLUE}  Mode: Ethereum Mainnet Fork${NC}"
fi
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if Forge is available
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Forge not found. Please install Foundry first.${NC}"
    echo "Run: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

if [ "$USE_LOCAL" = true ]; then
    # Local mode: Start Anvil with Prague hardfork

    # Check if Anvil is available
    if ! command -v anvil &> /dev/null; then
        echo -e "${RED}Error: Anvil not found. Please install Foundry first.${NC}"
        echo "Run: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        exit 1
    fi

    # Check if port is already in use
    if nc -z "$ANVIL_HOST" "$ANVIL_PORT" 2>/dev/null; then
        echo -e "${YELLOW}Warning: Port $ANVIL_PORT is already in use.${NC}"
        echo -e "${YELLOW}Attempting to use existing node at $LOCAL_RPC_URL${NC}"
    else
        # Start Anvil with Prague hardfork
        echo -e "${BLUE}Starting Anvil node with Prague hardfork...${NC}"
        echo -e "  Host: $ANVIL_HOST"
        echo -e "  Port: $ANVIL_PORT"
        echo -e "  Hardfork: prague"
        echo ""
        echo -e "${YELLOW}NOTE: Anvil's BLS12-381 precompiles have limited support for${NC}"
        echo -e "${YELLOW}      arbitrary curve points. Tests may be skipped.${NC}"
        echo -e "${YELLOW}      For full support, use mainnet fork mode (without --local).${NC}"
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

    RPC_URL="$LOCAL_RPC_URL"
else
    # Mainnet fork mode: Use public RPC endpoint directly
    echo -e "${BLUE}Using Ethereum mainnet fork for full BLS12-381 precompile support${NC}"
    echo -e "  RPC URL: $MAINNET_RPC_URL"
    echo ""
    echo -e "${GREEN}Mainnet (post-Pectra) has full EIP-2537 BLS12-381 precompile support.${NC}"
    echo ""

    RPC_URL="$MAINNET_RPC_URL"
fi

# Change to project directory
cd "$PROJECT_DIR"

# Run tests
echo -e "${BLUE}Running Forge tests...${NC}"
echo -e "  Fork URL: $RPC_URL"
echo ""

# Run forge test with the fork
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
