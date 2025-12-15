import { useState, useEffect } from 'react'
import { useAccount, useConnect, useDisconnect, useChainId, useReadContract, useDeployContract, useWaitForTransactionReceipt, useSwitchChain } from 'wagmi'
import { sepolia } from 'wagmi/chains'
import { formatUnits } from 'viem'
import { ShieldForm } from './components/ShieldForm'
import { UnshieldForm } from './components/UnshieldForm'
import { ProverStatus } from './components/ProverStatus'
import { initProver } from './lib/prover'
import {
  ERC20_ABI,
  MASP_VERIFIER_ABI,
  MASP_POOL_ABI,
  MASP_VERIFIER_BYTECODE,
  MASP_POOL_BYTECODE,
  getDefaultTokenAddress,
  getMaspPoolAddress,
  getMaspVerifierAddress,
  saveDeployedContracts,
} from './lib/contracts'
import './App.css'

type TabType = 'shield' | 'unshield'
type DeployStep = 'idle' | 'deploying-verifier' | 'waiting-verifier' | 'deploying-pool' | 'waiting-pool' | 'done'

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('shield')
  const [proverReady, setProverReady] = useState(false)
  const [proverError, setProverError] = useState<string | null>(null)
  const [deployStep, setDeployStep] = useState<DeployStep>('idle')
  const [deployError, setDeployError] = useState<string | null>(null)
  const [verifierAddress, setVerifierAddress] = useState<`0x${string}` | undefined>()
  const [poolAddress, setPoolAddress] = useState<`0x${string}` | undefined>()

  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()
  const chainId = useChainId()
  const { switchChain, isPending: isSwitchingChain } = useSwitchChain()

  // Check if we're on Sepolia
  const isOnSepolia = chainId === sepolia.id

  // Get default token address for the current chain
  const defaultToken = getDefaultTokenAddress(chainId)

  // Deploy contract hooks
  const { deployContractAsync, data: deployTxHash } = useDeployContract()
  const { data: deployReceipt } = useWaitForTransactionReceipt({
    hash: deployTxHash,
  })

  // Read token balance
  const { data: tokenBalance } = useReadContract({
    address: defaultToken,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address },
  })

  const { data: tokenSymbol } = useReadContract({
    address: defaultToken,
    abi: ERC20_ABI,
    functionName: 'symbol',
    query: { enabled: !!defaultToken },
  })

  const { data: tokenDecimals } = useReadContract({
    address: defaultToken,
    abi: ERC20_ABI,
    functionName: 'decimals',
    query: { enabled: !!defaultToken },
  })

  // Initialize WASM prover on mount
  useEffect(() => {
    const init = async () => {
      try {
        await initProver()
        setProverReady(true)
      } catch (err) {
        setProverError(err instanceof Error ? err.message : 'Failed to initialize prover')
      }
    }
    init()
  }, [])

  // Load deployed contract addresses on chain change
  useEffect(() => {
    const storedVerifier = getMaspVerifierAddress(chainId)
    const storedPool = getMaspPoolAddress(chainId)
    setVerifierAddress(storedVerifier)
    setPoolAddress(storedPool)
  }, [chainId])

  // Handle deploy receipt
  useEffect(() => {
    if (deployReceipt && deployReceipt.contractAddress) {
      const contractAddress = deployReceipt.contractAddress

      if (deployStep === 'waiting-verifier') {
        setVerifierAddress(contractAddress)
        saveDeployedContracts(chainId, { verifier: contractAddress })
        // Continue to deploy pool
        deployPool(contractAddress)
      } else if (deployStep === 'waiting-pool') {
        setPoolAddress(contractAddress)
        saveDeployedContracts(chainId, { pool: contractAddress })
        setDeployStep('done')
      }
    }
  }, [deployReceipt])

  const deployPool = async (verifierAddr: `0x${string}`) => {
    setDeployStep('deploying-pool')
    try {
      await deployContractAsync({
        abi: MASP_POOL_ABI,
        bytecode: MASP_POOL_BYTECODE,
        args: [verifierAddr],
        gas: BigInt(3_000_000), // Explicit gas limit for Sepolia
      })
      setDeployStep('waiting-pool')
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Failed to deploy pool')
      setDeployStep('idle')
    }
  }

  const handleDeploy = async () => {
    setDeployError(null)
    setDeployStep('deploying-verifier')

    try {
      // First deploy the verifier
      await deployContractAsync({
        abi: MASP_VERIFIER_ABI,
        bytecode: MASP_VERIFIER_BYTECODE,
        gas: BigInt(5_000_000), // Explicit gas limit for Sepolia
      })
      setDeployStep('waiting-verifier')
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Failed to deploy verifier')
      setDeployStep('idle')
    }
  }

  const isDeploying = deployStep !== 'idle' && deployStep !== 'done'
  const decimals = tokenDecimals ?? 18

  const getDeployButtonText = () => {
    switch (deployStep) {
      case 'deploying-verifier':
        return 'Deploying Verifier...'
      case 'waiting-verifier':
        return 'Waiting for Verifier...'
      case 'deploying-pool':
        return 'Deploying Pool...'
      case 'waiting-pool':
        return 'Waiting for Pool...'
      case 'done':
        return 'Contracts Deployed!'
      default:
        return 'Deploy MASP Contracts'
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>MASP Shield/Unshield</h1>
        <p className="subtitle">Multi-Asset Shielded Pool - Private ERC20 Transfers</p>

        <div className="wallet-section">
          {isConnected ? (
            <div className="wallet-info">
              <span className="address">
                {address?.slice(0, 6)}...{address?.slice(-4)}
              </span>
              <span className={`chain ${isOnSepolia ? 'correct' : 'wrong'}`}>
                {isOnSepolia ? 'Sepolia' : `Chain: ${chainId}`}
              </span>
              {!isOnSepolia && (
                <button
                  onClick={() => switchChain({ chainId: sepolia.id })}
                  disabled={isSwitchingChain}
                  className="switch-btn"
                >
                  {isSwitchingChain ? 'Switching...' : 'Switch to Sepolia'}
                </button>
              )}
              <button onClick={() => disconnect()} className="disconnect-btn">
                Disconnect
              </button>
            </div>
          ) : (
            <div className="connect-buttons">
              {connectors.map((connector) => (
                <button
                  key={connector.uid}
                  onClick={() => connect({ connector })}
                  className="connect-btn"
                >
                  Connect {connector.name}
                </button>
              ))}
            </div>
          )}
        </div>

        {isConnected && tokenBalance !== undefined && (
          <div className="token-balance">
            <span className="balance-label">Default Token Balance:</span>
            <span className="balance-value">
              {formatUnits(tokenBalance, decimals)} {tokenSymbol || 'WETH'}
            </span>
            <span className="token-address" title={defaultToken}>
              ({defaultToken.slice(0, 6)}...{defaultToken.slice(-4)})
            </span>
          </div>
        )}
      </header>

      <ProverStatus ready={proverReady} error={proverError} />

      {/* Contract Status Section */}
      {isConnected && (
        <div className="contract-section">
          <h3>Contract Status</h3>
          <div className="contract-status">
            <div className="contract-item">
              <span className="contract-label">Verifier:</span>
              {verifierAddress ? (
                <span className="contract-address deployed">
                  {verifierAddress.slice(0, 6)}...{verifierAddress.slice(-4)}
                </span>
              ) : (
                <span className="contract-address not-deployed">Not deployed</span>
              )}
            </div>
            <div className="contract-item">
              <span className="contract-label">Pool:</span>
              {poolAddress ? (
                <span className="contract-address deployed">
                  {poolAddress.slice(0, 6)}...{poolAddress.slice(-4)}
                </span>
              ) : (
                <span className="contract-address not-deployed">Not deployed</span>
              )}
            </div>
          </div>

          {!poolAddress && (
            <div className="deploy-section">
              <button
                onClick={handleDeploy}
                disabled={isDeploying || !isConnected}
                className="deploy-btn"
              >
                {getDeployButtonText()}
              </button>
              {deployError && <div className="deploy-error">{deployError}</div>}
              {isDeploying && (
                <div className="deploy-progress">
                  <div className="deploy-spinner"></div>
                  <span>This deploys both MASPVerifier and MASPPool contracts</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <nav className="tabs">
        <button
          className={`tab ${activeTab === 'shield' ? 'active' : ''}`}
          onClick={() => setActiveTab('shield')}
        >
          Shield (Deposit)
        </button>
        <button
          className={`tab ${activeTab === 'unshield' ? 'active' : ''}`}
          onClick={() => setActiveTab('unshield')}
        >
          Unshield (Withdraw)
        </button>
      </nav>

      <main className="main">
        {!isConnected ? (
          <div className="connect-prompt">
            <p>Please connect your wallet to continue</p>
          </div>
        ) : !proverReady ? (
          <div className="loading">
            <p>Initializing proof generator...</p>
            {proverError && <p className="error">{proverError}</p>}
          </div>
        ) : (
          <>
            {activeTab === 'shield' && <ShieldForm defaultToken={defaultToken} poolAddress={poolAddress} />}
            {activeTab === 'unshield' && <UnshieldForm defaultToken={defaultToken} poolAddress={poolAddress} />}
          </>
        )}
      </main>

      <footer className="footer">
        <p>Powered by BLS12-381 and Groth16 proofs (EIP-2537)</p>
      </footer>
    </div>
  )
}

export default App
