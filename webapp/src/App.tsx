import { useState, useEffect } from 'react'
import { useAccount, useConnect, useDisconnect, useChainId, useReadContract, usePublicClient, useWalletClient, useSwitchChain } from 'wagmi'
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
  clearDeployedContracts,
} from './lib/contracts'
import './App.css'

type TabType = 'shield' | 'unshield'
type DeployStep = 'idle' | 'deploying-verifier' | 'waiting-verifier' | 'deploying-pool' | 'waiting-pool' | 'verifying' | 'done'
type BytecodeStatus = 'unknown' | 'checking' | 'valid' | 'invalid' | 'error'

interface DeploymentStatus {
  step: DeployStep
  txHash?: `0x${string}`
  error?: string
  verifierBytecodeStatus: BytecodeStatus
  poolBytecodeStatus: BytecodeStatus
  pollingAttempt?: number
  lastPollingError?: string
}

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('shield')
  const [proverReady, setProverReady] = useState(false)
  const [proverError, setProverError] = useState<string | null>(null)
  const [verifierAddress, setVerifierAddress] = useState<`0x${string}` | undefined>()
  const [poolAddress, setPoolAddress] = useState<`0x${string}` | undefined>()
  const [deployment, setDeployment] = useState<DeploymentStatus>({
    step: 'idle',
    verifierBytecodeStatus: 'unknown',
    poolBytecodeStatus: 'unknown',
  })

  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()
  const chainId = useChainId()
  const { switchChain, isPending: isSwitchingChain } = useSwitchChain()
  const publicClient = usePublicClient()
  const { data: walletClient } = useWalletClient()

  // Check if we're on Sepolia
  const isOnSepolia = chainId === sepolia.id

  // Get default token address for the current chain
  const defaultToken = getDefaultTokenAddress(chainId)

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

    // Reset bytecode status when chain changes
    setDeployment(prev => ({
      ...prev,
      verifierBytecodeStatus: storedVerifier ? 'unknown' : 'unknown',
      poolBytecodeStatus: storedPool ? 'unknown' : 'unknown',
    }))
  }, [chainId])

  // Verify bytecode when addresses are set
  useEffect(() => {
    const verifyBytecode = async () => {
      if (!publicClient) return

      // Verify verifier bytecode
      if (verifierAddress && deployment.verifierBytecodeStatus === 'unknown') {
        setDeployment(prev => ({ ...prev, verifierBytecodeStatus: 'checking' }))
        try {
          const code = await publicClient.getCode({ address: verifierAddress })
          // Check if code exists (deployed contract has code)
          if (code && code !== '0x' && code.length > 10) {
            setDeployment(prev => ({ ...prev, verifierBytecodeStatus: 'valid' }))
          } else {
            setDeployment(prev => ({ ...prev, verifierBytecodeStatus: 'invalid' }))
          }
        } catch {
          setDeployment(prev => ({ ...prev, verifierBytecodeStatus: 'error' }))
        }
      }

      // Verify pool bytecode
      if (poolAddress && deployment.poolBytecodeStatus === 'unknown') {
        setDeployment(prev => ({ ...prev, poolBytecodeStatus: 'checking' }))
        try {
          const code = await publicClient.getCode({ address: poolAddress })
          if (code && code !== '0x' && code.length > 10) {
            setDeployment(prev => ({ ...prev, poolBytecodeStatus: 'valid' }))
          } else {
            setDeployment(prev => ({ ...prev, poolBytecodeStatus: 'invalid' }))
          }
        } catch {
          setDeployment(prev => ({ ...prev, poolBytecodeStatus: 'error' }))
        }
      }
    }

    verifyBytecode()
  }, [verifierAddress, poolAddress, publicClient, deployment.verifierBytecodeStatus, deployment.poolBytecodeStatus])

  // Manual polling for transaction receipt - more reliable than waitForTransactionReceipt
  const pollForReceipt = async (
    hash: `0x${string}`,
    timeoutMs: number = 180_000,
    pollIntervalMs: number = 3_000
  ) => {
    if (!publicClient) throw new Error('Public client not available')

    const startTime = Date.now()
    let attempts = 0
    let lastError: string | undefined

    while (Date.now() - startTime < timeoutMs) {
      attempts++
      setDeployment(prev => ({ ...prev, pollingAttempt: attempts, lastPollingError: lastError }))
      console.log(`[Deploy] Polling for receipt (attempt ${attempts}), hash: ${hash}`)

      try {
        const receipt = await publicClient.getTransactionReceipt({ hash })
        console.log('[Deploy] getTransactionReceipt response:', receipt)
        if (receipt) {
          console.log('[Deploy] Receipt found:', JSON.stringify(receipt, (_, v) => typeof v === 'bigint' ? v.toString() : v))
          setDeployment(prev => ({ ...prev, pollingAttempt: undefined, lastPollingError: undefined }))
          return receipt
        } else {
          lastError = 'Receipt returned null/undefined'
          console.log('[Deploy] Receipt was null/undefined')
        }
      } catch (err: unknown) {
        // Capture the actual error
        const errorMessage = err instanceof Error ? err.message : String(err)
        lastError = errorMessage
        console.error('[Deploy] getTransactionReceipt error:', errorMessage)
        console.error('[Deploy] Full error:', err)
        setDeployment(prev => ({ ...prev, lastPollingError: errorMessage }))
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, pollIntervalMs))
    }

    throw new Error(`Transaction receipt not found after ${timeoutMs / 1000} seconds. Last error: ${lastError || 'none'}`)
  }

  const handleDeploy = async () => {
    if (!walletClient || !publicClient) {
      setDeployment(prev => ({ ...prev, error: 'Wallet not connected' }))
      return
    }

    setDeployment({
      step: 'idle',
      verifierBytecodeStatus: 'unknown',
      poolBytecodeStatus: 'unknown',
      error: undefined,
      txHash: undefined,
    })

    try {
      let verifierAddr = getMaspVerifierAddress(chainId)

      // Deploy verifier if not already deployed
      if (!verifierAddr) {
        setDeployment(prev => ({ ...prev, step: 'deploying-verifier' }))

        const hash = await walletClient.deployContract({
          abi: MASP_VERIFIER_ABI,
          bytecode: MASP_VERIFIER_BYTECODE,
          gas: BigInt(12_000_000),
        })

        setDeployment(prev => ({ ...prev, step: 'waiting-verifier', txHash: hash }))
        console.log('[Deploy] Verifier tx hash:', hash)

        // Use manual polling instead of waitForTransactionReceipt
        const receipt = await pollForReceipt(hash)

        if (receipt.status === 'reverted') {
          throw new Error('Verifier deployment reverted')
        }

        if (!receipt.contractAddress) {
          throw new Error('No verifier contract address in receipt')
        }

        verifierAddr = receipt.contractAddress
        console.log('[Deploy] Verifier deployed at:', verifierAddr)
        setVerifierAddress(verifierAddr)
        saveDeployedContracts(chainId, { verifier: verifierAddr })
        setDeployment(prev => ({ ...prev, verifierBytecodeStatus: 'valid' }))
      }

      // Deploy pool
      setDeployment(prev => ({ ...prev, step: 'deploying-pool', txHash: undefined }))

      const poolHash = await walletClient.deployContract({
        abi: MASP_POOL_ABI,
        bytecode: MASP_POOL_BYTECODE,
        args: [verifierAddr],
        gas: BigInt(8_000_000),
      })

      setDeployment(prev => ({ ...prev, step: 'waiting-pool', txHash: poolHash }))
      console.log('[Deploy] Pool tx hash:', poolHash)

      // Use manual polling instead of waitForTransactionReceipt
      const poolReceipt = await pollForReceipt(poolHash)

      if (poolReceipt.status === 'reverted') {
        throw new Error('Pool deployment reverted')
      }

      if (!poolReceipt.contractAddress) {
        throw new Error('No pool contract address in receipt')
      }

      const poolAddr = poolReceipt.contractAddress
      console.log('[Deploy] Pool deployed at:', poolAddr)
      setPoolAddress(poolAddr)
      saveDeployedContracts(chainId, { pool: poolAddr })

      // Verify bytecode
      setDeployment(prev => ({ ...prev, step: 'verifying' }))

      const poolCode = await publicClient.getCode({ address: poolAddr })
      const poolValid = poolCode && poolCode !== '0x' && poolCode.length > 10

      setDeployment(prev => ({
        ...prev,
        step: 'done',
        poolBytecodeStatus: poolValid ? 'valid' : 'invalid',
      }))

    } catch (err) {
      console.error('[Deploy] Error:', err)
      setDeployment(prev => ({
        ...prev,
        step: 'idle',
        error: err instanceof Error ? err.message : 'Deployment failed',
      }))
    }
  }

  const isDeploying = deployment.step !== 'idle' && deployment.step !== 'done'
  const decimals = tokenDecimals ?? 18

  const handleClearContracts = () => {
    clearDeployedContracts(chainId)
    setVerifierAddress(undefined)
    setPoolAddress(undefined)
    setDeployment({
      step: 'idle',
      verifierBytecodeStatus: 'unknown',
      poolBytecodeStatus: 'unknown',
      error: undefined,
      txHash: undefined,
    })
  }

  const getDeployButtonText = () => {
    switch (deployment.step) {
      case 'deploying-verifier':
        return 'Deploying Verifier...'
      case 'waiting-verifier':
        return 'Waiting for Verifier...'
      case 'deploying-pool':
        return 'Deploying Pool...'
      case 'waiting-pool':
        return 'Waiting for Pool...'
      case 'verifying':
        return 'Verifying Bytecode...'
      case 'done':
        return 'Contracts Deployed!'
      default:
        return verifierAddress && !poolAddress ? 'Deploy MASP Pool' : 'Deploy MASP Contracts'
    }
  }

  const getBytecodeStatusIcon = (status: BytecodeStatus) => {
    switch (status) {
      case 'checking':
        return '⏳'
      case 'valid':
        return '✓'
      case 'invalid':
        return '✗'
      case 'error':
        return '⚠'
      default:
        return '?'
    }
  }

  const getBytecodeStatusClass = (status: BytecodeStatus) => {
    switch (status) {
      case 'valid':
        return 'bytecode-valid'
      case 'invalid':
        return 'bytecode-invalid'
      case 'error':
        return 'bytecode-error'
      default:
        return 'bytecode-unknown'
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
                <>
                  <span className="contract-address deployed">
                    {verifierAddress.slice(0, 6)}...{verifierAddress.slice(-4)}
                  </span>
                  <span className={`bytecode-status ${getBytecodeStatusClass(deployment.verifierBytecodeStatus)}`}>
                    {getBytecodeStatusIcon(deployment.verifierBytecodeStatus)}
                  </span>
                </>
              ) : (
                <span className="contract-address not-deployed">Not deployed</span>
              )}
            </div>
            <div className="contract-item">
              <span className="contract-label">Pool:</span>
              {poolAddress ? (
                <>
                  <span className="contract-address deployed">
                    {poolAddress.slice(0, 6)}...{poolAddress.slice(-4)}
                  </span>
                  <span className={`bytecode-status ${getBytecodeStatusClass(deployment.poolBytecodeStatus)}`}>
                    {getBytecodeStatusIcon(deployment.poolBytecodeStatus)}
                  </span>
                </>
              ) : (
                <span className="contract-address not-deployed">Not deployed</span>
              )}
            </div>
          </div>

          {/* Deployment Status Display */}
          {isDeploying && (
            <div className="deployment-status">
              <div className="deployment-step">
                <div className="deploy-spinner"></div>
                <span>{getDeployButtonText()}</span>
              </div>
              {deployment.txHash && (
                <div className="deployment-tx">
                  <span className="tx-label">Transaction:</span>
                  <a
                    href={`https://sepolia.etherscan.io/tx/${deployment.txHash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="tx-link"
                  >
                    {deployment.txHash.slice(0, 10)}...{deployment.txHash.slice(-8)}
                  </a>
                </div>
              )}
              {deployment.pollingAttempt && (
                <div className="deployment-polling">
                  <span className="polling-label">Polling attempt:</span>
                  <span className="polling-count">{deployment.pollingAttempt}</span>
                </div>
              )}
              {deployment.lastPollingError && (
                <div className="deployment-polling-error">
                  <span className="polling-error-label">Last RPC error:</span>
                  <code className="polling-error-message">{deployment.lastPollingError}</code>
                </div>
              )}
            </div>
          )}

          <div className="deploy-section">
            {!poolAddress ? (
              <>
                <button
                  onClick={handleDeploy}
                  disabled={isDeploying || !isConnected || !walletClient}
                  className="deploy-btn"
                >
                  {getDeployButtonText()}
                </button>
                {deployment.error && <div className="deploy-error">{deployment.error}</div>}
              </>
            ) : (
              <button
                onClick={handleClearContracts}
                disabled={isDeploying}
                className="btn secondary"
              >
                Clear & Redeploy Contracts
              </button>
            )}
          </div>

          {/* Bytecode Status Legend */}
          {(verifierAddress || poolAddress) && (
            <div className="bytecode-legend">
              <span className="legend-item"><span className="bytecode-valid">✓</span> = Bytecode verified</span>
              <span className="legend-item"><span className="bytecode-invalid">✗</span> = No bytecode found</span>
              <span className="legend-item"><span className="bytecode-unknown">?</span> = Not checked</span>
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
