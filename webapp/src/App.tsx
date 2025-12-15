import { useState, useEffect } from 'react'
import { useAccount, useConnect, useDisconnect, useChainId } from 'wagmi'
import { ShieldForm } from './components/ShieldForm'
import { UnshieldForm } from './components/UnshieldForm'
import { ProverStatus } from './components/ProverStatus'
import { initProver } from './lib/prover'
import './App.css'

type TabType = 'shield' | 'unshield'

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('shield')
  const [proverReady, setProverReady] = useState(false)
  const [proverError, setProverError] = useState<string | null>(null)

  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()
  const chainId = useChainId()

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
              <span className="chain">Chain: {chainId}</span>
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
      </header>

      <ProverStatus ready={proverReady} error={proverError} />

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
            {activeTab === 'shield' && <ShieldForm />}
            {activeTab === 'unshield' && <UnshieldForm />}
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
