import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { WagmiProvider, createConfig, http } from 'wagmi'
import { mainnet, sepolia, localhost } from 'wagmi/chains'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { injected } from 'wagmi/connectors'
import './index.css'
import App from './App.tsx'

// Configure wagmi - Sepolia is the primary network
const config = createConfig({
  chains: [sepolia, mainnet, localhost],
  connectors: [injected()],
  transports: {
    [sepolia.id]: http('https://rpc.sepolia.org'),
    [mainnet.id]: http(),
    [localhost.id]: http('http://localhost:8545'),
  },
})

const queryClient = new QueryClient()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>,
)
