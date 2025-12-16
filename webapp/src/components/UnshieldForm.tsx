import { useState, useEffect, useRef } from 'react';
import { useAccount, useWriteContract, useReadContract, useWaitForTransactionReceipt, usePublicClient } from 'wagmi';
import { parseUnits, isAddress, encodeFunctionData } from 'viem';
import {
  generateUnshieldProof,
  generateRandomness,
  deriveAssetType,
} from '../lib/prover';
import type { SpendProofResult, MerkleNode } from '../lib/prover';
import { MASP_POOL_ABI, ERC20_ABI } from '../lib/contracts';

interface UnshieldFormProps {
  defaultToken: `0x${string}`;
  poolAddress?: `0x${string}`;
  onSuccess?: () => void;
}

type SimulationStatus = 'idle' | 'simulating' | 'success' | 'error';

export function UnshieldForm({ defaultToken, poolAddress, onSuccess }: UnshieldFormProps) {
  const { address } = useAccount();
  const { writeContractAsync, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash: txHash });
  const publicClient = usePublicClient();

  const [tokenAddress, setTokenAddress] = useState<string>(defaultToken);
  const [amount, setAmount] = useState('');
  const [recipient, setRecipient] = useState('');

  // MASP-specific inputs
  const [proofGenerationKeyAk, setProofGenerationKeyAk] = useState('');
  const [proofGenerationKeyNsk, setProofGenerationKeyNsk] = useState('');
  const [diversifier, setDiversifier] = useState('');
  const [rcm, setRcm] = useState('');
  const [merklePathJson, setMerklePathJson] = useState('');

  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofGenerated, setProofGenerated] = useState(false);
  const [proofTime, setProofTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Simulation state
  const [simulationStatus, setSimulationStatus] = useState<SimulationStatus>('idle');
  const [simulationError, setSimulationError] = useState<string | null>(null);

  const maspPoolAddress = poolAddress;

  // Update token address when defaultToken changes
  useEffect(() => {
    setTokenAddress(defaultToken);
  }, [defaultToken]);

  // Call onSuccess when transaction is confirmed
  useEffect(() => {
    if (isSuccess) {
      onSuccess?.();
    }
  }, [isSuccess, onSuccess]);

  // Timer effect for proof generation
  useEffect(() => {
    if (isGeneratingProof) {
      const startTime = Date.now();
      timerRef.current = setInterval(() => {
        setElapsedTime(Date.now() - startTime);
      }, 50);
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [isGeneratingProof]);

  // Read token info
  const { data: tokenDecimals } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'decimals',
    query: { enabled: isAddress(tokenAddress) },
  });

  const { data: tokenSymbol } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'symbol',
    query: { enabled: isAddress(tokenAddress) },
  });

  // Read merkle root from pool
  const { data: merkleRoot } = useReadContract({
    address: maspPoolAddress,
    abi: MASP_POOL_ABI,
    functionName: 'getMerkleRoot',
    query: { enabled: !!maspPoolAddress },
  });

  const decimals = tokenDecimals ?? 18;

  // Parse merkle path from JSON
  const parseMerklePath = (json: string): MerkleNode[] => {
    try {
      const parsed = JSON.parse(json);
      if (!Array.isArray(parsed)) {
        throw new Error('Merkle path must be an array');
      }
      return parsed.map((node: { hash: string; is_right: boolean }) => ({
        hash: node.hash,
        is_right: node.is_right,
      }));
    } catch (e) {
      throw new Error('Invalid merkle path JSON: ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  // Simulate the unshield transaction
  const simulateTransaction = async (
    proofBytes: `0x${string}`,
    publicInputs: `0x${string}`[],
    amountBigInt: bigint,
    recipientAddr: `0x${string}`
  ): Promise<{ success: boolean; error?: string }> => {
    if (!publicClient || !maspPoolAddress || !address) {
      return { success: false, error: 'Client not ready' };
    }

    const SIMULATION_TIMEOUT = 15000;

    try {
      const data = encodeFunctionData({
        abi: MASP_POOL_ABI,
        functionName: 'unshield',
        args: [tokenAddress as `0x${string}`, amountBigInt, recipientAddr, proofBytes, publicInputs],
      });

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Simulation timed out after 15 seconds.')), SIMULATION_TIMEOUT);
      });

      await Promise.race([
        publicClient.call({
          account: address,
          to: maspPoolAddress,
          data,
        }),
        timeoutPromise,
      ]);

      return { success: true };
    } catch (err) {
      const errorStr = err instanceof Error ? err.message : String(err);

      if (errorStr.includes('InvalidProof')) {
        return { success: false, error: 'Proof verification failed. Invalid spend proof.' };
      }
      if (errorStr.includes('NullifierAlreadySpent')) {
        return { success: false, error: 'Nullifier already spent. These tokens have been withdrawn.' };
      }
      if (errorStr.includes('InvalidMerkleRoot')) {
        return { success: false, error: 'Invalid merkle root. The anchor is not a valid historical root.' };
      }
      if (errorStr.includes('Invalid public inputs')) {
        return { success: false, error: 'Invalid public inputs. Expected 7 inputs for Spend circuit.' };
      }

      return { success: false, error: `Simulation failed: ${errorStr.slice(0, 200)}` };
    }
  };

  const handleUnshield = async () => {
    if (!maspPoolAddress || !isAddress(tokenAddress) || !recipient || !merkleRoot) return;
    if (!proofGenerationKeyAk || !proofGenerationKeyNsk || !diversifier || !rcm) return;

    setError(null);
    setSimulationError(null);
    setIsGeneratingProof(true);
    setProofGenerated(false);
    setProofTime(null);
    setElapsedTime(0);
    setSimulationStatus('idle');

    const startTime = Date.now();

    try {
      const amountBigInt = parseUnits(amount, decimals);

      // Parse merkle path
      let merklePath: MerkleNode[] = [];
      if (merklePathJson.trim()) {
        merklePath = parseMerklePath(merklePathJson);
      }

      // Generate randomness values
      const ar = generateRandomness();  // Re-randomization scalar
      const rcv = generateRandomness(); // Value commitment randomness

      // Derive asset type from token address
      const assetType = deriveAssetType(tokenAddress);

      console.log('[UI] Starting Spend proof generation (real MASP)...');
      console.log('[UI] Token:', tokenAddress);
      console.log('[UI] Asset Type:', assetType);
      console.log('[UI] Amount:', amountBigInt.toString());
      console.log('[UI] Anchor (merkle root):', merkleRoot);
      console.log('[UI] Merkle path length:', merklePath.length);

      // Generate the unshield proof using real MASP Spend circuit
      const proofResult: SpendProofResult = await generateUnshieldProof({
        amount: '0x' + amountBigInt.toString(16),
        asset_type: assetType,
        proof_generation_key_ak: proofGenerationKeyAk,
        proof_generation_key_nsk: proofGenerationKeyNsk,
        diversifier: diversifier,
        rcm: rcm,
        ar: ar,
        anchor: merkleRoot as string,
        merkle_path: merklePath,
        rcv: rcv,
      });

      const elapsed = Date.now() - startTime;
      setProofTime(elapsed);
      saveProofTime(elapsed); // Save for future time estimates
      console.log(`[UI] Spend proof generation completed in ${elapsed}ms`);
      console.log('[UI] Proof result:', proofResult);

      if (!proofResult.success) {
        throw new Error(proofResult.error || 'Proof generation failed');
      }

      setProofGenerated(true);
      setIsGeneratingProof(false);

      // Convert proof to bytes
      const proofBytes = proofResult.proof.startsWith('0x')
        ? proofResult.proof as `0x${string}`
        : ('0x' + proofResult.proof) as `0x${string}`;

      // Build public inputs array for MASP Spend circuit (7 inputs)
      // Order: rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]
      const publicInputs: `0x${string}`[] = [
        formatBytes32(proofResult.rk_u),
        formatBytes32(proofResult.rk_v),
        formatBytes32(proofResult.cv_u),
        formatBytes32(proofResult.cv_v),
        formatBytes32(proofResult.anchor),
        formatBytes32(proofResult.nf_0),
        formatBytes32(proofResult.nf_1),
      ];

      console.log('[UI] Proof bytes length:', proofBytes.length);
      console.log('[UI] Public inputs (7 for Spend):', publicInputs);

      // Simulate the transaction before sending
      setSimulationStatus('simulating');
      console.log('[UI] Simulating transaction...');

      const simResult = await simulateTransaction(
        proofBytes,
        publicInputs,
        amountBigInt,
        recipient as `0x${string}`
      );

      if (!simResult.success) {
        setSimulationStatus('error');
        setSimulationError(simResult.error || 'Simulation failed');
        console.error('[UI] Simulation failed:', simResult.error);
        throw new Error(simResult.error || 'Transaction simulation failed');
      }

      setSimulationStatus('success');
      console.log('[UI] Simulation successful, submitting transaction...');

      // Submit the unshield transaction
      await writeContractAsync({
        address: maspPoolAddress,
        abi: MASP_POOL_ABI,
        functionName: 'unshield',
        args: [
          tokenAddress as `0x${string}`,
          amountBigInt,
          recipient as `0x${string}`,
          proofBytes,
          publicInputs,
        ],
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unshield operation failed';
      setError(errorMessage);
      setIsGeneratingProof(false);
      console.error('[UI] Unshield error:', err);
    }
  };

  // Helper to format a hex string as bytes32
  const formatBytes32 = (input: string): `0x${string}` => {
    const hex = input.startsWith('0x') ? input.slice(2) : input;
    return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
  };

  // Pre-fill recipient with connected wallet address
  const handleUseMyAddress = () => {
    if (address) {
      setRecipient(address);
    }
  };

  const canUnshield =
    isAddress(tokenAddress) &&
    amount &&
    isAddress(recipient) &&
    proofGenerationKeyAk &&
    proofGenerationKeyNsk &&
    diversifier &&
    rcm &&
    merkleRoot &&
    !isPending &&
    !isGeneratingProof &&
    !!maspPoolAddress;

  // Format time display
  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${(ms / 1000).toFixed(1)}s`;
  };

  // Get estimated proof time from localStorage (default 45s for Spend circuit - larger than Output)
  const getEstimatedProofTime = (): number => {
    try {
      const stored = localStorage.getItem('masp-spend-proof-times');
      if (stored) {
        const times = JSON.parse(stored) as number[];
        if (times.length > 0) {
          const recent = times.slice(-3);
          return Math.round(recent.reduce((a, b) => a + b, 0) / recent.length);
        }
      }
    } catch {
      // Ignore localStorage errors
    }
    return 45000; // Default 45 seconds (Spend is larger than Output)
  };

  // Save proof time to localStorage
  const saveProofTime = (ms: number) => {
    try {
      const stored = localStorage.getItem('masp-spend-proof-times');
      const times = stored ? JSON.parse(stored) as number[] : [];
      times.push(ms);
      if (times.length > 10) times.shift();
      localStorage.setItem('masp-spend-proof-times', JSON.stringify(times));
    } catch {
      // Ignore localStorage errors
    }
  };

  const estimatedTime = getEstimatedProofTime();
  const progressPercent = isGeneratingProof
    ? Math.min(95, Math.round((elapsedTime / estimatedTime) * 100))
    : 0;
  const remainingTime = Math.max(0, estimatedTime - elapsedTime);

  return (
    <div className="form-container">
      <h2>Unshield Tokens</h2>
      <p className="form-description">
        Withdraw tokens from the shielded pool using the Namada MASP Spend circuit.
        You need the proof generation key and note details from when you shielded the tokens.
      </p>

      <div className="form-group">
        <label htmlFor="tokenAddressUnshield">Token Address</label>
        <input
          id="tokenAddressUnshield"
          type="text"
          placeholder="0x..."
          value={tokenAddress}
          onChange={(e) => setTokenAddress(e.target.value)}
        />
        {tokenSymbol && <span className="token-info">{tokenSymbol}</span>}
      </div>

      <div className="form-group">
        <label htmlFor="amountUnshield">Amount</label>
        <input
          id="amountUnshield"
          type="text"
          placeholder="0.0"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <div className="form-group">
        <label htmlFor="recipient">Recipient Address</label>
        <div className="input-with-button">
          <input
            id="recipient"
            type="text"
            placeholder="0x..."
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
          />
          <button onClick={handleUseMyAddress} className="btn secondary small">
            Use My Address
          </button>
        </div>
      </div>

      <h3 className="section-title">Note Details</h3>

      <div className="form-group">
        <label htmlFor="proofGenKeyAk">Proof Generation Key (ak)</label>
        <input
          id="proofGenKeyAk"
          type="password"
          placeholder="0x... (32 bytes)"
          value={proofGenerationKeyAk}
          onChange={(e) => setProofGenerationKeyAk(e.target.value)}
        />
        <span className="form-hint warning">
          Secret key component - keep private!
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="proofGenKeyNsk">Proof Generation Key (nsk)</label>
        <input
          id="proofGenKeyNsk"
          type="password"
          placeholder="0x... (32 bytes)"
          value={proofGenerationKeyNsk}
          onChange={(e) => setProofGenerationKeyNsk(e.target.value)}
        />
        <span className="form-hint warning">
          Secret key component - keep private!
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="diversifier">Diversifier</label>
        <input
          id="diversifier"
          type="text"
          placeholder="0x... (11 bytes)"
          value={diversifier}
          onChange={(e) => setDiversifier(e.target.value)}
        />
        <span className="form-hint">
          The diversifier from the payment address used when shielding.
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="rcm">Note Commitment Randomness (rcm)</label>
        <input
          id="rcm"
          type="text"
          placeholder="0x... (32 bytes)"
          value={rcm}
          onChange={(e) => setRcm(e.target.value)}
        />
        <span className="form-hint">
          The randomness used to create the note commitment when shielding.
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="merklePath">Merkle Path (JSON)</label>
        <textarea
          id="merklePath"
          placeholder='[{"hash": "0x...", "is_right": true}, ...]'
          value={merklePathJson}
          onChange={(e) => setMerklePathJson(e.target.value)}
          rows={3}
        />
        <span className="form-hint">
          JSON array of merkle path nodes. Each node has "hash" (bytes32) and "is_right" (boolean).
        </span>
      </div>

      {merkleRoot && (
        <div className="info-box">
          <strong>Current Merkle Root (Anchor):</strong>
          <code>{(merkleRoot as string).slice(0, 18)}...</code>
        </div>
      )}

      {error && <div className="error-message">{error}</div>}

      {isSuccess && (
        <div className="success-message">
          Unshield successful! Transaction: {txHash?.slice(0, 10)}...
        </div>
      )}

      {isGeneratingProof && (
        <div className="proof-progress">
          <div className="proof-spinner"></div>
          <div className="proof-progress-text">
            <span>Generating MASP Spend proof...</span>
            <div className="proof-timing">
              <span className="proof-timer">{formatTime(elapsedTime)}</span>
              <span className="proof-separator"> / </span>
              <span className="proof-estimate">~{formatTime(estimatedTime)}</span>
            </div>
          </div>
          <div className="proof-progress-bar">
            <div
              className="proof-progress-bar-inner"
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>
          <div className="proof-progress-info">
            {remainingTime > 0 ? (
              <span>Estimated time remaining: ~{formatTime(remainingTime)}</span>
            ) : (
              <span>Almost done...</span>
            )}
            <span className="progress-percent">{progressPercent}%</span>
          </div>
        </div>
      )}

      {/* Simulation Status */}
      {simulationStatus === 'simulating' && (
        <div className="simulation-status simulating">
          <div className="simulation-spinner"></div>
          <span>Simulating transaction...</span>
        </div>
      )}

      {simulationStatus === 'success' && (
        <div className="simulation-status success">
          <span>Transaction simulation passed</span>
        </div>
      )}

      {simulationStatus === 'error' && simulationError && (
        <div className="simulation-status error">
          <strong>Simulation failed:</strong>
          <p>{simulationError}</p>
        </div>
      )}

      <div className="button-group">
        <button
          onClick={handleUnshield}
          disabled={!canUnshield}
          className="btn primary"
        >
          {isGeneratingProof
            ? 'Generating Proof...'
            : simulationStatus === 'simulating'
            ? 'Simulating...'
            : isPending
            ? 'Confirming...'
            : isConfirming
            ? 'Waiting for confirmation...'
            : 'Unshield Tokens'}
        </button>
      </div>

      {proofGenerated && proofTime !== null && (
        <div className="proof-status">
          MASP Spend proof generated in {formatTime(proofTime)} (BLS12-381 Groth16, 7 public inputs)
        </div>
      )}

      {!maspPoolAddress && (
        <div className="warning-message">
          MASP Pool contract not deployed on this network. Please deploy contracts first.
        </div>
      )}
    </div>
  );
}
