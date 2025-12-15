import { useState, useEffect, useRef } from 'react';
import { useAccount, useChainId, useWriteContract, useReadContract, useWaitForTransactionReceipt } from 'wagmi';
import { parseUnits, isAddress } from 'viem';
import { generateUnshieldProof } from '../lib/prover';
import { MASP_POOL_ABI, ERC20_ABI, getMaspPoolAddress } from '../lib/contracts';

export function UnshieldForm() {
  const { address } = useAccount();
  const chainId = useChainId();
  const { writeContractAsync, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash: txHash });

  const [tokenAddress, setTokenAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [recipient, setRecipient] = useState('');
  const [spendKey, setSpendKey] = useState('');
  const [noteCommitment, setNoteCommitment] = useState('');
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofGenerated, setProofGenerated] = useState(false);
  const [proofTime, setProofTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const maspPoolAddress = getMaspPoolAddress(chainId);

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

  const handleUnshield = async () => {
    if (!maspPoolAddress || !isAddress(tokenAddress) || !recipient || !spendKey || !merkleRoot) return;

    setError(null);
    setIsGeneratingProof(true);
    setProofGenerated(false);
    setProofTime(null);
    setElapsedTime(0);

    const startTime = Date.now();

    try {
      const amountBigInt = parseUnits(amount, decimals);

      console.log('[UI] Starting unshield proof generation...');

      // Generate the unshield proof
      const proofResult = await generateUnshieldProof({
        nullifier: noteCommitment, // Use note commitment to derive nullifier
        merkle_root: merkleRoot as string,
        merkle_path: [], // Simplified - real implementation needs actual path
        note_commitment: noteCommitment,
        amount: '0x' + amountBigInt.toString(16),
        recipient: recipient,
        spend_key: spendKey,
      });

      const elapsed = Date.now() - startTime;
      setProofTime(elapsed);
      console.log(`[UI] Unshield proof generation completed in ${elapsed}ms`);

      if (!proofResult.success) {
        throw new Error(proofResult.error || 'Proof generation failed');
      }

      setProofGenerated(true);
      setIsGeneratingProof(false);

      // Convert proof to bytes
      const proofBytes = ('0x' + proofResult.proof) as `0x${string}`;

      // Convert public inputs to bytes32 array
      const publicInputs = proofResult.public_inputs.map((input) => {
        const hex = input.startsWith('0x') ? input.slice(2) : input;
        return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
      });

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
      setError(err instanceof Error ? err.message : 'Unshield operation failed');
      setIsGeneratingProof(false);
    }
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
    spendKey &&
    noteCommitment &&
    !isPending &&
    !isGeneratingProof;

  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="form-container">
      <h2>Unshield Tokens</h2>
      <p className="form-description">
        Withdraw tokens from the shielded pool. You need the spend key and note commitment from when you shielded the tokens.
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

      <div className="form-group">
        <label htmlFor="noteCommitment">Note Commitment</label>
        <input
          id="noteCommitment"
          type="text"
          placeholder="0x..."
          value={noteCommitment}
          onChange={(e) => setNoteCommitment(e.target.value)}
        />
        <span className="form-hint">
          The note commitment from the Shield event when you deposited.
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="spendKey">Spend Key (Private)</label>
        <input
          id="spendKey"
          type="password"
          placeholder="0x..."
          value={spendKey}
          onChange={(e) => setSpendKey(e.target.value)}
        />
        <span className="form-hint warning">
          Keep this secret! This key proves ownership of the shielded tokens.
        </span>
      </div>

      {merkleRoot && (
        <div className="info-box">
          <strong>Current Merkle Root:</strong>
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
            <span>Generating zk-SNARK proof...</span>
            <span className="proof-timer">{formatTime(elapsedTime)}</span>
          </div>
          <div className="proof-progress-bar">
            <div className="proof-progress-bar-inner"></div>
          </div>
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
            : isPending
            ? 'Confirming...'
            : isConfirming
            ? 'Waiting for confirmation...'
            : 'Unshield Tokens'}
        </button>
      </div>

      {proofGenerated && proofTime !== null && (
        <div className="proof-status">
          Proof generated in {formatTime(proofTime)} (BLS12-381 Groth16, ~512 bytes)
        </div>
      )}

      {!maspPoolAddress && (
        <div className="warning-message">
          MASP Pool contract not deployed on this network (Chain ID: {chainId})
        </div>
      )}
    </div>
  );
}
