import { useState, useEffect, useRef, useCallback } from 'react';
import { useAccount, useWriteContract, useReadContract, useWaitForTransactionReceipt, usePublicClient } from 'wagmi';
import { parseUnits, formatUnits, isAddress, encodeFunctionData } from 'viem';
import { generateShieldProof, generateRandomness } from '../lib/prover';
import { MASP_POOL_ABI, ERC20_ABI } from '../lib/contracts';

interface ShieldFormProps {
  defaultToken: `0x${string}`;
  poolAddress?: `0x${string}`;
  onSuccess?: () => void;
}

type SimulationStatus = 'idle' | 'simulating' | 'success' | 'error';

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function ShieldForm({ defaultToken, poolAddress, onSuccess }: ShieldFormProps) {
  const { address } = useAccount();
  const { writeContractAsync, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash: txHash });
  const publicClient = usePublicClient();

  const [tokenAddress, setTokenAddress] = useState<string>(defaultToken);
  const [amount, setAmount] = useState('');
  const [recipientPk, setRecipientPk] = useState('');
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofGenerated, setProofGenerated] = useState(false);
  const [proofTime, setProofTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Simulation state
  const [simulationStatus, setSimulationStatus] = useState<SimulationStatus>('idle');
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [validation, setValidation] = useState<ValidationResult>({ valid: true, errors: [], warnings: [] });

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

  const { data: tokenBalance, refetch: refetchBalance } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [address!],
    query: { enabled: isAddress(tokenAddress) && !!address },
  });

  const { data: allowance, refetch: refetchAllowance } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'allowance',
    args: [address!, maspPoolAddress!],
    query: { enabled: isAddress(tokenAddress) && !!address && !!maspPoolAddress },
  });

  const decimals = tokenDecimals ?? 18;

  // Validate inputs and check for potential issues
  const validateInputs = useCallback((): ValidationResult => {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check pool address
    if (!maspPoolAddress) {
      errors.push('MASP Pool contract not deployed on this network');
    }

    // Check token address
    if (!isAddress(tokenAddress)) {
      errors.push('Invalid token address');
    }

    // Check amount
    if (!amount || amount === '0') {
      errors.push('Amount must be greater than 0');
    } else {
      try {
        const amountBigInt = parseUnits(amount, decimals);

        // Check balance
        if (tokenBalance !== undefined && amountBigInt > tokenBalance) {
          errors.push(`Insufficient balance. You have ${formatUnits(tokenBalance, decimals)} ${tokenSymbol || 'tokens'}`);
        }

        // Check allowance
        if (allowance !== undefined && amountBigInt > allowance) {
          errors.push(`Insufficient allowance. Current allowance: ${formatUnits(allowance, decimals)} ${tokenSymbol || 'tokens'}. Please approve first.`);
        }
      } catch {
        errors.push('Invalid amount format');
      }
    }

    // Check recipient public key
    if (!recipientPk) {
      errors.push('Recipient public key is required');
    } else if (!recipientPk.startsWith('0x')) {
      warnings.push('Public key should start with 0x');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }, [maspPoolAddress, tokenAddress, amount, decimals, tokenBalance, tokenSymbol, allowance, recipientPk]);

  // Update validation when inputs change
  useEffect(() => {
    if (amount && recipientPk && isAddress(tokenAddress)) {
      const result = validateInputs();
      setValidation(result);
    } else {
      setValidation({ valid: true, errors: [], warnings: [] });
    }
  }, [amount, recipientPk, tokenAddress, tokenBalance, allowance, validateInputs]);

  // Simulate the shield transaction with timeout
  const simulateTransaction = async (
    proofBytes: `0x${string}`,
    publicInputs: `0x${string}`[],
    amountBigInt: bigint
  ): Promise<{ success: boolean; error?: string }> => {
    if (!publicClient || !maspPoolAddress || !address) {
      return { success: false, error: 'Client not ready' };
    }

    // Add timeout to prevent hanging
    const SIMULATION_TIMEOUT = 15000; // 15 seconds

    try {
      // Encode the shield function call
      const data = encodeFunctionData({
        abi: MASP_POOL_ABI,
        functionName: 'shield',
        args: [tokenAddress as `0x${string}`, amountBigInt, proofBytes, publicInputs],
      });

      // Create timeout promise
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Simulation timed out after 15 seconds. The contract may not be deployed or the network is slow.')), SIMULATION_TIMEOUT);
      });

      // Simulate the transaction using eth_call with timeout
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
      // Parse the error to get a human-readable message
      const errorMessage = parseSimulationError(err);
      return { success: false, error: errorMessage };
    }
  };

  // Parse simulation errors into human-readable messages
  const parseSimulationError = (err: unknown): string => {
    const errorStr = err instanceof Error ? err.message : String(err);

    // Common error patterns
    if (errorStr.includes('InvalidProof') || errorStr.includes('0x09bde339')) {
      return 'Proof verification failed. The generated proof is invalid for this circuit.';
    }
    if (errorStr.includes('InvalidCommitment') || errorStr.includes('0x9dd854d3')) {
      return 'The note commitment has already been used.';
    }
    if (errorStr.includes('TransferFailed') || errorStr.includes('0x90b8ec18')) {
      return 'Token transfer failed. Check your balance and approval.';
    }
    if (errorStr.includes('Invalid public inputs')) {
      return 'Invalid public inputs. Expected 2 inputs: [valueCommitment, noteCommitment].';
    }
    if (errorStr.includes('ERC20: transfer amount exceeds balance')) {
      return 'Insufficient token balance for this transfer.';
    }
    if (errorStr.includes('ERC20: insufficient allowance') || errorStr.includes('ERC20: transfer amount exceeds allowance')) {
      return 'Insufficient token allowance. Please approve tokens first.';
    }
    if (errorStr.includes('execution reverted')) {
      // Try to extract the revert reason
      const reasonMatch = errorStr.match(/reason="([^"]+)"/);
      if (reasonMatch) {
        return `Transaction reverted: ${reasonMatch[1]}`;
      }
      return 'Transaction will revert. Check proof and inputs.';
    }

    return `Simulation failed: ${errorStr.slice(0, 200)}`;
  };

  const handleApprove = async () => {
    if (!maspPoolAddress || !isAddress(tokenAddress)) return;

    setError(null);
    try {
      const amountBigInt = parseUnits(amount, decimals);
      await writeContractAsync({
        address: tokenAddress as `0x${string}`,
        abi: ERC20_ABI,
        functionName: 'approve',
        args: [maspPoolAddress, amountBigInt],
      });
      // Refetch allowance after approval
      setTimeout(() => refetchAllowance(), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Approval failed');
    }
  };

  const handleShield = async () => {
    if (!maspPoolAddress || !isAddress(tokenAddress) || !recipientPk) return;

    // Pre-flight validation
    const validationResult = validateInputs();
    if (!validationResult.valid) {
      setError(validationResult.errors.join('\n'));
      return;
    }

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
      const randomness = generateRandomness();

      console.log('[UI] Starting proof generation...');
      console.log('[UI] Token:', tokenAddress);
      console.log('[UI] Amount:', amountBigInt.toString());
      console.log('[UI] Recipient PK:', recipientPk);

      // Generate the shield proof
      const proofResult = await generateShieldProof({
        token_address: tokenAddress,
        amount: '0x' + amountBigInt.toString(16),
        recipient_pk: recipientPk,
        randomness: randomness,
      });

      const elapsed = Date.now() - startTime;
      setProofTime(elapsed);
      console.log(`[UI] Proof generation completed in ${elapsed}ms`);
      console.log('[UI] Proof result:', proofResult);

      if (!proofResult.success) {
        throw new Error(proofResult.error || 'Proof generation failed');
      }

      // Validate public inputs count
      if (proofResult.public_inputs.length !== 2) {
        throw new Error(`Expected 2 public inputs, got ${proofResult.public_inputs.length}. The shield circuit requires [valueCommitment, noteCommitment].`);
      }

      setProofGenerated(true);
      setIsGeneratingProof(false);

      // Convert proof to bytes
      const proofBytes = ('0x' + proofResult.proof) as `0x${string}`;

      // Convert public inputs to bytes32 array
      const publicInputs = proofResult.public_inputs.map((input) => {
        // Ensure each input is properly formatted as bytes32
        const hex = input.startsWith('0x') ? input.slice(2) : input;
        return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
      });

      console.log('[UI] Proof bytes length:', proofBytes.length);
      console.log('[UI] Public inputs:', publicInputs);

      // Simulate the transaction before sending
      setSimulationStatus('simulating');
      console.log('[UI] Simulating transaction...');

      const simResult = await simulateTransaction(proofBytes, publicInputs, amountBigInt);

      if (!simResult.success) {
        setSimulationStatus('error');
        setSimulationError(simResult.error || 'Simulation failed');
        console.error('[UI] Simulation failed:', simResult.error);
        throw new Error(simResult.error || 'Transaction simulation failed');
      }

      setSimulationStatus('success');
      console.log('[UI] Simulation successful, submitting transaction...');

      // Submit the shield transaction
      await writeContractAsync({
        address: maspPoolAddress,
        abi: MASP_POOL_ABI,
        functionName: 'shield',
        args: [tokenAddress as `0x${string}`, amountBigInt, proofBytes, publicInputs],
      });

      // Refetch balance after successful shield
      setTimeout(() => refetchBalance(), 2000);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Shield operation failed';
      setError(errorMessage);
      setIsGeneratingProof(false);
      console.error('[UI] Shield error:', err);
    }
  };

  const needsApproval = (() => {
    if (!amount || !allowance) return false;
    try {
      const amountBigInt = parseUnits(amount, decimals);
      return allowance < amountBigInt;
    } catch {
      return false;
    }
  })();

  const insufficientBalance = (() => {
    if (!amount || tokenBalance === undefined) return false;
    try {
      const amountBigInt = parseUnits(amount, decimals);
      return amountBigInt > tokenBalance;
    } catch {
      return false;
    }
  })();

  const canShield = !needsApproval && !insufficientBalance && isAddress(tokenAddress) && amount && recipientPk && !isPending && !isGeneratingProof && !!maspPoolAddress;

  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="form-container">
      <h2>Shield Tokens</h2>
      <p className="form-description">
        Deposit ERC20 tokens into the shielded pool. Your tokens will be privately held and can be withdrawn later with a valid proof.
      </p>

      <div className="form-group">
        <label htmlFor="tokenAddress">Token Address</label>
        <input
          id="tokenAddress"
          type="text"
          placeholder="0x..."
          value={tokenAddress}
          onChange={(e) => setTokenAddress(e.target.value)}
        />
        {tokenSymbol && tokenBalance !== undefined && (
          <span className="token-info">
            Balance: {formatUnits(tokenBalance, decimals)} {tokenSymbol}
          </span>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="amount">Amount</label>
        <input
          id="amount"
          type="text"
          placeholder="0.0"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          className={insufficientBalance ? 'input-error' : ''}
        />
        {insufficientBalance && (
          <span className="form-hint warning">
            Insufficient balance
          </span>
        )}
        {needsApproval && !insufficientBalance && amount && (
          <span className="form-hint warning">
            Approval required before shielding
          </span>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="recipientPk">Recipient Public Key (Viewing Key)</label>
        <input
          id="recipientPk"
          type="text"
          placeholder="0x..."
          value={recipientPk}
          onChange={(e) => setRecipientPk(e.target.value)}
        />
        <span className="form-hint">
          This is the public key that will be able to view and spend the shielded tokens.
        </span>
      </div>

      {/* Validation Warnings */}
      {validation.warnings.length > 0 && (
        <div className="warning-message">
          {validation.warnings.map((warning, i) => (
            <div key={i}>{warning}</div>
          ))}
        </div>
      )}

      {/* Pre-flight Validation Errors */}
      {validation.errors.length > 0 && !error && (
        <div className="validation-errors">
          <strong>Please fix the following issues:</strong>
          <ul>
            {validation.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      {error && <div className="error-message">{error}</div>}

      {isSuccess && (
        <div className="success-message">
          Shield successful! Transaction: {txHash?.slice(0, 10)}...
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
        {needsApproval && !insufficientBalance ? (
          <button
            onClick={handleApprove}
            disabled={isPending || !isAddress(tokenAddress) || insufficientBalance}
            className="btn primary"
          >
            {isPending ? 'Approving...' : `Approve ${tokenSymbol || 'Token'}`}
          </button>
        ) : (
          <button
            onClick={handleShield}
            disabled={!canShield}
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
              : insufficientBalance
              ? 'Insufficient Balance'
              : 'Shield Tokens'}
          </button>
        )}
      </div>

      {proofGenerated && proofTime !== null && (
        <div className="proof-status">
          Proof generated in {formatTime(proofTime)} (BLS12-381 Groth16, ~512 bytes)
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
