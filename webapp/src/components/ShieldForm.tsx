import { useState, useEffect, useRef, useCallback } from 'react';
import { useAccount, useWriteContract, useReadContract, useWaitForTransactionReceipt, usePublicClient } from 'wagmi';
import { parseUnits, formatUnits, isAddress, encodeFunctionData } from 'viem';
import {
  generateShieldProof,
  generateRandomness,
  generateRandomPaymentAddress,
  deriveAssetType,
} from '../lib/prover';
import type { OutputProofResult } from '../lib/prover';
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
  const [recipientDiversifier, setRecipientDiversifier] = useState('');
  const [recipientPkD, setRecipientPkD] = useState('');
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

  // Generate a random valid payment address (diversifier + pk_d)
  const handleGeneratePaymentAddress = () => {
    try {
      const paymentAddr = generateRandomPaymentAddress();
      setRecipientDiversifier(paymentAddr.diversifier);
      setRecipientPkD(paymentAddr.pk_d);
      setError(null);
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      setError('Failed to generate payment address: ' + errorMsg);
    }
  };

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

    // Check recipient diversifier
    if (!recipientDiversifier) {
      errors.push('Recipient diversifier is required');
    } else if (!recipientDiversifier.startsWith('0x') || recipientDiversifier.length !== 24) { // 11 bytes = 22 hex + 0x
      warnings.push('Diversifier should be 11 bytes (0x + 22 hex chars)');
    }

    // Check recipient pk_d
    if (!recipientPkD) {
      errors.push('Recipient pk_d is required');
    } else if (!recipientPkD.startsWith('0x') || recipientPkD.length !== 66) { // 32 bytes = 64 hex + 0x
      warnings.push('pk_d should be 32 bytes (0x + 64 hex chars)');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }, [maspPoolAddress, tokenAddress, amount, decimals, tokenBalance, tokenSymbol, allowance, recipientDiversifier, recipientPkD]);

  // Update validation when inputs change
  useEffect(() => {
    if (amount && recipientDiversifier && recipientPkD && isAddress(tokenAddress)) {
      const result = validateInputs();
      setValidation(result);
    } else {
      setValidation({ valid: true, errors: [], warnings: [] });
    }
  }, [amount, recipientDiversifier, recipientPkD, tokenAddress, tokenBalance, allowance, validateInputs]);

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
      return 'Invalid public inputs. Expected 5 inputs: [cv.u, cv.v, epk.u, epk.v, cm].';
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
    if (!maspPoolAddress || !isAddress(tokenAddress) || !recipientDiversifier || !recipientPkD) return;

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

      // Generate randomness values for the proof
      const rcm = generateRandomness();  // Note commitment randomness
      const esk = generateRandomness();  // Ephemeral secret key
      const rcv = generateRandomness();  // Value commitment randomness

      // Derive asset type from token address
      const assetType = deriveAssetType(tokenAddress);

      console.log('[UI] Starting Output proof generation (real MASP)...');
      console.log('[UI] Token:', tokenAddress);
      console.log('[UI] Asset Type:', assetType);
      console.log('[UI] Amount:', amountBigInt.toString());
      console.log('[UI] Diversifier:', recipientDiversifier);
      console.log('[UI] pk_d:', recipientPkD);

      // Generate the shield proof using real MASP Output circuit
      const proofResult: OutputProofResult = await generateShieldProof({
        token_address: tokenAddress,
        amount: '0x' + amountBigInt.toString(16),
        asset_type: assetType,
        recipient_diversifier: recipientDiversifier,
        recipient_pk_d: recipientPkD,
        rcm: rcm,
        esk: esk,
        rcv: rcv,
      });

      const elapsed = Date.now() - startTime;
      setProofTime(elapsed);
      console.log(`[UI] Proof generation completed in ${elapsed}ms`);
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

      // Build public inputs array for MASP Output circuit (5 inputs)
      // Order: cv.u, cv.v, epk.u, epk.v, cm
      const publicInputs: `0x${string}`[] = [
        formatBytes32(proofResult.cv_u),
        formatBytes32(proofResult.cv_v),
        formatBytes32(proofResult.epk_u),
        formatBytes32(proofResult.epk_v),
        formatBytes32(proofResult.cm),
      ];

      console.log('[UI] Proof bytes length:', proofBytes.length);
      console.log('[UI] Public inputs (5 for Output):', publicInputs);

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
      // Handle different error types (Error, string from WASM, or unknown)
      let errorMessage: string;
      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'string') {
        errorMessage = err;
      } else if (err && typeof err === 'object' && 'message' in err) {
        errorMessage = String((err as { message: unknown }).message);
      } else {
        errorMessage = 'Shield operation failed: ' + String(err);
      }
      setError(errorMessage);
      setIsGeneratingProof(false);
      console.error('[UI] Shield error:', err);
    }
  };

  // Helper to format a hex string as bytes32
  const formatBytes32 = (input: string): `0x${string}` => {
    const hex = input.startsWith('0x') ? input.slice(2) : input;
    return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
  };

  const needsApproval = (() => {
    if (!amount || allowance === undefined) return false;
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

  const canShield = !needsApproval && !insufficientBalance && isAddress(tokenAddress) && amount && recipientDiversifier && recipientPkD && !isPending && !isGeneratingProof && !!maspPoolAddress;

  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="form-container">
      <h2>Shield Tokens</h2>
      <p className="form-description">
        Deposit ERC20 tokens into the shielded pool using the Namada MASP Output circuit.
        Your tokens will be privately held and can be withdrawn later with a valid spend proof.
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
        <label htmlFor="recipientAddress">
          Recipient Payment Address
          <button
            type="button"
            className="btn small secondary"
            onClick={handleGeneratePaymentAddress}
            style={{ marginLeft: '10px' }}
          >
            Generate Random Address
          </button>
        </label>
        <span className="form-hint" style={{ marginBottom: '8px', display: 'block' }}>
          Click "Generate Random Address" to create a valid payment address for testing, or enter your own diversifier and pk_d below.
        </span>
      </div>

      <div className="form-group">
        <label htmlFor="recipientDiversifier">Diversifier (11 bytes)</label>
        <input
          id="recipientDiversifier"
          type="text"
          placeholder="0x... (11 bytes)"
          value={recipientDiversifier}
          onChange={(e) => setRecipientDiversifier(e.target.value)}
        />
      </div>

      <div className="form-group">
        <label htmlFor="recipientPkD">pk_d - Diversified Transmission Key (32 bytes)</label>
        <input
          id="recipientPkD"
          type="text"
          placeholder="0x... (32 bytes)"
          value={recipientPkD}
          onChange={(e) => setRecipientPkD(e.target.value)}
        />
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
            <span>Generating MASP Output proof...</span>
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
          MASP Output proof generated in {formatTime(proofTime)} (BLS12-381 Groth16, 5 public inputs)
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
