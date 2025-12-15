import { useState } from 'react';
import { useAccount, useChainId, useWriteContract, useReadContract, useWaitForTransactionReceipt } from 'wagmi';
import { parseUnits, formatUnits, isAddress } from 'viem';
import { generateShieldProof, generateRandomness } from '../lib/prover';
import { MASP_POOL_ABI, ERC20_ABI, getMaspPoolAddress } from '../lib/contracts';

export function ShieldForm() {
  const { address } = useAccount();
  const chainId = useChainId();
  const { writeContractAsync, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash: txHash });

  const [tokenAddress, setTokenAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [recipientPk, setRecipientPk] = useState('');
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofGenerated, setProofGenerated] = useState(false);

  const maspPoolAddress = getMaspPoolAddress(chainId);

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

  const { data: tokenBalance } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [address!],
    query: { enabled: isAddress(tokenAddress) && !!address },
  });

  const { data: allowance } = useReadContract({
    address: tokenAddress as `0x${string}`,
    abi: ERC20_ABI,
    functionName: 'allowance',
    args: [address!, maspPoolAddress!],
    query: { enabled: isAddress(tokenAddress) && !!address && !!maspPoolAddress },
  });

  const decimals = tokenDecimals ?? 18;

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
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Approval failed');
    }
  };

  const handleShield = async () => {
    if (!maspPoolAddress || !isAddress(tokenAddress) || !recipientPk) return;

    setError(null);
    setIsGeneratingProof(true);
    setProofGenerated(false);

    try {
      const amountBigInt = parseUnits(amount, decimals);
      const randomness = generateRandomness();

      // Generate the shield proof
      const proofResult = await generateShieldProof({
        token_address: tokenAddress,
        amount: '0x' + amountBigInt.toString(16),
        recipient_pk: recipientPk,
        randomness: randomness,
      });

      if (!proofResult.success) {
        throw new Error(proofResult.error || 'Proof generation failed');
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

      // Submit the shield transaction
      await writeContractAsync({
        address: maspPoolAddress,
        abi: MASP_POOL_ABI,
        functionName: 'shield',
        args: [tokenAddress as `0x${string}`, amountBigInt, proofBytes, publicInputs],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Shield operation failed');
      setIsGeneratingProof(false);
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

  const canShield = !needsApproval && isAddress(tokenAddress) && amount && recipientPk && !isPending && !isGeneratingProof;

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
        />
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

      {error && <div className="error-message">{error}</div>}

      {isSuccess && (
        <div className="success-message">
          Shield successful! Transaction: {txHash?.slice(0, 10)}...
        </div>
      )}

      <div className="button-group">
        {needsApproval ? (
          <button
            onClick={handleApprove}
            disabled={isPending || !isAddress(tokenAddress)}
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
              : isPending
              ? 'Confirming...'
              : isConfirming
              ? 'Waiting for confirmation...'
              : 'Shield Tokens'}
          </button>
        )}
      </div>

      {proofGenerated && (
        <div className="proof-status">Proof generated successfully</div>
      )}

      {!maspPoolAddress && (
        <div className="warning-message">
          MASP Pool contract not deployed on this network (Chain ID: {chainId})
        </div>
      )}
    </div>
  );
}
