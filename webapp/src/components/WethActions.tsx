import { useState } from 'react';
import { useAccount, useBalance, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { parseEther, formatEther } from 'viem';
import { WETH_ABI, ERC20_ABI, SEPOLIA_WETH_ADDRESS } from '../lib/contracts';

interface WethActionsProps {
  onSuccess?: () => void;
}

export function WethActions({ onSuccess }: WethActionsProps) {
  const { address } = useAccount();
  const [wrapAmount, setWrapAmount] = useState('');
  const [unwrapAmount, setUnwrapAmount] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Get ETH balance
  const { data: ethBalance, refetch: refetchEthBalance } = useBalance({
    address,
  });

  // Get WETH balance using useReadContract
  const { data: wethBalanceRaw, refetch: refetchWethBalance } = useReadContract({
    address: SEPOLIA_WETH_ADDRESS,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address },
  });

  const wethBalance = wethBalanceRaw ? { value: wethBalanceRaw as bigint } : undefined;

  const { writeContractAsync, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash: txHash });

  const refetchBalances = () => {
    refetchEthBalance();
    refetchWethBalance();
    onSuccess?.();
  };

  const handleWrap = async () => {
    if (!wrapAmount || !address) return;

    setError(null);
    try {
      const amountWei = parseEther(wrapAmount);

      // Check if user has enough ETH
      if (ethBalance && amountWei > ethBalance.value) {
        setError(`Insufficient ETH balance. You have ${formatEther(ethBalance.value)} ETH`);
        return;
      }

      await writeContractAsync({
        address: SEPOLIA_WETH_ADDRESS,
        abi: WETH_ABI,
        functionName: 'deposit',
        value: amountWei,
      });

      setWrapAmount('');
      // Refetch balances after a short delay
      setTimeout(refetchBalances, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Wrap failed');
    }
  };

  const handleUnwrap = async () => {
    if (!unwrapAmount || !address) return;

    setError(null);
    try {
      const amountWei = parseEther(unwrapAmount);

      // Check if user has enough WETH
      if (wethBalance && amountWei > wethBalance.value) {
        setError(`Insufficient WETH balance. You have ${formatEther(wethBalance.value)} WETH`);
        return;
      }

      await writeContractAsync({
        address: SEPOLIA_WETH_ADDRESS,
        abi: WETH_ABI,
        functionName: 'withdraw',
        args: [amountWei],
      });

      setUnwrapAmount('');
      // Refetch balances after a short delay
      setTimeout(refetchBalances, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unwrap failed');
    }
  };

  const setMaxWrap = () => {
    if (ethBalance) {
      // Leave some ETH for gas (0.01 ETH)
      const maxAmount = ethBalance.value > parseEther('0.01')
        ? ethBalance.value - parseEther('0.01')
        : BigInt(0);
      setWrapAmount(formatEther(maxAmount));
    }
  };

  const setMaxUnwrap = () => {
    if (wethBalance) {
      setUnwrapAmount(formatEther(wethBalance.value));
    }
  };

  return (
    <div className="weth-actions">
      <h3>Wrap/Unwrap ETH</h3>
      <p className="weth-description">
        Convert between ETH and WETH (Wrapped Ether) to use with the shielded pool.
      </p>

      <div className="weth-balances">
        <div className="balance-item">
          <span className="balance-label">ETH Balance:</span>
          <span className="balance-value">
            {ethBalance ? formatEther(ethBalance.value) : '0'} ETH
          </span>
        </div>
        <div className="balance-item">
          <span className="balance-label">WETH Balance:</span>
          <span className="balance-value">
            {wethBalance ? formatEther(wethBalance.value) : '0'} WETH
          </span>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      {isSuccess && (
        <div className="success-message">
          Transaction confirmed! Balances updated.
        </div>
      )}

      <div className="weth-form-row">
        <div className="weth-form-group">
          <label>Wrap ETH to WETH</label>
          <div className="input-with-button">
            <input
              type="text"
              placeholder="0.0"
              value={wrapAmount}
              onChange={(e) => setWrapAmount(e.target.value)}
              disabled={isPending || isConfirming}
            />
            <button
              onClick={setMaxWrap}
              className="btn small secondary"
              disabled={isPending || isConfirming}
            >
              Max
            </button>
          </div>
          <button
            onClick={handleWrap}
            disabled={!wrapAmount || isPending || isConfirming}
            className="btn primary"
          >
            {isPending || isConfirming ? 'Processing...' : 'Wrap ETH'}
          </button>
        </div>

        <div className="weth-form-group">
          <label>Unwrap WETH to ETH</label>
          <div className="input-with-button">
            <input
              type="text"
              placeholder="0.0"
              value={unwrapAmount}
              onChange={(e) => setUnwrapAmount(e.target.value)}
              disabled={isPending || isConfirming}
            />
            <button
              onClick={setMaxUnwrap}
              className="btn small secondary"
              disabled={isPending || isConfirming}
            >
              Max
            </button>
          </div>
          <button
            onClick={handleUnwrap}
            disabled={!unwrapAmount || isPending || isConfirming}
            className="btn primary"
          >
            {isPending || isConfirming ? 'Processing...' : 'Unwrap WETH'}
          </button>
        </div>
      </div>
    </div>
  );
}
