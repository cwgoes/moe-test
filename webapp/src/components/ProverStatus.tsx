interface ProverStatusProps {
  ready: boolean;
  error: string | null;
}

export function ProverStatus({ ready, error }: ProverStatusProps) {
  if (error) {
    return (
      <div className="prover-status error">
        <span className="status-dot error"></span>
        <span>Prover Error: {error}</span>
      </div>
    );
  }

  if (!ready) {
    return (
      <div className="prover-status loading">
        <span className="status-dot loading"></span>
        <span>Initializing WASM prover...</span>
      </div>
    );
  }

  return (
    <div className="prover-status ready">
      <span className="status-dot ready"></span>
      <span>Prover Ready (BLS12-381 / Groth16)</span>
    </div>
  );
}
