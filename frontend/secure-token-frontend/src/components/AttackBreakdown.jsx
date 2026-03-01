export default function AttackBreakdown({ logs }) {

  const replay = logs.filter(
    (l) => l.status === "REPLAY_JTI"
  ).length;

  const signature = logs.filter(
    (l) => l.status === "BAD_SIGNATURE"
  ).length;

  const geo = logs.filter(
    (l) => l.status === "GEO_ANOMALY"
  ).length;

  return (
    <div className="grid grid-cols-3 gap-4">

      <div className="bg-[#020617] p-6 rounded-xl border border-red-500/20">
        <h3 className="text-red-400">Replay Attacks</h3>
        <p className="text-3xl">{replay}</p>
      </div>

      <div className="bg-[#020617] p-6 rounded-xl border border-yellow-500/20">
        <h3 className="text-yellow-400">Signature Failures</h3>
        <p className="text-3xl">{signature}</p>
      </div>

      <div className="bg-[#020617] p-6 rounded-xl border border-purple-500/20">
        <h3 className="text-purple-400">Geo Anomalies</h3>
        <p className="text-3xl">{geo}</p>
      </div>

    </div>
  );
}