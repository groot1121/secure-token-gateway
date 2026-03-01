export default function StatsBar({ stats }) {
  return (
    <div className="grid grid-cols-3 gap-4 mb-6">

      <StatCard title="Active Devices" value={stats.devices} />

      <StatCard title="Tokens Issued" value={stats.tokensIssued} />

      <StatCard title="Replay Attacks" value={stats.replayAttacks} />

    </div>
  );
}

function StatCard({ title, value }) {
  return (
    <div className="bg-[#0b1026] border border-[#1b2245] p-4 rounded-lg">
      <p className="text-gray-400 text-sm">{title}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}