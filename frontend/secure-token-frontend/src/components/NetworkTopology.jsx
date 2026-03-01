export default function NetworkTopology({ threatLevel }) {

  const color =
    threatLevel === "ATTACK"
      ? "bg-red-500"
      : threatLevel === "HIGH"
      ? "bg-orange-500"
      : "bg-green-500";

  return (
    <div className="bg-[#020617] rounded-xl p-6 border border-slate-700">

      <h2 className="text-cyan-400 mb-6">
        🌐 Network Topology
      </h2>

      <div className="flex items-center justify-center gap-10">

        <div className="bg-blue-600 px-6 py-3 rounded-lg">
          Client
        </div>

        <div className="w-20 h-1 bg-slate-600 relative">
          <div className={`absolute h-1 w-10 ${color} animate-pulse`} />
        </div>

        <div className="bg-purple-600 px-6 py-3 rounded-lg">
          Gateway
        </div>

        <div className="w-20 h-1 bg-slate-600 relative">
          <div className={`absolute h-1 w-10 ${color} animate-pulse`} />
        </div>

        <div className="bg-green-600 px-6 py-3 rounded-lg">
          Resource Server
        </div>

      </div>
    </div>
  );
}