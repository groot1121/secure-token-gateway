import { useMemo } from "react";

export default function RealAttackMap({ logs = [], threatLevel }) {

  // Ensure logs always exists
  const safeLogs = logs || [];

  const attackLogs = useMemo(() => {

    if (!Array.isArray(safeLogs)) return [];

    return safeLogs.filter(
      (log) =>
        log.status === "REPLAY_JTI" ||
        log.device_threat === "HIGH" ||
        log.device_threat === "ATTACK"
    );

  }, [safeLogs]);

  const active = threatLevel === "HIGH" || threatLevel === "ATTACK";

  return (

    <div className="bg-white/5 backdrop-blur-xl border border-white/10 p-6 rounded-xl mt-6">

      <h2 className="text-xl font-bold mb-4 text-red-400">
        📡 Live Attack Map
      </h2>

      <div className="relative h-64 bg-black rounded overflow-hidden">

        {active && attackLogs.length > 0 && (

          attackLogs.slice(0,5).map((_,i)=>(
            <div
              key={i}
              className="absolute w-3 h-3 bg-red-500 rounded-full animate-ping"
              style={{
                top: `${20 + i*10}%`,
                left: `${30 + i*15}%`
              }}
            />
          ))

        )}

        <div className="absolute inset-0 flex items-center justify-center text-gray-500">
          Global Network Monitoring
        </div>

      </div>

    </div>

  );

}