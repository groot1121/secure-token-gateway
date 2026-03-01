import { useMemo } from "react";

export default function PulsingAttackHeatmap({ logs }) {

  const heatmap = useMemo(() => {

    const map = {};

    logs.forEach((log) => {

      if (!log.ip) return;

      if (!map[log.ip]) {
        map[log.ip] = 0;
      }

      map[log.ip] += 1;

    });

    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

  }, [logs]);

  return (
    <div className="bg-[#0a0f2c] p-5 rounded-xl mt-6">

      <h2 className="text-lg font-bold text-red-400 mb-4">
        Attack Heatmap
      </h2>

      <div className="grid grid-cols-2 gap-3">

        {heatmap.map(([ip, count]) => (
          <div
            key={ip}
            className="bg-[#050816] p-3 rounded flex justify-between items-center animate-pulse"
          >
            <span>{ip}</span>
            <span className="text-red-500">{count}</span>
          </div>
        ))}

      </div>

    </div>
  );
}