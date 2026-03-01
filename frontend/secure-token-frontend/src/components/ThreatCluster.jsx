import { useMemo } from "react";

export default function ThreatCluster({ logs }) {

  const clusters = useMemo(() => {

    const map = {};

    logs.forEach((log) => {

      if (!log.status) return;

      if (!map[log.status]) {
        map[log.status] = 0;
      }

      map[log.status] += 1;
    });

    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

  }, [logs]);

  return (
    <div className="bg-[#0a0f2c] p-5 rounded-xl mt-6">

      <h2 className="text-lg font-bold text-purple-400 mb-4">
        Threat Clusters
      </h2>

      <div className="space-y-2">

        {clusters.map(([type, count]) => (
          <div
            key={type}
            className="flex justify-between bg-[#050816] p-3 rounded"
          >
            <span>{type}</span>
            <span className="text-red-400">{count}</span>
          </div>
        ))}

      </div>
    </div>
  );
}