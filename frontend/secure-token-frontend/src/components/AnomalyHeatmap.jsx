import { useMemo } from "react";

export default function AnomalyHeatmap({ logs }) {

  const anomalyData = useMemo(() => {
    return logs.slice(0, 20).map((log) => ({
      value: log.device_risk || 0
    }));
  }, [logs]);

  return (
    <div className="bg-white/5 backdrop-blur-xl border border-white/10 p-6 rounded-xl mt-6">
      <h2 className="text-xl font-bold mb-4 text-purple-400">
        🧠 AI Anomaly Heatmap
      </h2>

      <div className="grid grid-cols-10 gap-2">
        {anomalyData.map((item, idx) => {
          const intensity = Math.min(item.value / 800, 1);

          return (
            <div
              key={idx}
              className="h-8 rounded transition-all duration-500"
              style={{
                backgroundColor: `rgba(255,0,0,${intensity})`,
                boxShadow: `0 0 ${intensity * 20}px rgba(255,0,0,0.7)`
              }}
            />
          );
        })}
      </div>
    </div>
  );
}