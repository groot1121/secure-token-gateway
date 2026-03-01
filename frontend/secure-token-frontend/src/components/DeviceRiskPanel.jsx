export default function DeviceRiskPanel({ logs }) {
  const latestByDevice = {};

  logs.forEach((log) => {
    if (!latestByDevice[log.device_id]) {
      latestByDevice[log.device_id] = log.device_risk || 0;
    }
  });

  const sorted = Object.entries(latestByDevice).sort(
    (a, b) => b[1] - a[1]
  );

  return (
    <div className="bg-black p-4 rounded-lg border border-gray-700 mt-6">
      <h2 className="text-xl font-bold mb-3">Device Risk Leaderboard</h2>

      {sorted.length === 0 && (
        <div className="text-gray-400">No device activity yet</div>
      )}

      {sorted.map(([device, score]) => (
        <div
          key={device}
          className="flex justify-between p-2 mb-2 bg-gray-800 rounded"
        >
          <span>{device}</span>
          <span
            className={`font-bold ${
              score >= 20
                ? "text-red-500"
                : score >= 10
                ? "text-yellow-400"
                : "text-green-400"
            }`}
          >
            {score}
          </span>
        </div>
      ))}
    </div>
  );
}