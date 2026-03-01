import { useMemo } from "react";

export default function AIThreatPrediction({ logs }) {
  const prediction = useMemo(() => {
    const replay = logs.filter((l) => l.status === "REPLAY_JTI").length;
    const revoked = logs.filter((l) => l.status === "TOKEN_REVOKED").length;
    const denied = logs.filter((l) => l.action === "ACCESS_DENIED").length;

    const riskScore = replay * 4 + revoked * 6 + denied * 2;

    if (riskScore > 80)
      return { level: "CRITICAL", color: "text-red-600" };
    if (riskScore > 40)
      return { level: "HIGH", color: "text-orange-500" };
    if (riskScore > 20)
      return { level: "MEDIUM", color: "text-yellow-400" };

    return { level: "LOW", color: "text-green-400" };
  }, [logs]);

  return (
    <div className="bg-[#0a0f2c] rounded-xl p-6 shadow-lg">
      <h2 className="text-lg mb-3 text-blue-400 font-semibold">
        AI Threat Forecast
      </h2>

      <div className="text-center">
        <div className={`text-5xl font-bold ${prediction.color}`}>
          {prediction.level}
        </div>

        <p className="text-gray-400 mt-2">
          Predicted threat escalation based on attack patterns
        </p>
      </div>
    </div>
  );
}