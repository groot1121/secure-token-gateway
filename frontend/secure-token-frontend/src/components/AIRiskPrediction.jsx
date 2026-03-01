import { useMemo } from "react";

export default function AIRiskPrediction({ riskHistory }) {

  const prediction = useMemo(() => {
    if (riskHistory.length < 5) return [];

    const last = riskHistory.slice(-5);

    const slope =
      (last[last.length - 1].value - last[0].value) / last.length;

    const predictions = [];

    let lastValue = last[last.length - 1].value;

    for (let i = 1; i <= 10; i++) {
      lastValue = Math.max(0, lastValue + slope * 10);

      predictions.push({
        time: Date.now() + i * 10000,
        value: lastValue,
      });
    }

    return predictions;
  }, [riskHistory]);

  return (
    <div className="bg-[#0a0f2c] p-5 rounded-xl mt-6">

      <h2 className="text-lg font-bold mb-3 text-cyan-400">
        AI Risk Prediction
      </h2>

      <div className="space-y-2 text-sm">

        {prediction.map((p, i) => (
          <div
            key={i}
            className="flex justify-between bg-[#050816] px-3 py-2 rounded"
          >
            <span>+{(i + 1) * 10}s</span>
            <span className="text-red-400">
              {Math.round(p.value)}
            </span>
          </div>
        ))}

      </div>
    </div>
  );
}