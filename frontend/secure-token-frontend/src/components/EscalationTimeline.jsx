export default function EscalationTimeline({ logs }) {
  const levels = logs
    .map((l) => l.global_threat)
    .filter(Boolean)
    .slice(0, 6)
    .reverse();

  return (
    <div className="bg-white/5 p-6 rounded-xl mt-6">
      <h2 className="text-xl font-bold text-yellow-400 mb-4">
        📊 Threat Escalation Timeline
      </h2>

      <div className="flex items-center gap-4">
        {levels.map((lvl, idx) => (
          <div key={idx} className="flex items-center gap-2">
            <div
              className={`px-3 py-1 rounded ${
                lvl === "ATTACK"
                  ? "bg-red-600"
                  : lvl === "HIGH"
                  ? "bg-orange-500"
                  : lvl === "ELEVATED"
                  ? "bg-yellow-400"
                  : "bg-green-500"
              }`}
            >
              {lvl}
            </div>
            {idx !== levels.length - 1 && (
              <span className="text-gray-400">→</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}