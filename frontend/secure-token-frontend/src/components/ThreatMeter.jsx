export default function ThreatMeter({ level, score }) {

  const colors = {
    NORMAL: "text-green-400",
    LOW: "text-yellow-400",
    MEDIUM: "text-orange-400",
    HIGH: "text-red-400",
    ATTACK: "text-red-600"
  };

  return (
    <div className="bg-[#020617] p-6 rounded-xl border border-slate-700 flex justify-between">

      <div>
        <p className="text-slate-400">
          Global Threat Level
        </p>

        <h2 className={`text-3xl font-bold ${colors[level]}`}>
          {level}
        </h2>
      </div>

      <div className="text-right">
        <p className="text-slate-400">Risk Score</p>
        <h2 className="text-3xl font-bold">
          {score}
        </h2>
      </div>

    </div>
  );
}